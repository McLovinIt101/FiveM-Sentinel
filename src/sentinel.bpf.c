// SPDX-License-Identifier: Dual MIT/GPL
/*
 * FiveM-Sentinel — XDP data plane.
 *
 * Line-rate L3/L4 filtering for a FiveM/FXServer endpoint (UDP + TCP on the
 * game port). Decisions, cheapest first:
 *
 *   1. Parse Ethernet/IPv4 (CO-RE via vmlinux.h).
 *   2. Config gate     — only touch traffic to the protected ip:port.
 *   3. Allow / block lists (per source IP; blocks carry a TTL).
 *   4. Fragment drop   — IP fragments aimed at the game port are illegitimate.
 *   5. UDP path        — drop reflector source ports; per-source token bucket.
 *   6. TCP path        — drop illegal flag combos; per-source SYN token bucket;
 *                        issue a raw SYN-cookie SYN-ACK with XDP_TX (kernel
 *                        6.8+); per-source rate limit on HTTP requests to the
 *                        spammed JSON endpoints (players/info/dynamic).
 *   7. Stats           — every decision bumps a per-CPU counter.
 *
 * The SYN-cookie ACK validation and connection splice are intentionally left
 * to nftables SYNPROXY (deploy/nftables-synproxy.conf), which shares the
 * kernel's syncookie secret with the helper used here. XDP only *generates*
 * the cookie SYN-ACK, which is the part that must run at line rate. This mirrors
 * tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c.
 *
 * License note: the raw SYN-cookie helpers are GPL-only, hence the dual
 * MIT/GPL license string below (the rest of the project is MIT).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sentinel.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define NS_PER_SEC 1000000000ULL

/* TCP option kinds/lengths not present in vmlinux.h. */
#define TCPOPT_MSS 2
#define TCPOLEN_MSS 4

/* FiveM/Quake connectionless ("out-of-band") packets are prefixed with four
 * 0xFF bytes followed by an ASCII command (getinfo/getstatus/rcon/...). */
#define FIVEM_OOB_MAGIC 0xFFFFFFFFu

/* Request classification returned by classify_request(). */
#define REQ_NONE         0
#define REQ_JSON         1 /* players/info/dynamic.json */
#define REQ_CLIENT_POST  2 /* POST /client (legit connection init) */
#define REQ_CLIENT_OTHER 3 /* /client with a non-POST method */

/* ----------------------------- BPF maps --------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sentinel_config);
} config_map SEC(".maps");

/* Allowlisted source IPs bypass all filtering. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} allowlist SEC(".maps");

/* Blocklisted source IPs are dropped until block_entry.expire_ns. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct block_entry);
} blocklist SEC(".maps");

/* Per-source token buckets. LRU so a spoofed-source flood self-evicts. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, __u32);
	__type(value, struct token_bucket);
} udp_buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, __u32);
	__type(value, struct token_bucket);
} syn_buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct token_bucket);
} l7_buckets SEC(".maps");

/* Dedicated stricter bucket for getinfo/getstatus OOB queries (reflection). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, struct token_bucket);
} oob_buckets SEC(".maps");

/* Optional per-source ICMP bucket (off by default). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct token_bucket);
} icmp_buckets SEC(".maps");

/* Cross-layer anti-spoof gate: IPs that completed a TCP `POST /client` map to
 * an expiry. Game UDP is gated on a fresh entry here (opt-in). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, __u32);
	__type(value, __u64); /* expire_ns (bpf_ktime domain) */
} validated_clients SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT__MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Per-source count of rate-limit drops, consumed by `sentinel --auto` to
 * promote chronic offenders into the blocklist. LRU so it self-trims. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} offenders SEC(".maps");

/* --------------------------- small helpers ------------------------------ */

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);
	if (c)
		(*c)++;
}

/* Record a counter and return an XDP verdict in one shot (used from main). */
#define VERDICT(action, stat)                                                 \
	do {                                                                      \
		stat_inc(stat);                                                       \
		return (action);                                                     \
	} while (0)

/* Note a per-source rate-limit drop for the userspace auto-mitigation loop. */
static __always_inline void offense_inc(__u32 ip)
{
	__u64 *c = bpf_map_lookup_elem(&offenders, &ip);

	if (c) {
		(*c)++;
	} else {
		__u64 one = 1;

		bpf_map_update_elem(&offenders, &ip, &one, BPF_ANY);
	}
}

/*
 * Token bucket shared by the UDP/SYN/L7 limiters. `map` is passed by address
 * and resolved at inline time, so the verifier always sees a concrete map.
 * Refill time is only advanced by whole tokens added, so sustained traffic
 * with sub-token gaps still accrues credit correctly (no starvation drift).
 * Returns 1 to allow, 0 to drop.
 */
static __always_inline int tb_allow(void *map, __u32 key, __u32 rate,
				    __u32 burst, __u64 now)
{
	struct token_bucket *tb;

	if (rate == 0 || burst == 0)
		return 1; /* limiter disabled for this class */

	tb = bpf_map_lookup_elem(map, &key);
	if (!tb) {
		struct token_bucket fresh = {
			.tokens = burst - 1, /* this packet consumes one */
			.ts_ns = now,
		};
		bpf_map_update_elem(map, &key, &fresh, BPF_ANY);
		return 1;
	}

	__u64 elapsed = now - tb->ts_ns;
	__u64 add = (elapsed * rate) / NS_PER_SEC;
	if (add > 0) {
		__u64 t = tb->tokens + add;
		tb->tokens = t > burst ? burst : t;
		tb->ts_ns = now;
	}
	if (tb->tokens > 0) {
		tb->tokens--;
		return 1;
	}
	return 0;
}

/* Source ports that legitimate FiveM clients never use — i.e. classic UDP
 * reflection/amplification services. Inbound UDP from these is always bogus. */
static __always_inline int is_reflector_port(__be16 port)
{
	switch (bpf_ntohs(port)) {
	case 19:    /* CHARGEN  */
	case 53:    /* DNS      */
	case 123:   /* NTP      */
	case 137:   /* NetBIOS  */
	case 161:   /* SNMP     */
	case 389:   /* CLDAP    */
	case 1900:  /* SSDP     */
	case 3702:  /* WS-Disc  */
	case 5353:  /* mDNS     */
	case 11211: /* memcached*/
		return 1;
	}
	return 0;
}

/* Drop scan/evasion flag combinations and unsolicited SYN-ACKs. */
static __always_inline int bad_tcp_flags(const struct tcphdr *t)
{
	if (!t->syn && !t->ack && !t->fin && !t->rst && !t->psh && !t->urg)
		return 1; /* NULL scan */
	if (t->syn && t->fin)
		return 1; /* SYN+FIN */
	if (t->syn && t->rst)
		return 1; /* SYN+RST */
	if (t->fin && t->urg && t->psh)
		return 1; /* XMAS scan */
	if (t->fin && !t->ack)
		return 1; /* bare FIN */
	if (t->syn && t->ack)
		return 1; /* a server never receives a legit SYN-ACK */
	return 0;
}

/* Compare n literal bytes at p, bounds-checked against data_end. */
static __always_inline int mem_is(const __u8 *p, const void *data_end,
				  const char *s, int n)
{
	if ((const void *)(p + n) > data_end)
		return 0;
#pragma unroll
	for (int i = 0; i < n; i++)
		if (p[i] != (__u8)s[i])
			return 0;
	return 1;
}

/*
 * Classify a TCP payload's HTTP request line as one of the FiveM endpoints
 * attackers abuse. Single-segment request lines only (multi-segment is handled
 * by the nginx/Cloudflare layer). Returns a REQ_* value.
 */
static __always_inline int classify_request(const __u8 *p, const void *data_end)
{
	const __u8 *path = 0;
	int is_post = 0;

	if (mem_is(p, data_end, "GET ", 4))
		path = p + 4;
	else if (mem_is(p, data_end, "HEAD ", 5))
		path = p + 5;
	else if (mem_is(p, data_end, "POST ", 5)) {
		path = p + 5;
		is_post = 1;
	} else {
		return REQ_NONE;
	}

	if (mem_is(path, data_end, "/players.json", 13) ||
	    mem_is(path, data_end, "/dynamic.json", 13) ||
	    mem_is(path, data_end, "/info.json", 10))
		return REQ_JSON;

	if (mem_is(path, data_end, "/client", 7))
		return is_post ? REQ_CLIENT_POST : REQ_CLIENT_OTHER;

	return REQ_NONE;
}

/* Quake-style connectionless packet: first four payload bytes are 0xFF. */
static __always_inline int is_oob(const __u8 *p, const void *data_end)
{
	if ((const void *)(p + 4) > data_end)
		return 0;
	return p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff;
}

/*
 * Martian / bogon source addresses that can never be a legitimate internet
 * client. Deliberately EXCLUDES RFC1918 (10/8, 172.16/12, 192.168/16) and
 * RFC6598 CGNAT (100.64/10) because FiveM reverse proxies legitimately use
 * those between proxy and origin.
 */
static __always_inline int is_bogon_src(__u32 saddr_net)
{
	__u32 h = bpf_ntohl(saddr_net);
	__u8 top = h >> 24;

	if (top == 0 || top == 127)   /* 0.0.0.0/8 "this network", 127/8 loopback */
		return 1;
	if ((h >> 16) == 0xA9FE)      /* 169.254/16 link-local */
		return 1;
	if ((h >> 28) >= 0xE)         /* 224/4 multicast + 240/4 reserved + 255.* */
		return 1;
	return 0;
}

/* ------------------------- IP/TCP checksums ----------------------------- */

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

/* Fold a raw bpf_csum_diff result together with the TCP/UDP pseudo-header.
 * proto and len are the numeric values of the pseudo-header's 16-bit words. */
static __always_inline __u16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
					       __u16 len, __u8 proto, __u32 csum)
{
	__u64 s = csum;

	s += (__u32)saddr;
	s += (__u32)daddr;
	s += (__u32)proto;
	s += (__u32)len;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/* ----------------------- SYN-cookie offload (6.8+) ---------------------- */
/*
 * Transform the incoming SYN (in place) into a SYN-ACK carrying a kernel SYN
 * cookie, then XDP_TX it back out the same NIC. The ACK that completes the
 * handshake is validated by nftables SYNPROXY, which shares the cookie secret.
 *
 * Only plain Ethernet + IPv4 with no IP options is handled here; anything else
 * returns -1 so the caller falls back to passing the SYN up the stack (where
 * nft SYNPROXY / tcp_syncookies still protects it). A minimal MSS-only option
 * is advertised — sufficient for FiveM's small TCP exchanges. Returns an XDP
 * action, or -1 for "not handled, fall back".
 */
static __always_inline int emit_syn_cookie(struct xdp_md *ctx,
					   const struct sentinel_config *cfg)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u32 tcp_len, client_seq, cookie;
	__s64 v;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_ABORTED;
	if (ip->ihl != 5) /* IP options present: let the stack handle it */
		return -1;
	tcp = (void *)(ip + 1);
	if ((void *)(tcp + 1) > data_end)
		return XDP_ABORTED;

	tcp_len = tcp->doff * 4;
	if (tcp_len < sizeof(*tcp) || tcp_len > 60)
		return XDP_ABORTED;
	if ((void *)((__u8 *)tcp + tcp_len) > data_end)
		return XDP_ABORTED;

	v = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, tcp_len);
	if (v < 0)
		return XDP_ABORTED;
	cookie = (__u32)v;
	client_seq = bpf_ntohl(tcp->seq);

	/* Resize to Eth(14) + IP(20) + TCP(20 + 4-byte MSS option) = 58 bytes. */
	{
		__u32 new_size = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 4;
		int delta = (int)new_size - (int)((long)data_end - (long)data);

		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_ABORTED;
	}

	/* Pointers are invalidated by adjust_tail — re-derive and re-check. */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_ABORTED;
	tcp = (void *)(ip + 1);
	if ((void *)((__u8 *)tcp + sizeof(*tcp) + 4) > data_end)
		return XDP_ABORTED;

	/* Swap MAC. */
	{
		__u8 mac[6];

		__builtin_memcpy(mac, eth->h_source, 6);
		__builtin_memcpy(eth->h_source, eth->h_dest, 6);
		__builtin_memcpy(eth->h_dest, mac, 6);
	}

	/* Rewrite IPv4 header. */
	{
		__be32 s = ip->saddr;

		ip->saddr = ip->daddr;
		ip->daddr = s;
	}
	ip->ttl = cfg->syn_ttl ? cfg->syn_ttl : 64;
	ip->tos = 0;
	ip->id = 0;
	ip->frag_off = bpf_htons(0x4000); /* Don't Fragment */
	ip->tot_len = bpf_htons(sizeof(*ip) + sizeof(*tcp) + 4);
	ip->check = 0;

	/* Rewrite TCP header into a SYN-ACK. */
	{
		__be16 sp = tcp->source;

		tcp->source = tcp->dest;
		tcp->dest = sp;
	}
	tcp->ack_seq = bpf_htonl(client_seq + 1);
	tcp->seq = bpf_htonl(cookie);
	tcp->res1 = 0;
	tcp->doff = 6; /* 20 + 4 bytes of options */
	tcp->fin = 0;
	tcp->syn = 1;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 1;
	tcp->urg = 0;
	tcp->ece = 0;
	tcp->cwr = 0;
	tcp->window = bpf_htons(0xffff);
	tcp->urg_ptr = 0;
	tcp->check = 0;

	/* MSS option immediately after the 20-byte TCP header. */
	{
		__u8 *opt = (__u8 *)tcp + sizeof(*tcp);
		__u16 mss = cfg->syn_mss ? cfg->syn_mss : 1460;

		if ((void *)(opt + 4) > data_end)
			return XDP_ABORTED;
		opt[0] = TCPOPT_MSS;
		opt[1] = TCPOLEN_MSS;
		opt[2] = (mss >> 8) & 0xff;
		opt[3] = mss & 0xff;
	}

	/* Recompute checksums (TCP header is now 24 bytes, no payload). */
	v = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp) + 4, 0);
	if (v < 0)
		return XDP_ABORTED;
	tcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, sizeof(*tcp) + 4,
				      IPPROTO_TCP, (__u32)v);
	v = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);
	if (v < 0)
		return XDP_ABORTED;
	ip->check = csum_fold((__u32)v);

	return XDP_TX;
}

/* ------------------------------- main ----------------------------------- */

SEC("xdp")
int fivem_sentinel(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct sentinel_config *cfg;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct block_entry *blk;
	__u32 zero = 0, src, ihl;
	__u64 now;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		VERDICT(XDP_PASS, STAT_PASS_NOT_TARGET);

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg)
		return XDP_PASS; /* not configured yet — never interfere */
	if (ip->daddr != cfg->protected_ip)
		VERDICT(XDP_PASS, STAT_PASS_NOT_TARGET);

	now = bpf_ktime_get_ns();
	src = ip->saddr;

	/* Allow / block lists. */
	if (bpf_map_lookup_elem(&allowlist, &src))
		VERDICT(XDP_PASS, STAT_PASS_ALLOWLIST);
	blk = bpf_map_lookup_elem(&blocklist, &src);
	if (blk) {
		if (blk->expire_ns == 0 || now < blk->expire_ns)
			VERDICT(XDP_DROP, STAT_DROP_BLOCKLIST);
		bpf_map_delete_elem(&blocklist, &src); /* TTL elapsed */
	}

	/* Spoofed/bogon source addresses (martians) — never a real client. */
	if ((cfg->flags & F_DROP_BOGON_SRC) && is_bogon_src(src))
		VERDICT(XDP_DROP, STAT_DROP_BOGON);

	/* Fragments aimed at the game port are never legitimate FiveM traffic. */
	if ((cfg->flags & F_DROP_FRAGMENTS) &&
	    (ip->frag_off & bpf_htons(0x3fff)))
		VERDICT(XDP_DROP, STAT_DROP_FRAG);

	if (ip->ihl < 5)
		VERDICT(XDP_ABORTED, STAT_ABORTED);
	ihl = ip->ihl * 4;

	if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)ip + ihl;
		__u8 *payload;

		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		if (udp->dest != cfg->protected_port)
			VERDICT(XDP_PASS, STAT_PASS_NOT_TARGET);

		if ((cfg->flags & F_DROP_AMP_PORTS) &&
		    is_reflector_port(udp->source))
			VERDICT(XDP_DROP, STAT_DROP_AMP);

		payload = (__u8 *)(udp + 1);

		/* Connectionless server-browser queries (getinfo/getstatus, …).
		 * These are the ~37x amplification vector. They legitimately come
		 * from clients that have NOT connected, so they bypass the gate but
		 * get their own strict per-source limiter. */
		if (is_oob(payload, data_end)) {
			if ((void *)(payload + 5) > data_end)
				VERDICT(XDP_DROP, STAT_DROP_OOB_MALFORMED);
			if ((cfg->flags & F_OOB_RATELIMIT) &&
			    !tb_allow(&oob_buckets, src, cfg->oob_rps,
				      cfg->oob_burst, now)) {
				offense_inc(src);
				VERDICT(XDP_DROP, STAT_DROP_OOB_RATE);
			}
			VERDICT(XDP_PASS, STAT_PASS);
		}

		/* Anti-spoof gate: real game UDP is always preceded by a TCP
		 * `POST /client` from the same IP. Spoofed sources can't do that. */
		if (cfg->flags & F_UDP_REQUIRE_CONNECT) {
			__u64 *exp = bpf_map_lookup_elem(&validated_clients, &src);

			if (!exp || (*exp != 0 && now > *exp))
				VERDICT(XDP_DROP, STAT_DROP_UNVALIDATED);
			*exp = now + (__u64)cfg->connect_ttl * NS_PER_SEC; /* keepalive */
			stat_inc(STAT_PASS_VALIDATED);
		}

		if ((cfg->flags & F_UDP_RATELIMIT) &&
		    !tb_allow(&udp_buckets, src, cfg->udp_pps, cfg->udp_burst, now)) {
			offense_inc(src);
			VERDICT(XDP_DROP, STAT_DROP_UDP_RATE);
		}

		VERDICT(XDP_PASS, STAT_PASS);
	}

	if (ip->protocol == IPPROTO_ICMP) {
		if ((cfg->flags & F_ICMP_RATELIMIT) &&
		    !tb_allow(&icmp_buckets, src, cfg->icmp_rps, cfg->icmp_burst,
			      now)) {
			offense_inc(src);
			VERDICT(XDP_DROP, STAT_DROP_ICMP);
		}
		VERDICT(XDP_PASS, STAT_PASS);
	}

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)ip + ihl;
		__u32 doff;
		__u8 *payload;

		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		if (tcp->dest != cfg->protected_port)
			VERDICT(XDP_PASS, STAT_PASS_NOT_TARGET);

		if ((cfg->flags & F_TCP_FLAG_CHECK) && bad_tcp_flags(tcp))
			VERDICT(XDP_DROP, STAT_DROP_TCP_FLAGS);

		/* New connection attempt. */
		if (tcp->syn && !tcp->ack) {
			if ((cfg->flags & F_SYN_RATELIMIT) &&
			    !tb_allow(&syn_buckets, src, cfg->syn_pps,
				      cfg->syn_burst, now)) {
				offense_inc(src);
				VERDICT(XDP_DROP, STAT_DROP_SYN_RATE);
			}

			if (cfg->flags & F_SYN_COOKIES) {
				int r = emit_syn_cookie(ctx, cfg);

				if (r == XDP_TX) {
					stat_inc(STAT_SYN_COOKIE_TX);
					return XDP_TX;
				}
				if (r >= 0) /* ABORTED/DROP from the builder */
					return r;
				/* r < 0: not handled — pass SYN to the stack. */
			}
			VERDICT(XDP_PASS, STAT_PASS);
		}

		/* Established data segment: inspect the HTTP request line. */
		doff = tcp->doff * 4;
		if (doff < sizeof(*tcp))
			doff = sizeof(*tcp);
		if (doff > 60)
			doff = 60;
		payload = (__u8 *)tcp + doff;
		if ((void *)payload < data_end) {
			int rc = classify_request(payload, data_end);

			if (rc != REQ_NONE) {
				/* /client is POST-only; optionally drop other methods. */
				if (rc == REQ_CLIENT_OTHER &&
				    (cfg->flags & F_DROP_BAD_CLIENT_METHOD))
					VERDICT(XDP_DROP, STAT_DROP_BAD_CLIENT_METHOD);

				if ((cfg->flags & F_L7_RATELIMIT) &&
				    !tb_allow(&l7_buckets, src, cfg->l7_rps,
					      cfg->l7_burst, now)) {
					offense_inc(src);
					VERDICT(XDP_DROP, STAT_DROP_L7_RATE);
				}

				/* A real, in-budget POST /client validates this IP for
				 * the cross-layer UDP gate. */
				if (rc == REQ_CLIENT_POST &&
				    (cfg->flags & F_UDP_REQUIRE_CONNECT)) {
					__u64 exp = now +
						(__u64)cfg->connect_ttl * NS_PER_SEC;

					bpf_map_update_elem(&validated_clients, &src,
							    &exp, BPF_ANY);
				}
			}
		}

		VERDICT(XDP_PASS, STAT_PASS);
	}

	/* Other L4 protocols to the protected host are not our concern. */
	VERDICT(XDP_PASS, STAT_PASS_NOT_TARGET);
}

char _license[] SEC("license") = "Dual MIT/GPL";
