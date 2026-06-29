/* SPDX-License-Identifier: MIT */
/*
 * FiveM-Sentinel — shared definitions.
 *
 * This header is included by BOTH the XDP data plane (sentinel.bpf.c, which
 * gets fixed-width integer types from the BTF-generated vmlinux.h) and the
 * userspace control plane (sentinel.c, which gets them from <linux/types.h>).
 * Keep everything in here valid in both translation units — no helper calls,
 * no libc, no kernel-only macros.
 */
#ifndef FIVEM_SENTINEL_H
#define FIVEM_SENTINEL_H

/* vmlinux.h already pulls in __u8/__u16/__u32/__u64. Outside of it (userspace)
 * we need linux/types.h for the same names. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define SENTINEL_VERSION "1.0.0"

/* bpffs directory where the maps are pinned so the CLI can manage the block /
 * allow lists and read stats without re-attaching the program. */
#define SENTINEL_PIN_DIR "/sys/fs/bpf/fivem-sentinel"

/* ---- Feature toggles (sentinel_config.flags bitmask) -------------------- */
#define F_DROP_FRAGMENTS (1u << 0) /* drop IP fragments aimed at the game port  */
#define F_DROP_AMP_PORTS (1u << 1) /* drop UDP coming from reflector src ports  */
#define F_UDP_RATELIMIT  (1u << 2) /* per-source UDP token bucket               */
#define F_SYN_COOKIES    (1u << 3) /* issue/validate raw XDP SYN cookies (6.8+) */
#define F_SYN_RATELIMIT  (1u << 4) /* per-source SYN token bucket               */
#define F_L7_RATELIMIT   (1u << 5) /* in-XDP players.json/info.json limiter     */
#define F_TCP_FLAG_CHECK (1u << 6) /* drop illegal TCP flag combinations        */
/* v2 — FiveM-protocol-aware */
#define F_OOB_RATELIMIT  (1u << 7) /* limit Quake-style getinfo/getstatus OOB   */
#define F_DROP_BOGON_SRC (1u << 8) /* drop martian/bogon source addresses       */
#define F_UDP_REQUIRE_CONNECT (1u << 9) /* gate game UDP on a prior /client POST */
#define F_ICMP_RATELIMIT (1u << 10) /* per-source ICMP token bucket             */
#define F_DROP_BAD_CLIENT_METHOD (1u << 11) /* drop non-POST /client requests   */

/* Balanced defaults: volumetric + protocol-aware protection that cannot drop a
 * legitimate player. The anti-spoof gate, ICMP limiter and non-POST /client
 * drop are situational and stay OFF until explicitly enabled. */
#define F_DEFAULTS                                                             \
	(F_DROP_FRAGMENTS | F_DROP_AMP_PORTS | F_UDP_RATELIMIT | F_SYN_COOKIES |   \
	 F_SYN_RATELIMIT | F_L7_RATELIMIT | F_TCP_FLAG_CHECK | F_OOB_RATELIMIT |   \
	 F_DROP_BOGON_SRC)

/*
 * Runtime configuration. One entry, key 0, in config_map. Populated by the
 * userspace loader so nothing about the protected target is hardcoded in the
 * BPF object. Rates are tokens (packets/requests) per second; bursts are the
 * token-bucket capacity (max instantaneous allowance).
 */
struct sentinel_config {
	__u32 protected_ip;    /* IPv4 address to protect, network byte order */
	__u16 protected_port;  /* TCP+UDP port to protect, network byte order */
	__u16 flags;           /* F_* bitmask                                 */

	__u32 udp_pps;         /* per-source UDP refill rate (pkts/s)         */
	__u32 udp_burst;       /* per-source UDP bucket capacity              */
	__u32 syn_pps;         /* per-source SYN refill rate (SYNs/s)         */
	__u32 syn_burst;       /* per-source SYN bucket capacity              */
	__u32 l7_rps;          /* per-source L7 request refill rate (req/s)   */
	__u32 l7_burst;        /* per-source L7 bucket capacity               */

	/* v2 tunables */
	__u32 oob_rps;         /* per-source getinfo/getstatus refill rate    */
	__u32 oob_burst;       /* per-source OOB bucket capacity              */
	__u32 icmp_rps;        /* per-source ICMP refill rate                 */
	__u32 icmp_burst;      /* per-source ICMP bucket capacity             */
	__u32 connect_ttl;     /* seconds an IP stays "validated" after /client */

	__u32 default_block_ttl; /* seconds for --auto blocks; 0 = permanent  */

	/* Options advertised in the XDP-generated SYN-ACK. These must match the
	 * nftables SYNPROXY configuration (deploy/nftables-synproxy.conf) so the
	 * spliced connection negotiates consistent parameters. */
	__u16 syn_mss;         /* MSS to advertise, host order (e.g. 1460)    */
	__u8  syn_wscale;      /* window scale shift to advertise (0 = off)   */
	__u8  syn_ttl;         /* TTL of the generated SYN-ACK                */
};

/* Per-source token bucket value (used by udp_buckets/syn_buckets/l7_buckets). */
struct token_bucket {
	__u64 tokens;  /* whole tokens currently available */
	__u64 ts_ns;   /* timestamp of the last refill      */
};

/* blocklist value: absolute expiry in bpf_ktime ns (0 == never expires). */
struct block_entry {
	__u64 expire_ns;
};

/*
 * Stats counters. Indexes into the per-CPU `stats` array; userspace sums the
 * per-CPU values and prints them by name (see stat_names[] in sentinel.c).
 * Keep this enum and that table in sync.
 */
enum sentinel_stat {
	STAT_PASS = 0,         /* packet allowed through                       */
	STAT_PASS_ALLOWLIST,   /* allowed via allowlist short-circuit          */
	STAT_PASS_NOT_TARGET,  /* not addressed to the protected ip:port       */
	STAT_DROP_BLOCKLIST,   /* dropped: source on the blocklist             */
	STAT_DROP_FRAG,        /* dropped: IP fragment to the game port        */
	STAT_DROP_AMP,         /* dropped: UDP from a reflector source port    */
	STAT_DROP_UDP_RATE,    /* dropped: per-source UDP rate exceeded        */
	STAT_DROP_TCP_FLAGS,   /* dropped: illegal TCP flag combination        */
	STAT_DROP_SYN_RATE,    /* dropped: per-source SYN rate exceeded        */
	STAT_SYN_COOKIE_TX,    /* SYN-ACK with cookie transmitted (XDP_TX)     */
	STAT_DROP_ACK_INVALID, /* dropped: ACK failed SYN-cookie validation    */
	STAT_DROP_L7_RATE,     /* dropped: per-source L7 request rate exceeded */
	STAT_ABORTED,          /* XDP_ABORTED: malformed packet / helper error */
	/* v2 */
	STAT_DROP_OOB_RATE,    /* dropped: getinfo/getstatus OOB rate exceeded */
	STAT_DROP_OOB_MALFORMED, /* dropped: malformed/oversized OOB packet    */
	STAT_PASS_VALIDATED,   /* allowed UDP from an IP that did /client      */
	STAT_DROP_UNVALIDATED, /* dropped: game UDP with no prior /client      */
	STAT_DROP_BOGON,       /* dropped: martian/bogon source address        */
	STAT_DROP_ICMP,        /* dropped: per-source ICMP rate exceeded       */
	STAT_DROP_BAD_CLIENT_METHOD, /* dropped: non-POST request to /client   */
	STAT__MAX,
};

#endif /* FIVEM_SENTINEL_H */
