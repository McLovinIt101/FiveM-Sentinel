// SPDX-License-Identifier: MIT
/*
 * FiveM-Sentinel — userspace control plane.
 *
 * Loads/attaches the XDP data plane, configures it (no hardcoded target),
 * manages the allow/block lists, prints stats, and optionally runs an
 * auto-mitigation loop that promotes chronic offenders into the blocklist.
 *
 * Subcommands:
 *   load   --iface IF --ip A.B.C.D [--port N] [tunables] [--mode drv|skb] [--auto]
 *   unload --iface IF
 *   stats  [--watch]
 *   block  A.B.C.D [TTL_SECONDS]
 *   unblock A.B.C.D
 *   allow  A.B.C.D
 *   unallow A.B.C.D
 *   list
 *
 * After `load` exits, the program stays attached (netlink XDP) and its maps
 * stay pinned under SENTINEL_PIN_DIR, so the other subcommands operate purely
 * on the pinned maps and never need to reload the object.
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sentinel.h"
#include "sentinel.skel.h"

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static const char *const stat_names[STAT__MAX] = {
	[STAT_PASS] = "pass",
	[STAT_PASS_ALLOWLIST] = "pass_allowlist",
	[STAT_PASS_NOT_TARGET] = "pass_not_target",
	[STAT_DROP_BLOCKLIST] = "drop_blocklist",
	[STAT_DROP_FRAG] = "drop_fragment",
	[STAT_DROP_AMP] = "drop_amplification",
	[STAT_DROP_UDP_RATE] = "drop_udp_rate",
	[STAT_DROP_TCP_FLAGS] = "drop_tcp_flags",
	[STAT_DROP_SYN_RATE] = "drop_syn_rate",
	[STAT_SYN_COOKIE_TX] = "syn_cookie_tx",
	[STAT_DROP_ACK_INVALID] = "drop_ack_invalid",
	[STAT_DROP_L7_RATE] = "drop_l7_rate",
	[STAT_ABORTED] = "aborted",
	[STAT_DROP_OOB_RATE] = "drop_oob_rate",
	[STAT_DROP_OOB_MALFORMED] = "drop_oob_malformed",
	[STAT_PASS_VALIDATED] = "pass_validated",
	[STAT_DROP_UNVALIDATED] = "drop_unvalidated",
	[STAT_DROP_BOGON] = "drop_bogon",
	[STAT_DROP_ICMP] = "drop_icmp",
	[STAT_DROP_BAD_CLIENT_METHOD] = "drop_bad_client_method",
};

/* ----------------------------- utilities -------------------------------- */

static __u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int parse_ip(const char *s, __u32 *out /* network order */)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	*out = a.s_addr;
	return 0;
}

static const char *ip_str(__u32 net_order)
{
	static char buf[INET_ADDRSTRLEN];
	struct in_addr a = { .s_addr = net_order };

	return inet_ntop(AF_INET, &a, buf, sizeof(buf));
}

static int pin_path(char *buf, size_t len, const char *map)
{
	int n = snprintf(buf, len, "%s/%s", SENTINEL_PIN_DIR, map);

	return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

/* Open a pinned map by name; returns an fd or -1. */
static int open_pinned(const char *map)
{
	char path[256];
	int fd;

	if (pin_path(path, sizeof(path), map))
		return -1;
	fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "cannot open pinned map %s: %s\n"
				"(is the filter loaded?)\n",
			path, strerror(errno));
	return fd;
}

/* --------------------------- load / unload ------------------------------ */

struct load_opts {
	const char *iface;
	struct sentinel_config cfg;
	__u32 xdp_flags; /* XDP_FLAGS_DRV_MODE / SKB_MODE / 0 = best effort */
	bool auto_mode;
};

static void cfg_defaults(struct sentinel_config *c)
{
	memset(c, 0, sizeof(*c));
	c->protected_port = htons(30120);
	c->flags = F_DEFAULTS;
	c->udp_pps = 2000;   /* generous for a single legit player */
	c->udp_burst = 4000;
	c->syn_pps = 200;
	c->syn_burst = 400;
	c->l7_rps = 5;       /* players.json a few times a second is plenty */
	c->l7_burst = 15;
	c->oob_rps = 5;      /* getinfo/getstatus; FiveM itself uses ~2/s     */
	c->oob_burst = 15;
	c->icmp_rps = 10;    /* only used if F_ICMP_RATELIMIT is enabled       */
	c->icmp_burst = 20;
	c->connect_ttl = 120; /* IP stays validated 2 min after a /client POST */
	c->default_block_ttl = 600;
	c->syn_mss = 1460;
	c->syn_wscale = 7;
	c->syn_ttl = 64;
}

static int do_auto(struct sentinel *skel);

static int cmd_load(struct load_opts *o)
{
	struct sentinel *skel;
	int ifindex, err, prog_fd;
	__u32 key = 0;

	ifindex = if_nametoindex(o->iface);
	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s'\n", o->iface);
		return 1;
	}
	if (!o->cfg.protected_ip) {
		fprintf(stderr, "load requires --ip\n");
		return 1;
	}

	skel = sentinel__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	err = sentinel__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key),
				   &o->cfg, sizeof(o->cfg), BPF_ANY);
	if (err) {
		fprintf(stderr, "failed to write config: %s\n", strerror(-err));
		goto cleanup;
	}

	/* Pin maps so the other subcommands can manage them later. */
	mkdir(SENTINEL_PIN_DIR, 0700);
	bpf_object__unpin_maps(skel->obj, SENTINEL_PIN_DIR); /* ignore if absent */
	err = bpf_object__pin_maps(skel->obj, SENTINEL_PIN_DIR);
	if (err) {
		fprintf(stderr, "failed to pin maps in %s: %s\n",
			SENTINEL_PIN_DIR, strerror(-err));
		goto cleanup;
	}

	prog_fd = bpf_program__fd(skel->progs.fivem_sentinel);
	err = bpf_xdp_attach(ifindex, prog_fd, o->xdp_flags, NULL);
	if (err && o->xdp_flags == XDP_FLAGS_DRV_MODE) {
		fprintf(stderr, "native XDP attach failed (%s), retrying in SKB mode\n",
			strerror(-err));
		err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	}
	if (err) {
		fprintf(stderr, "failed to attach XDP to %s: %s\n", o->iface,
			strerror(-err));
		bpf_object__unpin_maps(skel->obj, SENTINEL_PIN_DIR);
		goto cleanup;
	}

	printf("FiveM-Sentinel %s attached to %s, protecting %s:%u\n",
	       SENTINEL_VERSION, o->iface, ip_str(o->cfg.protected_ip),
	       ntohs(o->cfg.protected_port));

	if (o->auto_mode) {
		signal(SIGINT, on_signal);
		signal(SIGTERM, on_signal);
		printf("auto-mitigation running; Ctrl-C to stop (filter stays attached)\n");
		err = do_auto(skel);
	}
	/* Program stays attached and maps stay pinned after we exit. */

cleanup:
	sentinel__destroy(skel);
	return err ? 1 : 0;
}

static int cmd_unload(const char *iface)
{
	int ifindex = if_nametoindex(iface);
	char path[256];

	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s'\n", iface);
		return 1;
	}
	/* Detach whichever XDP mode is currently attached. */
	if (bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL))
		bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

	/* Best-effort removal of pinned maps. */
	const char *maps[] = { "config_map", "allowlist", "blocklist",
			       "udp_buckets", "syn_buckets", "l7_buckets",
			       "oob_buckets", "icmp_buckets", "validated_clients",
			       "stats", "offenders" };
	for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++)
		if (!pin_path(path, sizeof(path), maps[i]))
			unlink(path);
	rmdir(SENTINEL_PIN_DIR);

	printf("FiveM-Sentinel detached from %s\n", iface);
	return 0;
}

/* ------------------------------ stats ----------------------------------- */

static int cmd_stats(bool watch)
{
	int fd = open_pinned("stats");
	int ncpu = libbpf_num_possible_cpus();

	if (fd < 0)
		return 1;
	if (ncpu <= 0)
		ncpu = 1;

	do {
		__u64 *vals = calloc(ncpu, sizeof(__u64));

		if (!vals) {
			close(fd);
			return 1;
		}
		if (watch)
			printf("\033[H\033[2J"); /* clear screen */
		printf("%-20s %s\n", "counter", "packets");
		printf("-------------------- ----------------\n");
		for (__u32 k = 0; k < STAT__MAX; k++) {
			__u64 sum = 0;

			if (bpf_map_lookup_elem(fd, &k, vals) == 0)
				for (int c = 0; c < ncpu; c++)
					sum += vals[c];
			printf("%-20s %llu\n",
			       stat_names[k] ? stat_names[k] : "?",
			       (unsigned long long)sum);
		}
		free(vals);
		if (watch)
			sleep(1);
	} while (watch);

	close(fd);
	return 0;
}

/* --------------------------- list management ---------------------------- */

static int cmd_block(const char *ipstr, __u64 ttl_sec)
{
	struct block_entry e = { 0 };
	int fd = open_pinned("blocklist");
	__u32 ip;

	if (fd < 0)
		return 1;
	if (parse_ip(ipstr, &ip)) {
		fprintf(stderr, "invalid IP '%s'\n", ipstr);
		close(fd);
		return 1;
	}
	if (ttl_sec)
		e.expire_ns = mono_ns() + ttl_sec * 1000000000ULL;
	if (bpf_map_update_elem(fd, &ip, &e, BPF_ANY)) {
		fprintf(stderr, "block failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	printf("blocked %s%s", ipstr, ttl_sec ? "" : " (permanent)\n");
	if (ttl_sec)
		printf(" for %llus\n", (unsigned long long)ttl_sec);
	close(fd);
	return 0;
}

static int map_del_ip(const char *map, const char *ipstr)
{
	int fd = open_pinned(map);
	__u32 ip;

	if (fd < 0)
		return 1;
	if (parse_ip(ipstr, &ip)) {
		fprintf(stderr, "invalid IP '%s'\n", ipstr);
		close(fd);
		return 1;
	}
	if (bpf_map_delete_elem(fd, &ip) && errno != ENOENT) {
		fprintf(stderr, "delete failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

static int cmd_allow(const char *ipstr)
{
	int fd = open_pinned("allowlist");
	__u32 ip;
	__u8 one = 1;

	if (fd < 0)
		return 1;
	if (parse_ip(ipstr, &ip)) {
		fprintf(stderr, "invalid IP '%s'\n", ipstr);
		close(fd);
		return 1;
	}
	if (bpf_map_update_elem(fd, &ip, &one, BPF_ANY)) {
		fprintf(stderr, "allow failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	printf("allowlisted %s\n", ipstr);
	close(fd);
	return 0;
}

static void dump_iplist(const char *map, const char *title, bool with_ttl)
{
	int fd = open_pinned(map);
	__u32 key = 0, next;
	__u64 now = mono_ns();

	if (fd < 0)
		return;
	printf("%s:\n", title);
	while (bpf_map_get_next_key(fd, &key, &next) == 0) {
		if (with_ttl) {
			struct block_entry e;

			if (bpf_map_lookup_elem(fd, &next, &e) == 0) {
				if (e.expire_ns == 0)
					printf("  %s (permanent)\n", ip_str(next));
				else if (e.expire_ns > now)
					printf("  %s (%llus left)\n", ip_str(next),
					       (unsigned long long)((e.expire_ns - now) / 1000000000ULL));
			}
		} else {
			printf("  %s\n", ip_str(next));
		}
		key = next;
	}
	close(fd);
}

static int cmd_list(void)
{
	dump_iplist("allowlist", "Allowlist", false);
	dump_iplist("blocklist", "Blocklist", true);
	return 0;
}

/* ------------------------- auto-mitigation ------------------------------ */
/*
 * Every few seconds, walk the offenders map. Any source whose rate-limit-drop
 * count crossed the threshold during the interval is blocked for the configured
 * TTL; counters are then cleared so the window restarts. This is the honest,
 * data-driven replacement for the removed "ML/anomaly" maps.
 */
static int do_auto(struct sentinel *skel)
{
	const __u64 threshold = 200; /* drops per interval before auto-block */
	int off_fd = bpf_map__fd(skel->maps.offenders);
	int blk_fd = bpf_map__fd(skel->maps.blocklist);
	struct sentinel_config cfg;
	__u32 key = 0;

	if (bpf_map__lookup_elem(skel->maps.config_map, &key, sizeof(key),
				 &cfg, sizeof(cfg), 0))
		cfg.default_block_ttl = 600;

	while (!exiting) {
		__u32 cur = 0, next;

		while (bpf_map_get_next_key(off_fd, &cur, &next) == 0) {
			__u64 count = 0;

			if (bpf_map_lookup_elem(off_fd, &next, &count) == 0 &&
			    count >= threshold) {
				struct block_entry e = { 0 };

				if (cfg.default_block_ttl)
					e.expire_ns = mono_ns() +
						(__u64)cfg.default_block_ttl * 1000000000ULL;
				bpf_map_update_elem(blk_fd, &next, &e, BPF_ANY);
				printf("auto-blocked %s (%llu drops)\n",
				       ip_str(next), (unsigned long long)count);
			}
			bpf_map_delete_elem(off_fd, &next);
			cur = next;
		}
		for (int i = 0; i < 30 && !exiting; i++)
			usleep(100000); /* ~3s, responsive to Ctrl-C */
	}
	return 0;
}

/* ------------------------------ CLI ------------------------------------- */

static void usage(const char *argv0)
{
	fprintf(stderr,
		"FiveM-Sentinel %s — XDP DDoS filter for FiveM\n\n"
		"Usage:\n"
		"  %s load --iface IF --ip A.B.C.D [options]\n"
		"  %s unload --iface IF\n"
		"  %s stats [--watch]\n"
		"  %s block A.B.C.D [ttl_seconds]\n"
		"  %s unblock A.B.C.D\n"
		"  %s allow A.B.C.D\n"
		"  %s unallow A.B.C.D\n"
		"  %s list\n\n"
		"load options:\n"
		"  --port N            protected port (default 30120)\n"
		"  --udp-pps N         per-source UDP rate (default 2000)\n"
		"  --udp-burst N       per-source UDP burst (default 4000)\n"
		"  --syn-pps N         per-source SYN rate (default 200)\n"
		"  --syn-burst N       per-source SYN burst (default 400)\n"
		"  --l7-rps N          per-source request rate for json/client (default 5)\n"
		"  --l7-burst N        per-source request burst (default 15)\n"
		"  --oob-rps N         per-source getinfo/getstatus rate (default 5)\n"
		"  --oob-burst N       per-source OOB burst (default 15)\n"
		"  --block-ttl N       auto-block TTL seconds (default 600)\n"
		"  --mode drv|skb      XDP attach mode (default: drv, fallback skb)\n"
		"  --no-syn-cookies    disable in-XDP SYN-cookie generation\n"
		"  --no-bogon          disable martian/bogon source dropping\n"
		"  --require-connect   gate game UDP on a prior TCP POST /client (anti-spoof)\n"
		"  --connect-ttl N     seconds an IP stays validated (default 120)\n"
		"  --icmp-rps N        enable + set per-source ICMP rate (default off)\n"
		"  --drop-bad-client-method  drop non-POST requests to /client\n"
		"  --auto              run auto-mitigation loop in the foreground\n",
		SENTINEL_VERSION, argv0, argv0, argv0, argv0, argv0, argv0, argv0,
		argv0, argv0);
}

enum {
	OPT_IFACE = 256, OPT_IP, OPT_PORT, OPT_UDP_PPS, OPT_UDP_BURST,
	OPT_SYN_PPS, OPT_SYN_BURST, OPT_L7_RPS, OPT_L7_BURST, OPT_BLOCK_TTL,
	OPT_MODE, OPT_NO_SYN_COOKIES, OPT_AUTO, OPT_WATCH,
	OPT_OOB_RPS, OPT_OOB_BURST, OPT_NO_BOGON, OPT_REQUIRE_CONNECT,
	OPT_CONNECT_TTL, OPT_ICMP_RPS, OPT_DROP_BAD_CLIENT_METHOD,
};

int main(int argc, char **argv)
{
	static const struct option lopts[] = {
		{ "iface", required_argument, 0, OPT_IFACE },
		{ "ip", required_argument, 0, OPT_IP },
		{ "port", required_argument, 0, OPT_PORT },
		{ "udp-pps", required_argument, 0, OPT_UDP_PPS },
		{ "udp-burst", required_argument, 0, OPT_UDP_BURST },
		{ "syn-pps", required_argument, 0, OPT_SYN_PPS },
		{ "syn-burst", required_argument, 0, OPT_SYN_BURST },
		{ "l7-rps", required_argument, 0, OPT_L7_RPS },
		{ "l7-burst", required_argument, 0, OPT_L7_BURST },
		{ "block-ttl", required_argument, 0, OPT_BLOCK_TTL },
		{ "mode", required_argument, 0, OPT_MODE },
		{ "no-syn-cookies", no_argument, 0, OPT_NO_SYN_COOKIES },
		{ "auto", no_argument, 0, OPT_AUTO },
		{ "watch", no_argument, 0, OPT_WATCH },
		{ "oob-rps", required_argument, 0, OPT_OOB_RPS },
		{ "oob-burst", required_argument, 0, OPT_OOB_BURST },
		{ "no-bogon", no_argument, 0, OPT_NO_BOGON },
		{ "require-connect", no_argument, 0, OPT_REQUIRE_CONNECT },
		{ "connect-ttl", required_argument, 0, OPT_CONNECT_TTL },
		{ "icmp-rps", required_argument, 0, OPT_ICMP_RPS },
		{ "drop-bad-client-method", no_argument, 0, OPT_DROP_BAD_CLIENT_METHOD },
		{ 0 },
	};
	struct load_opts lo = { .xdp_flags = XDP_FLAGS_DRV_MODE };
	bool watch = false;
	const char *cmd;
	int c;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	cmd = argv[1];

	cfg_defaults(&lo.cfg);

	/* getopt over args after the subcommand. */
	optind = 2;
	while ((c = getopt_long(argc, argv, "", lopts, NULL)) != -1) {
		switch (c) {
		case OPT_IFACE: lo.iface = optarg; break;
		case OPT_IP:
			if (parse_ip(optarg, &lo.cfg.protected_ip)) {
				fprintf(stderr, "invalid --ip '%s'\n", optarg);
				return 1;
			}
			break;
		case OPT_PORT: lo.cfg.protected_port = htons(atoi(optarg)); break;
		case OPT_UDP_PPS: lo.cfg.udp_pps = atoi(optarg); break;
		case OPT_UDP_BURST: lo.cfg.udp_burst = atoi(optarg); break;
		case OPT_SYN_PPS: lo.cfg.syn_pps = atoi(optarg); break;
		case OPT_SYN_BURST: lo.cfg.syn_burst = atoi(optarg); break;
		case OPT_L7_RPS: lo.cfg.l7_rps = atoi(optarg); break;
		case OPT_L7_BURST: lo.cfg.l7_burst = atoi(optarg); break;
		case OPT_BLOCK_TTL: lo.cfg.default_block_ttl = atoi(optarg); break;
		case OPT_MODE:
			if (!strcmp(optarg, "skb"))
				lo.xdp_flags = XDP_FLAGS_SKB_MODE;
			else if (!strcmp(optarg, "drv"))
				lo.xdp_flags = XDP_FLAGS_DRV_MODE;
			else {
				fprintf(stderr, "--mode must be drv or skb\n");
				return 1;
			}
			break;
		case OPT_NO_SYN_COOKIES: lo.cfg.flags &= ~F_SYN_COOKIES; break;
		case OPT_OOB_RPS: lo.cfg.oob_rps = atoi(optarg); break;
		case OPT_OOB_BURST: lo.cfg.oob_burst = atoi(optarg); break;
		case OPT_NO_BOGON: lo.cfg.flags &= ~F_DROP_BOGON_SRC; break;
		case OPT_REQUIRE_CONNECT: lo.cfg.flags |= F_UDP_REQUIRE_CONNECT; break;
		case OPT_CONNECT_TTL: lo.cfg.connect_ttl = atoi(optarg); break;
		case OPT_ICMP_RPS:
			lo.cfg.icmp_rps = atoi(optarg);
			lo.cfg.flags |= F_ICMP_RATELIMIT;
			break;
		case OPT_DROP_BAD_CLIENT_METHOD:
			lo.cfg.flags |= F_DROP_BAD_CLIENT_METHOD;
			break;
		case OPT_AUTO: lo.auto_mode = true; break;
		case OPT_WATCH: watch = true; break;
		default: usage(argv[0]); return 1;
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	{
		struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
		setrlimit(RLIMIT_MEMLOCK, &r);
	}

	if (!strcmp(cmd, "load")) {
		if (!lo.iface) {
			fprintf(stderr, "load requires --iface\n");
			return 1;
		}
		return cmd_load(&lo);
	}
	if (!strcmp(cmd, "unload")) {
		if (!lo.iface) {
			fprintf(stderr, "unload requires --iface\n");
			return 1;
		}
		return cmd_unload(lo.iface);
	}
	if (!strcmp(cmd, "stats"))
		return cmd_stats(watch);
	if (!strcmp(cmd, "list"))
		return cmd_list();

	/* Commands taking a positional IP (and optional TTL). */
	if (!strcmp(cmd, "block")) {
		if (optind >= argc) { usage(argv[0]); return 1; }
		return cmd_block(argv[optind],
				 optind + 1 < argc ? strtoull(argv[optind + 1], NULL, 10) : 0);
	}
	if (!strcmp(cmd, "unblock")) {
		if (optind >= argc) { usage(argv[0]); return 1; }
		return map_del_ip("blocklist", argv[optind]);
	}
	if (!strcmp(cmd, "allow")) {
		if (optind >= argc) { usage(argv[0]); return 1; }
		return cmd_allow(argv[optind]);
	}
	if (!strcmp(cmd, "unallow")) {
		if (optind >= argc) { usage(argv[0]); return 1; }
		return map_del_ip("allowlist", argv[optind]);
	}

	usage(argv[0]);
	return 1;
}
