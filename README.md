# FiveM-Sentinel

A layered DDoS filter for FiveM / FXServer. It combines a **kernel-level XDP
program** for line-rate L3/L4 mitigation (UDP floods, SYN floods, reflection)
with an **nginx micro-cache** and **FXServer hardening** for the Layer-7 problem
every FiveM operator eventually hits: people spamming `players.json` /
`info.json` / `dynamic.json` until the server thread stalls and the server drops
offline.

It is honest about where each problem is solved. XDP is great at dropping junk
packets cheaply; it is *not* the right place to reassemble TCP streams or cache
JSON, so that work lives in nginx. Each layer does what it is actually good at.

```
                         ┌─────────────────────────────────────────────┐
   Internet  ───────────▶│  Filter / proxy host                        │
   (players + attackers) │                                             │
                         │   NIC ──▶ XDP (sentinel)   L3/L4, line rate │
                         │            │  drop: UDP flood, amp, bad SYN, │
                         │            │        bad flags, blocklisted,  │
                         │            │        JSON-endpoint spam       │
                         │            │  XDP_TX SYN-ACK cookies         │
                         │            ▼                                 │
                         │   nft SYNPROXY  ── validates handshake ACK   │
                         │            │                                 │
                         │            ├─▶ nginx :443  L7 cache+limit ──▶ FXServer
                         │            │     players/info/dynamic.json     :30120
                         │            └─▶ nginx stream :30120 (UDP/TCP) ─▶ (game)
                         └─────────────────────────────────────────────┘
```

---

## What it protects against

| Vector | Layer | How |
| --- | --- | --- |
| UDP flood on the game port | XDP | per-source token bucket; spoofed sources self-evict from an LRU map |
| UDP reflection / amplification | XDP | drop UDP whose **source** port is a known reflector (DNS/NTP/SSDP/memcached/…) |
| TCP SYN flood | XDP + nft | XDP issues SYN-cookie SYN-ACKs with `XDP_TX`; nftables SYNPROXY validates the ACK |
| Port/stealth scans, flag-evasion | XDP | drop NULL/XMAS/SYN+FIN/SYN+RST/bare-FIN and unsolicited SYN-ACK |
| `getinfo`/`getstatus` reflection/amplification | XDP | detect Quake-style connectionless packets (`0xFFFFFFFF` prefix), drop malformed, strict per-source limiter for the ~37x amplification vector |
| `players.json`/`info.json`/`dynamic.json`/`/client` spam | XDP + nginx + Cloudflare | XDP per-source request-line limiter; nginx micro-cache; Cloudflare edge cache + rate limits (see [deploy/cloudflare.md](deploy/cloudflare.md)) |
| Spoofed UDP floods | XDP (opt-in) | cross-layer anti-spoof gate: game UDP is gated until that IP completes a TCP `POST /client` (`--require-connect`) |
| Spoofed/martian sources | XDP | drop bogon source addresses (0/8, 127/8, 169.254/16, 224/4, 240/4) — excludes RFC1918/CGNAT used by proxies |
| Ping floods | XDP (opt-in) | per-source ICMP token bucket (`--icmp-rps`) |
| IP fragmentation tricks | XDP | drop fragments aimed at the game port |
| Known-bad sources | XDP | allow/block lists with TTLs; optional `--auto` promotion of chronic offenders |

### What it is **not**

- Not a substitute for upstream/network-provider scrubbing against truly
  volumetric (100Gbps+) attacks — XDP drops cheaply but your uplink still has to
  receive the packets. Pair it with provider-level protection or a tunnel for
  large attacks.
- The in-XDP L7 limiter only sees the **first TCP segment** of a request, so it
  catches the common single-packet request-line flood. Multi-segment and
  slow-loris style abuse is handled by the nginx layer. Use both.

---

## Requirements

- **Linux kernel 6.8+** with BTF (`CONFIG_DEBUG_INFO_BTF=y`) — required for the
  raw XDP SYN-cookie helpers (`bpf_tcp_raw_gen_syncookie_ipv4`) and CO-RE.
- `clang`/`llvm`, `libbpf` (≥ 1.0) + headers, `bpftool`, `libelf`, `zlib`.
- A NIC driver with native XDP for best performance (the loader automatically
  falls back to generic/SKB mode otherwise).
- `nftables` with `CONFIG_NFT_SYNPROXY` for the TCP handshake path; `nginx`
  (with the `stream` module) for the L7 cache.

Install (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                        linux-tools-common linux-tools-$(uname -r) \
                        nftables nginx
```

---

## Build

```bash
make            # generates tools/vmlinux.h, builds build/sentinel.bpf.o + build/sentinel
sudo make install   # installs the CLI to /usr/local/sbin/sentinel
```

`make` regenerates `tools/vmlinux.h` from the running kernel's BTF the first
time. To refresh it for a different kernel: `make vmlinux`.

---

## Quick start

```bash
# Attach to the public NIC and protect your FXServer's address:
sudo sentinel load --iface eth0 --ip 203.0.113.10 --port 30120

# Watch what it's doing:
sudo sentinel stats --watch

# Detach:
sudo sentinel unload --iface eth0
```

The program stays attached and its maps stay pinned under
`/sys/fs/bpf/fivem-sentinel/` after `load` returns, so the other commands work
without reloading. Then set up the L7 layer:

1. Edit and apply `deploy/nginx-fivem.conf` (cache + rate limit the JSON
   endpoints, proxy the rest).
2. Edit and apply `deploy/nftables-synproxy.conf` and its sysctls (handshake
   validation for the XDP SYN-cookie path).
3. Append `deploy/server.cfg.snippet` to your FXServer `server.cfg`
   (indirect listing, `sv_endpointPrivacy`, split HTTP/UDP listeners).

---

## CLI reference

```
sentinel load   --iface IF --ip A.B.C.D [--port N] [tunables] [--mode drv|skb] [--auto]
sentinel unload --iface IF
sentinel stats  [--watch]
sentinel block   A.B.C.D [ttl_seconds]     # ttl 0 / omitted = permanent
sentinel unblock A.B.C.D
sentinel allow   A.B.C.D                    # bypass all filtering for this IP
sentinel unallow A.B.C.D
sentinel list                              # show allow/block lists
```

### Tunables (load)

| Flag | Default | Meaning |
| --- | --- | --- |
| `--udp-pps` / `--udp-burst` | 2000 / 4000 | per-source UDP packet rate / burst |
| `--syn-pps` / `--syn-burst` | 200 / 400 | per-source new-connection (SYN) rate / burst |
| `--l7-rps` / `--l7-burst` | 5 / 15 | per-source rate for `*.json` and `/client` requests |
| `--oob-rps` / `--oob-burst` | 5 / 15 | per-source rate for `getinfo`/`getstatus` OOB queries |
| `--block-ttl` | 600 | TTL (s) applied by `--auto` blocks |
| `--mode` | drv→skb | XDP attach mode |
| `--no-syn-cookies` | off | disable in-XDP SYN-cookie generation (use plain SYN rate limit + kernel/nft SYNPROXY instead) |
| `--no-bogon` | off | disable martian/bogon source dropping (on by default) |
| `--require-connect` | off | **anti-spoof gate**: drop game UDP from IPs that haven't done a TCP `POST /client` |
| `--connect-ttl` | 120 | seconds an IP stays validated after a `/client` POST |
| `--icmp-rps` | off | enable + set per-source ICMP rate limit |
| `--drop-bad-client-method` | off | drop non-POST requests to `/client` |
| `--auto` | off | foreground loop that auto-blocks chronic rate-limit offenders |

Defaults are deliberately generous for legitimate players; tune `--udp-pps`
down only if you have measured your real per-client packet rate.

> **Anti-spoof gate caveat:** `--require-connect` assumes the TCP `/client`
> handshake and the game UDP arrive with the **same** client source IP — true
> when Sentinel runs directly on the FiveM host (or a same-IP proxy). It is
> **not** safe when the connect endpoint is fronted by a different-IP
> proxy/Cloudflare while UDP is direct, which is why it is off by default.

---

## How the XDP pipeline works

Decisions are ordered cheapest-first so junk dies before any expensive work
(`src/sentinel.bpf.c`):

1. Parse Ethernet/IPv4 (CO-RE).
2. **Config gate** — ignore anything not addressed to the protected `ip:port`.
3. **Allow / block lists** (per source IP; blocks carry an expiry).
4. **Bogon drop** — martian source addresses can't be a real client.
5. **Fragment drop** for the game port.
6. **UDP** — drop reflector source ports; if the payload is a Quake-style
   connectionless query (`getinfo`/`getstatus`), apply the strict OOB limiter;
   otherwise apply the optional anti-spoof gate, then the per-source token bucket.
7. **TCP** — drop illegal flag combos; per-source SYN token bucket; on a pure
   SYN, generate a cookie and `XDP_TX` the SYN-ACK; on established data, classify
   the HTTP request line (`*.json` + `/client`), rate-limit it, and validate the
   source for the UDP gate on a real `POST /client`.
8. **ICMP** — optional per-source token bucket.
9. **Stats** — every decision bumps a per-CPU counter (read via `sentinel stats`).

The SYN-cookie **ACK validation and connection splice are delegated to nftables
SYNPROXY**, which shares the kernel's cookie secret. XDP only generates the
SYN-ACK — the part that has to run at line rate during a flood. This mirrors the
kernel's own `tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c`.

> The XDP SYN-ACK advertises an MSS option only (no window scale / SACK /
> timestamps) to keep the in-kernel packet rewrite minimal and robust. That is
> fine for FiveM's small TCP exchanges. To advertise more options, extend
> `emit_syn_cookie()` and match them in the nft `synproxy` rule.

---

## Observability

`sentinel stats` aggregates the per-CPU counters by reason, e.g.:

```
counter              packets
-------------------- ----------------
pass                 184223
drop_udp_rate        59210
drop_amplification   12044
drop_syn_rate        331
syn_cookie_tx        128
drop_l7_rate         872
drop_blocklist       40
```

---

## Security / operational notes

- Run the filter on the box that actually receives the traffic (the proxy host
  in the topology above, or the FXServer host itself if you don't proxy).
- `allow`-list your own management IPs so you can never lock yourself out.
- The maps are pinned under `/sys/fs/bpf/fivem-sentinel/`; `unload` removes them.
- If you can't run kernel 6.8+, load with `--no-syn-cookies` and rely on the
  nft SYNPROXY config (which also works standalone) for SYN protection.

---

## Project layout

```
src/sentinel.bpf.c   XDP data plane (CO-RE)
src/sentinel.h       structs/enums shared by BPF + userspace
src/sentinel.c       libbpf control plane / CLI
deploy/nginx-fivem.conf       L7 cache + per-IP rate limits
deploy/nftables-synproxy.conf SYNPROXY pairing for the SYN-cookie path
deploy/server.cfg.snippet     FXServer hardening
deploy/cloudflare.md          edge L7 protection (cache + rate limits + WAF)
tools/gen_vmlinux.sh          BTF -> vmlinux.h helper
Makefile
```

## Roadmap / extension points

- IPv6 path (the data plane is IPv4-only today).
- GeoIP / ASN allow-block integration in the `--auto` loop.
- Prometheus exporter for the stats map.

## License

MIT (see `LICENSE`). The BPF object is built as `Dual MIT/GPL` because the raw
SYN-cookie kernel helpers are GPL-only.
