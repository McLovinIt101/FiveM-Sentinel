# Cloudflare for FiveM — edge L7 protection

Cloudflare is the strongest place to stop `players.json` / `info.json` /
`dynamic.json` / `/client` spam, because the requests are absorbed at
Cloudflare's edge and **never reach your origin at all**. It complements
FiveM-Sentinel (which protects the raw game port at L3/L4) — it does not replace
it.

## What can and can't go through Cloudflare

| Traffic | Through Cloudflare? |
| --- | --- |
| The **connect endpoint** (HTTP/HTTPS: `info.json`, `players.json`, `dynamic.json`, `/client`, `/files`) | **Yes** — free orange-cloud proxy on 443 |
| Raw **game traffic** (UDP/TCP on 30120, ENet) | **No** on free/Pro — needs **Spectrum** (Business/Enterprise) |

So the realistic free setup: proxy the connect endpoint through Cloudflare, keep
the game port direct-to-origin and protected by Sentinel + nftables.

## DNS

- `connect.example.com` → your origin's HTTP — **Proxied (orange cloud)**.
- `play.example.com` (or the A record players actually connect to for UDP) →
  **DNS only (grey cloud)**. Never rely on the orange cloud to hide the game IP.

## server.cfg

Point the listing/connect host at the proxied hostname so the FiveM client
fetches the JSON through Cloudflare:

```
set sv_forceIndirectListing true
set sv_listingHostOverride "connect.example.com"
set sv_endpointPrivacy true
```

## Cache Rules (the actual spam fix)

Dashboard → **Caching → Cache Rules → Create rule**. The JSON endpoints are
served as dynamic by default (uncached); force a short edge cache so repeated
hits are served from Cloudflare:

- **Rule name:** `fivem-json-microcache`
- **When incoming requests match:**
  `(http.request.uri.path in {"/info.json" "/players.json" "/dynamic.json"})`
- **Then:**
  - Cache eligibility → **Eligible for cache**
  - Edge TTL → **Override origin, 5 seconds** (3–10s is fine)
  - Browser TTL → **Override, 5 seconds**

Result: no matter how hard the endpoints are hammered, your origin sees at most
~1 request per endpoint per 5s.

## Rate Limiting Rules

Dashboard → **Security → WAF → Rate limiting rules**. (One rule is free.)

- **JSON flood:**
  - Expression: `(http.request.uri.path in {"/info.json" "/players.json" "/dynamic.json"})`
  - Characteristics: **IP**
  - When rate exceeds: **30 requests / 10 seconds**
  - Action: **Block**, duration **60s**
  - Tip: enable "Also apply rate limiting to cached assets" so cached responses
    still count toward the limit.
- **/client abuse** (separate rule if you have the budget, or fold into a custom
  WAF rule):
  - Expression: `(http.request.uri.path eq "/client" and http.request.method eq "POST")`
  - When rate exceeds: **10 requests / 10 seconds** per IP
  - Action: **Managed Challenge** (don't hard-block — it's the real connect path)

## WAF / Bot

- Turn on the **Cloudflare Managed Ruleset** (free).
- **Bot Fight Mode** on (Security → Bots).
- Security level: **Medium**. Avoid "I'm Under Attack" mode on the connect
  endpoint — its JS challenge breaks the FiveM client, which is not a browser.

## Game traffic (optional, paid)

To put the raw game port behind Cloudflare you need **Spectrum** (Business/
Enterprise): Spectrum → Create application → UDP (and TCP) → port 30120 → origin
IP:port. Until then, the game port stays direct and is protected by Sentinel and
`deploy/nftables-synproxy.conf`.

## How this layers with Sentinel

```
JSON / /client  ──▶ Cloudflare edge (cache + rate limit + WAF)  ──▶ origin HTTP
game UDP/TCP    ──▶ origin NIC ──▶ XDP (sentinel) + nft SYNPROXY ──▶ FXServer
```

Edge handles the L7 spam; Sentinel handles the volumetric L3/L4 that Cloudflare
free can't see. Both at once is the goal.
