#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// *** Configuration Constants ***
#define FIVEM_SERVER_IP   0x7F000001   // Server IP (127.0.0.1 here as example, use actual IP in production)
#define FIVEM_SERVER_PORT 30120       // FiveM server UDP/TCP port to protect
#define MAX_PACKET_RATE   13000       // Max packets per second per CPU (rate limit threshold)

// Secret for SYN cookie generation (should be random in real use)
#define COOKIE_SECRET     0x1A2B3C4D  

// Common UDP amplifier ports (DNS, NTP, SSDP, Memcached, etc.)
#define AMP_PORT_DNS      53    // DNS
#define AMP_PORT_NTP      123   // NTP
#define AMP_PORT_SSDP     1900  // SSDP
#define AMP_PORT_MEMCACHED 11211// Memcached
#define AMP_PORT_CHARGEN  19    // CHARGEN (classic amplification)

// *** BPF Maps ***
// Per-CPU rate limit map (key=0, value=last packet timestamp on that CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit_map SEC(".maps");

// Blocklist for IPs (drop traffic from these IPs)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);   // source IP
    __type(value, __u8);  // bool flag (1 = blocked)
} blocklist_map SEC(".maps");

// Allowlist for IPs (bypass all filtering)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);   // source IP
    __type(value, __u8);  // bool flag (1 = allowed)
} allowlist_map SEC(".maps");

// Connection tracking map (LRU) to track active flows (both TCP and UDP)
struct flow_key_t { __u64 key; };  // dummy struct to align 64-bit key if needed
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // flow 5-tuple key
    __type(value, __u64); // last seen timestamp (ns) or state info
} conntrack_map SEC(".maps");

// Known malicious payload patterns for DPI (signature map)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);  // 32-bit pattern (e.g., hash or first 4 bytes)
    __type(value, __u8); // flag (1 = known bad)
} dpi_map SEC(".maps");

// Anomaly detection map (flow anomaly scores)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);  // flow key
    __type(value, __u64); // anomaly score
} anomaly_map SEC(".maps");

// Machine-learning threat map (flows flagged by ML model)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); // flow key
    __type(value, __u8); // threat level (1 = suspicious, 2 = high threat)
} ml_threat_map SEC(".maps");

// *** Helper Functions ***

// Parse UDP header (returns NULL if out-of-bounds)
static __always_inline struct udphdr *parse_udp(void *data, void *data_end, struct iphdr *ip) {
    struct udphdr *udp = (struct udphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(udp + 1) > data_end) {
        return NULL; // Packet not large enough for UDP header
    }
    return udp;
}

// Parse TCP header (returns NULL if out-of-bounds)
static __always_inline struct tcphdr *parse_tcp(void *data, void *data_end, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(tcp + 1) > data_end) {
        return NULL; // Packet not large enough for TCP header
    }
    return tcp;
}

// Generate a 64-bit flow key from 5-tuple (src/dst IPs and ports, protocol)
static __always_inline __u64 generate_flow_key(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    // Combine into 64 bits: 32 bits of src_ip, 16 bits of src_port, 8 bits of proto, 8 bits of dst_port (low 8 bits)
    // This is a simple combination; it should uniquely identify flows in this context.
    __u64 key = 0;
    key |= (__u64)src_ip << 32;
    key |= (__u64)src_port << 16;
    key |= (__u64)protocol << 8;
    key |= (__u64)(dst_port & 0xFF);
    // (Note: if needed, include dst_ip and full ports for complete uniqueness, but here assume server IP/port fixed)
    return key;
}

// SYN cookie generation for TCP SYN packets (uses secret for randomness)
static __always_inline __u32 generate_syn_cookie(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u32 seq) {
    // Simple cookie: XOR of addresses, ports, sequence, and a secret
    __u32 cookie = saddr ^ daddr ^ ((__u32)sport << 16 | (__u32)dport) ^ seq ^ COOKIE_SECRET;
    // In practice, we might use hash functions and time-based components for cookies
    return cookie;
}

// Handle TCP SYN flood: validate SYN packet via cookie, returns XDP_DROP if invalid, else XDP_PASS
static __always_inline int handle_tcp_syn_flood(struct iphdr *ip, struct tcphdr *tcp) {
    if (tcp->syn && !tcp->ack) {  // SYN (no ACK) – new connection attempt
        __u32 cookie = generate_syn_cookie(ip->saddr, ip->daddr, tcp->source, tcp->dest, tcp->seq);
        // Drop the SYN if the sequence number doesn't match the expected cookie
        if (tcp->seq != cookie) {
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

// Check for TCP bypass attempt via abnormal flags or state
static __always_inline int detect_tcp_bypass(struct tcphdr *tcp) {
    // Drop any packet with no control flags (NULL scan) or an unsolicited SYN-ACK
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) ||   // no SYN/ACK/FIN/RST flag
        (tcp->syn && tcp->ack)) {                               // SYN+ACK from external (unexpected)
        return 1;  // suspected bypass/scanning packet
    }
    // Drop if URG flag is set (rarely legitimate, often used in attacks to evade filters)
    if (tcp->urg) {
        return 1;
    }
    return 0;
}

// Perform deep packet inspection for known malicious patterns
static __always_inline int deep_packet_inspection(void *data, void *data_end) {
    // Check the first few bytes of payload for any known bad signature
    // (We assume Ethernet+IP+(TCP/UDP) headers have been parsed and `data` now points at payload start)
    // Ensure at least 4 bytes of payload exist to read a pattern
    if (data + sizeof(__u32) <= data_end) {
        __u32 p = *(__u32 *)data;  // read first 4 bytes
        __u8 *flag = bpf_map_lookup_elem(&dpi_map, &p);
        if (flag && *flag == 1) {
            return 1;  // payload contains known malicious pattern
        }
    }
    // (Additional pattern checks could be added here for other offsets if needed)
    return 0;
}

// Check anomaly score for the flow and decide if packet should be dropped
static __always_inline int detect_anomaly(__u64 flow_key) {
    __u64 *score = bpf_map_lookup_elem(&anomaly_map, &flow_key);
    if (score) {
        if (*score > 500) {
            return 1;  // severe anomaly detected, drop
        }
        // (For scores in moderate range, we currently also drop. This threshold can be tuned to reduce false positives.)
        if (*score > 200) {
            return 1;  // moderate anomaly detected, drop as well (could be changed to alert-only if desired)
        }
    }
    return 0;
}

// Check machine learning threat flags for the flow
static __always_inline int ml_threat_detection(__u64 flow_key) {
    __u8 *threat_level = bpf_map_lookup_elem(&ml_threat_map, &flow_key);
    if (threat_level) {
        if (*threat_level >= 2) {
            return 1;  // high-confidence threat – drop
        }
        if (*threat_level == 1) {
            // Low-confidence threat – we choose not to drop immediately to reduce false positives
            // (Could implement logging or slower path handling here)
            return 0;
        }
    }
    return 0;
}

// *** Main XDP Program ***

SEC("xdp")
int fivem_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }
    // Only handle IPv4 packets (IPv6 or others are passed through)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    // Parse IPv4 header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_ABORTED;
    }

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // *** Allowlist / Blocklist Checks ***
    // If source IP is in allowlist, bypass all further filtering
    __u8 *allow_flag = bpf_map_lookup_elem(&allowlist_map, &src_ip);
    if (allow_flag && *allow_flag == 1) {
        return XDP_PASS;
    }
    // If source IP is in blocklist, drop immediately
    __u8 *block_flag = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (block_flag && *block_flag == 1) {
        return XDP_DROP;
    }

    // We proceed to inspect traffic destined for our FiveM server
    // If packet is not addressed to our server IP/port, we let it pass (not our concern)
    if (dst_ip != bpf_htonl(FIVEM_SERVER_IP)) {
        return XDP_PASS;
    }

    // Get current time (for rate limiting and connection tracking)
    __u64 now = bpf_ktime_get_ns();

    // Prepare a flow key for tracking (we'll fill it based on protocol below)
    __u64 flow_key = 0;
    __u64 *last_seen = NULL;

    if (ip->protocol == IPPROTO_UDP) {
        // Parse UDP header
        struct udphdr *udp = parse_udp(data, data_end, ip);
        if (!udp) {
            return XDP_ABORTED;
        }
        // Check if UDP destination port matches the FiveM server port
        if (udp->dest != bpf_htons(FIVEM_SERVER_PORT)) {
            return XDP_PASS;  // not targeting our server port, ignore
        }
        // UDP Amplification protection: drop packets from common amplifier ports if size is large
        __u32 pkt_len = (__u32)((unsigned long)data_end - (unsigned long)data);
        if ((udp->source == bpf_htons(AMP_PORT_DNS)      || 
             udp->source == bpf_htons(AMP_PORT_NTP)      || 
             udp->source == bpf_htons(AMP_PORT_SSDP)     ||
             udp->source == bpf_htons(AMP_PORT_MEMCACHED)|| 
             udp->source == bpf_htons(AMP_PORT_CHARGEN)) &&
             pkt_len > 512) {
            // Likely a reflected amplified packet (large UDP from known service port)
            return XDP_DROP;
        }

        // Compute flow key (using 5-tuple: src IP, dst IP, src port, dst port, protocol)
        flow_key = generate_flow_key(src_ip, dst_ip, udp->source, udp->dest, IPPROTO_UDP);

        // Connection tracking: update or create entry for this UDP flow
        last_seen = bpf_map_lookup_elem(&conntrack_map, &flow_key);
        if (last_seen) {
            *last_seen = now;  // update timestamp for existing flow
        } else {
            bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
        }

        // Deep Packet Inspection: drop if payload matches known malicious pattern
        void *udp_payload = (void *)(udp + 1);
        if (udp_payload < data_end) {  // there is payload
            if (deep_packet_inspection(udp_payload, data_end)) {
                return XDP_DROP;
            }
        }

        // Anomaly Detection: drop if this flow’s anomaly score is above threshold
        if (detect_anomaly(flow_key)) {
            return XDP_DROP;
        }

        // ML-Based Threat Detection: drop if ML flagged this flow as a serious threat
        if (ml_threat_detection(flow_key)) {
            return XDP_DROP;
        }

        // (No further UDP-specific checks)
    } 
    else if (ip->protocol == IPPROTO_TCP) {
        // Parse TCP header
        struct tcphdr *tcp = parse_tcp(data, data_end, ip);
        if (!tcp) {
            return XDP_ABORTED;
        }
        // Check if TCP destination port matches FiveM server port
        if (tcp->dest != bpf_htons(FIVEM_SERVER_PORT)) {
            return XDP_PASS;  // not for our service
        }

        // SYN Flood protection: apply SYN cookie validation on initial SYNs
        if (handle_tcp_syn_flood(ip, tcp) == XDP_DROP) {
            return XDP_DROP;
        }

        // Compute flow key for TCP connection
        flow_key = generate_flow_key(src_ip, dst_ip, tcp->source, tcp->dest, IPPROTO_TCP);

        // Connection tracking with stateful bypass protection
        last_seen = bpf_map_lookup_elem(&conntrack_map, &flow_key);
        if (last_seen) {
            // Existing connection – update last seen timestamp
            *last_seen = now;
        } else {
            // No entry found: if this is not a new SYN, it's an out-of-state packet -> drop
            if (!(tcp->syn && !tcp->ack)) {
                return XDP_DROP;
            }
            // Otherwise, it's a valid new SYN, create a new flow entry
            bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
        }

        // Additional TCP bypass checks for abnormal flags
        if (detect_tcp_bypass(tcp)) {
            return XDP_DROP;
        }

        // Deep Packet Inspection for TCP payload
        void *tcp_payload = (void *)((__u8 *)tcp + (tcp->doff * 4));
        if (tcp_payload < data_end) {  // there is payload (doff is header length in 32-bit words)
            if (deep_packet_inspection(tcp_payload, data_end)) {
                return XDP_DROP;
            }
        }

        // Anomaly Detection for this TCP flow
        if (detect_anomaly(flow_key)) {
            return XDP_DROP;
        }

        // ML-Based Threat Detection for this flow
        if (ml_threat_detection(flow_key)) {
            return XDP_DROP;
        }
    } 
    else {
        // For other protocols (ICMP, etc.), just pass through (or we could drop by default if not needed)
        return XDP_PASS;
    }

    // *** Global Rate Limiting (per-CPU) ***
    __u32 idx = 0;
    __u64 *last_time = bpf_map_lookup_elem(&rate_limit_map, &idx);
    if (last_time) {
        // If packets are coming faster than the allowed rate, drop this packet
        __u64 interval_ns = 1000000000ull / MAX_PACKET_RATE;  // nanoseconds per packet allowed
        if (now - *last_time < interval_ns) {
            return XDP_DROP;
        }
        // Update last packet time
        *last_time = now;
    }

    // If all checks passed, allow the packet through to the server
    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
