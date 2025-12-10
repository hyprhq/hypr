// SPDX-License-Identifier: GPL-2.0
//
// Drift L4 Ingress eBPF Program
//
// This program implements Layer 4 (TCP/UDP) port forwarding for incoming traffic.
// It attaches to the TC (Traffic Control) ingress hook and performs destination NAT
// (DNAT) to redirect traffic from host ports to VM backend IP:port pairs.
//
// Architecture:
// - Client → Host:8080 → VM:192.168.1.10:80
// - Rewrites packet destination from Host:8080 to VM IP:port
// - Creates conntrack entry for reverse NAT on egress path
//
// Key Features:
// - Zero-copy packet processing in kernel datapath
// - Per-CPU statistics for low-overhead metrics
// - LRU conntrack for automatic connection cleanup
// - Supports both TCP and UDP protocols
// - Full checksum recalculation for packet integrity

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// TC action return codes
#ifndef TC_ACT_OK
#define TC_ACT_OK 0        // Continue processing
#endif

// Ethernet and IP header constants
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800    // IPv4 protocol
#define ETH_HLEN 14        // Ethernet header length
#define IP_HLEN 20         // IP header length (minimum, without options)
#endif

// ============================================================================
// Port Mapping Configuration
// ============================================================================
//
// The portmap associates (protocol, host_port) with (backend_ip, backend_port).
// This allows external traffic destined for a host port to be forwarded to
// a specific VM backend.

// Key structure: identifies a host port + protocol
struct portmap_key {
	__u8 proto;       // IPPROTO_TCP (6) or IPPROTO_UDP (17)
	__u8 pad;         // Padding for alignment
	__be16 port;      // Host port in network byte order
};

// Value structure: specifies backend destination
struct portmap_value {
	__u32 dst_ip;     // Backend VM IP in HOST byte order (important!)
	__be16 dst_port;  // Backend port in network byte order
	__u16 pad;        // Padding for alignment
};

// Port mapping table (populated by userspace)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct portmap_key);
	__type(value, struct portmap_value);
} portmap SEC(".maps");

// ============================================================================
// Connection Tracking
// ============================================================================
//
// Conntrack maintains state for active connections to enable reverse NAT.
// When ingress rewrites destination (Client→Host → Client→VM), we must
// remember the original destination so egress can rewrite source (VM→Client)
// back to appear as (Host→Client).

// Conntrack key: identifies a connection by 5-tuple
struct conntrack_key {
	__be32 src_ip;    // Client IP (network byte order)
	__be32 dst_ip;    // Backend VM IP (network byte order)
	__be16 src_port;  // Client port (network byte order)
	__be16 dst_port;  // Backend port (network byte order)
	__u8 proto;       // Protocol (TCP or UDP)
	__u8 pad[3];      // Padding for alignment
};

// Conntrack value: stores original pre-NAT destination
struct conntrack_value {
	__be32 orig_dst_ip;    // Original host IP (network byte order)
	__be16 orig_dst_port;  // Original host port (network byte order)
	__u16 pad;             // Padding
	__u64 last_seen;       // Timestamp for connection tracking
};

// ============================================================================
// Compile-time Configuration
// ============================================================================
//
// These constants can be overridden at compile time via -D flags:
//   clang -DCONNTRACK_MAX_ENTRIES=131072 ...

#ifndef CONNTRACK_MAX_ENTRIES
#define CONNTRACK_MAX_ENTRIES 65536  // Default: ~64K concurrent connections
#endif

// Conntrack table (LRU evicts oldest entries automatically)
//
// IMPORTANT: LRU Eviction Behavior & Risks
// -----------------------------------------
// This map uses BPF_MAP_TYPE_LRU_HASH which automatically evicts the least-recently-used
// entries when the map reaches capacity. While this prevents memory exhaustion, it has
// implications for connection tracking:
//
// 1. **Connection Drop Risk**: Under heavy load with many unique 5-tuples, legitimate
//    connections may be evicted before they complete. This is particularly problematic
//    for long-lived TCP connections or bursty workloads that create many short connections.
//
// 2. **TCP State Machine**: This implementation is "stateless-ish" - it doesn't track
//    TCP state transitions (SYN/ACK/FIN/RST). A proper conntrack would track state
//    and handle FIN/RST races properly. The current approach may:
//    - Keep entries for connections that have already closed (until LRU eviction)
//    - Evict entries for connections that are still active
//
// 3. **Sizing Considerations**: The CONNTRACK_MAX_ENTRIES limit should be tuned based on
//    expected concurrent connection count. For high-throughput scenarios, consider:
//    - Increasing via -DCONNTRACK_MAX_ENTRIES=N (costs more memory in kernel space)
//    - Implementing active expiration based on last_seen timestamp (user-space reaper)
//    - Adding per-CPU maps to reduce contention
//
// 4. **Failure Mode**: When an entry is evicted prematurely, return traffic will not
//    be correctly SNATed on egress, causing asymmetric routing that breaks the connection.
//
// Memory usage: ~96 bytes/entry (key=24 + value=24 + LRU overhead ~48)
// Default 64K entries ≈ 6MB kernel memory
//
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONNTRACK_MAX_ENTRIES);
	__type(key, struct conntrack_key);
	__type(value, struct conntrack_value);
} conntrack SEC(".maps");

// ============================================================================
// Metrics
// ============================================================================
//
// Per-CPU statistics arrays for low-overhead monitoring.
// Using PERCPU avoids atomic operations and cache line contention.

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// Stat indices
#define STAT_INGRESS_PACKETS 0
#define STAT_INGRESS_BYTES   1

// Update a statistic counter atomically
static __always_inline void update_stats(__u32 idx, __u64 delta)
{
	__u64 *count = bpf_map_lookup_elem(&stats, &idx);
	if (count)
		__sync_fetch_and_add(count, delta);
}

// ============================================================================
// Main Ingress Handler
// ============================================================================
//
// Attached to TC ingress hook. Processes incoming packets and performs DNAT
// for packets matching port forwarding rules.

SEC("tc")
int drift_l4_ingress(struct __sk_buff *skb)
{
	// Get packet data pointers (skb linear data region)
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// ========================================================================
	// Layer 2: Ethernet Header Parsing
	// ========================================================================
	struct ethhdr *eth = data;
	// Bounds check: ensure we can read ethernet header
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	// Only process IPv4 packets
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	// ========================================================================
	// Layer 3: IP Header Parsing
	// ========================================================================
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	// Bounds check: ensure we can read IP header
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;

	// Validate IP header length (IHL field is in 4-byte words)
	if (iph->ihl < 5)
		return TC_ACT_OK;

	__u8 proto = iph->protocol;
	const __u32 l3_off = ETH_HLEN;
	const __u32 l4_off = ETH_HLEN + IP_HLEN;

	// ========================================================================
	// Layer 4: TCP Processing
	// ========================================================================
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
		// Bounds check: ensure we can read TCP header
		if ((void *)(tcph + 1) > data_end)
			return TC_ACT_OK;

		// Look up port forwarding rule for this destination port
		struct portmap_key key = {
			.proto = proto,
			.port = tcph->dest,  // Network byte order
		};

		struct portmap_value *val = bpf_map_lookup_elem(&portmap, &key);
		if (!val)
			return TC_ACT_OK;  // No forwarding rule, pass through

		// --------------------------------------------------------------------
		// CRITICAL: Save all packet values BEFORE modifying packet
		// --------------------------------------------------------------------
		// Packet-modifying helpers (bpf_skb_store_bytes, bpf_l3_csum_replace,
		// bpf_l4_csum_replace) invalidate all packet pointers (data, data_end,
		// eth, iph, tcph). We must extract all needed values first.
		__be32 orig_dst_ip = iph->daddr;
		__be16 orig_dst_port = tcph->dest;
		__be32 client_src_ip = iph->saddr;
		__be16 client_src_port = tcph->source;

		// New destination from portmap
		// NOTE: Map stores dst_ip in HOST byte order, but on little-endian
		// systems the memory representation matches network byte order
		__u32 new_dst_ip = val->dst_ip;
		__be16 new_dst_port = val->dst_port;

		// --------------------------------------------------------------------
		// Checksum Updates
		// --------------------------------------------------------------------
		// TCP checksum must be updated BEFORE packet modification.
		// Order: L4 checksum, then L3 checksum, then packet rewrite.

		// Update TCP checksum for port change
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
		                        orig_dst_port, new_dst_port, sizeof(new_dst_port)))
			return TC_ACT_OK;

		// Update TCP checksum for IP change (BPF_F_PSEUDO_HDR for pseudoheader)
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
		                        orig_dst_ip, new_dst_ip, sizeof(new_dst_ip) | BPF_F_PSEUDO_HDR))
			return TC_ACT_OK;

		// Update IP header checksum
		if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
		                        orig_dst_ip, new_dst_ip, sizeof(new_dst_ip)))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Packet Rewrite
		// --------------------------------------------------------------------
		// Write new destination port
		if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest),
		                        &new_dst_port, sizeof(new_dst_port), 0))
			return TC_ACT_OK;

		// Write new destination IP
		if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr),
		                        &new_dst_ip, sizeof(new_dst_ip), 0))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Connection Tracking
		// --------------------------------------------------------------------
		// Create conntrack entry for reverse NAT on egress.
		// This allows egress program to rewrite VM→Client packets back to
		// Host→Client, making the NAT transparent to the client.
		struct conntrack_key ct_key = {
			.src_ip = client_src_ip,       // Client IP (network order)
			.dst_ip = new_dst_ip,           // Backend VM IP (host order works for key)
			.src_port = client_src_port,    // Client port (network order)
			.dst_port = new_dst_port,       // Backend port (network order)
			.proto = proto,
		};

		struct conntrack_value ct_val = {
			.orig_dst_ip = orig_dst_ip,     // Original host IP
			.orig_dst_port = orig_dst_port, // Original host port
			.last_seen = bpf_ktime_get_ns(),
		};

		bpf_map_update_elem(&conntrack, &ct_key, &ct_val, BPF_ANY);

		// Update metrics
		update_stats(STAT_INGRESS_PACKETS, 1);

	// ========================================================================
	// Layer 4: UDP Processing
	// ========================================================================
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)(iph + 1);
		// Bounds check: ensure we can read UDP header
		if ((void *)(udph + 1) > data_end)
			return TC_ACT_OK;

		// Look up port forwarding rule
		struct portmap_key key = {
			.proto = proto,
			.port = udph->dest,
		};

		struct portmap_value *val = bpf_map_lookup_elem(&portmap, &key);
		if (!val)
			return TC_ACT_OK;  // No forwarding rule

		// Save packet values before modification
		__be32 orig_dst_ip = iph->daddr;
		__be16 orig_dst_port = udph->dest;
		__be32 client_src_ip = iph->saddr;
		__be16 client_src_port = udph->source;

		// New destination
		__u32 new_dst_ip = val->dst_ip;
		__be16 new_dst_port = val->dst_port;

		// --------------------------------------------------------------------
		// Checksum Updates
		// --------------------------------------------------------------------
		// UDP checksum is optional (can be 0). Only update if present.
		if (udph->check) {
			if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
			                        orig_dst_port, new_dst_port, sizeof(new_dst_port)))
				return TC_ACT_OK;

			if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
			                        orig_dst_ip, new_dst_ip, sizeof(new_dst_ip) | BPF_F_PSEUDO_HDR))
				return TC_ACT_OK;
		}

		// Update IP checksum
		if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
		                        orig_dst_ip, new_dst_ip, sizeof(new_dst_ip)))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Packet Rewrite
		// --------------------------------------------------------------------
		if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, dest),
		                        &new_dst_port, sizeof(new_dst_port), 0))
			return TC_ACT_OK;

		if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr),
		                        &new_dst_ip, sizeof(new_dst_ip), 0))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Connection Tracking
		// --------------------------------------------------------------------
		struct conntrack_key ct_key = {
			.src_ip = client_src_ip,
			.dst_ip = new_dst_ip,
			.src_port = client_src_port,
			.dst_port = new_dst_port,
			.proto = proto,
		};

		struct conntrack_value ct_val = {
			.orig_dst_ip = orig_dst_ip,
			.orig_dst_port = orig_dst_port,
			.last_seen = bpf_ktime_get_ns(),
		};

		bpf_map_update_elem(&conntrack, &ct_key, &ct_val, BPF_ANY);

		// Update metrics
		update_stats(STAT_INGRESS_PACKETS, 1);
	}

	return TC_ACT_OK;
}

// Required for eBPF programs
char _license[] SEC("license") = "GPL";
