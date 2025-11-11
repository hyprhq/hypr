// SPDX-License-Identifier: GPL-2.0
//
// Drift L4 Egress eBPF Program
//
// This program implements reverse NAT for Layer 4 (TCP/UDP) return traffic.
// It attaches to the TC (Traffic Control) egress hook and performs source NAT
// (SNAT) to rewrite response packets from VMs back to the original host address.
//
// Architecture:
// - VM:192.168.1.10:80 → Client → appears as Host:8080 → Client
// - Looks up original destination from conntrack (created by ingress)
// - Rewrites packet source to original host IP:port
//
// Key Features:
// - Stateless reverse NAT using conntrack lookup
// - Per-CPU statistics for low-overhead metrics
// - Supports both TCP and UDP protocols
// - Full checksum recalculation for packet integrity
// - Works in tandem with drift_l4_ingress.c

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
#define IP_HLEN 20         // IP header length (minimum)
#endif

// ============================================================================
// Connection Tracking
// ============================================================================
//
// Conntrack is shared with the ingress program. Ingress creates entries
// mapping (Client IP:port, VM IP:port) → original host IP:port.
// Egress uses this to rewrite VM→Client responses to appear as Host→Client.

// Conntrack key: identifies a connection by 5-tuple
struct conntrack_key {
	__be32 src_ip;    // Source IP (network byte order)
	__be32 dst_ip;    // Destination IP (network byte order)
	__be16 src_port;  // Source port (network byte order)
	__be16 dst_port;  // Destination port (network byte order)
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

// Conntrack table (shared with ingress via pinned map)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conntrack_key);
	__type(value, struct conntrack_value);
} conntrack SEC(".maps");

// ============================================================================
// Metrics
// ============================================================================
//
// Per-CPU statistics arrays for low-overhead monitoring.
// Shared with ingress program for unified metrics.

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// Stat indices (different from ingress to avoid conflicts)
#define STAT_EGRESS_PACKETS  2
#define STAT_EGRESS_BYTES    3

// Update a statistic counter atomically
static __always_inline void update_stats(__u32 idx, __u64 delta)
{
	__u64 *count = bpf_map_lookup_elem(&stats, &idx);
	if (count)
		__sync_fetch_and_add(count, delta);
}

// ============================================================================
// Main Egress Handler
// ============================================================================
//
// Attached to TC egress hook. Processes outgoing packets (VM→Client responses)
// and performs reverse NAT by looking up original host destination in conntrack.

SEC("tc")
int drift_l4_egress(struct __sk_buff *skb)
{
	// Get packet data pointers
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

	// Validate IP header length
	if (iph->ihl < 5)
		return TC_ACT_OK;

	__u8 proto = iph->protocol;
	const __u32 l3_off = ETH_HLEN;
	const __u32 l4_off = ETH_HLEN + IP_HLEN;

	// ========================================================================
	// Layer 4: TCP Processing
	// ========================================================================
	if (proto == IPPROTO_TCP) {
		void *l4 = data + l4_off;
		// Bounds check: ensure we can read TCP header
		if (l4 + sizeof(struct tcphdr) > data_end)
			return TC_ACT_OK;

		struct tcphdr *tcph = l4;

		// --------------------------------------------------------------------
		// Conntrack Lookup
		// --------------------------------------------------------------------
		// For egress (VM→Client response), we need to find the original
		// host IP:port that the client connected to.
		//
		// Packet structure for response:
		// - Source: VM IP:port (iph->saddr, tcph->source)
		// - Dest: Client IP:port (iph->daddr, tcph->dest)
		//
		// Conntrack key was created by ingress as:
		// - src_ip: Client IP
		// - dst_ip: VM IP
		// - src_port: Client port
		// - dst_port: VM port
		//
		// To look up reverse direction, we swap src/dst:
		struct conntrack_key ct_key = {
			.src_ip = iph->daddr,     // Client IP (destination in response)
			.dst_ip = iph->saddr,     // VM IP (source in response)
			.src_port = tcph->dest,   // Client port
			.dst_port = tcph->source, // VM port
			.proto = proto,
		};

		struct conntrack_value *ct_val = bpf_map_lookup_elem(&conntrack, &ct_key);
		if (!ct_val)
			return TC_ACT_OK;  // No conntrack entry, pass through

		// --------------------------------------------------------------------
		// Reverse NAT
		// --------------------------------------------------------------------
		// Rewrite source from VM IP:port to original host IP:port.
		// This makes the response appear to come from the host, not the VM,
		// maintaining transparency for the client.
		__be32 new_src_ip = ct_val->orig_dst_ip;
		__be16 new_src_port = ct_val->orig_dst_port;

		// Save old values for checksum calculation
		__be16 old_port = tcph->source;
		__be32 old_ip = iph->saddr;

		// --------------------------------------------------------------------
		// Checksum Updates
		// --------------------------------------------------------------------
		// Update TCP checksum for port change
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
		                        old_port, new_src_port, sizeof(new_src_port)))
			return TC_ACT_OK;

		// Update TCP checksum for IP change
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
		                        old_ip, new_src_ip, sizeof(new_src_ip) | BPF_F_PSEUDO_HDR))
			return TC_ACT_OK;

		// Update IP header checksum
		if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
		                        old_ip, new_src_ip, sizeof(new_src_ip)))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Packet Rewrite
		// --------------------------------------------------------------------
		// Write new source port
		if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, source),
		                        &new_src_port, sizeof(new_src_port), 0))
			return TC_ACT_OK;

		// Write new source IP
		if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr),
		                        &new_src_ip, sizeof(new_src_ip), 0))
			return TC_ACT_OK;

		// Update metrics
		update_stats(STAT_EGRESS_PACKETS, 1);
		update_stats(STAT_EGRESS_BYTES, skb->len);

	// ========================================================================
	// Layer 4: UDP Processing
	// ========================================================================
	} else if (proto == IPPROTO_UDP) {
		void *l4 = data + l4_off;
		// Bounds check: ensure we can read UDP header
		if (l4 + sizeof(struct udphdr) > data_end)
			return TC_ACT_OK;

		struct udphdr *udph = l4;

		// --------------------------------------------------------------------
		// Conntrack Lookup
		// --------------------------------------------------------------------
		// Same logic as TCP: swap src/dst to find reverse direction
		struct conntrack_key ct_key = {
			.src_ip = iph->daddr,
			.dst_ip = iph->saddr,
			.src_port = udph->dest,
			.dst_port = udph->source,
			.proto = proto,
		};

		struct conntrack_value *ct_val = bpf_map_lookup_elem(&conntrack, &ct_key);
		if (!ct_val)
			return TC_ACT_OK;

		// Rewrite source to original host IP:port
		__be32 new_src_ip = ct_val->orig_dst_ip;
		__be16 new_src_port = ct_val->orig_dst_port;

		__be16 old_port = udph->source;
		__be32 old_ip = iph->saddr;

		// --------------------------------------------------------------------
		// Checksum Updates
		// --------------------------------------------------------------------
		// UDP checksum is optional. Only update if present.
		if (udph->check) {
			if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
			                        old_port, new_src_port, sizeof(new_src_port)))
				return TC_ACT_OK;

			if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check),
			                        old_ip, new_src_ip, sizeof(new_src_ip) | BPF_F_PSEUDO_HDR))
				return TC_ACT_OK;
		}

		// Update IP checksum
		if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
		                        old_ip, new_src_ip, sizeof(new_src_ip)))
			return TC_ACT_OK;

		// --------------------------------------------------------------------
		// Packet Rewrite
		// --------------------------------------------------------------------
		// Write new source port
		if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, source),
		                        &new_src_port, sizeof(new_src_port), 0))
			return TC_ACT_OK;

		// Write new source IP
		if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr),
		                        &new_src_ip, sizeof(new_src_ip), 0))
			return TC_ACT_OK;

		// Update metrics
		update_stats(STAT_EGRESS_PACKETS, 1);
		update_stats(STAT_EGRESS_BYTES, skb->len);
	}

	return TC_ACT_OK;
}

// Required for eBPF programs
char _license[] SEC("license") = "GPL";
