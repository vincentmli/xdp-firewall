//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

enum {
	BPF_F_NO_PREALLOC = (1U << 0),
};

struct ip4_trie_key {
	__u32 prefixlen;
	__u8 saddr[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct ip4_trie_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} firewall_map SEC(".maps");

SEC("xdp")
int firewall(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// Only IPv4 supported for this example
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		// Malformed Ethernet header
		return XDP_ABORTED;
	}

	if (ether->h_proto != 0x08U) { // htons(ETH_P_IP) -> 0x08U
		// Non IPv4 traffic
		return XDP_PASS;
	}

	data += sizeof(*ether);
	struct iphdr *ip = data;
	if (data + sizeof(*ip) > data_end) {
		// Malformed IPv4 header
		return XDP_ABORTED;
	}

	// L4
	if (ip->protocol != 0x06) { // IPPROTO_TCP -> 6
		// Non TCP
		return XDP_PASS;
	}
	data += ip->ihl * 4;
	struct tcphdr *tcp = data;
	if (data + sizeof(*tcp) > data_end) {
		return XDP_ABORTED;
	}

	//	struct ip4_trie_key key;

	struct {
		__u32 prefixlen;
		__u32 saddr;
	} key;

	key.prefixlen  = 32;
	key.saddr      = ip->saddr;
	__u64 *blocked = 0;

	if (tcp->dest == bpf_htons(8080)) {
		if ((blocked = bpf_map_lookup_elem(&firewall_map, &key))) {
			return XDP_DROP;
		}
	}

	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
