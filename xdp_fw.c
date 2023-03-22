//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define IPV4_PREFIX_LEN 32

enum {
	BPF_F_NO_PREALLOC = (1U << 0),
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
        __u32   prefixlen;      /* up to 32 for AF_INET, 128 for AF_INET6 */
        __u8    data[0];        /* Arbitrary size */
};

struct src_ip4_trie_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 saddr[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct src_ip4_trie_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} firewall_map SEC(".maps");

typedef char groupkey[64];

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    groupkey* key;
    __type(value, __u32);
} group_map SEC(".maps");

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

	struct src_ip4_trie_key key;
	key.lpm_key.prefixlen = IPV4_PREFIX_LEN;
	key.saddr[0]   = ip->saddr & 0xff;
	key.saddr[1]   = (ip->saddr >> 8) & 0xff;
	key.saddr[2]   = (ip->saddr >> 16) & 0xff;
	key.saddr[3]   = (ip->saddr >> 24) & 0xff;

	if (tcp->dest == bpf_htons(8080)) {
		__u32 *drops = bpf_map_lookup_elem(&firewall_map, &key);
		if (drops) { // source IP in block list, drop it
			__u32 *value = 0;
			groupkey gkey = "firewall_map";
			value = bpf_map_lookup_elem(&group_map, &gkey);
			/*
			 * https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-September/001088.html
			 * R0 invalid mem access 'map_value_or_null', do NULL
			 * check before dereference
			 */
			if ( value ) {
				if ( *value == 1 ) {
					__sync_fetch_and_add(drops, 1);
					return XDP_DROP;
				}
			}
		}
	}

	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
