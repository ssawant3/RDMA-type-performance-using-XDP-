#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map 1: Destination IP -> Target Port to block */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // source IPv4 Address
    __type(value, __u32); // dest Port Number
} block_config_map SEC(".maps");

/* Map 2: Global Protocol Filter (e.g., Index 0 = 17 for UDP) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);  // Protocol ID
} block_proto_map SEC(".maps");

SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 3. Check if source IP exists in our map
    __u32 src_ip = iph->saddr; 
    __u32 *target_port = bpf_map_lookup_elem(&block_config_map, &src_ip);
    
    if (!target_port)
        return XDP_PASS; // IP not in block list

    // 4. Check if Protocol matches the one in our Proto Map
    __u32 proto_key = 0;
    __u8 *target_proto = bpf_map_lookup_elem(&block_proto_map, &proto_key);
    
    if (!target_proto || iph->protocol != *target_proto)
        return XDP_PASS; // Protocol doesn't match (e.g., not UDP)

    // 5. Check Destination Port (for UDP)
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        // Compare packet port with map port (handling byte order)
        if (udp->dest == bpf_htons((__u16)*target_port)) {
            return XDP_DROP; // IP + Protocol + Port all match!
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";