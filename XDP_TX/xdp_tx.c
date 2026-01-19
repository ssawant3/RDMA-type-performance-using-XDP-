#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN 6

/* Map 1: Source IP -> Target Port to Match */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IPv4 Address
    __type(value, __u32); // Dest Port Number
} block_config_map SEC(".maps");

/* Map 2: Global Protocol Filter (e.g., Index 0 = 17 for UDP) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);  // Protocol ID
} block_proto_map SEC(".maps");

// Helper function to swap MAC addresses
static __always_inline void swap_mac_addresses(struct ethhdr *eth) {
    unsigned char temp[ETH_ALEN];
    
    // Copy Dest MAC to Temp
    __builtin_memcpy(temp, eth->h_dest, ETH_ALEN);
    
    // Copy Source MAC to Dest
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    
    // Copy Temp (Original Dest) to Source
    __builtin_memcpy(eth->h_source, temp, ETH_ALEN);
}

SEC("xdp")
int xdp_tx_mac_swap(struct xdp_md *ctx) {
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

    // 3. Check if Source IP exists in our map
    // Note: We use saddr (Source IP) as the key
    __u32 src_ip = iph->saddr; 
    __u32 *target_port = bpf_map_lookup_elem(&block_config_map, &src_ip);
    
    if (!target_port)
        return XDP_PASS; // Source IP not in list, let it pass to stack

    // 4. Check if Protocol matches the one in our Proto Map
    __u32 proto_key = 0;
    __u8 *target_proto = bpf_map_lookup_elem(&block_proto_map, &proto_key);
    
    if (!target_proto || iph->protocol != *target_proto)
        return XDP_PASS; // Protocol mismatch

    // 5. Check Destination Port (for UDP) and Perform Action
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        // Compare packet port with map port
        if (udp->dest == bpf_htons((__u16)*target_port)) {
            
            // --- MATCH FOUND ---
            
            // Swap MAC addresses (Dest <-> Source)
            swap_mac_addresses(eth);

            // Send it back out the same interface
            return XDP_TX; 
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";