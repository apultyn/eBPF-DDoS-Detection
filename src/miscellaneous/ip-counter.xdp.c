// Simple XDP program counting packets from each IPv4 or IPv6 addresses

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); // many different BPF map types
    // three parts:
    //      LRU - LAST RECENTLY USED - when the map is full (all 16384 addresses are used), last used number is evicted
    //      PERCPU - performance + no race condition - every CPU has it's own seperate counter
    //      HASH - key/value table
    __uint(max_entries, 16384);
    __type(key, __u32);   // IPv4 source address
    __type(value, __u64); // packet count
} ip_counts_v4 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u128);  // IPv6 source address
    __type(value, __u64); // packet count
} ip_counts_v6 SEC(".maps");

SEC("xdp.frags")
int xdp_packet_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data; // Ethernet header

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) // IPv4
    {
        struct iphdr *ipv4 = (void *)(eth + 1); // Skip the Ethernet header to IP header
        if ((void *)(ipv4 + 1) > data_end)      // always checking read data
            return XDP_PASS;

        __u32 key = ipv4->saddr;
        __u64 *count = bpf_map_lookup_elem(&ip_counts_v4, &key);

        if (count)
        {
            (*count)++;
        }
        else
        {
            __u64 one = 1;
            bpf_map_update_elem(&ip_counts_v4, &key, &one, BPF_ANY);
        }
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) // IPv6
    {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_PASS;

        __u128 key;
        __builtin_memcpy(&key, &ipv6->saddr, sizeof(key));
        __u64 *count = bpf_map_lookup_elem(&ip_counts_v6, &key);

        if (count)
        {
            (*count)++;
        }
        else
        {
            __u64 one = 1;
            bpf_map_update_elem(&ip_counts_v6, &key, &one, BPF_ANY);
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

// clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c ip-counter.xdp.c -o ip-counter.xdp.o
// sudo ip link set dev enp3s0 xdp obj ip-counter.xdp.o sec xdp.frags
// sudo bpftool map dump name ip_counts_v6
// sudo ip link set dev enp3s0 xdp off