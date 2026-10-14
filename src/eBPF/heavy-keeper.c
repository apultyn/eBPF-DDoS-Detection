// --------- Synopsis --------- //
// This file constitute a preliminary implementation for HeavyKeeper in kernel space
// ¤ Remember that this is a XDP hook on received packets
// - In other words, this program will run per packet

// --------- Commands --------- //
// 1. Compile Code: clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c heavy_keeper.c -o heavy_keeper.o
// - g: Generate debug information flag
// - O2: Aggressive compilation flag
// - I: Header Path
// 2. Attach to Network Interface: sudo ip link set dev lo xdpgeneric obj heavy_keeper.o sec xdp
// 3. Show Attached Links: ip link show
// 4. Expose Filepath for Userspace Programs: sudo bpftool map pin name data_sketch_map /sys/fs/bpf/heavy_keeper_map
// 5. Read From Debug Tracepipe: sudo cat /sys/kernel/debug/tracing/trace_pipe
// 6. Detatch from Network Interface: sudo ip link set dev lo xdpgeneric off

// -------- Information -------- //
// struct xdp_md {
//     __u32 data;            -->  Memory pointer to the FIRST byte of the packet
//     __u32 data_end;        -->  Memory pointer to ONE PAST the LAST byte of the packet
//     __u32 data_meta;       -->  Pointer to custom packet metadata
//     __u32 ingress_ifindex; -->  Interface index
//     __u32 rx_queue_index;  -->  Hardware RX queue index
//     __u32 egress_ifindex;
// };
//
// struct ethhdr {
//     unsigned char   h_dest[ETH_ALEN];   --> Destination ethernet address (6 bytes)
//     unsigned char   h_source[ETH_ALEN]; --> Source ethernet address      (6 bytes)
//     __be16          h_proto;            --> Packet type ID field         (2 bytes)
// } __attribute__((packed));

// ---- Include Packages ---- //
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ------- Definitions ------- //
#define FINGERPRINT_SEED 0x75a2e345

// ¤ HeavyKeeper Tuning Parameters
#define DEPTH 3
#define WIDTH 65536
#define MASK (WIDTH - 1)
#define TOTAL_BUCKETS (DEPTH * WIDTH)
#define DECAY_THRESHOLD 64

// -------- Constants -------- //

// Premade seed table
static const __u32 INDEX_SEEDS[DEPTH] = {
    0x9747b28c,
    0x5bd1e995,
    0x239b921b};

// Precomputed fixed-point thresholds for P = (1.08)^(-C) * 65535
// ¤ We multiply by 65535 to the 0-1 range into an unsigned 16-bit number
static const __u16 DECAY_TABLE[DECAY_THRESHOLD] = {
    65535, 60680, 56185, 52023, 48170, 44602, 41298, 38239,
    35406, 32783, 30355, 28106, 26024, 24097, 22312, 20659,
    19129, 17712, 16400, 15185, 14060, 13019, 12055, 11162,
    10335, 9569, 8860, 8204, 7596, 7034, 6513, 6030,
    5584, 5170, 4787, 4433, 4104, 3800, 3519, 3258,
    3017, 2793, 2586, 2395, 2217, 2053, 1901, 1760,
    1630, 1509, 1397, 1294, 1198, 1109, 1027, 951,
    881, 815, 755, 699, 647, 599, 555, 514};

// -------- Licensing -------- //
char LICENSE[] SEC("license") = "GPL";

// ----- Data Structures ----- //
struct bucket
{
    __u16 fp;    // 16-bit fingerprint of the IP (0 = empty slot)
    __u16 _pad;  // Explicit padding for 4-byte natural alignment
    __u32 count; // 32-bit packet count
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);   // Allocate data structure as a fixed-size contiguous array
    __uint(max_entries, TOTAL_BUCKETS); // Number of addressable cells
    __type(key, __u32);                 // Flattened index: (row * WIDTH) + bucket_index
    __type(value, struct bucket);       // What each cell contains
} data_sketch_map SEC(".maps");

// ----- Helper Functions ----- //

// This helper function parses packets
static __always_inline int parse_packet(struct xdp_md *ctx, struct in6_addr *unified_ip)
{
    // Memory addresses to raw packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Memory addresses for packet header data
    struct ethhdr *eth = data;

    // Ethernet layer: memory bound check
    // ¤ Required for kernel verifier
    // ¤ Pointer Arithmetic:
    // - (eth+1) = data memory address + sizeof(eth)
    //           = data memory address + 14 bytes
    // ¤ Checks if ethernet header is within allowed memory space
    // - If it's outside allowed memory, we exit program logic
    if ((void *)(eth + 1) > data_end)
    {
        bpf_printk("Packet ethernet header is larger than allocated memory space\n");
        return 0;
    } // --> Exit Program Logic

    // Network layer: memory bound check + protocol check
    // ¤ Note that network byte order is big-endian and CPU byte order is little-endian
    // - ETH_P_IP is the Ethernet Identifier for IPv4 (little-endian)
    // - We convert it to big-endian using bpf_htons() so we compare correctly
    // ¤ Checks if ethernet protocol is IPv4 or IPv6 and their respective memory bounds
    // - If it's another protocol, we exit program logic
    // - If it's correct procotol, we can safely store IP addresses
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {                                          // IPv4 check
        struct iphdr *iph = (void *)(eth + 1); // Define IPv4 header
        if ((void *)(iph + 1) > data_end)
        { // Memory bounds check
            return 0;
        } // --> Exit Program Logic
        // Standard mapping of IPv4 to IPv6 protocol using in6_addr union struct
        unified_ip->s6_addr[10] = 0xff;
        unified_ip->s6_addr[11] = 0xff;
        unified_ip->s6_addr32[3] = iph->saddr;
        bpf_printk("IPv4 packet logged from: %pI4\n", &iph->saddr);
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {                                             // IPv6 check
        struct ipv6hdr *ip6h = (void *)(eth + 1); // Define IPv6 header
        if ((void *)(ip6h + 1) > data_end)
        { // Memory bounds check
            return 0;
        } // --> Exit Program Logic
        *unified_ip = ip6h->saddr;
        bpf_printk("IPv6 packet logged from: %pI6\n", &ip6h->saddr);
    }
    else
    {
        bpf_printk("Non-IP Packet Detected!");
        return 0;
    }

    return 1;
}

// Helper function that performs 32-bitwise left rotation
// Parameter x: 32-bit integer to rotate
// Parameter r: number of rotations (max 31)
static __always_inline __u32 rotate_left32(__u32 x, __s8 r)
{
    return (x << r) | (x >> (32 - r));
}

// Helper function that performs Murmur3 32-bit core mix step for one 4-byte block
// ¤ Creates an avalanche effect
// - Ensure IP addresses that differ with one bit look completely random after hashing is done
static __always_inline __u32 scramble32(__u32 k)
{
    k *= 0xcc9e2d51;          // Non-linear multiplication with odd prime number constant
    k = rotate_left32(k, 15); // Rotate to make sure higher bits affect lower bits
    k *= 0x1b873593;          // Non-linear multiplication with odd prime number constant
    return k;
}

// Helper function that computes a 32-bit MurmurHash3 across the 16-byte struct in6_addr
static __always_inline __u32 hash32(const struct in6_addr *ip, __u32 seed)
{
    // Define accumulator
    __u32 h = seed;

// Hash the 16-byte IP-address in steps of 4-byte loops and accumulate to h
// ¤ We unfurl the loop to avoid verifier complaints
#pragma unroll
    for (int i = 0; i < 4; i++)
    {
        __u32 k = ip->s6_addr32[i];
        h ^= scramble32(k);       // Scramble
        h = rotate_left32(h, 13); // Rotate to shift bit positions (otherwise they would line up predictably)
        h = h * 5 + 0xe6546b64;   // This is an affine transformation that equates to (h << 2) + h
    }

    // Shift-multiply-shift sequence (Murmur fmix32)
    h ^= 16;         // Length Binding
    h ^= h >> 16;    // High-to-Low Diffusion
    h *= 0x85ebca6b; // Non-linear Multiplication
    h ^= h >> 13;    // High-to-Low Diffusion
    h *= 0xc2b2ae35; // Non-linear Multiplication
    h ^= h >> 16;    // High-to-Low Diffusion

    return h;
}

// Helper function for HeavyKeeper decay
// ¤ Note that the random number is generated outside this function and passed to it
static __always_inline int decay(__u32 count, __u32 random_value)
{
    // If count >= 64, do not decay
    if (count >= DECAY_THRESHOLD)
        return 0;

    // O(1) array lookup
    __u16 random_sample = (__u16)(random_value & 0xffff);
    return random_sample < DECAY_TABLE[count]; // return 0 for large flows, returns 1 for small flows
}

// Helper function that updates the HeavyKeeper sketch across all rows called on each parsed packet
static __always_inline void update(const struct in6_addr *ip)
{
    // Compute fingerprint for specific IP address
    __u32 fp_raw = hash32(ip, FINGERPRINT_SEED);
    __u16 fp = (__u16)(fp_raw ^ (fp_raw >> 16)); // Take lower 16 bits to match bitsize
    if (fp == 0)
        fp = 1; // Reserve 0 for empty slots

// Iterate through all rows
#pragma unroll
    for (int row = 0; row < DEPTH; row++)
    {
        // Compute column index for this row using SEEDS[row] & bitwise MASK
        __u32 column_index = hash32(ip, INDEX_SEEDS[row]) & MASK; // Restrict bucket index to 32-bits
        __u32 flat_index = (row * WIDTH) + column_index;          // Calculate flat index

        // Lookup cell in data sketch map
        // ¤ We return a pointer to a bucket struct
        struct bucket *b = bpf_map_lookup_elem(&data_sketch_map, &flat_index);
        if (!b) // Satisfy verifier null-pointer check (this should never occur)
            continue;

        // Case A: Index lands on empty bucket --> Populate it
        // ¤ Packet is not part of current network traffic flow
        if (b->count == 0)
        {
            b->fp = fp;
            b->count = 1;
            continue;
        }

        // Case B: Index lands on a filled bucket with fingerprint match --> Increment count
        // ¤ Packet is part of current network traffic flow
        if (b->fp == fp)
        {
            __sync_fetch_and_add(&b->count, 1); // Atomic fetch and add
            continue;
        }

        // Case C: Index lands on a filled bucket without fingerprint match --> Collision --> Probabilistic decay
        __u32 random_value = bpf_get_prandom_u32(); // Use built-in bpf function to retrieve random value
        if (decay(b->count, random_value))          // If decay returns 1 --> Proceed
        {
            // Decrement counter
            if (b->count > 0)
                b->count--;

            // If count hits 0:
            // ¤ Evict old flow
            // ¤ Arriving packet claims bucket
            if (b->count == 0)
            {
                b->fp = fp;
                b->count = 1;
            }
        }
    }
}

// ---------- Main ----------- //

SEC("xdp") // Specify program entry point
int heavy_keeper(struct xdp_md *ctx)
{
    struct in6_addr unified_ip = {};

    // This function parses the raw packet:
    // ¤ Returns 1 if successful, 0 if not successful
    if (parse_packet(ctx, &unified_ip) <= 0)
        return XDP_PASS; // --> Exit Program Logic

    // Hash IP, decay and add to corresponding bucket
    update(&unified_ip);

    return XDP_PASS;
}
