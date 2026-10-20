//go:build ignore

// --------- Synopsis --------- //
// This file is the XDP blocklist for the user-space detector
// ¤ Remember that this is a XDP hook on received packets
// - In other words, this program will run per packet
// ¤ It only drops sources the user-space detector has flagged; all other packets pass to the
//   AF_PACKET socket the detector reads, unchanged
// ¤ It does no counting beyond the blocklist itself, so the per-packet cost it adds to the
//   user-space path is one parse and one hash lookup

// --------- Commands --------- //
// 1. Compile Code: clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c blocklist.c -o blocklist.o
// - g: Generate debug information flag
// - O2: Aggressive compilation flag
// - I: Header Path
// 2. Attach to Network Interface: sudo ip link set dev enp3s0 xdpgeneric obj blocklist.o sec xdp
// ¤ Use the same XDP mode (xdpgeneric or xdpdrv) as the kernel-space runs, so the cost of a drop is comparable
// 3. Show Attached Links: ip link show
// 4. Maps are pinned automatically (LIBBPF_PIN_BY_NAME) to /sys/fs/bpf/<map name>
// ¤ The names are prefixed with us_ so they do not collide with the kernel-space program's pins
// ¤ If a map's definition changes, remove its old pin first or loading fails:
//   sudo rm -f /sys/fs/bpf/us_blocklist_map /sys/fs/bpf/us_blocked_stats
// 5. Inspect the blocklist: sudo bpftool map dump pinned /sys/fs/bpf/us_blocklist_map
// 6. Inspect the drop totals: sudo bpftool map dump pinned /sys/fs/bpf/us_blocked_stats
// 7. Detatch from Network Interface: sudo ip link set dev enp3s0 xdpgeneric off
// 8. Delete Maps: sudo rm -f /sys/fs/bpf/us_blocklist_map /sys/fs/bpf/us_blocked_stats

// ---- Include Packages ---- //
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ------- Definitions ------- //

// ¤ Blocklist Parameters
#define BLOCKLIST_SIZE 1000 // Max number of blocked IP addresses, same as the kernel-space blocklist

// -------- Licensing -------- //
char LICENSE[] SEC("license") = "GPL";

// ----- Data Structures ----- //

// Value of a blocklist entry, laid out like the kernel-space one
// ¤ Userspace inserts the entry with last_seen_ns = now and drops = 0
// ¤ XDP refreshes both on every dropped packet
// ¤ Userspace evicts the most stale entry (oldest last_seen_ns, ties broken by fewest drops) when the map is full
struct block_entry
{
    __u64 last_seen_ns; // CLOCK_TAI time of the last dropped packet
    __u64 drops;        // Number of packets dropped
};

struct { // Data structure to store IP blocklist (modified from userspace)
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH); // Per-CPU so a flood does not bounce one cache line between cores
    __uint(max_entries, BLOCKLIST_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // Pin filepath ending to struct name
} us_blocklist_map SEC(".maps");

struct blocked_totals { __u64 packets; __u64 bytes; };

struct { // Packets and bytes dropped by the blocklist since the program was loaded
    // ¤ A single cumulative entry, not one per window slot: user-space windows follow the packets'
    //   socket timestamps, not CLOCK_TAI slots, so the detector takes the difference at each window close
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct blocked_totals);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} us_blocked_stats SEC(".maps");

// ----- Helper Functions ----- //

// This helper function parses packets
// ¤ Same parsing and key layout as parse_packet in kernelspace/heavykeeper/heavy_keeper.c, so a source
//   has the same key in both blocklists: IPv4 is stored as an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
// ¤ Unlike the user-space capture, VLAN tags are not followed, so tagged traffic is never dropped
static __always_inline int parse_packet(struct xdp_md *ctx, struct in6_addr *unified_ip)
{
    // Memory addresses to raw packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Memory addresses for packet header data
    struct ethhdr *eth = data;

    // Ethernet layer: memory bound check
    // ¤ Required for kernel verifier
    if ((void *)(eth + 1) > data_end)
    {
        return 0;
    } // --> Exit Program Logic

    // Network layer: memory bound check + protocol check
    // ¤ Network byte order is big-endian, so the protocol is compared with bpf_htons()
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
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {                                             // IPv6 check
        struct ipv6hdr *ip6h = (void *)(eth + 1); // Define IPv6 header
        if ((void *)(ip6h + 1) > data_end)
        { // Memory bounds check
            return 0;
        } // --> Exit Program Logic
        *unified_ip = ip6h->saddr;
    }
    else
    {
        return 0; // Non-IP packet
    }

    return 1;
}

// ---------- Main ----------- //

SEC("xdp") // Specify program entry point
int us_blocklist(struct xdp_md *ctx)
{
    struct in6_addr unified_ip = {};

    // This function parses the raw packet:
    // ¤ Returns 1 if successful, 0 if not successful
    if (parse_packet(ctx, &unified_ip) <= 0)
        return XDP_PASS; // --> Exit Program Logic

    // Drop blocked sources before they reach the detector's socket
    // ¤ The entry is this CPU's copy, so no atomics are needed
    struct block_entry *blocked = bpf_map_lookup_elem(&us_blocklist_map, &unified_ip);
    if (!blocked)
        return XDP_PASS;

    blocked->last_seen_ns = bpf_ktime_get_tai_ns();
    blocked->drops++;

    __u32 key = 0;
    struct blocked_totals *bt = bpf_map_lookup_elem(&us_blocked_stats, &key);
    if (bt) {
        bt->packets++;
        bt->bytes += ctx->data_end - ctx->data;
    }

    return XDP_DROP;
}
