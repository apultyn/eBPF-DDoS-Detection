#ifndef HEAVYKEEPER_H
#define HEAVYKEEPER_H

/* ============================================================
 * HeavyKeeper constants, identical to the Go reference
 * ============================================================ */
#define HK_DECAY_LUT_SIZE 64     /* boundary of precomputed decay table */
#define HK_FP_SALT 0xa5a5a5a5    /* fingerprint salt */
#define HK_MAX_COUNT 0xffffffffu /* saturation point of a bucket counter */
#define HK_SEED_BASE 0x9e3779b9u
#define HK_KEY_SEED 0x9e3779b97f4a7c15ull

/* Mask sizes for IP addresses */
#ifndef HK_PREFIX_V4
#define HK_PREFIX_V4 32
#endif

#ifndef HK_PREFIX_V6
#define HK_PREFIX_V6 64
#endif
/* =========================== */

/* Height of sketch (and amount of hash functions) */
#ifndef HK_HEIGHT
#define HK_HEIGHT 4
#endif

/* Width of sketch (how many hash values are stored) */
#ifndef HK_WIDTH
#define HK_WIDTH 1024
#endif

/* eBPF compiler checks*/
#if (HK_WIDTH & (HK_WIDTH - 1)) != 0
#error "HK_WIDTH must be a power of two"
#endif

#if HK_HEIGHT * HK_WIDTH > 4096
#error "sketch exceeds the 32 KiB per-CPU value limit"
#endif

/* For flattening the 2-dimenshional table */
#define HK_BUCKETS (HK_HEIGHT * HK_WIDTH)

/* How many IP's are blocked */
#ifndef HK_BLOCK_ENTRIES
#define HK_BLOCK_ENTRIES 65536
#endif

/* 0: just log blocked packets
 * 1: drop blocked packets */
#ifndef HK_ENFORCE
#define HK_ENFORCE 0
#endif

/* Window length in ms */
#ifndef HK_WINDOW_MS
#define HK_WINDOW_MS 1000
#endif

/* ============================================================
 * Packets per window from one key that trigger a block,
 * per IP family
 * ============================================================ */
#ifndef HK_THRESHOLD_V4
#define HK_THRESHOLD_V4 50000
#endif

#ifndef HK_THRESHOLD_V6
#define HK_THRESHOLD_V6 100000
#endif
/* ============================================================ */

/* Upper boundry for CPU number as of year 2026 */
#ifndef HK_MAX_CPUS
#define HK_MAX_CPUS 4096
#endif

/* Sketch bucket */
struct hk_bucket
{
    __u16 fp;
    __u32 count;
};

/* Sketch flattened to array - b[row * HK_WIDTH + col] */
struct hk_sketch
{
    struct hk_bucket b[HK_BUCKETS];
};

/*
 * Flow key: a source address, masked to the family's prefix, as the 16
 * bytes of an IPv6 address in network byte order. IPv4 is stored
 * IPv4-mapped (::ffff:a.b.c.d), so the families can never collide and
 * bpftool prints every key as the address bytes in order.
 */
struct hk_key
{
    __u8 addr[16];
} __attribute__((aligned(4)));

/*
 * Per-CPU state. epoch is the window the CPU's sketch belongs to; it is
 * written only after the sketch has been cleared, so another CPU that
 * sees the current epoch never reads stale counts.
 */
struct hk_state
{
    __u64 epoch;
    __u64 packets;   /* every frame seen                              */
    __u64 ipv4;      /* IPv4 frames counted in the sketch             */
    __u64 ipv6;      /* IPv6 frames counted in the sketch             */
    __u64 non_ip;    /* well-formed frames of another protocol        */
    __u64 malformed; /* truncated Ethernet, VLAN, IPv4 or IPv6 headers */
    __u64 dropped;   /* frames dropped because their source is blocked */
    __u64 blocked;   /* blocklist entries created                     */
    __u64 checks;    /* cross-CPU sums performed                      */
};

/* Structure storing blocked element by the algorithm */
struct hk_block
{
};

/* The sketch's view of a key: where it lives in each row and its fingerprint */
struct hk_hash
{
    __u32 slot[HK_HEIGHT];
    __u16 fp;
};

/* Results of parsing incoming packet */
enum hk_parse
{
    HK_PARSE_IPV4,
    HK_PARSE_IPV6,
    HK_PARSE_OTHER,
    HK_PARSE_ERROR,
};

#endif