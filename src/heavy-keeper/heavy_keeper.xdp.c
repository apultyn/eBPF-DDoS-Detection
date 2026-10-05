#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "heavy_keeper.h"

/* ============================================================
 * Casting allows libbpf loader to overwrite the values without
 * recompilation
 * ============================================================ */
volatile const __u32 hk_prefix_v4 = HK_PREFIX_V4;
volatile const __u32 hk_prefix_v6 = HK_PREFIX_V6;
volatile const __u32 hk_enforce = HK_ENFORCE;
volatile const __u64 hk_window_ns = HK_WINDOW_MS * 1000000ULL;
volatile const __u32 hk_threshold_v4 = HK_THRESHOLD_V4;
volatile const __u32 hk_threshold_v6 = HK_THRESHOLD_V6;

volatile const __u32 hk_decay_lut[HK_DECAY_LUT_SIZE] = {
#include "hk_decay_lut.h"
};

/* ============================================================
 * Maps
 * ============================================================ */

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // no restrictions on structure of the value, map per CPU
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hk_sketch);
} hk_sketch SEC(".maps"); // stores whole sketch

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hk_state);
} hk_state SEC(".maps"); // stores sketch's state

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HK_BLOCK_ENTRIES);
    __type(key, __u32);
    __type(value, struct hk_block);
} hk_blocklist SEC(".maps"); // stores blocklist

/* ============================================================
 * Hashing
 * ============================================================ */

static __always_inline __u32 hk_mix32(__u32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static __always_inline __u64 hk_mix64(__u64 z)
{
    z ^= z >> 30;
    z *= 0xbf58476d1ce4e5b9ull;
    z ^= z >> 27;
    z *= 0x94d049bb133111ebull;
    z ^= z >> 31;
    return z;
}

static __always_inline __u32 hk_word(const struct hk_key *k, int i)
{
    return bpf_ntohl(((const __be32 *)k->addr)[i]);
}

static __always_inline __u32 hk_seed(__u32 row)
{
    return hk_mix32(row + HK_SEED_BASE);
}

static __always_inline void hk_hash_key(const struct hk_key *k,
                                        struct hk_hash *h)
{
    __u64 a = (__u64)hk_word(k, 0) << 32 | hk_word(k, 1);
    __u64 b = (__u64)hk_word(k, 2) << 32 | hk_word(k, 3);

    __u64 d = hk_mix64(hk_mix64(a ^ HK_KEY_SEED) ^ b);
    __u32 lo = (__u32)d;
    __u32 hi = (__u32)(d >> 32);

#pragma unroll
    for (__u32 row = 0; row < HK_HEIGHT; row++)
        h->slot[row] = row * HK_WIDTH +
                       (hk_mix32(lo ^ hk_seed(row)) & (HK_WIDTH - 1));

    h->fp = (__u16)(hk_mix32(hi ^ HK_FP_SALT) >> 16);
}

static __always_inline __be32 hk_mask_word(__be32 w, int bits)
{
    if (bits <= 0)
        return 0;
    if (bits >= 32)
        return w;
    return bpf_htonl(bpf_ntohl(w) & (~0u << (32 - bits)));
}

static __always_inline void hk_mask_key(struct hk_key *k, int len)
{
    __be32 *w = (__be32 *)k->addr;

#pragma unroll
    for (int i = 0; i < 4; i++)
        w[i] = hk_mask_word(w[i], len - 32 * i);
}

static __always_inline enum hk_parse hk_parse_key(void *data, void *data_end,
                                                  struct hk_key *key)
{
    struct ethhdr *eth = data;
    void *cursor = eth + 1;
    if (cursor > data_end)
        return HK_PARSE_ERROR;

    __be16 proto = eth->h_proto;
    __be32 *w = (__be32 *)key->addr;

    if (proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = cursor;
        if ((void *)(iph + 1) > data_end)
            return HK_PARSE_ERROR;

        w[0] = 0;
        w[1] = 0;
        w[2] = bpf_htonl(0x0000ffff);
        w[3] = iph->saddr;
        hk_mask_key(key, 96 + hk_prefix_v4);
        return HK_PARSE_IPV4;
    }
    if (proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return HK_PARSE_ERROR;

        __builtin_memcpy(key->addr, &ip6->saddr, sizeof(key->addr));
        hk_mask_key(key, hk_prefix_v6);
        return HK_PARSE_IPV6;
    }
    return HK_PARSE_OTHER;
}

/* ============================================================
 * HeavyKeeper insert
 * ============================================================ */

static __always_inline __u32 hk_insert(struct hk_sketch *sk,
                                       const struct hk_hash *h)
{
    __u16 fp = h->fp;
    __u32 best = 0;

#pragma unroll
    for (__u32 row = 0; row < HK_HEIGHT; row++)
    {
        __u32 s = h->slot[row];
        if (s >= HK_BUCKETS)
            return best;

        struct hk_bucket *b = &sk->b[s];
        __u32 c = b->count;

        if (c == 0)
        {
            /* Empty bucket: claim it. */
            b->fp = fp;
            b->count = 1;
            if (best < 1)
                best = 1;
        }
        else if (b->fp == fp)
        {
            /* Same flow. Saturate rather than wrap. */
            if (c < HK_MAX_COUNT)
                b->count = ++c;
            if (c > best)
                best = c;
        }
        else if (c < HK_DECAY_LUT_SIZE &&
                 bpf_get_prandom_u32() < hk_decay_lut[c])
        {
            /*
             * Held by another flow: exponential-weakening decay.
             * At or above the table size the decay probability is
             * zero, so the random draw is skipped.
             */
            if (--c == 0)
            {
                /* The previous owner has been evicted. */
                b->fp = fp;
                b->count = 1;
                if (best < 1)
                    best = 1;
            }
            else
            {
                b->count = c;
            }
        }
    }

    return best;
}

/* ============================================================
 * Cross-CPU estimate
 * ============================================================ */

struct hk_sum_ctx
{
    __u64 epoch;
    struct hk_hash h;
    __u32 total;
};

static long hk_sum_cpu(__u32 cpu, void *data)
{
    struct hk_sum_ctx *ctx = data;
    __u32 zero = 0;

    struct hk_state *st = bpf_map_lookup_percpu_elem(&hk_state, &zero, cpu);
    if (!st)
        return 1; /* past the last possible CPU */

    /* A CPU that has not seen this window yet holds stale counts. */
    if (st->epoch != ctx->epoch)
        return 0;

    struct hk_sketch *sk = bpf_map_lookup_percpu_elem(&hk_sketch, &zero, cpu);
    if (!sk)
        return 1;

    __u32 best = 0;

#pragma unroll
    for (int row = 0; row < HK_HEIGHT; row++)
    {
        __u32 s = ctx->h.slot[row];
        if (s >= HK_BUCKETS)
            return 1;

        struct hk_bucket *b = &sk->b[s];
        if (b->fp == ctx->h.fp && b->count > best)
            best = b->count;
    }

    ctx->total += best;
    return 0;
}

static __always_inline __u32 hk_global_estimate(const struct hk_hash *h,
                                                __u64 epoch)
{
    struct hk_sum_ctx ctx = {
        .epoch = epoch,
        .h = *h,
    };

    bpf_loop(HK_MAX_CPUS, hk_sum_cpu, &ctx, 0);
    return ctx.total;
}

/* ============================================================
 * Window reset
 * ============================================================ */

struct hk_clear_ctx
{
    struct hk_sketch *sk;
};

/* Clears one 64-byte cache line (eight buckets) per iteration. */
static long hk_clear_line(__u32 i, void *data)
{
    struct hk_clear_ctx *ctx = data;

    if (i >= HK_BUCKETS / 8)
        return 1;

    __u64 *line = (__u64 *)&ctx->sk->b[i * 8];

#pragma unroll
    for (int j = 0; j < 8; j++)
        line[j] = 0;

    return 0;
}
/* ============================================================ */

SEC("xdp")
int xdp_heavykeeper(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    struct hk_state *st = bpf_map_lookup_elem(&hk_state, &zero);
    struct hk_sketch *sk = bpf_map_lookup_elem(&hk_sketch, &zero);
    if (!st || !sk)
        return XDP_PASS;

    st->packets++;

    struct hk_key key;
    enum hk_parse kind = hk_parse_key(data, end, &key);

    switch (kind)
    {
    case HK_PARSE_IPV4:
    case HK_PARSE_IPV6:
        break;
    case HK_PARSE_OTHER:
        st->non_ip++;
        return XDP_PASS;
    default:
        st->malformed++;
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_coarse_ns();

    /* 1. Check if already blocked */
    bool blocked = false;
    struct hk_block *blk = bpf_map_lookup_elem(&hk_blocklist, &key);
    if (blk)
    {
        if (hk_enforce)
        {
            st->dropped++;
            return XDP_DROP;
        }
    }

    /* 2. Roll the window if needed */
    __u64 epoch = now / hk_window_ns;
    if (st->epoch != epoch)
    {
        struct hk_clear_ctx cc = {.sk = sk};
        bpf_loop(HK_BUCKETS / 8, hk_clear_line, &cc, 0);
        st->epoch = epoch;
    }

    __u32 threshold;
    if (kind == HK_PARSE_IPV4)
    {
        st->ipv4++;
        threshold = hk_threshold_v4;
    }
    else
    {
        st->ipv6++;
        threshold = hk_threshold_v6;
    }

    /* 3. Count and decide */
    struct hk_hash h;
    hk_hash_key(&key, &h);

    __u32 est = hk_insert(sk, &h);
    if (est == 0 || threshold == 0)
        return XDP_PASS;

    if (est < threshold)
    {
        st->checks++;
        est = hk_global_estimate(&h, epoch);
        if (est < threshold)
            return XDP_PASS;
    }

    /* Only for monitoring mode - no update needed */
    if (blocked)
        return XDP_PASS;

    struct hk_block nb = {};
    bpf_map_update_elem(&hk_blocklist, &key, &nb, BPF_ANY);
    st->blocked++;

    if (hk_enforce)
    {
        st->dropped++;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
