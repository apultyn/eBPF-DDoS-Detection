#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "heavy_keeper.h"

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

static __always_inline void hk_mask_key(struct hk_key *k, int len)
{
    __be32 *w = (__be32 *)k->addr;

#pragma unroll
    for (int i = 0; i < 4; i++)
        w[i] = hk_mask_word(w[i], len - 32 * i);
}

static __always_inline __be32 hk_mask_word(__be32 w, int bits)
{
    if (bits <= 0)
        return 0;
    if (bits >= 32)
        return w;
    return bpf_htonl(bpf_ntohl(w) & (~0u << (32 - bits)));
}

static __always_inline enum hk_parse hk_parse_key(void *data, void *data_end,
                                                  struct hk_key *key)
{
    struct ethhdr *eth = data;
    void *cursor = eth + 1;
    if (cursor > data_end)
        return HK_PARSE_ERROR;

    __be16 proto = eth->h_proto;

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
    else if (proto == bpf_htons(ETH_P_IPV6))
    {
    }
    else
    {
        return HK_PARSE_OTHER;
    }
}

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
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";