#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

BPF_LPM_TRIE(whitelist_map, struct lpm_key_v4, u8, 2000);
BPF_TABLE("lru_hash", u32, u64, blacklist_map, 500000);

int xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;

    struct lpm_key_v4 wl_key = {};
    wl_key.prefixlen = 32;
    wl_key.addr      = src_ip;
    if (whitelist_map.lookup(&wl_key) != NULL)
        return XDP_PASS;

    if (blacklist_map.lookup(&src_ip) != NULL)
        return XDP_DROP;

    return XDP_PASS;
}