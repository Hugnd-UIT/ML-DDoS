/*
 * xdp_filter.c — eBPF/XDP Data Plane Enforcement
 *
 * Vai trò: Tầng thi hành cho hệ thống IPS chống DDoS.
 * Được compile và attach vào interface mạng bởi gatekeeper.py (Control Plane)
 * thông qua thư viện BCC.
 *
 * Luồng xử lý mỗi gói tin (per-packet pipeline):
 *   Ethernet → (bóc tối đa 2 lớp VLAN tag) → IPv4 / IPv6 parse
 *       ↓
 *   [1] Whitelist check (LPM Trie)  → khớp → XDP_PASS
 *       ↓ không khớp
 *   [2] Blacklist check (LRU Hash)  → khớp → XDP_DROP
 *       ↓ không khớp
 *   [3] Default                                XDP_PASS
 *
 * Lịch sử sửa lỗi:
 *   - Gói VLAN-tagged (802.1Q/802.1AD) trước đây được PASS thẳng vì h_proto
 *     là ETH_P_8021Q chứ không phải ETH_P_IP, tức là một attacker gửi traffic
 *     có tag sẽ đi vòng qua toàn bộ blacklist. Nay bóc tới 2 lớp tag.
 *   - IPv6 trước đây hoàn toàn không được xử lý ở cả kernel lẫn user space,
 *     nên nếu interface có địa chỉ IPv6 global thì đó là bypass 100%.
 *     Nay có map blacklist/whitelist riêng cho IPv6.
 */

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* ── Struct key cho LPM Trie ────────────────────────────────────────────────
 * BPF_MAP_TYPE_LPM_TRIE yêu cầu key đầu tiên là prefixlen (độ dài prefix tính
 * bằng bit), theo sau là dữ liệu địa chỉ. Kernel tự động tìm match dài nhất.
 */
struct lpm_key_v4 {
    __u32 prefixlen; /* Độ dài prefix (vd: 32 cho /32, 24 cho /24) */
    __u32 addr;      /* Địa chỉ mạng dưới dạng Network Byte Order  */
};

struct lpm_key_v6 {
    __u32 prefixlen; /* 0..128 */
    __u8  addr[16];  /* Network Byte Order */
};

/* Key cho blacklist IPv6 — hash thường, không phải trie */
struct in6_key {
    __u8 addr[16];
};

/* VLAN header tự định nghĩa: struct vlan_hdr của kernel không có mặt trên
 * mọi bản linux-headers, còn layout thì cố định nên tự khai báo an toàn hơn.
 */
struct vlan_tag {
    __be16 tci;
    __be16 encapsulated_proto;
};

/* ── eBPF Maps ───────────────────────────────────────────────────────────────
 *
 * whitelist_map / whitelist6_map  [BPF_MAP_TYPE_LPM_TRIE]
 *   Danh sách dải CIDR được phép đi qua vô điều kiện.
 *   Được gatekeeper.py nạp từ WHITELIST_CIDRS + các dải hạ tầng bắt buộc
 *   (IAP, metadata, health check). KHÔNG còn nạp toàn bộ dải khách hàng của
 *   GCP/Fastly nữa — xem enforcer.load_whitelist().
 *   Max entries nâng từ 2 000 lên 8 192: bản cũ tràn map trong im lặng khiến
 *   whitelist chỉ được nạp một phần ngẫu nhiên.
 *
 * blacklist_map / blacklist6_map  [BPF_MAP_TYPE_LRU_HASH]
 *   Các IP nguồn bị AI/Python phán quyết là tấn công.
 *   LRU tự động đẩy entry cũ nhất ra khi đầy — không bao giờ trả lỗi E2BIG,
 *   đảm bảo hệ thống ổn định ngay cả khi hứng chịu bão IP Spoofing.
 */
BPF_LPM_TRIE(whitelist_map,  struct lpm_key_v4, u8, 8192);
BPF_LPM_TRIE(whitelist6_map, struct lpm_key_v6, u8, 4096);

BPF_TABLE("lru_hash", u32,             u8, blacklist_map,  500000);
BPF_TABLE("lru_hash", struct in6_key,  u8, blacklist6_map, 100000);


/* ── Bộ đếm thống kê ─────────────────────────────────────────────────────────
 *
 * Trước đây tầng data plane hoàn toàn câm: không có cách nào biết XDP thực sự
 * đã DROP bao nhiêu gói, hay gói VLAN/IPv6 có được bóc đúng hay không. Mọi
 * khẳng định về hiệu quả chặn đều chỉ dựa vào log phía Python — tức là đếm số
 * QUYẾT ĐỊNH chặn, không phải số GÓI bị chặn, hai con số khác nhau hàng nghìn
 * lần vì một lệnh ban chặn cả trận flood theo sau nó.
 *
 * PERCPU_ARRAY để mỗi CPU cộng vào ô riêng, không tranh chấp cache line — đây
 * là đường nóng chạy ở tốc độ đường truyền, một biến chia sẻ sẽ tự nó thành
 * nút cổ chai. Python cộng lại các ô khi đọc.
 */
enum stat_slot {
    STAT_TOTAL = 0,       /* Tổng gói đi qua chương trình XDP  */
    STAT_PASS_WL,         /* PASS vì khớp whitelist            */
    STAT_DROP_V4,         /* DROP vì khớp blacklist IPv4       */
    STAT_DROP_V6,         /* DROP vì khớp blacklist IPv6       */
    STAT_VLAN,            /* Gói có ít nhất 1 tag VLAN         */
    STAT_V6_SEEN,         /* Gói IPv6 đã được phân tích        */
    STAT_NON_IP,          /* ARP và các ethertype khác         */
    STAT_MAX
};

BPF_PERCPU_ARRAY(stats_map, u64, STAT_MAX);

static __always_inline void bump(u32 slot)
{
    u64 *slot_value = stats_map.lookup(&slot);

    if (slot_value)
        *slot_value += 1;
}


/* ── IPv4 decision ─────────────────────────────────────────────────────────── */
static __always_inline int decide_v4(void *nh, void *data_end)
{
    struct iphdr *ip = nh;

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr; /* Network Byte Order — khớp cách Python nạp map */

    /* [1] Whitelist: tra với prefixlen=32, kernel tự leo lên prefix ngắn hơn */
    struct lpm_key_v4 wl_key = {};
    wl_key.prefixlen = 32;
    wl_key.addr      = src_ip;

    if (whitelist_map.lookup(&wl_key) != NULL) {
        bump(STAT_PASS_WL);
        return XDP_PASS;
    }

    /* [2] Blacklist: drop ngay tại tầng driver */
    if (blacklist_map.lookup(&src_ip) != NULL) {
        bump(STAT_DROP_V4);
        return XDP_DROP;
    }

    return XDP_PASS;
}


/* ── IPv6 decision ─────────────────────────────────────────────────────────── */
static __always_inline int decide_v6(void *nh, void *data_end)
{
    struct ipv6hdr *ip6 = nh;

    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    bump(STAT_V6_SEEN);

    /* [1] Whitelist */
    struct lpm_key_v6 wl_key = {};
    wl_key.prefixlen = 128;
    __builtin_memcpy(wl_key.addr, &ip6->saddr, 16);

    if (whitelist6_map.lookup(&wl_key) != NULL) {
        bump(STAT_PASS_WL);
        return XDP_PASS;
    }

    /* [2] Blacklist */
    struct in6_key bl_key = {};
    __builtin_memcpy(bl_key.addr, &ip6->saddr, 16);

    if (blacklist6_map.lookup(&bl_key) != NULL) {
        bump(STAT_DROP_V6);
        return XDP_DROP;
    }

    return XDP_PASS;
}


/* ── XDP Program ─────────────────────────────────────────────────────────────
 *
 * Được load bởi: b.load_func("xdp_prog", BPF.XDP) trong gatekeeper.py
 *
 * Lưu ý thiết kế:
 *   - Whitelist được kiểm tra TRƯỚC blacklist để đảm bảo IP quản trị
 *     không bao giờ bị chặn dù nằm trong cả hai map.
 */
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bump(STAT_TOTAL);

    __be16 h_proto = eth->h_proto;
    void  *nh      = (void *)(eth + 1);

    /* Bóc tối đa 2 lớp VLAN tag (QinQ). Vòng lặp phải unroll để verifier
     * chấp nhận, và mỗi vòng phải tự kiểm tra bounds.
     */
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto != bpf_htons(ETH_P_8021Q) &&
            h_proto != bpf_htons(ETH_P_8021AD))
            break;

        struct vlan_tag *vlan = nh;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        if (i == 0)
            bump(STAT_VLAN);

        h_proto = vlan->encapsulated_proto;
        nh      = (void *)(vlan + 1);
    }

    if (h_proto == bpf_htons(ETH_P_IP))
        return decide_v4(nh, data_end);

    if (h_proto == bpf_htons(ETH_P_IPV6))
        return decide_v6(nh, data_end);

    /* ARP và các ethertype khác → để Network Stack xử lý */
    bump(STAT_NON_IP);

    return XDP_PASS;
}
