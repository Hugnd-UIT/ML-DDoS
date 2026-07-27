/*
 * xdp_filter.c — eBPF/XDP Data Plane Enforcement
 *
 * Vai trò: Tầng thi cho hệ thống IPS chống DDoS.
 * Được compile và attach vào interface mạng bởi gatekeeper.py (Control Plane)
 * thông qua thư viện BCC.
 *
 * Luồng xử lý mỗi gói tin (per-packet pipeline):
 *   Ethernet → IPv4 parse
 *       ↓
 *   [1] Whitelist check (LPM Trie)  → khớp → XDP_PASS  
 *       ↓ không khớp
 *   [2] Blacklist check (LRU Hash)  → khớp → XDP_DROP  
 *       ↓ không khớp
 *   [3] Default                                XDP_PASS
 */

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* ── Struct key cho LPM Trie ────────────────────────────────────────────────
 * BPF_MAP_TYPE_LPM_TRIE yêu cầu key đầu tiên là prefixlen (độ dài prefix tính
 * bằng bit), theo sau là dữ liệu địa chỉ. Kernel tự động tìm match dài nhất.
 */
struct lpm_key_v4 {
    __u32 prefixlen; /* Độ dài prefix (vd: 32 cho /32, 24 cho /24) */
    __u32 addr;      /* Địa chỉ mạng dưới dạng Network Byte Order  */
};

/* ── eBPF Maps ───────────────────────────────────────────────────────────────
 *
 * whitelist_map  [BPF_MAP_TYPE_LPM_TRIE]
 *   Lưu danh sách dải CIDR được phép đi qua vô điều kiện.
 *   Được gatekeeper.py nạp từ GCP Cloud IP Ranges + các dải IAP/Metadata tĩnh.
 *   Max entries 2000: đủ chứa ~1 200 GCP prefix + dư buffer.
 *
 * blacklist_map  [BPF_MAP_TYPE_LRU_HASH]
 *   Lưu các IP nguồn bị AI/Python phán quyết là tấn công.
 *   LRU tự động đẩy entry cũ nhất ra khi đầy — không bao giờ trả lỗi E2BIG,
 *   đảm bảo hệ thống ổn định ngay cả khi hứng chịu bão IP Spoofing.
 *   Max entries 500 000: đủ chứa tình huống Botnet quy mô lớn.
 */
BPF_LPM_TRIE(whitelist_map, struct lpm_key_v4, u8, 2000);
BPF_TABLE("lru_hash", u32, u8, blacklist_map, 500000);

/* ── XDP Program ─────────────────────────────────────────────────────────────
 *
 * Được load bởi: b.load_func("xdp_prog", BPF.XDP) trong gatekeeper.py
 * Tương thích:   BCC (bcc-tools) và clang/libbpf (với cờ SEC("xdp"))
 *
 * Lưu ý thiết kế:
 *   - Whitelist được kiểm tra TRƯỚC blacklist để đảm bảo IP quản trị
 *     không bao giờ bị chặn dù nằm trong cả hai map.
 */
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Chỉ xử lý IPv4 — bỏ qua ARP, IPv6, ... */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr; /* Network Byte Order — khớp với cách Python nạp map */

    /* ── [1] Whitelist check ─────────────────────────────────────────────────
     * Tra cứu với prefixlen=32 (exact /32). Kernel tự động leo lên prefix ngắn
     * hơn (/24, /16, ...) và trả về match dài nhất — đúng chuẩn LPM Trie.
     */
    struct lpm_key_v4 wl_key = {};
    wl_key.prefixlen = 32;
    wl_key.addr      = src_ip;
    if (whitelist_map.lookup(&wl_key) != NULL)
        return XDP_PASS;

    /* ── [2] Blacklist check ─────────────────────────────────────────────────
     * IP bị AI/Python ghi vào blacklist_map → drop ngay tại tầng driver,
     * trước khi gói tin chạm tới Network Stack hay tcpdump của OS.
     */
    if (blacklist_map.lookup(&src_ip) != NULL)
        return XDP_DROP;

    /* ── [3] Default: PASS ───────────────────────────────────────────────────
     * Traffic mới, chưa phân loại → cho lên Network Stack.
     * NFStreamer/Python sẽ capture, trích xuất feature và phân tích bằng AI.
     */
    return XDP_PASS;
}
