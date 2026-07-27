#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// Định nghĩa struct key cho bảng LPM Trie (Whitelist CIDR)
struct bpf_lpm_trie_key_v4 {
    u32 prefixlen;
    u32 data;
};

/* =========================================================================
 * 1. KHAI BÁO BẢNG BỘ NHỚ (eBPF MAPS)
 * ========================================================================= */

// Map Whitelist (`whitelist_map`): BPF_MAP_TYPE_LPM_TRIE
// - Mục đích: Lưu dải CIDR (Kim bài miễn tử cho GCP Console SSH, DNS nội bộ,...)
// - Key: bpf_lpm_trie_key_v4 (chứa prefix length và IPv4)
// - Value: u8 (Cờ đánh dấu PASS)
// - Max entries: 2000 (GCP IPv4 prefix list hiện tại ~1200 entries, để dư buffer)
BPF_LPM_TRIE(whitelist_map, struct bpf_lpm_trie_key_v4, u8, 2000);

// Map Blacklist (`blacklist_map`): BPF_MAP_TYPE_LRU_HASH
// - Mục đích: Lưu trữ các IP Tấn công bị phát hiện bởi AI/Python.
// - BẮT BUỘC dùng LRU_HASH: Tự động xóa entry cũ nhất ra ngoài khi bảng đạt giới hạn. 
//   Ngăn chặn hoàn toàn lỗi đầy bộ nhớ (E2BIG) khi hứng chịu bão IP Spoofing từ Botnet.
// - Key: u32 (Source IPv4 address)
// - Value: u8 (Cờ đánh dấu DROP)
// - Max entries: 500000 (5 trăm ngàn IPs)
BPF_TABLE("lru_hash", u32, u8, blacklist_map, 500000);

/* =========================================================================
 * 2. LOGIC XỬ LÝ GÓI TIN (Data Plane Enforcement)
 * =========================================================================
 * Hàm này có thể được gắn cờ SEC("xdp") nếu dùng clang/libbpf thuần, 
 * hoặc load thẳng thông qua load_func("xdp_prog", BPF.XDP) của thư viện bcc.
 */
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Phân tích Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Chỉ xử lý các gói tin IPv4
    // (Bỏ qua IPv6, ARP, ICMPv6,...)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Phân tích IPv4 header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    u32 src_ip = ip->saddr;

    /* ---------------------------------------------------------------------
     * BƯỚC 1: KIỂM TRA WHITELIST (ƯU TIÊN 1)
     * Tuyệt đối không bao giờ chặn traffic quản trị GCP, Internal Services.
     * --------------------------------------------------------------------- */
    struct bpf_lpm_trie_key_v4 wl_key = {};
    // Tra cứu gói tin hiện tại từ Data Plane (match chính xác 1 IP /32).
    // LPM Trie map sẽ tự động tìm kiếm match từ node dài nhất (/32) lên /24, /16...
    wl_key.prefixlen = 32; 
    wl_key.data = src_ip;
    
    u8 *wl_value = whitelist_map.lookup(&wl_key);
    if (wl_value != NULL) {
        // IP nguồn nằm trong Whitelist -> Lập tức cho qua.
        return XDP_PASS;
    }

    /* ---------------------------------------------------------------------
     * BƯỚC 2: KIỂM TRA BLACKLIST (LINE-RATE MITIGATION)
     * --------------------------------------------------------------------- */
    u8 *bl_value = blacklist_map.lookup(&src_ip);
    if (bl_value != NULL) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
