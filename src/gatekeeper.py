"""
╔══════════════════════════════════════════════════════════════════╗
║         GATEKEEPER IPS — HYBRID AI + eBPF/XDP CONTROL PLANE     ║
║  Phát hiện DDoS bằng XGBoost + Thi hành án bằng eBPF/XDP        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import time
import socket
import struct
import fcntl
import argparse
import threading
import ipaddress
import requests
import ctypes
import warnings
import joblib
import numpy as np
import xgboost as xgb
from collections import defaultdict
from bcc import BPF
from cachetools import TTLCache
from nfstream import NFStreamer

# ── Cấu hình hệ thống ─────────────────────────────────────────────────────────

# Đường dẫn tới model XGBoost (phân loại nhị phân: DDoS / Benign)
MODEL_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "models", "binary.pkl"
)

# Sliding Window: tổng số src2dst_packets từ một src_ip
# tích luỹ trong WINDOW_SECONDS giây vượt ngưỡng → kích hoạt ban ngay
WINDOW_SECONDS        = 5
PACKET_WINDOW_THRESHOLD = 500

# ──────────────────────────────────────────────────────────────────────────────


def parse_args():
    """Phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        description="Gatekeeper IPS — Hybrid AI XGBoost + eBPF/XDP",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        metavar="IFACE",
        help="Interface mạng cần bảo vệ (vd: ens4, eth0)"
    )
    return parser.parse_args()


def get_vm_ip(ifname):
    """
    Trả về địa chỉ IPv4 gắn với interface `ifname` qua ioctl SIOCGIFADDR.
    Dùng để lọc traffic Egress (do chính máy chủ chủ động gửi ra ngoài).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', bytes(ifname[:15], 'utf-8'))
                )[20:24]
            )
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def ip_to_int(ip_str):
    """Chuyển IPv4 string → unsigned 32-bit integer (Network Byte Order) cho eBPF map."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int):
    """Chuyển unsigned 32-bit integer từ eBPF map → IPv4 string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))


def auto_load_gcp_whitelist(bpf_instance):
    """
    Fetch danh sách dải IPv4 của Google Cloud (cloud.json + goog.json) từ endpoint
    public của Google, bổ sung RFC 1918 private ranges và các dải tĩnh bắt buộc,
    rồi nạp tất cả xuống eBPF LPM_TRIE map.

    Trả về list các IPv4Network để Control Plane Python tự kiểm tra trước
    khi ra lệnh ban — tránh tình trạng AI phán nhầm và ban nhầm IP hợp lệ.
    """
    _banner("ĐỒNG BỘ WHITELIST")
    whitelist_map = bpf_instance.get_table("whitelist_map")

    cidrs = []

    # Fetch GCP Cloud IP Ranges (các dải IP của GCP infrastructure)
    try:
        resp = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        cloud_prefixes = [
            p["ipv4Prefix"]
            for p in resp.json().get("prefixes", [])
            if "ipv4Prefix" in p
        ]
        cidrs += cloud_prefixes
        print(f"  [+] GCP cloud.json: {len(cloud_prefixes)} prefix.")
    except Exception as exc:
        print(f"  [!] Không tải được cloud.json: {exc}")




    # RFC 1918 private ranges — bảo vệ mạng nội bộ VPC (DB, microservices, backends)
    # Đảm bảo AI không bao giờ block traffic giữa các VM trong cùng VPC
    private_ranges = [
        "10.0.0.0/8",      # GCP VPC internal (10.128.0.0/9, 10.240.0.0/12, ...)
        "172.16.0.0/12",   # Private class B
        "192.168.0.0/16",  # Private class C
    ]
    cidrs += private_ranges

    # Dải tĩnh bắt buộc — phải luôn có dù mọi fetch đều thất bại
    cidrs += [
        "35.235.240.0/20",   # GCP IAP — Identity-Aware Proxy (SSH Console)
        "169.254.169.254/32" # GCP Metadata Server (ops-agent, auth)
    ]

    # Loại bỏ duplicate trước khi nạp
    cidrs = list(dict.fromkeys(cidrs))
    print(f"  [*] Nạp {len(cidrs)} dải CIDR vào eBPF Whitelist (LPM Trie)...")
    py_whitelist, ok = [], 0
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            key = whitelist_map.Key(net.prefixlen, ip_to_int(str(net.network_address)))
            whitelist_map[key] = whitelist_map.Leaf(1)
            py_whitelist.append(net)
            ok += 1
        except Exception:
            pass  # Bỏ qua IPv6 prefix hoặc entry không hợp lệ

    print(f"  [+] Nạp thành công {ok} quy tắc xuống Data Plane.")
    return py_whitelist


def memory_manager(blacklist_map, ttl_cache, lock):
    """
    Daemon thread đồng bộ hoá eBPF blacklist_map (Kernel) với TTLCache (User-space).

    Chu kỳ mỗi 5 giây: quét các entry trong blacklist_map, nếu IP tương ứng
    đã biến mất khỏi TTLCache (TTL 300s hết hạn) thì xoá khỏi eBPF map.

    Thiết kế lock-efficient: Việc scan map (đọc nhiều, chậm) được thực hiện
    NGOÀI critical section. Lock chỉ được giữ trong khoảnh khắc xoá entry —
    tránh block Main Thread (AI inference) trong thời gian dài.
    """
    while True:
        try:
            time.sleep(5)

            # Bước 1: Scan map NGOÀI lock — đọc nhanh, không chặn Main Thread
            candidates = []
            try:
                for key, _ in blacklist_map.items():
                    if int_to_ip(key.value) not in ttl_cache:
                        candidates.append(key)
            except Exception:
                pass

            # Bước 2: Xoá entry với lock — brief critical section
            with lock:
                for key in candidates:
                    ip_str = int_to_ip(key.value)
                    # Double-check dưới lock: tránh xoá IP vừa được ban lại
                    if ip_str not in ttl_cache:
                        try:
                            del blacklist_map[key]
                            print(f"  [↩] AMNESTY  {ip_str:<18} TTL hết hạn → gỡ khỏi XDP Blacklist")
                        except Exception:
                            pass
        except Exception as exc:
            print(f"  [-] Memory Manager lỗi: {exc}")


def load_ai_model():
    """
    Tải XGBClassifier từ binary.pkl bằng joblib.
    Nếu thất bại, hệ thống sẽ báo lỗi và thoát an toàn.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = joblib.load(MODEL_FILE)
        print(f"  [+] Model loaded: {type(model).__name__}  ←  {MODEL_FILE}")
        return model
    except Exception as exc:
        print(f"  [✗] Không tải được model: {exc}")
        print(f"  [✗] Cần có file model thực để hoạt động. Thoát hệ thống...")
        import sys
        sys.exit(1)


def extract_features(flow):
    """
    Trích xuất 19 đặc trưng thống kê luồng chuẩn CIC-DDoS2019 từ NFStream flow.
    Yêu cầu NFStreamer khởi tạo với `statistical_analysis=True`.
    """
    return np.array([[
        flow.bidirectional_duration_ms,  # 00 — tổng thời gian luồng (ms)
        flow.bidirectional_packets,      # 01 — tổng packet hai chiều
        flow.bidirectional_bytes,        # 02 — tổng bytes hai chiều
        flow.src2dst_packets,            # 03 — packet chiều client→server
        flow.src2dst_bytes,              # 04 — bytes chiều client→server
        flow.dst2src_packets,            # 05 — packet chiều server→client
        flow.dst2src_bytes,              # 06 — bytes chiều server→client
        flow.bidirectional_min_ps,       # 07 — packet size nhỏ nhất
        flow.bidirectional_mean_ps,      # 08 — packet size trung bình
        flow.bidirectional_stddev_ps,    # 09 — độ lệch chuẩn packet size
        flow.bidirectional_max_ps,       # 10 — packet size lớn nhất
        flow.src2dst_min_ps,             # 11 — pkt size nhỏ nhất chiều →
        flow.src2dst_mean_ps,            # 12 — pkt size TB chiều →
        flow.src2dst_max_ps,             # 13 — pkt size lớn nhất chiều →
        flow.dst2src_min_ps,             # 14 — pkt size nhỏ nhất chiều ←
        flow.dst2src_mean_ps,            # 15 — pkt size TB chiều ←
        flow.dst2src_max_ps,             # 16 — pkt size lớn nhất chiều ←
        flow.bidirectional_syn_packets,  # 17 — tổng SYN packet
        flow.bidirectional_ack_packets,  # 18 — tổng ACK packet
    ]], dtype=np.float32)


def ban_ip(src_ip, blacklist_map, ttl_cache, lock):
    """
    Ghi IP vào hai tầng cấm:
      1. TTLCache (User-space) — tự hết hạn sau 300s.
      2. eBPF blacklist_map (Kernel) — XDP DROP mọi packet ở line-rate.
    """
    with lock:
        ttl_cache[src_ip] = True
        blacklist_map[blacklist_map.Key(ip_to_int(src_ip))] = blacklist_map.Leaf(1)


def _banner(title, width=65):
    """In banner phân đoạn ra terminal."""
    print(f"\n  {'─' * width}")
    print(f"  {title}")
    print(f"  {'─' * width}")


def main():
    args      = parse_args()
    INTERFACE = args.interface
    XDP_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xdp_filter.c")

    print()
    print("  ╔" + "═" * 63 + "╗")
    print("  ║   🛡  GATEKEEPER IPS  —  AI XGBoost + eBPF/XDP          ║")
    print("  ║   Interface : {:<47}║".format(INTERFACE))
    print("  ╚" + "═" * 63 + "╝")
    print()

    # ── 1. Compile & Attach XDP ───────────────────────────────────────────────
    _banner("1/4  KHỞI TẠO DATA PLANE (eBPF/XDP)")
    print(f"  [*] Biên dịch: {XDP_FILE}")
    try:
        # Redirect fd2 (stderr) sang /dev/null trong lúc BCC gọi clang compile
        # để ẩn các warning không liên quan về macro redefinition của kernel headers
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        saved_stderr = os.dup(2)
        os.dup2(devnull_fd, 2)
        try:
            b  = BPF(src_file=XDP_FILE)
        finally:
            os.dup2(saved_stderr, 2)
            os.close(saved_stderr)
            os.close(devnull_fd)
        fn = b.load_func("xdp_prog", BPF.XDP)
        try:
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=0)
            print(f"  [+] XDP attached → Native (Driver) Mode  [{INTERFACE}]")
        except Exception:
            print(f"  [~] Native Mode không khả dụng, thử Generic (SKB) Mode...")
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=2)
            print(f"  [+] XDP attached → Generic (SKB) Mode  [{INTERFACE}]")
    except Exception as exc:
        print(f"  [✗] FATAL: Không thể tải eBPF — {exc}")
        print(f"  [✗] Hãy chạy bằng sudo.")
        return

    # ── 2. Whitelist ──────────────────────────────────────────────────────────
    py_whitelist = auto_load_gcp_whitelist(b)
    blacklist_map = b.get_table("blacklist_map")

    def is_whitelisted(ip_str):
        """Trả về True nếu ip_str khớp với bất kỳ CIDR nào trong whitelist."""
        try:
            addr = ipaddress.IPv4Address(ip_str)
            return any(addr in net for net in py_whitelist)
        except Exception:
            return False

    # ── 3. Memory Manager ─────────────────────────────────────────────────────
    _banner("2/4  KHỞI TẠO BỘ NHỚ USER-SPACE")
    ttl_cache = TTLCache(maxsize=50000, ttl=300)
    bpf_lock  = threading.Lock()
    threading.Thread(
        target=memory_manager,
        args=(blacklist_map, ttl_cache, bpf_lock),
        daemon=True
    ).start()
    print(f"  [+] TTLCache sẵn sàng  (maxsize=50 000, ttl=300s)")
    print(f"  [+] Memory Manager daemon started")

    # ── 4. AI Engine ─────────────────────────────────────────────────────────
    _banner("3/4  KHỞI TẠO AI ENGINE (XGBoost)")
    ai_model = load_ai_model()

    # ── 5. Host IP (Egress Filter) ───────────────────────────────────────────
    _banner("4/4  CẤU HÌNH EGRESS FILTER")
    vm_ip = get_vm_ip(INTERFACE)
    print(f"  [+] Host IP: {vm_ip}  (traffic Egress từ địa chỉ này sẽ bị bỏ qua)")

    # Sliding Window: { src_ip: [(timestamp, packet_count), ...] }
    packet_window = defaultdict(list)

    # ── Ready ─────────────────────────────────────────────────────────────────
    print()
    print("  ╔" + "═" * 63 + "╗")
    print("  ║   ✅  HỆ THỐNG SẴN SÀNG — ĐANG GIÁM SÁT INGRESS TRAFFIC ║")
    print("  ╚" + "═" * 63 + "╝")
    print()

    try:
        # active_timeout=1 : xuất flow đã active > 1s (bắt flood liên tục)
        # idle_timeout=1   : xuất flow idle > 1s (bắt micro-flow rotating-port)
        # statistical_analysis=True : tính min/mean/stddev/max packet size
        streamer = NFStreamer(
            source=INTERFACE,
            active_timeout=1,
            idle_timeout=1,
            statistical_analysis=True
        )

        for flow in streamer:
            try:
                # A. Bỏ qua IPv6 — inet_aton chỉ xử lý IPv4
                if ":" in flow.src_ip:
                    continue

                # B. Bỏ qua traffic Egress (do chính máy chủ gửi ra ngoài)
                if flow.src_ip in (vm_ip, "127.0.0.1"):
                    continue

                # C. Bỏ qua IP đã bị ban trong TTL 300s hiện tại
                if flow.src_ip in ttl_cache:
                    continue

                # D. Sliding Window — phát hiện SYN/UDP/ACK Flood rotating source-port
                #    hping3 dùng source port khác nhau → mỗi packet là 1 micro-flow riêng
                #    → gom tổng packet theo src_ip trong cửa sổ WINDOW_SECONDS giây
                #
                #    Chống OOM: key được xoá khỏi dict ngay khi window trống,
                #    và dict bị clear khẩn cấp nếu vượt 100 000 entries (IP Spoofing storm)
                now = time.time()

                # Guard: giới hạn kích thước dict để chống OOM khi IP Spoofing quy mô lớn
                if len(packet_window) > 100_000:
                    packet_window.clear()

                window  = packet_window[flow.src_ip]
                window.append((now, flow.src2dst_packets))
                filtered = [(t, p) for t, p in window if now - t <= WINDOW_SECONDS]

                if filtered:
                    packet_window[flow.src_ip] = filtered
                else:
                    # Window trống — xoá key để giải phóng RAM (chống memory leak)
                    packet_window.pop(flow.src_ip, None)
                    continue

                total_pkts = sum(p for _, p in filtered)

                if total_pkts > PACKET_WINDOW_THRESHOLD:
                    if not is_whitelisted(flow.src_ip):
                        ban_ip(flow.src_ip, blacklist_map, ttl_cache, bpf_lock)
                        packet_window.pop(flow.src_ip, None)
                        print(
                            f"  [!] FLOOD DETECT  {flow.src_ip:<18} "
                            f"{total_pkts} pkts/{WINDOW_SECONDS}s  → XDP DROP"
                        )
                    continue

                # E. ML Inference — XGBClassifier phân loại luồng
                features   = extract_features(flow)
                prediction = ai_model.predict(features)
                pred_val   = int(prediction[0]) if isinstance(prediction, (list, np.ndarray)) else int(prediction)

                if pred_val >= 1:
                    if not is_whitelisted(flow.src_ip):
                        ban_ip(flow.src_ip, blacklist_map, ttl_cache, bpf_lock)
                        print(
                            f"  [!] AI DETECTED   {flow.src_ip:<18} "
                            f"→ {flow.dst_ip}  pred={pred_val}  → XDP DROP"
                        )

            except Exception as flow_err:
                # Lỗi trên một flow đơn lẻ không được crash toàn vòng lặp
                print(f"  [-] Flow error ({flow.src_ip}): {flow_err}")

    except KeyboardInterrupt:
        print("\n  [~] Ctrl+C nhận được — đang dọn dẹp...")
    except Exception as exc:
        print(f"\n  [✗] Lỗi không phục hồi được: {exc}")
    finally:
        # Luôn gỡ XDP khi thoát — không để lại filter trên interface
        try:
            try:
                b.remove_xdp(INTERFACE, flags=0)
            except Exception:
                b.remove_xdp(INTERFACE, flags=2)
            print("  [+] XDP filter đã gỡ khỏi interface an toàn.\n")
        except Exception:
            pass


if __name__ == "__main__":
    main()