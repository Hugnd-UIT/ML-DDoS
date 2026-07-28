"""
╔══════════════════════════════════════════════════════════════════╗
║         GATEKEEPER IPS — HYBRID AI + eBPF/XDP CONTROL PLANE      ║
║  Phát hiện DDoS bằng XGBoost + Thi hành án bằng eBPF/XDP         ║
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

# ── Cấu hình hệ thống ──────────────────────────────────────────────────

# Đường dẫn tới model XGBoost (phân loại nhị phân: DDoS / Benign)
MODEL_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "models", "binary.pkl"
)

# Multi-vector Rate Limiting (Sliding Window)
WINDOW_SECONDS     = 5
SYN_THRESHOLD      = 200    # Bắt SYN Flood
UDP_ICMP_THRESHOLD = 1000   # Bắt UDP/ICMP Flood
TOTAL_THRESHOLD    = 3000   # Bắt các loại flood khác (ACK, RST, FIN...)

# Exponential Backoff Ban TTL — IP tái phạm sẽ bị phạt nặng hơn sau mỗi lần
BAN_TTL = [
    5   * 60,   # Lần 1: 5 phút
    60  * 60,   # Lần 2: 1 tiếng
    24  * 3600, # Lần 3+: 24 tiếng
]

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


def get_all_local_ips(ifname):
    """
    Trả về tập hợp tất cả địa chỉ IPv4 gắn với interface `ifname`.
    Dùng để lọc Egress traffic: bỏ qua mọi flow đến từ bất kỳ IP nào của chính máy chủ.
    """
    import subprocess
    ips = set()
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", ifname],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip = line.split()[1].split("/")[0]
                ips.add(ip)
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ip = socket.inet_ntoa(
                    fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
                    )[20:24]
                )
                ips.add(ip)
            finally:
                s.close()
        except Exception:
            pass
    ips.add("127.0.0.1")
    return ips


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
    try:
        resp = requests.get("https://www.gstatic.com/ipranges/goog.json", timeout=10)
        goog_prefixes = [
            p["ipv4Prefix"]
            for p in resp.json().get("prefixes", [])
            if "ipv4Prefix" in p
        ]
        cidrs += goog_prefixes
        print(f"  [+] GCP goog.json:  {len(goog_prefixes)} prefix.")
    except Exception as exc:
        print(f"  [!] Không tải được goog.json: {exc}")

    try:
        resp = requests.get("https://api.fastly.com/public-ip-list", timeout=10)
        fastly_data = resp.json()
        fastly_prefixes = fastly_data.get("addresses", []) + fastly_data.get("ipv4_addresses", [])
        cidrs += fastly_prefixes
        print(f"  [+] Fastly CDN:     {len(fastly_prefixes)} prefix.")
    except Exception as exc:
        cidrs += ["151.101.0.0/16"]
        print(f"  [!] Không tải được Fastly IP list: {exc}. Dùng fallback 151.101.0.0/16.")

    cidrs += [
        "35.235.240.0/20",   # GCP IAP — Identity-Aware Proxy (SSH Console)
        "169.254.169.254/32" # GCP Metadata Server (ops-agent, auth)
    ]

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


def memory_manager(blacklist_map, ban_registry, lock):
    """Daemon: mỗi 5s quét ban_registry, gỡ eBPF entry khi TTL hết hạn."""
    while True:
        try:
            time.sleep(5)
            now = time.time()

            # Scan ngoài lock (read-only) → tránh block Main Thread
            expired_ips = [
                ip for ip, expire_ts in list(ban_registry.items())
                if expire_ts <= now
            ]

            # Xóa dưới lock — brief critical section
            with lock:
                for ip in expired_ips:
                    expire_ts = ban_registry.get(ip)
                    if expire_ts and expire_ts <= now:   # double-check race condition
                        del ban_registry[ip]
                        try:
                            del blacklist_map[blacklist_map.Key(ip_to_int(ip))]
                        except Exception:
                            pass
        except Exception as exc:
            print(f"  [-] Memory Manager error: {exc}")


def load_ai_model():
    """
    Tải XGBClassifier từ binary.pkl bằng joblib.
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


def ban_ip_backoff(src_ip, blacklist_map, ban_registry, offense_history, lock):
    """
    Ban IP với TTL tăng lũy tiến (Exponential Backoff): 5 phút → 1 tiếng → 24 tiếng.
    Lịch sử vi phạm (offense_history) lưu 24h, hoàn toàn độc lập với trạng thái ban hiện tại.
    """
    with lock:
        count = offense_history.get(src_ip, 0) + 1
        offense_history[src_ip] = count
        
        ttl_secs  = BAN_TTL[min(count - 1, len(BAN_TTL) - 1)]
        ban_registry[src_ip] = time.time() + ttl_secs
        blacklist_map[blacklist_map.Key(ip_to_int(src_ip))] = blacklist_map.Leaf(1)
    return count, ttl_secs


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

    # ── 3. Memory Manager ───────────────────────────────────────────────
    _banner("2/4  KHỞI TẠO BỘ NHớ USER-SPACE")
    # ban_registry: { src_ip: expire_timestamp } -> quản lý án phạt hiện tại
    ban_registry = {}
    # offense_history: { src_ip: count } -> ghi nhớ "tiền án" trong 24h bằng TTLCache
    offense_history = TTLCache(maxsize=100_000, ttl=86400)
    
    bpf_lock = threading.Lock()
    threading.Thread(
        target=memory_manager,
        args=(blacklist_map, ban_registry, bpf_lock),
        daemon=True
    ).start()
    print(f"  [+] Offense History khởi tạo (TTLCache 24h)")
    print(f"  [+] Memory Manager daemon started")

    # ── 4. AI Engine ─────────────────────────────────────────────────────────
    _banner("3/4  KHỞI TẠO AI ENGINE (XGBoost)")
    ai_model = load_ai_model()

    # ── 5. Thu thập tất cả IP của máy chủ (Egress Filter) ──────────────────
    _banner("4/4  CẤU HÌNH EGRESS FILTER")
    local_ips = get_all_local_ips(INTERFACE)
    print(f"  [+] Local IPs detected: {', '.join(sorted(local_ips))}")
    print(f"  [+] Mọi flow từ các địa chỉ này sẽ bỏ qua (Egress + Alias filter)")

    # Sliding Window: TTLCache tự động đá key cũ (LRU) khi vượt maxsize
    # và xóa key hết hạn (ttl=60s), khắc phục lỗi tràn RAM và tránh xóa sạch data.
    packet_window = TTLCache(maxsize=100_000, ttl=60)

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

                # B. Bỏ qua Egress: flow từ bất kỳ IP nào của chính máy chủ
                #    (primary IP, alias IP, loopback)
                if flow.src_ip in local_ips:
                    continue

                # C. Bỏ qua IP đang trong thời gian bị phạt
                expire_ts = ban_registry.get(flow.src_ip)
                if expire_ts and expire_ts > time.time():
                    continue

                # D. Multi-vector Rate Limiting (Sliding Window)
                #    3 kênh đếm song song để bắt mọi loại bão (SYN, UDP, ACK, RST...)
                now = time.time()

                syn_count   = flow.bidirectional_syn_packets
                total_count = flow.bidirectional_packets
                # NFStream protocol: 1 = ICMP, 17 = UDP
                udp_icmp_count = total_count if flow.protocol in (1, 17) else 0

                if flow.src_ip not in packet_window:
                    packet_window[flow.src_ip] = []

                window = packet_window[flow.src_ip]
                window.append((now, syn_count, udp_icmp_count, total_count))
                filtered = [(t, s, u, p) for (t, s, u, p) in window if now - t <= WINDOW_SECONDS]

                if filtered:
                    packet_window[flow.src_ip] = filtered
                else:
                    packet_window.pop(flow.src_ip, None)
                    continue

                total_syn      = sum(s for _, s, _, _ in filtered)
                total_udp_icmp = sum(u for _, _, u, _ in filtered)
                total_pkts     = sum(p for _, _, _, p in filtered)

                if (total_syn > SYN_THRESHOLD or 
                    total_udp_icmp > UDP_ICMP_THRESHOLD or 
                    total_pkts > TOTAL_THRESHOLD):
                    if not is_whitelisted(flow.src_ip):
                        count, ttl_secs = ban_ip_backoff(
                            flow.src_ip, blacklist_map, ban_registry, offense_history, bpf_lock
                        )
                        packet_window.pop(flow.src_ip, None)
                        ttl_label = f"{ttl_secs // 3600}h" if ttl_secs >= 3600 else f"{ttl_secs // 60}m"
                        print(
                            f"  [BLOCK] {flow.src_ip:<20} "
                            f"DDoS DETECTED  │ ban {ttl_label:<4} │ offense #{count}"
                        )
                    continue

                # E. ML Inference — chỉ chạy với flow >= 10 packet để loại
                #    single-packet scanner/health-check (giảm false positive)
                if flow.bidirectional_packets < 10:
                    continue

                features   = extract_features(flow)
                prediction = ai_model.predict(features)
                pred_val   = int(prediction[0]) if isinstance(prediction, (list, np.ndarray)) else int(prediction)

                if pred_val >= 1:
                    if not is_whitelisted(flow.src_ip):
                        count, ttl_secs = ban_ip_backoff(
                            flow.src_ip, blacklist_map, ban_registry, offense_history, bpf_lock
                        )
                        ttl_label = f"{ttl_secs // 3600}h" if ttl_secs >= 3600 else f"{ttl_secs // 60}m"
                        print(
                            f"  [BLOCK] {flow.src_ip:<20} "
                            f"DDoS DETECTED  │ ban {ttl_label:<4} │ offense #{count}"
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