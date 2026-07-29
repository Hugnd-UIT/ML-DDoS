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
import warnings
import joblib
import numpy as np
import xgboost as xgb
from cachetools import TTLCache
from nfstream import NFStreamer

from enforcer import XDPEnforcer

# ── Cấu hình hệ thống ──────────────────────────────────────────────────────────

# Đường dẫn tới model XGBoost (phân loại nhị phân: DDoS / Benign)
MODEL_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "models", "binary.pkl"
)

# Multi-vector Rate Limiting (Sliding Window)
WINDOW_SECONDS     = 5
SYN_THRESHOLD      = 200    # Bắt SYN Flood
UDP_ICMP_THRESHOLD = 1000   # Bắt UDP/ICMP Flood
TOTAL_THRESHOLD    = 3000   # Bắt các loại flood khác (ACK, RST, FIN...)

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


def load_ai_model():
    """Tải XGBClassifier từ binary.pkl bằng joblib."""
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

    # ── 1. Khởi tạo Data Plane (eBPF/XDP) ────────────────────────────────────
    _banner("1/4  KHỞI TẠO DATA PLANE (eBPF/XDP)")
    enforcer = XDPEnforcer(INTERFACE, XDP_FILE)
    if not enforcer.load_and_attach():
        return

    # ── 2. Whitelist ──────────────────────────────────────────────────────────
    _banner("ĐỒNG BỘ WHITELIST")
    enforcer.load_whitelist()

    # ── 3. Memory Manager & State ─────────────────────────────────────────────
    _banner("2/4  KHỞI TẠO BỘ NHỚ USER-SPACE")
    print(f"  [+] Offense History khởi tạo (TTLCache 24h)")
    print(f"  [+] Memory Manager daemon started")

    # ── 4. AI Engine ─────────────────────────────────────────────────────────
    _banner("3/4  KHỞI TẠO AI ENGINE (XGBoost)")
    ai_model = load_ai_model()

    # ── 5. Egress Filter ──────────────────────────────────────────────────────
    _banner("4/4  CẤU HÌNH EGRESS FILTER")
    local_ips = get_all_local_ips(INTERFACE)
    print(f"  [+] Local IPs detected: {', '.join(sorted(local_ips))}")
    print(f"  [+] Mọi flow từ các địa chỉ này sẽ bỏ qua (Egress + Alias filter)")

    # Sliding Window: TTLCache tự động đá key cũ (LRU) khi vượt maxsize
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
                if flow.src_ip in local_ips:
                    continue

                # C. Bỏ qua IP đang trong thời gian bị phạt
                if enforcer.is_banned(flow.src_ip):
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
                    if not enforcer.is_whitelisted(flow.src_ip):
                        count, ttl_secs = enforcer.block_ip(flow.src_ip)
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
                    if not enforcer.is_whitelisted(flow.src_ip):
                        count, ttl_secs = enforcer.block_ip(flow.src_ip)
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
        enforcer.detach()


if __name__ == "__main__":
    main()