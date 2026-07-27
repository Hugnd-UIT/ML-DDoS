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
import numpy as np
import xgboost as xgb
from collections import defaultdict
from bcc import BPF
from cachetools import TTLCache
from nfstream import NFStreamer

# --- CẤU HÌNH HỆ THỐNG ---
MODEL_FILE = "xgboost_model.json"  # File mô hình AI (đặt cùng thư mục với script)

# Ngưỡng Sliding Window: nếu tổng packet từ 1 src_ip vượt mức này
# trong cửa sổ WINDOW_SECONDS giây → đưa vào ML phân tích ngay
WINDOW_SECONDS = 5
PACKET_WINDOW_THRESHOLD = 500
# -------------------------


def parse_args():
    """Parse tham số dòng lệnh (ví dụ: -i ens4)."""
    parser = argparse.ArgumentParser(description="Gatekeeper IPS — AI XGBoost + eBPF/XDP")
    parser.add_argument("-i", "--interface", required=True, help="Tên interface mạng cần bảo vệ (vd: ens4)")
    return parser.parse_args()


def get_vm_ip(ifname):
    """Trích xuất địa chỉ IP của interface mạng để nhận diện traffic nội bộ (Egress Filter)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', bytes(ifname[:15], 'utf-8'))
            )[20:24])
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def ip_to_int(ip_str):
    """Chuyển đổi IP string sang integer dạng Network Byte Order để ghi vào eBPF map."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int):
    """Chuyển đổi integer từ eBPF map (Network Byte Order) về IP string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))


def auto_load_gcp_whitelist(bpf_instance):
    """
    Tải danh sách dải CIDR của Google Cloud từ API public, kết hợp với các dải
    tĩnh bắt buộc (SSH IAP, Metadata Server), nạp xuống eBPF LPM_TRIE map.
    Đảm bảo traffic quản trị hệ thống không bao giờ bị chặn nhầm.
    """
    print("[*] Đang đồng bộ Whitelist từ Google Cloud IP Ranges...")
    whitelist_map = bpf_instance.get_table("whitelist_map")

    cidrs = []
    try:
        r = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        data = r.json()
        cidrs = [
            prefix['ipv4Prefix']
            for prefix in data.get('prefixes', [])
            if 'ipv4Prefix' in prefix
        ]
    except Exception as e:
        print(f"[-] Không tải được GCP IP Ranges ({e}). Tiếp tục với danh sách tĩnh.")

    # Các dải bắt buộc phải có — không phụ thuộc vào kết quả fetch
    cidrs.append("35.235.240.0/20")    # GCP IAP (Identity-Aware Proxy) cho SSH Console
    cidrs.append("169.254.169.254/32")  # GCP Metadata Server (dùng cho auth và ops agent)

    # Giới hạn theo capacity của map (max_entries = 2000 trong xdp_filter.c)
    print(f"[*] Nạp {len(cidrs)} dải CIDR vào eBPF Whitelist (LPM Trie)...")
    success_count = 0
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            key = whitelist_map.Key(net.prefixlen, ip_to_int(str(net.network_address)))
            whitelist_map[key] = whitelist_map.Leaf(1)
            success_count += 1
        except Exception:
            pass  # Bỏ qua IPv6 prefix và các entry không hợp lệ

    print(f"[+] Nạp thành công {success_count} quy tắc Whitelist xuống Data Plane.")


def memory_manager(blacklist_map, ttl_cache, lock):
    """
    Daemon thread chạy nền, đồng bộ trạng thái giữa TTLCache (User-space) và
    eBPF blacklist_map (Kernel-space). Khi TTL của một IP hết hạn (300s),
    tự động gỡ khỏi eBPF map để ân xá và giải phóng đường truyền.
    """
    while True:
        try:
            time.sleep(5)
            expired_keys = []

            with lock:
                for key, _ in blacklist_map.items():
                    ip_str = int_to_ip(key.value)
                    if ip_str not in ttl_cache:
                        expired_keys.append(key)

                for key in expired_keys:
                    ip_str = int_to_ip(key.value)
                    del blacklist_map[key]
                    print(f"[i] AMNESTY | {ip_str} hết hạn 300s → gỡ khỏi XDP Blacklist.")

        except Exception as e:
            print(f"[-] Memory Manager lỗi: {e}")


def load_ai_model():
    """
    Tải mô hình XGBoost từ file. Nếu file không tồn tại hoặc lỗi,
    fallback sang MockAI dựa trên ngưỡng packet count để hệ thống
    không sập hoàn toàn khi thiếu model (Graceful Degradation).
    """
    try:
        model = xgb.Booster()
        model.load_model(MODEL_FILE)
        print(f"[+] Đã tải mô hình XGBoost từ {MODEL_FILE}.")
        return model
    except Exception as e:
        print(f"[!] Không tải được {MODEL_FILE}: {e}")
        print(f"[!] Chạy MockAI fallback — ngưỡng phát hiện: bidirectional_packets > {PACKET_WINDOW_THRESHOLD}.")

        class MockAI:
            def predict(self, features_matrix):
                # features_matrix là numpy array shape (1, 19)
                # features[0][1] = bidirectional_packets (index 1 trong extract_features)
                pkts = features_matrix[0][1]
                return [1.0] if pkts > PACKET_WINDOW_THRESHOLD else [0.0]

        return MockAI()


def extract_features(flow):
    """
    Trích xuất 19 đặc trưng thống kê luồng chuẩn CIC-DDoS2019 từ đối tượng NFStream flow.
    Yêu cầu NFStreamer khởi tạo với statistical_analysis=True.
    """
    features = [
        flow.bidirectional_duration_ms,   # 0
        flow.bidirectional_packets,        # 1
        flow.bidirectional_bytes,          # 2
        flow.src2dst_packets,              # 3
        flow.src2dst_bytes,                # 4
        flow.dst2src_packets,              # 5
        flow.dst2src_bytes,                # 6
        flow.bidirectional_min_ps,         # 7
        flow.bidirectional_mean_ps,        # 8
        flow.bidirectional_stddev_ps,      # 9
        flow.bidirectional_max_ps,         # 10
        flow.src2dst_min_ps,               # 11
        flow.src2dst_mean_ps,              # 12
        flow.src2dst_max_ps,               # 13
        flow.dst2src_min_ps,               # 14
        flow.dst2src_mean_ps,              # 15
        flow.dst2src_max_ps,               # 16
        flow.bidirectional_syn_packets,    # 17
        flow.bidirectional_ack_packets     # 18
    ]
    return np.array([features], dtype=np.float32)


def ban_ip(src_ip, blacklist_map, ttl_cache, lock):
    """
    Ghi IP vào TTLCache (User-space, tự xóa sau 300s) và eBPF blacklist_map
    (Kernel-space, XDP sẽ DROP mọi packet từ IP này ở tốc độ line-rate).
    """
    with lock:
        ttl_cache[src_ip] = True
        key = blacklist_map.Key(ip_to_int(src_ip))
        blacklist_map[key] = blacklist_map.Leaf(1)


def main():
    args = parse_args()
    INTERFACE = args.interface

    # Đường dẫn tuyệt đối đến xdp_filter.c, đảm bảo đúng bất kể CWD khi chạy script
    XDP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xdp_filter.c")

    print("=" * 65)
    print(" 🚀 KHỞI ĐỘNG GATEKEEPER IPS (AI XGBoost + eBPF/XDP)")
    print("=" * 65)

    # --- 1. Biên dịch và nạp eBPF / Attach XDP ---
    print(f"[*] 1. Compile và attach {XDP_FILE} vào {INTERFACE}...")
    try:
        b = BPF(src_file=XDP_FILE)
        fn = b.load_func("xdp_prog", BPF.XDP)
        try:
            # Ưu tiên Native XDP (chạy ở tầng Driver, hiệu năng cao nhất)
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=0)
            print(f"[+] XDP attached — Native (Driver) Mode.")
        except Exception:
            # Fallback: Generic XDP (SKB Mode) — tương thích với card mạng ảo hóa GCP/AWS
            print(f"[*] Native Mode không hỗ trợ → chuyển sang Generic (SKB) Mode...")
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=2)
            print(f"[+] XDP attached — Generic (SKB) Mode.")
    except Exception as e:
        print(f"[-] FATAL: Không thể tải eBPF ({e}). Chạy bằng sudo?")
        return

    # --- 2. Nạp Whitelist ---
    auto_load_gcp_whitelist(b)
    blacklist_map = b.get_table("blacklist_map")

    # --- 3. Khởi tạo bộ nhớ User-space ---
    print("[*] 2. Khởi tạo TTLCache (maxsize=50000, ttl=300s)...")
    ttl_cache = TTLCache(maxsize=50000, ttl=300)
    bpf_lock = threading.Lock()  # Mutex bảo vệ truy cập đồng thời vào eBPF map
    mem_thread = threading.Thread(
        target=memory_manager,
        args=(blacklist_map, ttl_cache, bpf_lock),
        daemon=True
    )
    mem_thread.start()

    # --- 4. Tải AI Engine ---
    print("[*] 3. Tải AI Engine (XGBoost)...")
    ai_model = load_ai_model()

    # --- 5. Lấy IP máy chủ để lọc Egress ---
    vm_ip = get_vm_ip(INTERFACE)
    print(f"[*] 4. Host IP = {vm_ip} (sẽ bỏ qua traffic Egress từ địa chỉ này).")

    # --- 6. Sliding Window Counter: đếm tổng packet theo src_ip ---
    # Dùng để phát hiện SYN Flood dạng rotating source-port (vd: hping3 mặc định),
    # nơi mỗi packet có source port khác nhau nên NFStreamer tạo ra nhiều micro-flow.
    # Cấu trúc: { src_ip: [timestamp_of_packet, ...] }
    packet_window = defaultdict(list)

    print("\n" + "=" * 65)
    print(" 🛡️  HỆ THỐNG ĐÃ SẴN SÀNG — ĐANG GIÁM SÁT TRAFFIC INGRESS")
    print("=" * 65 + "\n")

    try:
        # statistical_analysis=True bắt buộc để có các feature min/mean/max packet size
        streamer = NFStreamer(source=INTERFACE, active_timeout=1, statistical_analysis=True)

        for flow in streamer:
            print(f"[DEBUG] {flow.src_ip} -> {flow.dst_ip} | pkts={flow.bidirectional_packets} | duration_ms={flow.bidirectional_duration_ms}")

            # === Bọc toàn bộ xử lý của mỗi flow trong try-except riêng ===
            # Lỗi trên một flow không được phép crash hệ thống hay gỡ XDP.
            try:
                # --- BƯỚC A: Bỏ qua traffic Egress (do chính máy chủ gửi ra) ---
                if flow.src_ip == vm_ip or flow.src_ip == "127.0.0.1":
                    continue

                # --- BƯỚC B: Bỏ qua IP đã bị ban (đang trong TTL 300s) ---
                if flow.src_ip in ttl_cache:
                    continue

                # --- BƯỚC C: Sliding Window — phát hiện SYN Flood rotating-port ---
                now = time.time()
                window = packet_window[flow.src_ip]
                # Ghi nhận số packet của flow hiện tại vào cửa sổ thời gian
                window.append((now, flow.src2dst_packets))
                # Loại bỏ các entry cũ hơn WINDOW_SECONDS giây
                packet_window[flow.src_ip] = [(t, p) for t, p in window if now - t <= WINDOW_SECONDS]
                # Tính tổng packet trong cửa sổ
                total_pkts_in_window = sum(p for _, p in packet_window[flow.src_ip])

                if total_pkts_in_window > PACKET_WINDOW_THRESHOLD:
                    # Ngưỡng sliding window vượt mức → đây là dấu hiệu flood rõ ràng
                    ban_ip(flow.src_ip, blacklist_map, ttl_cache, bpf_lock)
                    packet_window.pop(flow.src_ip, None)  # Reset counter sau khi ban
                    print(f"[!] SLIDING WINDOW DETECT | {flow.src_ip} | {total_pkts_in_window} pkts/{WINDOW_SECONDS}s → XDP Blacklist!")
                    continue

                # --- BƯỚC D: ML Inference (XGBoost) ---
                features = extract_features(flow)
                dmatrix = xgb.DMatrix(features) if isinstance(ai_model, xgb.Booster) else features
                prediction = ai_model.predict(dmatrix)
                pred_val = float(prediction[0]) if isinstance(prediction, (list, np.ndarray)) else float(prediction)

                if pred_val >= 0.5:
                    ban_ip(flow.src_ip, blacklist_map, ttl_cache, bpf_lock)
                    print(f"[!] AI DETECTED DDOS | {flow.src_ip} -> {flow.dst_ip} | pred={pred_val:.3f} → XDP Blacklist!")

            except Exception as flow_err:
                # Lỗi trên flow đơn lẻ: in cảnh báo và tiếp tục, KHÔNG thoát vòng lặp
                print(f"[-] Flow processing error ({flow.src_ip}): {flow_err}")
                continue

    except KeyboardInterrupt:
        print("\n[*] Nhận tín hiệu tắt từ Admin. Đang dọn dẹp...")
    except Exception as e:
        print(f"\n[-] Lỗi nghiêm trọng không phục hồi được: {e}")
    finally:
        # Luôn gỡ XDP khi thoát để không để lại filter trên interface
        try:
            try:
                b.remove_xdp(INTERFACE, flags=0)
            except Exception:
                b.remove_xdp(INTERFACE, flags=2)
            print("[+] Đã gỡ XDP Filter khỏi interface an toàn.")
        except Exception:
            pass


if __name__ == "__main__":
    main()