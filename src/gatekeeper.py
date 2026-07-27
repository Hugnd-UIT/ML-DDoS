import os
import time
import socket
import struct
import fcntl
import threading
import ipaddress
import requests
import ctypes
import numpy as np
import xgboost as xgb
from bcc import BPF
from cachetools import TTLCache
from nfstream import NFStreamer

# --- CẤU HÌNH HỆ THỐNG ---
INTERFACE = "ens4"                 # Giao diện mạng cần bảo vệ
XDP_FILE = "xdp_filter.c"          # Đường dẫn mã nguồn eBPF (Data Plane)
MODEL_FILE = "xgboost_model.json"  # File mô hình AI
# -------------------------

def get_vm_ip(ifname):
    """Trích xuất IP của Interface mạng để cấu hình."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24])
    except Exception:
        return "127.0.0.1"

def ip_to_int(ip_str):
    """Chuyển đổi IP dạng chuỗi sang Interger (Network Byte Order) cho eBPF."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    """Chuyển đổi Integer từ eBPF (Network Byte Order) về lại IP dạng chuỗi."""
    return socket.inet_ntoa(struct.pack("I", ip_int))

def auto_load_gcp_whitelist(bpf_instance):
    """
    1. KHỞI TẠO VÀ NẠP TỰ ĐỘNG (ZERO-MAINTENANCE):
    Tải danh sách IP từ GCP, kết hợp cùng IP SSH/DNS và nạp xuống eBPF LPM_TRIE.
    """
    print("[*] Đang tiến hành đồng bộ Whitelist từ Google Cloud...")
    whitelist_map = bpf_instance.get_table("whitelist_map")
    
    cidrs = []
    # Fetch danh sách Public IPs của GCP (Các dịch vụ nội bộ Google)
    try:
        r = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        data = r.json()
        cidrs = [prefix['ipv4Prefix'] for prefix in data.get('prefixes', []) if 'ipv4Prefix' in prefix]
    except Exception as e:
        print(f"[-] Cảnh báo: Không tải được GCP IPs ({e}). Hệ thống vẫn tiếp tục nạp IP tĩnh.")

    cidrs.append("35.235.240.0/20")    # SSH IAP Console của GCP
    cidrs.append("169.254.169.254/32")  # DNS và Metadata Authentication Server

    # Nạp xuống Kernel (LPM_TRIE)
    print(f"[*] Tiến hành nạp {len(cidrs)} dải IP/Subnet vào eBPF Whitelist (LPM Trie)...")
    success_count = 0
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            prefixlen = net.prefixlen
            ip_str = str(net.network_address)
            
            # Khởi tạo struct key cho LPM_TRIE
            key = whitelist_map.Key(prefixlen, ip_to_int(ip_str))
            whitelist_map[key] = whitelist_map.Leaf(1)
            success_count += 1
        except Exception:
            pass 
            
    print(f"[+] Hoàn tất. Đã nạp thành công {success_count} quy tắc Whitelist xuống Data Plane.")

def memory_manager(blacklist_map, ttl_cache):
    """
    2. QUẢN LÝ BỘ NHỚ RAM:
    """
    while True:
        try:
            time.sleep(5) 
            expired_keys = []
            
            # Lặp qua tất cả IPs đang bị phong tỏa dưới Kernel
            for key, _ in blacklist_map.items():
                ip_str = int_to_ip(key.value)
                
                if ip_str not in ttl_cache:
                    expired_keys.append(key)
                    
            for key in expired_keys:
                ip_str = int_to_ip(key.value)
                del blacklist_map[key] 
                print(f"[i] AMNESTY | {ip_str} đã hết hạn 300s, gỡ khỏi eBPF Blacklist.")
                
        except Exception as e:
            print(f"[-] Memory Manager - Lỗi đồng bộ: {e}")

def load_ai_model():
    try:
        model = xgb.Booster()
        model.load_model(MODEL_FILE)
        return model
    except Exception as e:
        print(f"[!] Lỗi nạp mô hình {MODEL_FILE}: {e}")
        print(f"[!] Chạy chế độ Mock AI (Cứu hộ). Khóa IP nếu Packet > 500/flow.")
        class MockAI:
            def predict(self, features_matrix):
                feats = features_matrix.get_data().toarray() if hasattr(features_matrix, 'get_data') else features_matrix
                if feats[0][1] > 500:
                    return [1.0]
                return [0.0]
        return MockAI()

def extract_features(flow):
    features = [
        flow.bidirectional_duration_ms,
        flow.bidirectional_packets,
        flow.bidirectional_bytes,
        flow.src2dst_packets,
        flow.src2dst_bytes,
        flow.dst2src_packets,
        flow.dst2src_bytes,
        flow.bidirectional_min_ps,
        flow.bidirectional_mean_ps,
        flow.bidirectional_stddev_ps,
        flow.bidirectional_max_ps,
        flow.src2dst_min_ps,
        flow.src2dst_mean_ps,
        flow.src2dst_max_ps,
        flow.dst2src_min_ps,
        flow.dst2src_mean_ps,
        flow.dst2src_max_ps,
        flow.bidirectional_syn_packets,
        flow.bidirectional_ack_packets
    ]
    return np.array([features], dtype=np.float32)

def main():
    print("="*65)
    print(" 🚀 KHỞI ĐỘNG HỆ THỐNG")
    print("="*65)

    print(f"[*] 1. Đang compile và attach {XDP_FILE} vào {INTERFACE}...")
    try:
        b = BPF(src_file=XDP_FILE)
        fn = b.load_func("xdp_prog", BPF.XDP)
        try:
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=0)
            print(f"[+] Attach XDP thành công ở chế độ Native (Driver Mode)!")
        except Exception as e_native:
            print(f"[*] Chế độ Native bị từ chối. Tự động chuyển sang chế độ Generic (SKB Mode)...")
            b.attach_xdp(dev=INTERFACE, fn=fn, flags=2)
            print(f"[+] Attach XDP thành công ở chế độ Generic (SKB Mode)!")
    except Exception as e:
        print(f"[-] FATAL ERROR: Không thể tải eBPF ({e}). Vui lòng kiểm tra quyền Root.")
        return

    auto_load_gcp_whitelist(b)
    blacklist_map = b.get_table("blacklist_map")
    
    print("[*] 2. Khởi tạo TTLCache (50,000 max_entries, 300s TTL)...")
    ttl_cache = TTLCache(maxsize=50000, ttl=300)
    mem_thread = threading.Thread(target=memory_manager, args=(blacklist_map, ttl_cache), daemon=True)
    mem_thread.start()

    print("[*] 3. Tải AI Engine (XGBoost)...")
    ai_model = load_ai_model()
    
    vm_ip = get_vm_ip(INTERFACE)
    print(f"[*] 4. Trích xuất Host IP ({vm_ip})")

    print("\n" + "="*65)
    print(" 🛡️ HỆ THỐNG ĐÃ SẴN SÀNG - ĐANG KIỂM SOÁT TRAFFIC")
    print("="*65 + "\n")

    try:
        # Khởi tạo NFStreamer với statistical_analysis=True để bật tính năng đo lường Packet Size & Inter-arrival Time
        streamer = NFStreamer(source=INTERFACE, active_timeout=1, statistical_analysis=True)
        
        for flow in streamer:
            print(f"[DEBUG] {flow.src_ip} -> {flow.dst_ip} | pkts={flow.bidirectional_packets} | duration_ms={flow.bidirectional_duration_ms}")
            # -------------------------------------------------------------
            # BƯỚC A: LỌC EGRESS BẮT BUỘC
            # Bỏ qua mọi traffic do nội tại máy chủ tự sinh ra (Ví dụ: 
            # Ops Agent gửi metrics, ứng dụng gọi DB, request apt-get...)
            # -------------------------------------------------------------
            if flow.src_ip == vm_ip or flow.src_ip == "127.0.0.1":
                continue
                
            if flow.src_ip in ttl_cache:
                continue 

            features = extract_features(flow)
            dmatrix = xgb.DMatrix(features) if isinstance(ai_model, xgb.Booster) else features
            prediction = ai_model.predict(dmatrix)
            
            pred_val = prediction[0] if isinstance(prediction, (list, np.ndarray)) else prediction
            
            if pred_val >= 0.5: 
                ttl_cache[flow.src_ip] = True
                
                ip_int = ip_to_int(flow.src_ip)
                key = blacklist_map.Key(ip_int)
                blacklist_map[key] = blacklist_map.Leaf(1)
                
                print(f"[!] AI DETECTED DDOS | Flow: {flow.src_ip} -> {flow.dst_ip} | Pushing to XDP Blacklist!")

    except KeyboardInterrupt:
        print("\n[*] Tín hiệu ngắt từ System Admin. Đang hạ tầng an toàn...")
    except Exception as e:
        print(f"\n[-] Xảy ra sự cố ngoại lệ (Fail-safe): {e}")
    finally:
        try:
            try:
                b.remove_xdp(INTERFACE, flags=0)
            except Exception:
                b.remove_xdp(INTERFACE, flags=2)
            print("[+] Đã gỡ bỏ an toàn XDP Filter khỏi Interface. Hệ thống trở lại bình thường.")
        except Exception:
            pass

if __name__ == "__main__":
    main()