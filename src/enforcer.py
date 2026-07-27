import os
import socket
import struct
import threading
import time
import collections

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

from cachetools import TTLCache

# Cấu hình đường dẫn và thông số XDP
XDP_C_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xdp_filter.c")
DEFAULT_INTERFACE = os.environ.get("GW_INTERFACE", "ens4")
BLACKLIST_TTL = int(os.environ.get("GW_BLACKLIST_TTL", "300"))
TTL_SWEEP_INTERVAL = 30
TTL_CACHE_MAXSIZE = 50_000

class AttackSignature:
    # Lưu thông tin chữ ký tấn công DDoS
    def __init__(self, src_ip, protocol, dst_port, fwd_len_mean, pps=0.0, reason="AI_DETECTED_DDOS"):
        self.src_ip = src_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.fwd_len_mean = fwd_len_mean
        self.pps = pps
        self.reason = reason

    @property
    def signature_key(self):
        return f"PROTO:{self.protocol}_PORT:{self.dst_port}_LEN:{round(self.fwd_len_mean, -1)}"

def ip_to_int(ip_str):
    # Chuyển đổi IP dạng chuỗi sang định dạng số nguyên
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    # Chuyển đổi IP dạng số nguyên sang chuỗi
    return socket.inet_ntoa(struct.pack("I", ip_int))

class XDPEnforcer:
    # Lớp chịu trách nhiệm gắn chương trình XDP vào Card mạng và quản lý BPF Map
    def __init__(self, interface=DEFAULT_INTERFACE, dry_run=False):
        self.interface = interface
        self.dry_run = dry_run or not BCC_AVAILABLE
        self.bpf = None
        self.blacklist_map = None
        self.whitelist_map = None
        self.ttl_cache = TTLCache(maxsize=TTL_CACHE_MAXSIZE, ttl=BLACKLIST_TTL)
        self.lock = threading.Lock()
        
        # Chạy luồng nền xóa các IP đã hết hạn
        threading.Thread(target=self.ttl_sweep_daemon, daemon=True).start()
        if not BCC_AVAILABLE:
            print("[-] bcc not available - Running in DRY RUN mode")

    def load_and_attach(self):
        # Biên dịch file C và gắn vào card mạng
        if self.dry_run:
            print("[!] DRY-RUN: Skipping XDP attach.")
            return True
            
        print(f"[*] Compiling {XDP_C_FILE} & attaching to {self.interface}...")
        try:
            self.bpf = BPF(src_file=XDP_C_FILE)
            fn = self.bpf.load_func("xdp_prog", BPF.XDP)
            try:
                self.bpf.attach_xdp(dev=self.interface, fn=fn, flags=0)
                print("[+] Attached XDP in Native Mode")
            except Exception:
                self.bpf.attach_xdp(dev=self.interface, fn=fn, flags=2)
                print("[+] Attached XDP in Generic Mode")

            self.blacklist_map = self.bpf.get_table("blacklist_map")
            self.whitelist_map = self.bpf.get_table("whitelist_map")
            print("[+] BPF Maps are ready.")
            return True
        except Exception as e:
            print(f"[-] FATAL Error loading eBPF: {e}")
            return False

    def detach(self):
        # Gỡ bỏ chương trình XDP khỏi card mạng
        if self.dry_run or not self.bpf: 
            return
        try:
            try: 
                self.bpf.remove_xdp(self.interface, flags=0)
            except: 
                self.bpf.remove_xdp(self.interface, flags=2)
            print(f"[+] Detached XDP from {self.interface}")
        except Exception as e:
            print(f"[-] Detach error: {e}")

    def block_signature(self, sig):
        # Khóa một IP tấn công và ghi vào BPF Map
        with self.lock:
            if sig.src_ip in self.ttl_cache:
                return "ALREADY_BLOCKED"

            self.ttl_cache[sig.src_ip] = sig.signature_key
            
            if not self.dry_run and self.blacklist_map:
                try:
                    self.blacklist_map[self.blacklist_map.Key(ip_to_int(sig.src_ip))] = self.blacklist_map.Leaf(1)
                except Exception as e:
                    print(f"[-] BPF map error: {e}")
                    return "ERROR"

            print(f"[!] BLOCKED: {sig.src_ip} | {sig.signature_key} | {sig.pps:.1f} pps")
            
            try:
                import notifier
                threading.Thread(target=notifier.send_block_alert, args=(sig,), daemon=True).start()
            except ImportError:
                pass
                
            return "BLOCKED" if not self.dry_run else "DRY_RUN"

    def unblock_ip(self, ip_str):
        # Gỡ block một IP khỏi BPF Map
        with self.lock:
            existed = ip_str in self.ttl_cache
            self.ttl_cache.pop(ip_str, None)

            if not self.dry_run and self.blacklist_map and existed:
                try:
                    del self.blacklist_map[self.blacklist_map.Key(ip_to_int(ip_str))]
                    print(f"[+] UNBLOCKED - manual: {ip_str}")
                except Exception as e:
                    print(f"[-] Remove BPF entry error: {e}")
                    return False
            return existed

    def ttl_sweep_daemon(self):
        # Vòng lặp định kỳ quét và xóa các IP đã hết hạn TTL
        while True:
            time.sleep(TTL_SWEEP_INTERVAL)
            if self.dry_run or not self.blacklist_map: 
                continue
            
            with self.lock:
                valid_ips = set(self.ttl_cache.keys())
            
            expired = []
            try:
                for bpf_key, _ in self.blacklist_map.items():
                    ip = int_to_ip(bpf_key.value)
                    if ip not in valid_ips:
                        expired.append((bpf_key, ip))
            except Exception:
                continue
                
            with self.lock:
                for bpf_key, ip in expired:
                    if ip not in self.ttl_cache:
                        try:
                            del self.blacklist_map[bpf_key]
                            print(f"[+] AMNESTY: {ip} removed from eBPF - TTL expired")
                        except Exception:
                            pass

enforcer_instance = None
def get_enforcer():
    # Lấy instance duy nhất của enforcer
    global enforcer_instance
    if enforcer_instance is None:
        enforcer_instance = XDPEnforcer()
    return enforcer_instance

class TokenBucketEnforcer:
    # Lớp giới hạn tốc độ dựa trên Token Bucket
    def __init__(self, pps=100.0, burst=150.0, win=60.0, ratio=0.85):
        self.pps = pps
        self.burst = burst
        self.win = win
        self.ratio = ratio
        self.buckets = collections.defaultdict(lambda: [self.burst, time.monotonic()])
        self.sustained = collections.defaultdict(lambda: [time.monotonic(), 0.0])

    def evaluate_traffic(self, label, proto, port, fwd_len, pkts=1.0):
        # Đánh giá luồng traffic xem có vượt ngưỡng không
        if label == 0: 
            return "PASS"
            
        key = f"PROTO:{proto}_PORT:{port}_LEN:{round(fwd_len, -1)}"
        b = self.buckets[key]
        now = time.monotonic()
        b[0] = min(self.burst, b[0] + (now - b[1]) * self.pps)
        b[1] = now
        
        if b[0] >= pkts:
            b[0] -= pkts
            s = self.sustained[key]
            if now - s[0] >= self.win:
                s[0] = now
                s[1] = pkts
                return "PASS"
            s[1] += pkts
            avg = s[1]/(now - s[0]) if (now-s[0])>0 else 0
            if avg >= self.pps * self.ratio: 
                return "PASS_SUSPICIOUS"
            return "PASS"
        return "DROP"