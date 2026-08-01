"""
enforcer.py — XDP Data Plane Controller
Quản lý eBPF/XDP: compile, attach, whitelist, ban/unban với Exponential Backoff.
"""

import os
import socket
import struct
import threading
import time
import ipaddress
import requests

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

from cachetools import TTLCache

# ── Hằng số ───────────────────────────────────────────────────────────────────

# Exponential Backoff Ban TTL
BAN_TTL = [
    5   * 60,    # Lần 1: 5 phút
    60  * 60,    # Lần 2: 1 tiếng
    24  * 3600,  # Lần 3+: 24 tiếng
]


# ── Tiện ích chuyển đổi IP ─────────────────────────────────────────────────────

def ip_to_int(ip_str):
    """Chuyển IPv4 string → unsigned 32-bit integer (Network Byte Order) cho eBPF map."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int):
    """Chuyển unsigned 32-bit integer từ eBPF map → IPv4 string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))


# ── XDP Enforcer ───────────────────────────────────────────────────────────────

class XDPEnforcer:
    """
    Quản lý toàn bộ tầng Data Plane (eBPF/XDP) và State Management.
    Bao gồm: compile & attach XDP, whitelist, ban registry, offense history,
    exponential backoff, và memory manager daemon.
    """

    def __init__(self, interface: str, xdp_file: str):
        self.interface = interface
        self.xdp_file  = xdp_file

        # eBPF handles
        self.bpf           = None
        self.blacklist_map = None
        self.whitelist_map = None
        self.py_whitelist  = []  
        self.ban_registry    = {}
        self.offense_history = TTLCache(maxsize=100_000, ttl=86400)
        self.lock = threading.Lock()

        threading.Thread(target=self._memory_manager, daemon=True).start()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def load_and_attach(self) -> bool:
        """Compile xdp_filter.c và attach vào card mạng."""
        if not BCC_AVAILABLE:
            print("  [✗] FATAL: Thư viện bcc không khả dụng.")
            return False

        print(f"  [*] Biên dịch: {self.xdp_file}")
        try:
            devnull_fd   = os.open(os.devnull, os.O_WRONLY)
            saved_stderr = os.dup(2)
            os.dup2(devnull_fd, 2)
            try:
                self.bpf = BPF(src_file=self.xdp_file)
            finally:
                os.dup2(saved_stderr, 2)
                os.close(saved_stderr)
                os.close(devnull_fd)

            fn = self.bpf.load_func("xdp_prog", BPF.XDP)
            try:
                self.bpf.attach_xdp(dev=self.interface, fn=fn, flags=0)
                print(f"  [+] XDP attached → Native (Driver) Mode  [{self.interface}]")
            except Exception:
                print(f"  [~] Native Mode không khả dụng, thử Generic (SKB) Mode...")
                self.bpf.attach_xdp(dev=self.interface, fn=fn, flags=2)
                print(f"  [+] XDP attached → Generic (SKB) Mode  [{self.interface}]")

            self.blacklist_map = self.bpf.get_table("blacklist_map")
            self.whitelist_map = self.bpf.get_table("whitelist_map")
            return True

        except Exception as exc:
            print(f"  [✗] FATAL: Không thể tải eBPF — {exc}")
            print(f"  [✗] Hãy chạy bằng sudo.")
            return False

    def detach(self):
        """Gỡ XDP khỏi card mạng — luôn gọi trong finally khi thoát."""
        if not self.bpf:
            return
        try:
            try:
                self.bpf.remove_xdp(self.interface, flags=0)
            except Exception:
                self.bpf.remove_xdp(self.interface, flags=2)
            print("  [+] XDP filter đã gỡ khỏi interface an toàn.\n")
        except Exception:
            pass

    # ── Whitelist ──────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_canonical_ips() -> list:
        """
        Resolve DNS động các hostname chính thức của Canonical/Ubuntu.
        Vì Canonical dùng DNS load-balancing (không có API JSON như GCP),
        cách chuẩn nhất là resolve hostname → lấy IP hiện tại tại thời điểm khởi động.

        Trả về list các CIDR string "/32" (host route) + fallback CIDR tĩnh.
        """
        # Các hostname chính thức cần resolve
        # — apt update/install, security patches, unattended-upgrades, snap, motd
        canonical_hostnames = [
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "ports.ubuntu.com",
            "changelogs.ubuntu.com",
            "motd.ubuntu.com",
            "api.snapcraft.io",
            "canonical.com",
            "launchpad.net",
        ]

        resolved = []
        for hostname in canonical_hostnames:
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
                ips = list({info[4][0] for info in infos})
                for ip in ips:
                    resolved.append(f"{ip}/32")
                print(f"  [+] Canonical DNS [{hostname}]: {', '.join(ips)}")
            except Exception as exc:
                print(f"  [!] Không resolve được {hostname}: {exc}")

        canonical_static_cidrs = [
            "91.189.88.0/21",
        ]
        resolved += canonical_static_cidrs
        print(f"  [+] Canonical static CIDR fallback: {', '.join(canonical_static_cidrs)}")

        return resolved

    def load_whitelist(self) -> list:
        """
        Fetch GCP cloud.json + goog.json + Fastly + Canonical (DNS resolve),
        nạp xuống eBPF LPM_TRIE map.
        Trả về list[IPv4Network].
        """
        cidrs = []

        # Fetch GCP Cloud IP Ranges
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

        # Canonical/Ubuntu — resolve DNS động tại thời điểm khởi động
        canonical_cidrs = self._resolve_canonical_ips()
        cidrs += canonical_cidrs

        cidrs += [
            "35.235.240.0/20",    # GCP IAP — Identity-Aware Proxy (SSH Console)
            "169.254.169.254/32"  # GCP Metadata Server (ops-agent, auth)
        ]

        cidrs = list(dict.fromkeys(cidrs))  # loại duplicate

        print(f"  [*] Nạp {len(cidrs)} dải CIDR vào eBPF Whitelist (LPM Trie)...")
        ok = 0
        for cidr in cidrs:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                key = self.whitelist_map.Key(net.prefixlen, ip_to_int(str(net.network_address)))
                self.whitelist_map[key] = self.whitelist_map.Leaf(1)
                self.py_whitelist.append(net)
                ok += 1
            except Exception:
                pass  # Bỏ qua IPv6 prefix hoặc entry không hợp lệ

        print(f"  [+] Nạp thành công {ok} quy tắc xuống Data Plane.")
        return self.py_whitelist


    def is_whitelisted(self, ip_str: str) -> bool:
        """Trả về True nếu ip_str khớp với bất kỳ CIDR nào trong whitelist."""
        try:
            addr = ipaddress.IPv4Address(ip_str)
            return any(addr in net for net in self.py_whitelist)
        except Exception:
            return False

    # ── Ban / Unban ────────────────────────────────────────────────────────────

    def is_banned(self, ip_str: str) -> bool:
        expire_ts = self.ban_registry.get(ip_str)
        return bool(expire_ts and expire_ts > time.time())

    def block_ip(self, src_ip: str):
        """
        Ban IP với TTL tăng lũy tiến.
        """
        with self.lock:
            count = self.offense_history.get(src_ip, 0) + 1
            self.offense_history[src_ip] = count

            ttl_secs = BAN_TTL[min(count - 1, len(BAN_TTL) - 1)]
            self.ban_registry[src_ip] = time.time() + ttl_secs
            self.blacklist_map[self.blacklist_map.Key(ip_to_int(src_ip))] = self.blacklist_map.Leaf(1)
        return count, ttl_secs

    # ── Memory Manager Daemon ──────────────────────────────────────────────────

    def _memory_manager(self):
        """Daemon: mỗi 5s quét ban_registry, gỡ eBPF entry khi TTL hết hạn."""
        while True:
            try:
                time.sleep(5)
                now = time.time()

                # Scan ngoài lock (read-only) → tránh block Main Thread
                expired_ips = [
                    ip for ip, expire_ts in list(self.ban_registry.items())
                    if expire_ts <= now
                ]

                # Xóa dưới lock — brief critical section
                with self.lock:
                    for ip in expired_ips:
                        expire_ts = self.ban_registry.get(ip)
                        if expire_ts and expire_ts <= now:   # double-check race condition
                            del self.ban_registry[ip]
                            try:
                                del self.blacklist_map[self.blacklist_map.Key(ip_to_int(ip))]
                            except Exception:
                                pass
            except Exception as exc:
                print(f"  [-] Memory Manager error: {exc}")