"""
Manage eBPF/XDP:
compile, attach, whitelist, ban/unban, and exponential backoff.

Sửa lỗi bảo mật đã ghi nhận:
  - load_whitelist() không còn nạp toàn bộ dải IP khách hàng của GCP/Fastly.
    Dải cloud.json phủ hàng triệu địa chỉ mà bất kỳ ai cũng thuê được, và vì
    whitelist được tra TRƯỚC blacklist trong XDP nên đó là cửa hậu hoàn chỉnh.
  - Lỗi nạp map không còn bị nuốt: mọi entry hỏng đều được đếm và in ra.
  - is_whitelisted() dùng chỉ mục longest-prefix thay vì quét tuyến tính.
  - _offense_counts đổi từ dict thường sang TTLCache (trước đây rò rỉ vô hạn).
  - _memory_manager() chụp snapshot ban_registry BÊN TRONG lock.
  - Hỗ trợ IPv6 song song IPv4.
"""


import ctypes
import heapq
import ipaddress
import os
import socket
import struct
import threading
import time

import requests

from cachetools import TTLCache


# Check whether BCC is available
try:
    from bcc import BPF

    BCC_AVAILABLE = True

except ImportError:
    BCC_AVAILABLE = False


# Set ban TTL values for exponential backoff
BAN_TTL = [
    5 * 60,       # Attempt 1: 5 minutes
    60 * 60,      # Attempt 2: 1 hour
    24 * 3600     # Attempt 3+: 24 hours
]


# Dải hạ tầng bắt buộc phải qua được, nếu không mất luôn khả năng quản trị máy.
#
# Cố ý giữ danh sách này NGẮN. Bản trước nạp cả cloud.json (dải khách hàng GCP),
# goog.json và Fastly — tổng cộng vài triệu địa chỉ mà bất kỳ ai thuê một con
# VM cũng có. Whitelist được tra trước blacklist trong xdp_filter.c, nên mọi
# địa chỉ nằm trong đó là miễn nhiễm tuyệt đối với IPS.
MANDATORY_CIDRS = [
    "35.235.240.0/20",     # GCP IAP TCP forwarding (SSH qua console)
    "169.254.169.254/32",  # GCE metadata server
    "35.191.0.0/16",       # GCP health check
    "130.211.0.0/22",      # GCP health check
]

# Hostname của Canonical: cần thiết để `apt update` không tự bắn vào chân mình.
# Đây là traffic TRẢ VỀ từ máy chủ Ubuntu nên src IP là của Canonical, phạm vi
# hẹp (một nhúm /32 + một dải /21), khác hẳn việc whitelist cả một cloud.
CANONICAL_HOSTNAMES = [
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "changelogs.ubuntu.com",
    "motd.ubuntu.com",
    "api.snapcraft.io",
    "canonical.com",
    "launchpad.net",
]

CANONICAL_STATIC_CIDRS = [
    "91.189.88.0/21",
]

# Biến môi trường cho các dải do quản trị viên tự khai (IP văn phòng, VPN, ...).
# Ví dụ: WHITELIST_CIDRS="203.0.113.7/32,198.51.100.0/24"
ENV_WHITELIST_VAR = "WHITELIST_CIDRS"

# Bật lại hành vi cũ (nạp cloud.json/goog.json/Fastly) khi thật sự cần, ví dụ
# khi server chỉ nhận traffic sau một CDN. Mặc định TẮT vì nó vô hiệu hoá IPS.
ENV_ALLOW_BULK_CLOUD = "WHITELIST_BULK_CLOUD"

# Whitelist Canonical bằng DNS. Mặc định TẮT — xem _resolve_canonical_ips().
ENV_ALLOW_CANONICAL = "WHITELIST_CANONICAL"


# Trần cứng cho sổ ban trong user space.
#
# ban_registry là dict thường duy nhất còn lại không có giới hạn: mỗi IP bị
# chặn thêm một entry sống ít nhất 5 phút. Trong một trận flood source giả mạo
# (đúng kịch bản GlobalFloodDetector sinh ra để bắt) tốc độ chặn có thể lên
# hàng nghìn IP/giây, và chính máy phòng thủ lại là thứ hết RAM trước.
# Đặt bằng max_entries của blacklist_map trong xdp_filter.c: giữ nhiều hơn
# cũng vô nghĩa vì LRU của kernel đã đẩy entry cũ ra rồi.
MAX_TRACKED_BANS = 500_000

# Số IP tối đa gỡ ban trong MỘT chu kỳ dọn dẹp. Xem _memory_manager().
MAX_UNBAN_PER_CYCLE = 5_000


# Các ô của stats_map trong xdp_filter.c. Thứ tự PHẢI khớp enum stat_slot.
STAT_SLOTS = [
    ("total",        "Gói qua XDP"),
    ("pass_wl",      "PASS do whitelist"),
    ("drop_v4",      "DROP IPv4"),
    ("drop_v6",      "DROP IPv6"),
    ("vlan",         "Gói có tag VLAN"),
    ("v6_seen",      "Gói IPv6"),
    ("non_ip",       "Không phải IP (ARP...)"),
]


# Convert an IPv4 address to an unsigned 32-bit integer.
#
# Giữ nguyên struct.unpack("I", ...) theo native byte order: xdp_filter.c đọc
# ip->saddr (Network Byte Order) như một u32 trong bộ nhớ host, nên trên máy
# little-endian hai bên khớp nhau. Đổi sang "!I" sẽ làm lệch key.
def ip_to_int(ip_str):
    return struct.unpack(
        "I",
        socket.inet_aton(ip_str)
    )[0]


# Convert an unsigned 32-bit integer to an IPv4 address
def int_to_ip(ip_int):
    return socket.inet_ntoa(
        struct.pack(
            "I",
            ip_int
        )
    )


# Kiểm tra nhanh một chuỗi có phải địa chỉ IPv6 hay không
def is_ipv6(ip_str):
    return ":" in ip_str


# BCC ánh xạ `__u8 addr[16]` trong struct C thành mảng ctypes c_ubyte 16 phần tử
ADDR16 = ctypes.c_ubyte * 16


# Đóng gói một địa chỉ IPv6 thành mảng ctypes để đưa vào eBPF map
def ipv6_to_addr16(ip_str):
    return ADDR16(
        *socket.inet_pton(socket.AF_INET6, ip_str)
    )


# Chỉ mục CIDR tra theo longest-prefix.
#
# Bản cũ dùng `any(addr in net for net in self.py_whitelist)`, tức là quét
# tuyến tính hơn 1 500 đối tượng IPv4Network cho MỖI flow bị nghi ngờ — ngay
# trên đường nóng, đúng lúc hệ thống đang bị tấn công. Ở đây chỉ cần tối đa
# 33 (IPv4) hoặc 129 (IPv6) phép tra hash, và thực tế ít hơn nhiều vì chỉ có
# vài độ dài prefix khác nhau.
class CidrIndex:

    def __init__(self):
        self._tables = {4: {}, 6: {}}
        self._prefix_order = {4: [], 6: []}
        self.networks = []

    # Thêm một mạng vào chỉ mục
    def add(self, net):
        table = self._tables[net.version]

        table.setdefault(net.prefixlen, set()).add(
            int(net.network_address)
        )

        self.networks.append(net)

        # Tra từ prefix dài nhất tới ngắn nhất
        self._prefix_order[net.version] = sorted(table, reverse=True)

    # Kiểm tra một địa chỉ có nằm trong chỉ mục không
    def contains(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)

        except ValueError:
            return False

        table = self._tables[addr.version]

        if not table:
            return False

        bits = 32 if addr.version == 4 else 128
        value = int(addr)

        for prefixlen in self._prefix_order[addr.version]:
            if prefixlen == 0:
                return True

            mask = ((1 << prefixlen) - 1) << (bits - prefixlen)

            if (value & mask) in table[prefixlen]:
                return True

        return False

    def __len__(self):
        return len(self.networks)


# Store information about a detected attack
class AttackSignature:

    # Initialize attack signature information
    def __init__(
        self,
        src_ip,
        protocol="UNKNOWN",
        dst_port=0,
        fwd_len_mean=0.0,
        pps=0.0,
        reason="AI_INFERENCE (Binary Model)",
        features=None
    ):
        self.src_ip = src_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.fwd_len_mean = fwd_len_mean
        self.pps = pps
        self.reason = reason

        # Store the feature vector from the AI detection path
        self.features = features

    # Build a unique signature key for the attack
    @property
    def signature_key(self):
        return (
            f"PROTO:{self.protocol}"
            f"_PORT:{self.dst_port}"
            f"_LEN:{round(self.fwd_len_mean, -1)}"
        )


# Manage the XDP data plane and state management
class XDPEnforcer:

    # Initialize the XDP enforcer
    def __init__(
        self,
        interface: str,
        xdp_file: str
    ):
        self.interface = interface
        self.xdp_file = xdp_file

        # Initialize eBPF handles
        self.bpf = None
        self.blacklist_map = None
        self.blacklist6_map = None
        self.whitelist_map = None
        self.whitelist6_map = None
        self.stats_map = None

        # Initialize whitelist and ban state.
        #
        # ban_registry giữ hạn hết ban để tra cứu, _ban_heap giữ ĐÚNG các mốc
        # hết hạn theo thứ tự tăng dần. Có heap thì vòng dọn dẹp chỉ chạm vào
        # những IP thật sự đã hết hạn, thay vì quét lại toàn bộ sổ ban mỗi 5
        # giây — với 500 000 entry đó là 100 000 phép so sánh mỗi giây, thực
        # hiện ngay trong lock mà đường bắt gói cũng đang cần.
        self.whitelist_index = CidrIndex()
        self.ban_registry = {}
        self._ban_heap = []

        # Track repeated offenses for exponential backoff.
        #
        # Cả hai đều phải là TTLCache có maxsize. Bản trước dùng dict thường cho
        # _offense_counts, nên một trận flood với source giả mạo ngẫu nhiên làm
        # dict phình vô hạn cho tới khi chính máy phòng thủ bị OOM.
        self.offense_history = TTLCache(
            maxsize=100_000,
            ttl=86400
        )

        self.offense_counts = TTLCache(
            maxsize=100_000,
            ttl=86400
        )

        # Create a lock for shared state
        self.lock = threading.Lock()

        # Start the memory manager in the background
        self._stop_event = threading.Event()

        threading.Thread(
            target=self._memory_manager,
            daemon=True
        ).start()


    # Tương thích ngược: một số script cũ đọc enforcer.py_whitelist
    @property
    def py_whitelist(self):
        return self.whitelist_index.networks


    # Compile and attach the XDP program
    def load_and_attach(self) -> bool:
        # Check whether BCC is available
        if not BCC_AVAILABLE:
            print(
                "  [✗] FATAL: BCC library is not available."
            )
            return False

        # Show the XDP source file
        print(
            f"  [*] Compiling: {self.xdp_file}"
        )

        try:
            # Redirect BCC compiler stderr
            devnull_fd = os.open(
                os.devnull,
                os.O_WRONLY
            )

            saved_stderr = os.dup(2)

            os.dup2(
                devnull_fd,
                2
            )

            try:
                # Compile the eBPF program
                self.bpf = BPF(
                    src_file=self.xdp_file
                )

            finally:
                # Restore the original stderr
                os.dup2(
                    saved_stderr,
                    2
                )

                os.close(
                    saved_stderr
                )

                os.close(
                    devnull_fd
                )

            # Load the XDP program
            fn = self.bpf.load_func(
                "xdp_prog",
                BPF.XDP
            )

            try:
                # Try Native Driver Mode first
                self.bpf.attach_xdp(
                    dev=self.interface,
                    fn=fn,
                    flags=0
                )

                print(
                    f"  [+] XDP attached → Native Driver Mode"
                    f"  [{self.interface}]"
                )

            except Exception:
                # Fall back to Generic SKB Mode
                print(
                    "  [~] Native Mode unavailable, "
                    "trying Generic SKB Mode..."
                )

                self.bpf.attach_xdp(
                    dev=self.interface,
                    fn=fn,
                    flags=2
                )

                print(
                    f"  [+] XDP attached → Generic SKB Mode"
                    f"  [{self.interface}]"
                )

            # Load the blacklist and whitelist maps
            self.blacklist_map = self.bpf.get_table(
                "blacklist_map"
            )

            self.whitelist_map = self.bpf.get_table(
                "whitelist_map"
            )

            # Map IPv6: nếu chạy với xdp_filter.c cũ thì không có, hệ thống vẫn
            # hoạt động ở chế độ IPv4-only nhưng phải nói rõ ra.
            try:
                self.blacklist6_map = self.bpf.get_table("blacklist6_map")
                self.whitelist6_map = self.bpf.get_table("whitelist6_map")

                print("  [+] IPv6 enforcement maps ready")

            except Exception:
                self.blacklist6_map = None
                self.whitelist6_map = None

                print(
                    "  [!] IPv6 maps not found in the loaded eBPF program; "
                    "running IPv4-only."
                )

            # Bộ đếm data plane. Không bắt buộc, nên thiếu thì chỉ mất số liệu.
            try:
                self.stats_map = self.bpf.get_table("stats_map")

                print("  [+] XDP statistics counters ready")

            except Exception:
                self.stats_map = None

            return True

        except Exception as exc:
            # Show XDP initialization errors
            print(
                f"  [✗] FATAL: Unable to load eBPF — {exc}"
            )

            print(
                "  [✗] Please run with sudo."
            )

            return False


    # Detach the XDP program safely
    def detach(self):
        # Dừng luồng memory manager trước
        self._stop_event.set()

        # Skip detaching when BPF was never loaded
        if not self.bpf:
            return

        try:
            try:
                # Remove Native Driver Mode
                self.bpf.remove_xdp(
                    self.interface,
                    flags=0
                )

            except Exception:
                # Fall back to Generic SKB Mode
                self.bpf.remove_xdp(
                    self.interface,
                    flags=2
                )

            # Confirm that XDP was detached
            print(
                "  [+] XDP filter safely detached "
                "from the interface.\n"
            )

        except Exception:
            # Ignore cleanup errors during shutdown
            pass


    # Resolve official Canonical and Ubuntu IP ranges.
    #
    # TẮT theo mặc định, vì hai lý do độc lập:
    #
    #  1. Không cần thiết. `apt update` là kết nối do MÁY CHỦ khởi tạo, nên
    #     NFStream báo flow với src_ip là địa chỉ local và gatekeeper đã bỏ qua
    #     ở bước local_ips. Không có đường nào để Canonical bị đưa vào
    #     blacklist, nên whitelist nó không cứu được gì cả.
    #
    #  2. Whitelist bằng DNS là whitelist theo thứ kẻ khác điều khiển được.
    #     Ai chi phối được câu trả lời DNS lúc IPS khởi động — resolver bị
    #     chiếm, cache poisoning, một máy cùng mạng — là tự đưa được IP của
    #     mình vào danh sách miễn nhiễm tuyệt đối. Thêm nữa, launchpad.net và
    #     canonical.com nằm trên CDN dùng chung, nên một /32 ở đó còn phục vụ
    #     cả những tên miền khác không liên quan.
    #
    # Đây chính là lỗi của bản whitelist cloud.json, chỉ ở quy mô nhỏ hơn.
    @staticmethod
    def _resolve_canonical_ips() -> list:
        enabled = os.environ.get(
            ENV_ALLOW_CANONICAL, ""
        ).strip().lower() in ("1", "true", "yes", "on")

        if not enabled:
            print(
                "  [+] Canonical/Ubuntu DNS whitelist: DISABLED "
                f"(bật bằng {ENV_ALLOW_CANONICAL}=1)"
            )

            print(
                "      Lý do: apt là kết nối do máy chủ khởi tạo nên không bao "
                "giờ bị chặn, còn whitelist theo DNS thì kẻ chi phối được "
                "resolver sẽ tự đưa mình vào danh sách miễn nhiễm."
            )

            return []

        # Store resolved CIDR ranges
        resolved = []

        # Resolve each Canonical hostname
        for hostname in CANONICAL_HOSTNAMES:
            try:
                # Get IPv4 addresses for the hostname
                infos = socket.getaddrinfo(
                    hostname,
                    None,
                    socket.AF_INET
                )

                # Remove duplicate IP addresses
                ips = sorted(
                    {
                        info[4][0]
                        for info in infos
                    }
                )

                # Convert IPs to host CIDRs
                for ip in ips:
                    resolved.append(
                        f"{ip}/32"
                    )

                # Show resolved addresses
                print(
                    f"  [+] Canonical DNS [{hostname}]: "
                    f"{', '.join(ips)}"
                )

            except Exception as exc:
                # Show DNS resolution errors
                print(
                    f"  [!] Unable to resolve "
                    f"{hostname}: {exc}"
                )

        # Add static Canonical fallback ranges
        resolved += CANONICAL_STATIC_CIDRS

        print(
            "  [+] Canonical static CIDR fallback: "
            f"{', '.join(CANONICAL_STATIC_CIDRS)}"
        )

        return resolved


    # Đọc các dải do quản trị viên khai trong biến môi trường
    @staticmethod
    def _admin_cidrs() -> list:
        raw = os.environ.get(ENV_WHITELIST_VAR, "").strip()

        if not raw:
            print(
                f"  [!] {ENV_WHITELIST_VAR} chưa được đặt. "
                f"Chỉ whitelist các dải hạ tầng bắt buộc."
            )

            return []

        entries = [
            part.strip()
            for part in raw.replace(";", ",").split(",")
            if part.strip()
        ]

        print(
            f"  [+] {ENV_WHITELIST_VAR}: {len(entries)} dải do admin khai "
            f"({', '.join(entries)})"
        )

        return entries


    # Tải các dải CDN/cloud dạng khối. TẮT theo mặc định.
    @staticmethod
    def _bulk_cloud_cidrs() -> list:
        enabled = os.environ.get(
            ENV_ALLOW_BULK_CLOUD, ""
        ).strip().lower() in ("1", "true", "yes", "on")

        if not enabled:
            print(
                "  [+] Bulk cloud/CDN whitelist: DISABLED "
                f"(bật bằng {ENV_ALLOW_BULK_CLOUD}=1 nếu server nằm sau CDN)"
            )

            print(
                "      Lý do: cloud.json là dải KHÁCH HÀNG của GCP. "
                "Whitelist nó đồng nghĩa miễn nhiễm cho mọi VM thuê được."
            )

            return []

        print(
            f"  [!] CẢNH BÁO: {ENV_ALLOW_BULK_CLOUD} đang bật. "
            f"Mọi IP thuộc GCP/Fastly sẽ KHÔNG BAO GIỜ bị chặn."
        )

        cidrs = []

        sources = [
            ("GCP cloud.json", "https://www.gstatic.com/ipranges/cloud.json"),
            ("GCP goog.json", "https://www.gstatic.com/ipranges/goog.json"),
        ]

        for label, url in sources:
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()

                prefixes = [
                    prefix["ipv4Prefix"]
                    for prefix in resp.json().get("prefixes", [])
                    if "ipv4Prefix" in prefix
                ]

                cidrs += prefixes

                print(f"  [+] {label}: {len(prefixes)} prefixes.")

            except Exception as exc:
                print(f"  [!] Unable to download {label}: {exc}")

        try:
            resp = requests.get(
                "https://api.fastly.com/public-ip-list",
                timeout=10
            )

            resp.raise_for_status()

            fastly_data = resp.json()

            fastly_prefixes = (
                fastly_data.get("addresses", [])
                + fastly_data.get("ipv4_addresses", [])
            )

            cidrs += fastly_prefixes

            print(f"  [+] Fastly CDN: {len(fastly_prefixes)} prefixes.")

        except Exception as exc:
            print(f"  [!] Unable to download Fastly IP list: {exc}")

        return cidrs


    # Load external IP ranges into the eBPF whitelist
    def load_whitelist(self) -> list:
        # Thứ tự: hạ tầng bắt buộc → admin khai báo → Canonical → (tuỳ chọn) bulk
        cidrs = list(MANDATORY_CIDRS)

        print(
            "  [+] Dải hạ tầng bắt buộc: "
            f"{', '.join(MANDATORY_CIDRS)}"
        )

        cidrs += self._admin_cidrs()
        cidrs += self._resolve_canonical_ips()
        cidrs += self._bulk_cloud_cidrs()

        # Remove duplicate CIDR ranges
        cidrs = list(
            dict.fromkeys(cidrs)
        )

        # Show the number of whitelist ranges
        print(
            f"  [*] Loading {len(cidrs)} CIDR ranges "
            f"into eBPF Whitelist LPM Trie..."
        )

        ok = 0
        invalid = []
        rejected = []

        # Load each CIDR into the eBPF map
        for cidr in cidrs:
            # Bản cũ gói toàn bộ vòng này trong `except: pass`, nên khi map đầy
            # (max_entries 2 000 < số prefix của GCP) whitelist chỉ được nạp một
            # phần ngẫu nhiên mà không ai biết. Nay phân biệt rõ hai loại lỗi.
            try:
                net = ipaddress.ip_network(cidr, strict=False)

            except ValueError as exc:
                invalid.append(f"{cidr} ({exc})")
                continue

            try:
                if net.version == 4:
                    key = self.whitelist_map.Key(
                        net.prefixlen,
                        ip_to_int(str(net.network_address))
                    )

                    self.whitelist_map[key] = self.whitelist_map.Leaf(1)

                else:
                    if self.whitelist6_map is None:
                        rejected.append(f"{cidr} (IPv6 map unavailable)")
                        continue

                    key = self.whitelist6_map.Key(
                        net.prefixlen,
                        ipv6_to_addr16(str(net.network_address))
                    )

                    self.whitelist6_map[key] = self.whitelist6_map.Leaf(1)

                self.whitelist_index.add(net)

                ok += 1

            except Exception as exc:
                rejected.append(f"{cidr} ({exc})")

        # Show the number of loaded rules
        print(
            f"  [+] Successfully loaded "
            f"{ok}/{len(cidrs)} rules into the Data Plane."
        )

        # Báo động nếu có entry bị từ chối: nghĩa là whitelist trong kernel KHÁC
        # với whitelist trong user space, và hai tầng sẽ ra quyết định lệch nhau.
        if invalid:
            print(f"  [!] {len(invalid)} CIDR không hợp lệ, đã bỏ qua:")

            for item in invalid[:10]:
                print(f"      - {item}")

        if rejected:
            print(
                f"  [✗] {len(rejected)} CIDR KHÔNG nạp được vào eBPF map "
                f"(map đầy hoặc lỗi kernel):"
            )

            for item in rejected[:10]:
                print(f"      - {item}")

            print(
                "  [✗] Whitelist kernel và user space đang lệch nhau. "
                "Tăng max_entries trong xdp_filter.c rồi chạy lại."
            )

        return self.whitelist_index.networks


    # Đọc bộ đếm của tầng data plane.
    #
    # stats_map là PERCPU_ARRAY, nên mỗi ô trả về một danh sách giá trị — một
    # phần tử cho mỗi CPU. Phải CỘNG LẠI; lấy phần tử đầu là số của đúng một
    # lõi, tức là chia cho số lõi một cách âm thầm.
    def read_stats(self) -> dict:
        if self.stats_map is None:
            return {}

        out = {}

        for index, (name, _) in enumerate(STAT_SLOTS):
            try:
                per_cpu = self.stats_map[ctypes.c_int(index)]

                out[name] = sum(
                    int(getattr(value, "value", value))
                    for value in per_cpu
                )

            except Exception:
                out[name] = 0

        return out


    # In bảng số liệu data plane. Đây là bằng chứng duy nhất cho thấy XDP
    # thực sự DROP gói, và cho thấy nhánh VLAN/IPv6 có được đi qua hay không.
    def print_stats(self):
        stats = self.read_stats()

        if not stats:
            print("  [!] Không có stats_map — biên dịch lại src/xdp_filter.c.")

            return

        print("\n  ── XDP DATA PLANE COUNTERS ──────────────────────────")

        for name, label in STAT_SLOTS:
            print(f"     {label:<26} {stats.get(name, 0):>15,}")

        total = stats.get("total", 0)
        dropped = stats.get("drop_v4", 0) + stats.get("drop_v6", 0)

        if total:
            print(
                f"     {'Tỉ lệ DROP':<26} {dropped / total:>14.4%}"
            )

        print()


    # Check whether an IP belongs to the whitelist
    def is_whitelisted(
        self,
        ip_str: str
    ) -> bool:
        return self.whitelist_index.contains(ip_str)


    # Xây key eBPF cho một địa chỉ, tự chọn map IPv4 hay IPv6
    def _blacklist_key(self, ip_str):
        if is_ipv6(ip_str):
            if self.blacklist6_map is None:
                return None, None

            key = self.blacklist6_map.Key(
                ipv6_to_addr16(ip_str)
            )

            return self.blacklist6_map, key

        return self.blacklist_map, self.blacklist_map.Key(ip_to_int(ip_str))


    # Check whether an IP is currently banned
    def is_banned(
        self,
        ip_str: str
    ) -> bool:
        try:
            table, key = self._blacklist_key(ip_str)

            if table is None:
                return False

            # Check whether the key exists in the blacklist
            table[key]

            return True

        except KeyError:
            return False

        except Exception:
            return False


    # Block an attacking IP with exponential backoff
    def block_ip(
        self,
        sig: "AttackSignature"
    ):
        # Extract the attacking IP
        ip_str = sig.src_ip

        # Chốt chặn cuối: không bao giờ ban một IP đã whitelist, kể cả khi
        # caller quên kiểm tra. block_ip() là API công khai của enforcer.
        if self.is_whitelisted(ip_str):
            return 0, 0

        # Lock shared ban state
        with self.lock:
            # Skip IPs that are already banned
            if self.is_banned(ip_str):
                return 0, 0

            # Get the current time
            now = time.time()

            # Read the previous offense timestamp
            last_offense = self.offense_history.get(ip_str)

            # Reset the offense count after 24 hours
            if last_offense is None or now - last_offense > 86400:
                count = 1

            else:
                # Increase the offense count
                count = self.offense_counts.get(ip_str, 0) + 1

            # Store the current offense count
            self.offense_counts[ip_str] = count

            # Store the latest offense timestamp
            self.offense_history[ip_str] = now

            # Select the TTL using exponential backoff
            ttl_index = min(
                count - 1,
                len(BAN_TTL) - 1
            )

            ttl_secs = BAN_TTL[
                ttl_index
            ]

            # Add the IP to the eBPF blacklist
            try:
                table, key = self._blacklist_key(ip_str)

                if table is None:
                    print(
                        f"  [!] Không thể chặn {ip_str}: "
                        f"eBPF program không có map IPv6."
                    )

                    return 0, 0

                table[key] = table.Leaf(ttl_secs)

            except Exception as exc:
                print(f"  [!] Lỗi ghi blacklist map cho {ip_str}: {exc}")

                return 0, 0

            # Store the ban expiration time
            expires_at = now + ttl_secs

            self.ban_registry[ip_str] = expires_at

            heapq.heappush(self._ban_heap, (expires_at, ip_str))

            # Trần cứng cho sổ ban. Kernel đã có LRU cho blacklist_map, phía
            # Python thì chưa — nên trước khi vượt trần, ép hết hạn IP có mốc
            # gần nhất. Đó cũng chính là IP mà LRU của kernel sẽ đẩy ra trước.
            if len(self.ban_registry) > MAX_TRACKED_BANS:
                self._evict_oldest_unlocked()

        # Send notifications outside the shared lock
        try:
            # Import the Telegram notifier
            from notifier import send_block_alert

            # Send the block event to Telegram
            send_block_alert(sig)

        except Exception as exc:
            # Show Telegram notification errors
            print(
                f"  [!] Telegram notifier error: {exc}"
            )

        # Send the event to GCS
        try:
            # Import the GCS logging utility collector
            from gcs_utility import get_collector

            # Store the attack event in GCS
            get_collector().record_from_signature(
                sig,
                features=getattr(sig, "features", None)
            )

        except Exception as exc:
            # Show GCS logging errors
            print(
                f"  [!] GCS logger error: {exc}"
            )

        # Show the completed ban action
        print(
            f"  [+] BLOCKED {ip_str} "
            f"for {ttl_secs}s "
            f"offense #{count}"
        )

        return count, ttl_secs


    # Xoá một entry khỏi eBPF map. KHÔNG chạm vào ban_registry và không in gì,
    # để caller quyết định khi nào giữ lock và khi nào log.
    def _drop_from_map(self, ip_str: str):
        try:
            table, key = self._blacklist_key(ip_str)

            if table is not None:
                del table[key]

        except Exception:
            # Entry có thể đã bị LRU của kernel đẩy ra từ trước
            pass


    # Ép hết hạn IP có mốc gần nhất khi sổ ban chạm trần. Gọi khi ĐANG giữ lock.
    def _evict_oldest_unlocked(self):
        while self._ban_heap and len(self.ban_registry) > MAX_TRACKED_BANS:
            _, ip = heapq.heappop(self._ban_heap)

            self.ban_registry.pop(ip, None)


    # Remove an IP from the eBPF blacklist
    def unban_ip(
        self,
        ip_str: str
    ):
        self._drop_from_map(ip_str)

        # Remove the IP from the local ban registry
        self.ban_registry.pop(
            ip_str,
            None
        )

        # Show the completed unban action
        print(
            f"  [−] UNBANNED {ip_str}"
        )


    # Remove expired bans in the background
    def _memory_manager(self):
        # Keep the memory manager running until shutdown
        while not self._stop_event.is_set():
            try:
                now = time.time()

                # Bước 1 — CHỈ chọn danh sách, làm thật nhanh trong lock.
                #
                # Bản trước duyệt self.ban_registry.items() ngoài lock trong khi
                # block_ip() ghi vào cùng dict ở luồng bắt gói, nên Python ném
                # "dictionary changed size during iteration"; lỗi bị nuốt rồi
                # thử lại sau 5s, và vì nó chỉ xảy ra khi đang có block — tức
                # đúng lúc bị tấn công — vòng dọn dẹp gần như không bao giờ
                # chạy xong, IP không bao giờ được gỡ.
                #
                # Bản sau đó sửa được lỗi trên nhưng lại gọi unban_ip() cho
                # từng IP NGAY TRONG lock, mỗi lượt kèm một syscall xoá map và
                # một dòng print. Vì hầu hết ban đều dùng cùng TTL 300s, cả
                # trận tấn công hết hạn gần như cùng lúc: hàng chục nghìn
                # syscall + print nối tiếp nhau trong khi vẫn giữ lock mà
                # block_ip() đang chờ — IPS ngừng chặn suốt cơn bão gỡ ban đó.
                expired = []

                with self.lock:
                    while (
                        self._ban_heap
                        and self._ban_heap[0][0] <= now
                        and len(expired) < MAX_UNBAN_PER_CYCLE
                    ):
                        expiry, ip = heapq.heappop(self._ban_heap)

                        current = self.ban_registry.get(ip)

                        # Entry cũ trong heap: IP đã bị ban lại với hạn xa hơn
                        # (hoặc đã bị gỡ). Bỏ qua, đừng gỡ nhầm ban đang hiệu lực.
                        if current is None or current > expiry:
                            continue

                        del self.ban_registry[ip]

                        expired.append(ip)

                # Bước 2 — syscall xoá map chạy NGOÀI lock
                for ip in expired:
                    self._drop_from_map(ip)

                # Bước 3 — một dòng tổng kết thay vì một dòng mỗi IP
                if expired:
                    if len(expired) <= 5:
                        for ip in expired:
                            print(f"  [−] UNBANNED {ip}")

                    else:
                        print(
                            f"  [−] UNBANNED {len(expired):,} IP hết hạn "
                            f"(còn {len(self.ban_registry):,} IP đang bị chặn)"
                        )

            except Exception as exc:
                # Show memory manager errors
                print(
                    f"  [-] Memory Manager error: {exc}"
                )

            # Wait before scanning the ban registry again
            self._stop_event.wait(5)
