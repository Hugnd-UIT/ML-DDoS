import ipaddress
import json
import os
import socket
import struct
import threading
import time

import requests
from cachetools import TTLCache

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


BAN_TTL = [
    5 * 60,
    60 * 60,
    24 * 3600
]


def ip_to_int(ip_str):
    return struct.unpack(
        "I",
        socket.inet_aton(ip_str)
    )[0]


def int_to_ip(ip_int):
    return socket.inet_ntoa(
        struct.pack(
            "I",
            ip_int
        )
    )


class Signature:

    def __init__(
        self,
        src_ip,
        protocol="UNKNOWN",
        dst_port=0,
        fwd_len_mean=0.0,
        pps=0.0,
        reason="AI_INFERENCE",
        features=None,
        fwd_pkts=0,
        bwd_pkts=0,
        syn_count=0,
        ack_count=0,
        rst_count=0,
        flow_duration_ms=0.0,
        flow_bytes_s=0.0
    ):
        self.src_ip = src_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.fwd_len_mean = fwd_len_mean
        self.pps = pps
        self.reason = reason
        self.features = features
        self.fwd_pkts = fwd_pkts
        self.bwd_pkts = bwd_pkts
        self.syn_count = syn_count
        self.ack_count = ack_count
        self.rst_count = rst_count
        self.flow_duration_ms = flow_duration_ms
        self.flow_bytes_s = flow_bytes_s

    @property
    def signature(self):
        return (
            f"PROTO:{self.protocol}"
            f"_PORT:{self.dst_port}"
            f"_LEN:{round(self.fwd_len_mean, -1)}"
        )


class Enforcer:

    def __init__(
        self,
        interface: str,
        xdp_file: str = None
    ):
        self.interface = interface
        self.xdp_file = xdp_file or os.path.join(
            os.path.dirname(__file__),
            'xdp.c'
        )

        self.bpf = None
        self.blacklist_map = None
        self.whitelist_map = None

        self.py_whitelist = []
        self.ban_registry = {}

        self.offense_history = TTLCache(
            maxsize=100_000,
            ttl=86400
        )

        self.lock = threading.RLock()

        threading.Thread(
            target=self._memory_manager,
            daemon=True
        ).start()

    def load_xdp(self) -> bool:
        if not BCC_AVAILABLE:
            print(
                "  [✗] FATAL: BCC library is not available."
            )
            return False

        print(
            f"  [*] Compiling: {self.xdp_file}"
        )

        try:
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
                self.bpf = BPF(
                    src_file=self.xdp_file
                )

            finally:
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

            fn = self.bpf.load_func(
                "xdp",
                BPF.XDP
            )

            try:
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

            self.blacklist_map = self.bpf.get_table(
                "blacklist_map"
            )

            self.whitelist_map = self.bpf.get_table(
                "whitelist_map"
            )

            return True

        except Exception as exc:
            print(
                f"  [✗] FATAL: Unable to load eBPF — {exc}"
            )

            print(
                "  [✗] Please run with sudo / root permissions."
            )

            return False

    def detach_xdp(self):
        if not self.bpf:
            return

        try:
            try:
                self.bpf.remove_xdp(
                    self.interface,
                    flags=0
                )

            except Exception:
                self.bpf.remove_xdp(
                    self.interface,
                    flags=2
                )

            print(
                "  [+] XDP filter safely detached "
                "from the interface.\n"
            )

        except Exception:
            pass

    @staticmethod
    def _resolve_ips() -> list:
        canonical_hostnames = [
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "ports.ubuntu.com",
            "changelogs.ubuntu.com",
            "motd.ubuntu.com",
            "api.snapcraft.io",
            "canonical.com",
            "launchpad.net"
        ]

        resolved = []

        for hostname in canonical_hostnames:
            try:
                infos = socket.getaddrinfo(
                    hostname,
                    None,
                    socket.AF_INET
                )

                ips = list(
                    {
                        info[4][0]
                        for info in infos
                    }
                )

                for ip in ips:
                    resolved.append(
                        f"{ip}/32"
                    )

                print(
                    f"  [+] Canonical DNS [{hostname}]: "
                    f"{', '.join(ips)}"
                )

            except Exception as exc:
                print(
                    f"  [!] Unable to resolve "
                    f"{hostname}: {exc}"
                )

        canonical_static_cidrs = [
            "91.189.88.0/21"
        ]

        resolved += canonical_static_cidrs

        print(
            "  [+] Canonical static CIDR fallback: "
            f"{', '.join(canonical_static_cidrs)}"
        )

        return resolved

    def load_whitelist(self) -> list:
        cidrs = []

        try:
            resp = requests.get(
                "https://www.gstatic.com/ipranges/cloud.json",
                timeout=10
            )

            cloud_prefixes = [
                prefix["ipv4Prefix"]
                for prefix in resp.json().get(
                    "prefixes",
                    []
                )
                if "ipv4Prefix" in prefix
            ]

            cidrs += cloud_prefixes

            print(
                f"  [+] GCP cloud.json: "
                f"{len(cloud_prefixes)} prefixes."
            )

        except Exception as exc:
            print(
                f"  [!] Unable to download "
                f"cloud.json: {exc}"
            )

        try:
            resp = requests.get(
                "https://www.gstatic.com/ipranges/goog.json",
                timeout=10
            )

            goog_prefixes = [
                prefix["ipv4Prefix"]
                for prefix in resp.json().get(
                    "prefixes",
                    []
                )
                if "ipv4Prefix" in prefix
            ]

            cidrs += goog_prefixes

            print(
                f"  [+] GCP goog.json: "
                f"{len(goog_prefixes)} prefixes."
            )

        except Exception as exc:
            print(
                f"  [!] Unable to download "
                f"goog.json: {exc}"
            )

        try:
            resp = requests.get(
                "https://api.fastly.com/public-ip-list",
                timeout=10
            )

            fastly_data = resp.json()

            fastly_prefixes = (
                fastly_data.get("addresses", [])
                + fastly_data.get("ipv4_addresses", [])
            )

            cidrs += fastly_prefixes

            print(
                f"  [+] Fastly CDN: "
                f"{len(fastly_prefixes)} prefixes."
            )

        except Exception as exc:
            cidrs += [
                "151.101.0.0/16"
            ]

            print(
                f"  [!] Unable to download "
                f"Fastly IP list: {exc}. "
                f"Using fallback 151.101.0.0/16."
            )

        canonical_cidrs = (
            self._resolve_ips()
        )

        cidrs += canonical_cidrs

        cidrs += [
            "35.235.240.0/20",
            "169.254.169.254/32"
        ]

        cidrs = list(
            dict.fromkeys(cidrs)
        )

        print(
            f"  [*] Loading {len(cidrs)} CIDR ranges "
            f"into eBPF Whitelist LPM Trie..."
        )

        ok = 0

        for cidr in cidrs:
            try:
                net = ipaddress.IPv4Network(
                    cidr,
                    strict=False
                )

                key = self.whitelist_map.Key(
                    net.prefixlen,
                    ip_to_int(
                        str(net.network_address)
                    )
                )

                self.whitelist_map[key] = (
                    self.whitelist_map.Leaf(1)
                )

                self.py_whitelist.append(net)

                ok += 1

            except Exception:
                pass

        print(
            f"  [+] Successfully loaded "
            f"{ok} rules into the Data Plane."
        )

        return self.py_whitelist

    def check_whitelist(
        self,
        ip_str: str
    ) -> bool:
        try:
            addr = ipaddress.IPv4Address(
                ip_str
            )

            return any(
                addr in net
                for net in self.py_whitelist
            )

        except Exception:
            return False

    def check_blacklist(
        self,
        ip_str: str
    ) -> bool:
        try:
            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            self.blacklist_map[key]

            return True

        except KeyError:
            return False

        except Exception:
            return False

    def block_ip(
        self,
        sig: "Signature"
    ):
        ip_str = sig.src_ip

        with self.lock:
            if self.check_blacklist(ip_str):
                return 0, 0

            now = time.time()

            last_offense = (
                self.offense_history.get(
                    ip_str
                )
            )

            if (
                last_offense is None
                or now - last_offense > 86400
            ):
                count = 1

            else:
                count = (
                    getattr(
                        self,
                        "_offense_counts",
                        {}
                    ).get(
                        ip_str,
                        0
                    ) + 1
                )

            if not hasattr(
                self,
                "_offense_counts"
            ):
                self._offense_counts = {}

            self._offense_counts[
                ip_str
            ] = count

            self.offense_history[
                ip_str
            ] = now

            ttl_index = min(
                count - 1,
                len(BAN_TTL) - 1
            )

            ttl_secs = BAN_TTL[
                ttl_index
            ]

            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            self.blacklist_map[key] = (
                self.blacklist_map.Leaf(
                    ttl_secs
                )
            )

            self.ban_registry[
                ip_str
            ] = now + ttl_secs

        try:
            log_dir = os.path.join(
                os.path.dirname(__file__),
                '..',
                'logs'
            )
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, 'alerts.log')
            alert_entry = {
                "timestamp": now,
                "src_ip": ip_str,
                "protocol": sig.protocol,
                "dst_port": sig.dst_port,
                "reason": sig.reason,
                "pps": sig.pps,
                "ttl_secs": ttl_secs,
                "offense_count": count,
                "avg_packet_size": round(sig.fwd_len_mean, 2),
                "fwd_pkts": sig.fwd_pkts,
                "bwd_pkts": sig.bwd_pkts,
                "syn_count": sig.syn_count,
                "ack_count": sig.ack_count,
                "rst_count": sig.rst_count,
                "flow_duration_ms": round(sig.flow_duration_ms, 3),
                "flow_bytes_s": round(sig.flow_bytes_s, 2)
            }
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_entry) + '\n')
        except Exception:
            pass

        return count, ttl_secs

    def unban_ip(
        self,
        ip_str: str
    ):
        try:
            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            del self.blacklist_map[key]

        except Exception:
            pass

        with self.lock:
            self.ban_registry.pop(
                ip_str,
                None
            )

        print(
            f"  [−] UNBANNED {ip_str}"
        )

    def _memory_manager(self):
        while True:
            try:
                now = time.time()

                expired = [
                    ip
                    for ip, expiry in self.ban_registry.items()
                    if expiry <= now
                ]

                if expired:
                    with self.lock:
                        for ip in expired:
                            if (
                                ip in self.ban_registry
                                and self.ban_registry[ip] <= now
                            ):
                                self.unban_ip(ip)

            except Exception as exc:
                print(
                    f"  [-] Memory Manager error: {exc}"
                )

            time.sleep(5)
