"""
Manage eBPF/XDP:
compile, attach, whitelist, ban/unban, and exponential backoff.
"""


import os
import socket
import struct
import threading
import time
import ipaddress

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


# Convert an IPv4 address to an unsigned 32-bit integer
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

        # Store the 19-feature vector from the AI detection path
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
        self.whitelist_map = None

        # Initialize whitelist and ban state
        self.py_whitelist = []
        self.ban_registry = {}

        # Track repeated offenses for exponential backoff
        self.offense_history = TTLCache(
            maxsize=100_000,
            ttl=86400
        )

        # Create a lock for shared state
        self.lock = threading.Lock()

        # Start the memory manager in the background
        threading.Thread(
            target=self._memory_manager,
            daemon=True
        ).start()


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


    # Resolve official Canonical and Ubuntu IP ranges
    @staticmethod
    def _resolve_canonical_ips() -> list:
        # Define official Canonical hostnames
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

        # Store resolved CIDR ranges
        resolved = []

        # Resolve each Canonical hostname
        for hostname in canonical_hostnames:
            try:
                # Get IPv4 addresses for the hostname
                infos = socket.getaddrinfo(
                    hostname,
                    None,
                    socket.AF_INET
                )

                # Remove duplicate IP addresses
                ips = list(
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

        # Define static Canonical fallback ranges
        canonical_static_cidrs = [
            "91.189.88.0/21"
        ]

        # Add static fallback ranges
        resolved += canonical_static_cidrs

        # Show static fallback ranges
        print(
            "  [+] Canonical static CIDR fallback: "
            f"{', '.join(canonical_static_cidrs)}"
        )

        return resolved


    # Load external IP ranges into the eBPF whitelist
    def load_whitelist(self) -> list:
        # Create an empty CIDR list
        cidrs = []

        # Fetch GCP Cloud IP ranges
        try:
            resp = requests.get(
                "https://www.gstatic.com/ipranges/cloud.json",
                timeout=10
            )

            # Extract IPv4 prefixes
            cloud_prefixes = [
                prefix["ipv4Prefix"]
                for prefix in resp.json().get(
                    "prefixes",
                    []
                )
                if "ipv4Prefix" in prefix
            ]

            # Add GCP ranges to the whitelist
            cidrs += cloud_prefixes

            print(
                f"  [+] GCP cloud.json: "
                f"{len(cloud_prefixes)} prefixes."
            )

        except Exception as exc:
            # Show GCP Cloud range errors
            print(
                f"  [!] Unable to download "
                f"cloud.json: {exc}"
            )

        # Fetch GCP Google IP ranges
        try:
            resp = requests.get(
                "https://www.gstatic.com/ipranges/goog.json",
                timeout=10
            )

            # Extract IPv4 prefixes
            goog_prefixes = [
                prefix["ipv4Prefix"]
                for prefix in resp.json().get(
                    "prefixes",
                    []
                )
                if "ipv4Prefix" in prefix
            ]

            # Add Google ranges to the whitelist
            cidrs += goog_prefixes

            print(
                f"  [+] GCP goog.json: "
                f"{len(goog_prefixes)} prefixes."
            )

        except Exception as exc:
            # Show GCP Google range errors
            print(
                f"  [!] Unable to download "
                f"goog.json: {exc}"
            )

        # Fetch Fastly CDN IP ranges
        try:
            resp = requests.get(
                "https://api.fastly.com/public-ip-list",
                timeout=10
            )

            # Parse Fastly IP range data
            fastly_data = resp.json()

            # Extract Fastly IPv4 ranges
            fastly_prefixes = (
                fastly_data.get("addresses", [])
                + fastly_data.get("ipv4_addresses", [])
            )

            # Add Fastly ranges to the whitelist
            cidrs += fastly_prefixes

            print(
                f"  [+] Fastly CDN: "
                f"{len(fastly_prefixes)} prefixes."
            )

        except Exception as exc:
            # Use a static Fastly fallback range
            cidrs += [
                "151.101.0.0/16"
            ]

            print(
                f"  [!] Unable to download "
                f"Fastly IP list: {exc}. "
                f"Using fallback 151.101.0.0/16."
            )

        # Resolve Canonical and Ubuntu ranges
        canonical_cidrs = (
            self._resolve_canonical_ips()
        )

        # Add Canonical ranges to the whitelist
        cidrs += canonical_cidrs

        # Add required infrastructure ranges
        cidrs += [
            "35.235.240.0/20",
            "169.254.169.254/32"
        ]

        # Remove duplicate CIDR ranges
        cidrs = list(
            dict.fromkeys(cidrs)
        )

        # Show the number of whitelist ranges
        print(
            f"  [*] Loading {len(cidrs)} CIDR ranges "
            f"into eBPF Whitelist LPM Trie..."
        )

        # Track successfully loaded rules
        ok = 0

        # Load each CIDR into the eBPF map
        for cidr in cidrs:
            try:
                # Convert the CIDR into an IPv4 network
                net = ipaddress.IPv4Network(
                    cidr,
                    strict=False
                )

                # Build the LPM Trie key
                key = self.whitelist_map.Key(
                    net.prefixlen,
                    ip_to_int(
                        str(net.network_address)
                    )
                )

                # Add the network to the eBPF whitelist
                self.whitelist_map[key] = (
                    self.whitelist_map.Leaf(1)
                )

                # Store the network in Python state
                self.py_whitelist.append(net)

                # Increase the successful rule count
                ok += 1

            except Exception:
                # Skip invalid or unsupported entries
                pass

        # Show the number of loaded rules
        print(
            f"  [+] Successfully loaded "
            f"{ok} rules into the Data Plane."
        )

        return self.py_whitelist


    # Check whether an IP belongs to the whitelist
    def is_whitelisted(
        self,
        ip_str: str
    ) -> bool:
        try:
            # Convert the input string to an IPv4 address
            addr = ipaddress.IPv4Address(
                ip_str
            )

            # Check the address against every whitelist network
            return any(
                addr in net
                for net in self.py_whitelist
            )

        except Exception:
            # Return false for invalid IP addresses
            return False


    # Check whether an IP is currently banned
    def is_banned(
        self,
        ip_str: str
    ) -> bool:
        try:
            # Convert the IP address into an eBPF map key
            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            # Check whether the key exists in the blacklist
            self.blacklist_map[key]

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

        # Lock shared ban state
        with self.lock:
            # Skip IPs that are already banned
            if self.is_banned(ip_str):
                return 0, 0

            # Get the current time
            now = time.time()

            # Read the previous offense timestamp
            last_offense = (
                self.offense_history.get(
                    ip_str
                )
            )

            # Reset the offense count after 24 hours
            if (
                last_offense is None
                or now - last_offense > 86400
            ):
                count = 1

            else:
                # Increase the offense count
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

            # Initialize the offense counter when needed
            if not hasattr(
                self,
                "_offense_counts"
            ):
                self._offense_counts = {}

            # Store the current offense count
            self._offense_counts[
                ip_str
            ] = count

            # Store the latest offense timestamp
            self.offense_history[
                ip_str
            ] = now

            # Select the TTL using exponential backoff
            ttl_index = min(
                count - 1,
                len(BAN_TTL) - 1
            )

            ttl_secs = BAN_TTL[
                ttl_index
            ]

            # Add the IP to the eBPF blacklist
            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            self.blacklist_map[key] = (
                self.blacklist_map.Leaf(
                    ttl_secs
                )
            )

            # Store the ban expiration time
            self.ban_registry[
                ip_str
            ] = now + ttl_secs

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


    # Remove an IP from the eBPF blacklist
    def unban_ip(
        self,
        ip_str: str
    ):
        try:
            # Build the eBPF blacklist key
            key = self.blacklist_map.Key(
                ip_to_int(ip_str)
            )

            # Remove the IP from the blacklist
            del self.blacklist_map[key]

        except Exception:
            # Ignore missing or already removed entries
            pass

        # Remove the IP from the local ban registry
        with self.lock:
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
        # Keep the memory manager running continuously
        while True:
            try:
                # Get the current timestamp
                now = time.time()

                # Find expired bans without holding the lock
                expired = [
                    ip
                    for ip, expiry in self.ban_registry.items()
                    if expiry <= now
                ]

                # Remove expired bans inside the lock
                if expired:
                    with self.lock:
                        for ip in expired:
                            # Double-check the ban before removing it
                            if (
                                ip in self.ban_registry
                                and self.ban_registry[ip] <= now
                            ):
                                self.unban_ip(ip)

            except Exception as exc:
                # Show memory manager errors
                print(
                    f"  [-] Memory Manager error: {exc}"
                )

            # Wait before scanning the ban registry again
            time.sleep(5)