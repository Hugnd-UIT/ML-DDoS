"""
╔══════════════════════════════════════════════════════════════════╗
║         GATEKEEPER IPS — HYBRID AI + eBPF/XDP CONTROL PLANE      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import fcntl
import os
import socket
import struct
import time
import warnings

import joblib
import numpy as np
import xgboost as xgb

from cachetools import TTLCache
from nfstream import NFStreamer

from enforcer import XDPEnforcer, AttackSignature


# Map IANA protocol numbers to readable protocol names
PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


# Convert a protocol number into a readable name
def proto_name(proto_num):
    return PROTO_NAMES.get(
        int(proto_num),
        str(proto_num)
    )


# Set the path to the binary XGBoost model
MODEL_FILE = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "..",
    "models",
    "binary.pkl"
)


# Configure the multi-vector sliding window
WINDOW_SECONDS = 5

SYN_THRESHOLD = 200

UDP_ICMP_THRESHOLD = 1000

TOTAL_THRESHOLD = 3000


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Gatekeeper IPS — "
            "Hybrid AI XGBoost + eBPF/XDP"
        ),
        formatter_class=(
            argparse.RawDescriptionHelpFormatter
        )
    )

    # Define the protected network interface
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        metavar="IFACE",
        help=(
            "Network interface to protect "
            "for example ens4 or eth0"
        )
    )

    return parser.parse_args()


# Get all IPv4 addresses assigned to the interface
def get_all_local_ips(ifname):
    import subprocess

    # Store detected local addresses
    ips = set()

    # Try to detect addresses using the ip command
    try:
        result = subprocess.run(
            [
                "ip",
                "-4",
                "addr",
                "show",
                ifname
            ],
            capture_output=True,
            text=True,
            timeout=3
        )

        # Parse IPv4 addresses from command output
        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("inet "):
                ip = line.split()[1]
                ip = ip.split("/")[0]

                ips.add(ip)

    except Exception:
        pass

    # Use ioctl as a fallback when ip command fails
    if not ips:
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            try:
                # Request the interface IPv4 address
                address = fcntl.ioctl(
                    sock.fileno(),
                    0x8915,
                    struct.pack(
                        "256s",
                        bytes(
                            ifname[:15],
                            "utf-8"
                        )
                    )
                )

                # Convert the returned address to IPv4
                ip = socket.inet_ntoa(
                    address[20:24]
                )

                ips.add(ip)

            finally:
                # Close the fallback socket
                sock.close()

        except Exception:
            pass

    # Always ignore localhost traffic
    ips.add("127.0.0.1")

    return ips


# Load the trained XGBoost model
def load_ai_model():
    try:
        # Suppress model loading warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            model = joblib.load(
                MODEL_FILE
            )

        # Show the loaded model information
        print(
            f"  [+] Model loaded: "
            f"{type(model).__name__}"
        )

        print(
            f"      Path: {MODEL_FILE}"
        )

        return model

    except Exception as exc:
        # Stop the system when the model cannot be loaded
        print(
            f"  [✗] Unable to load model: {exc}"
        )

        print(
            "  [✗] A valid model file is required."
        )

        print(
            "  [✗] Exiting system..."
        )

        import sys

        sys.exit(1)


# Extract the 19 CIC-DDoS2019 features from an NFStream flow
def extract_features(flow):
    # Calculate flow duration
    duration_us = (
        float(
            flow.bidirectional_duration_ms
        )
        * 1000.0
    )

    duration_s = max(
        float(
            flow.bidirectional_duration_ms
        ) / 1000.0,
        1e-9
    )


    # Calculate traffic rates
    flow_bytes_per_s = (
        float(
            flow.bidirectional_bytes
        )
        / duration_s
    )

    flow_packets_per_s = (
        float(
            flow.bidirectional_packets
        )
        / duration_s
    )


    # Calculate forward and backward traffic totals
    fwd_pkts = float(
        flow.src2dst_packets
    )

    bwd_pkts = float(
        flow.dst2src_packets
    )

    fwd_bytes = float(
        flow.src2dst_bytes
    )

    bwd_bytes = float(
        flow.dst2src_bytes
    )


    # Calculate the backward-to-forward packet ratio
    if fwd_pkts > 0:
        down_up_ratio = (
            bwd_pkts / fwd_pkts
        )
    else:
        down_up_ratio = 0.0


    # Extract packet length statistics
    fwd_len_max = float(
        flow.src2dst_max_ps
    )

    fwd_len_min = float(
        flow.src2dst_min_ps
    )

    fwd_len_mean = float(
        flow.src2dst_mean_ps
    )

    bwd_len_mean = float(
        flow.dst2src_mean_ps
    )


    # Calculate inter-arrival time statistics
    total_pkts = int(
        flow.bidirectional_packets
    )

    if total_pkts > 1:
        iat_mean_us = (
            duration_us
            / (total_pkts - 1)
        )
    else:
        iat_mean_us = 0.0

    iat_std_us = 0.0


    # Calculate forward inter-arrival time
    try:
        fwd_iat_total_us = (
            float(
                flow.src2dst_duration_ms
            )
            * 1000.0
        )

    except AttributeError:
        # Use the full flow duration as fallback
        fwd_iat_total_us = duration_us


    # Extract TCP flag statistics
    syn_count = float(
        flow.bidirectional_syn_packets
    )

    ack_count = float(
        flow.bidirectional_ack_packets
    )


    # Extract the initial forward TCP window size
    try:
        init_win_fwd = float(
            flow.src2dst_init_win
        )

    except AttributeError:
        # Use zero when NFStream does not provide the field
        init_win_fwd = 0.0


    # Extract the network protocol number
    protocol = float(
        flow.protocol
    )


    # Build the feature vector in parser.py order
    features = np.array(
        [[
            duration_us,
            flow_bytes_per_s,
            flow_packets_per_s,
            fwd_pkts,
            bwd_pkts,
            down_up_ratio,
            fwd_bytes,
            bwd_bytes,
            fwd_len_max,
            fwd_len_min,
            fwd_len_mean,
            bwd_len_mean,
            iat_mean_us,
            iat_std_us,
            fwd_iat_total_us,
            protocol,
            syn_count,
            ack_count,
            init_win_fwd
        ]],
        dtype=np.float32
    )


    # Replace invalid numeric values with zero
    features = np.nan_to_num(
        features,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    return features


# Print a section banner
def _banner(
    title,
    width=65
):
    # Print the top border
    print(
        f"\n  {'─' * width}"
    )

    # Print the section title
    print(
        f"  {title}"
    )

    # Print the bottom border
    print(
        f"  {'─' * width}"
    )


# Start the Gatekeeper IPS
def main():
    # Parse command-line arguments
    args = parse_args()

    # Get the protected network interface
    interface = args.interface

    # Set the XDP source file path
    xdp_file = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "xdp_filter.c"
    )


    # Print the application header
    print()

    print(
        "  ╔" + "═" * 63 + "╗"
    )

    print(
        "  ║   GATEKEEPER IPS  —  AI XGBoost + eBPF/XDP          ║"
    )

    print(
        f"  ║   Interface : {interface:<47}║"
    )

    print(
        "  ╚" + "═" * 63 + "╝"
    )

    print()


    # Initialize the XDP data plane
    _banner(
        "1/4  INITIALIZING DATA PLANE eBPF/XDP"
    )

    enforcer = XDPEnforcer(
        interface,
        xdp_file
    )

    # Stop startup when XDP cannot be attached
    if not enforcer.load_and_attach():
        return


    # Synchronize the whitelist
    _banner(
        "WHITELIST SYNCHRONIZATION"
    )

    enforcer.load_whitelist()


    # Initialize user-space memory and state
    _banner(
        "2/4  INITIALIZING USER-SPACE MEMORY"
    )

    print(
        "  [+] Offense History initialized "
        "TTLCache 24h"
    )

    print(
        "  [+] Memory Manager daemon started"
    )


    # Initialize the AI engine
    _banner(
        "3/4  INITIALIZING AI ENGINE XGBoost"
    )

    ai_model = load_ai_model()


    # Configure the egress traffic filter
    _banner(
        "4/4  CONFIGURING EGRESS FILTER"
    )

    local_ips = get_all_local_ips(
        interface
    )

    print(
        f"  [+] Local IPs detected: "
        f"{', '.join(sorted(local_ips))}"
    )

    print(
        "  [+] Traffic originating from these "
        "addresses will be ignored"
    )


    # Create the sliding-window packet tracker
    packet_window = TTLCache(
        maxsize=100_000,
        ttl=60
    )


    # Show that the system is ready
    print()

    print(
        "  ╔" + "═" * 63 + "╗"
    )

    print(
        "  ║   GATEKEEPER READY — MONITORING INGRESS TRAFFIC     ║"
    )

    print(
        "  ╚" + "═" * 63 + "╝"
    )

    print()

    try:
        # Create the NFStream traffic monitor
        streamer = NFStreamer(
            source=interface,
            active_timeout=1,
            idle_timeout=1,
            statistical_analysis=True
        )

        # Process each detected network flow
        for flow in streamer:
            try:
                # Ignore IPv6 traffic
                if ":" in flow.src_ip:
                    continue


                # Ignore traffic originating from local IPs
                if flow.src_ip in local_ips:
                    continue


                # Ignore IPs that are already banned
                if enforcer.is_banned(
                    flow.src_ip
                ):
                    continue


                # Get the current timestamp
                now = time.time()


                # Get SYN and total packet counts
                syn_count = (
                    flow.bidirectional_syn_packets
                )

                total_count = (
                    flow.bidirectional_packets
                )


                # Count UDP and ICMP packets separately
                if flow.protocol in (1, 17):
                    udp_icmp_count = total_count
                else:
                    udp_icmp_count = 0


                # Create a tracking entry for new source IPs
                if flow.src_ip not in packet_window:
                    packet_window[
                        flow.src_ip
                    ] = []


                # Get the packet history for this IP
                window = packet_window[
                    flow.src_ip
                ]


                # Add the current flow to the sliding window
                window.append(
                    (
                        now,
                        syn_count,
                        udp_icmp_count,
                        total_count
                    )
                )


                # Keep only entries inside the time window
                filtered = [
                    (
                        timestamp,
                        syn,
                        udp_icmp,
                        packets
                    )
                    for (
                        timestamp,
                        syn,
                        udp_icmp,
                        packets
                    ) in window
                    if now - timestamp <= WINDOW_SECONDS
                ]


                # Remove empty tracking entries
                if not filtered:
                    packet_window.pop(
                        flow.src_ip,
                        None
                    )

                    continue


                # Save the filtered sliding window
                packet_window[
                    flow.src_ip
                ] = filtered


                # Calculate total SYN traffic
                total_syn = sum(
                    syn
                    for _, syn, _, _ in filtered
                )


                # Calculate total UDP and ICMP traffic
                total_udp_icmp = sum(
                    udp_icmp
                    for _, _, udp_icmp, _ in filtered
                )


                # Calculate total packets
                total_pkts = sum(
                    packets
                    for _, _, _, packets in filtered
                )


                # ── TUYẾN 1: AI XGBoost (Trọng tâm phát hiện chính) ─────────────────────
                # Chỉ phân tích flow đủ lớn để AI có dữ liệu ý nghĩa (>= 10 packets).
                # Đây là tuyến phát hiện chính của hệ thống.
                if flow.bidirectional_packets >= 10:
                    features   = extract_features(flow)
                    prediction = ai_model.predict(features)

                    if isinstance(prediction, (list, np.ndarray)):
                        pred_val = int(prediction[0])
                    else:
                        pred_val = int(prediction)

                    if pred_val >= 1:
                        if not enforcer.is_whitelisted(flow.src_ip):
                            duration_s = max(
                                float(flow.bidirectional_duration_ms) / 1000.0,
                                1e-9
                            )

                            sig = AttackSignature(
                                src_ip       = flow.src_ip,
                                protocol     = proto_name(flow.protocol),
                                dst_port     = int(getattr(flow, "dst_port", 0)),
                                fwd_len_mean = float(getattr(flow, "src2dst_mean_ps", 0.0)),
                                pps          = float(flow.bidirectional_packets) / duration_s,
                                reason       = "AI_INFERENCE (Binary Model)",
                                features     = features[0].tolist()
                            )

                            count, ttl_secs = enforcer.block_ip(sig)

                            ttl_label = (
                                f"{ttl_secs // 3600}h"
                                if ttl_secs >= 3600
                                else f"{ttl_secs // 60}m"
                            )

                            print(
                                f"  [BLOCK] {flow.src_ip:<20} "
                                f"AI_INFERENCE (Binary) "
                                f"│ ban {ttl_label:<4} "
                                f"│ offense #{count}"
                            )

                        # Đã xử lý qua AI, không cần Rate Limiter kiểm tra lại
                        packet_window.pop(flow.src_ip, None)
                        continue

                # ── TUYẾN 2: Rate Limiter (Lưới an toàn cho bão cực lớn) ─────────────────
                # Chỉ kích hoạt khi flow quá nhỏ cho AI (< 10 packets) NHƯNG khối lượng
                # gói tin trong cửa sổ trượt vượt ngưỡng volumetric cực cao.
                # Đây là biện pháp phòng vệ cuối chống bão SYN/UDP xả chớp nhoáng.
                threshold_exceeded = (
                    total_syn      > SYN_THRESHOLD
                    or total_udp_icmp > UDP_ICMP_THRESHOLD
                    or total_pkts  > TOTAL_THRESHOLD
                )

                if threshold_exceeded:
                    if not enforcer.is_whitelisted(flow.src_ip):
                        rule_reason = "RATE_LIMIT (Volumetric)"
                        rl_features = extract_features(flow)

                        sig = AttackSignature(
                            src_ip       = flow.src_ip,
                            protocol     = proto_name(flow.protocol),
                            dst_port     = int(getattr(flow, "dst_port", 0)),
                            fwd_len_mean = float(getattr(flow, "src2dst_mean_ps", 0.0)),
                            pps          = total_pkts / WINDOW_SECONDS,
                            reason       = rule_reason,
                            features     = rl_features[0].tolist() if rl_features is not None else None
                        )

                        count, ttl_secs = enforcer.block_ip(sig)

                        packet_window.pop(flow.src_ip, None)

                        ttl_label = (
                            f"{ttl_secs // 3600}h"
                            if ttl_secs >= 3600
                            else f"{ttl_secs // 60}m"
                        )

                        print(
                            f"  [BLOCK] {flow.src_ip:<20} "
                            f"{rule_reason:<20} "
                            f"│ ban {ttl_label:<4} "
                            f"│ offense #{count}"
                        )


            # Handle errors from individual flows
            except Exception as flow_err:
                print(
                    f"  [-] Flow error "
                    f"({flow.src_ip}): {flow_err}"
                )


    # Handle manual shutdown
    except KeyboardInterrupt:
        print(
            "\n  [~] Ctrl+C received "
            "— cleaning up..."
        )


    # Handle unrecoverable runtime errors
    except Exception as exc:
        print(
            f"\n  [✗] Fatal error: {exc}"
        )


    # Always detach XDP before exiting
    finally:
        try:
            from gcs_utility import get_collector
            get_collector().stop()
        except Exception as e:
            print(f"  [-] Lỗi dừng GCS collector: {e}")

        enforcer.detach()


# Start the Gatekeeper application
if __name__ == "__main__":
    main()