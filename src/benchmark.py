import argparse
import json
import os
import socket
import struct
import subprocess
import time


# Check whether the requests library is available
try:
    import requests

    REQUESTS_AVAILABLE = True

except ImportError:
    REQUESTS_AVAILABLE = False


# Check whether the Google Cloud Storage SDK is available
try:
    from google.cloud import storage as gcs

    GCS_AVAILABLE = True

except ImportError:
    GCS_AVAILABLE = False


# Load environment configuration
TG_BOT_TOKEN = os.environ.get(
    "TG_BOT_TOKEN",
    ""
)

TG_CHAT_ID = os.environ.get(
    "TG_CHAT_ID",
    ""
)

GCS_BUCKET_NAME = os.environ.get(
    "GCS_BUCKET_NAME",
    ""
)

GCS_LOG_PREFIX = os.environ.get(
    "GCS_LOG_PREFIX",
    "ddos-logs/"
)


# Read SoftIRQ statistics from proc stat
def read_softirq(cpu="cpu"):
    # Read CPU statistics from proc stat
    try:
        with open("/proc/stat") as f:
            # Find the requested CPU line
            for line in f:
                if line.startswith(cpu):
                    # Split the CPU statistics
                    parts = line.split()

                    # Make sure enough values are available
                    while len(parts) < 11:
                        parts.append("0")

                    # Convert CPU values to integers
                    vals = [
                        int(value)
                        for value in parts[1:10]
                    ]

                    # Return total CPU time and SoftIRQ time
                    return sum(vals), vals[6]

    except FileNotFoundError:
        return None, None

    return None, None


# Measure SoftIRQ usage over a period of time
def check_softirq(duration=30):
    # Show monitoring information
    print(
        f"\n[*] Monitoring SoftIRQ for {duration}s..."
    )

    # Read initial SoftIRQ statistics
    tot1, siq1 = read_softirq()

    # Stop if proc stat is unavailable
    if tot1 is None:
        print(
            "[-] Error: /proc/stat not found - requires Linux"
        )
        return

    # Wait before taking the second measurement
    time.sleep(duration)

    # Read final SoftIRQ statistics
    tot2, siq2 = read_softirq()

    # Calculate CPU and SoftIRQ differences
    dtot = tot2 - tot1
    dsiq = siq2 - siq1

    # Calculate SoftIRQ percentage
    if dtot > 0:
        pct = (dsiq / dtot) * 100

        # Show SoftIRQ usage
        print(
            f"[*] Avg SoftIRQ: {pct:.2f}%"
        )

        # Check the SoftIRQ threshold
        if pct < 10:
            print(
                "[+] VERDICT: PASS - <10%"
            )

        else:
            print(
                "[-] VERDICT: FAIL - >=10%"
            )


# Check the BPF blacklist map
def check_bpfmap(map_name="blacklist_map"):
    # Show the BPF map being checked
    print(
        f"\n[*] Dumping BPF Map: {map_name}..."
    )

    # Run bpftool and read the map contents
    try:
        res = subprocess.run(
            [
                "bpftool",
                "map",
                "dump",
                "name",
                map_name,
                "--json"
            ],
            capture_output=True,
            text=True
        )

        # Process the BPF map when the command succeeds
        if res.returncode == 0:
            # Parse bpftool JSON output
            data = json.loads(
                res.stdout
            )

            # Show the number of blocked IPs
            print(
                f"[*] Found {len(data)} blocked IPs"
            )

            # Show up to ten blocked IPs
            for i, entry in enumerate(
                data[:10]
            ):
                # Extract the IP value from the BPF key
                val = entry.get(
                    "key",
                    {}
                ).get(
                    "value",
                    0
                )

                # Convert the integer value to an IPv4 address
                ip = socket.inet_ntoa(
                    struct.pack(
                        "I",
                        val
                    )
                )

                # Show the blocked IP
                print(
                    f"  {i + 1}. {ip}"
                )

            # Show when more than ten IPs are blocked
            if len(data) > 10:
                print(
                    "  ..."
                )

            # Check whether the map contains blocked IPs
            if len(data) > 0:
                print(
                    "[+] VERDICT: PASS"
                )

            else:
                print(
                    "[-] VERDICT: EMPTY"
                )

        else:
            print(
                "[-] bpftool error or map not found"
            )

    except Exception as e:
        # Show errors while parsing bpftool output
        print(
            f"[-] Error parsing bpftool output: {e}"
        )


# Test Telegram API latency
def check_latency(probes=5):
    # Show latency test information
    print(
        f"\n[*] Testing Telegram Latency - {probes} probes..."
    )

    # Skip the test when required dependencies are missing
    if not REQUESTS_AVAILABLE or not TG_BOT_TOKEN:
        print(
            "[-] Skipping: missing requests library "
            "or TG_BOT_TOKEN"
        )
        return

    # Build the Telegram API endpoint
    url = (
        f"https://api.telegram.org/bot"
        f"{TG_BOT_TOKEN}/sendMessage"
    )

    # Build the Telegram test payload
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": "[BENCHMARK] Latency test"
    }

    # Store successful latency measurements
    lats = []

    # Run the requested number of latency probes
    for i in range(probes):
        # Start the latency timer
        t0 = time.time()

        try:
            # Send the Telegram request
            r = requests.post(
                url,
                json=payload,
                timeout=5
            )

            # Stop the latency timer
            t1 = time.time()

            # Store successful latency results
            if r.status_code == 200:
                lats.append(
                    (t1 - t0) * 1000
                )

                print(
                    f"  Probe {i + 1}: "
                    f"{lats[-1]:.1f} ms"
                )

            else:
                print(
                    f"  Probe {i + 1}: "
                    f"HTTP {r.status_code}"
                )

        except Exception as e:
            # Show failed probe information
            print(
                f"  Probe {i + 1}: Failed - {e}"
            )

    # Calculate the average latency
    if lats:
        avg = sum(lats) / len(lats)

        # Show average latency
        print(
            f"[*] Avg Latency: {avg:.1f} ms"
        )

        # Check the latency threshold
        if avg < 1000:
            print(
                "[+] VERDICT: PASS - <1000ms"
            )

        else:
            print(
                "[-] VERDICT: FAIL"
            )


# Check whether logs have been uploaded to GCS
def check_gcs():
    # Show the GCS bucket being checked
    print(
        f"\n[*] Checking GCS Bucket: {GCS_BUCKET_NAME}..."
    )

    # Skip the check when required dependencies are missing
    if not GCS_AVAILABLE or not GCS_BUCKET_NAME:
        print(
            "[-] Skipping: missing google-cloud-storage SDK "
            "or GCS_BUCKET_NAME"
        )
        return

    # Connect to Google Cloud Storage
    try:
        client = gcs.Client()

        # Get logs from the configured prefix
        blobs = list(
            client.list_blobs(
                GCS_BUCKET_NAME,
                prefix=GCS_LOG_PREFIX
            )
        )

        # Process available logs
        if blobs:
            # Find the most recently updated log
            latest = sorted(
                blobs,
                key=lambda blob: blob.updated
            )[-1]

            # Calculate log age in minutes
            age = (
                time.time()
                - latest.updated.timestamp()
            ) / 60

            # Show latest log information
            print(
                f"[*] Latest log: "
                f"{latest.name} - "
                f"{latest.size} bytes"
            )

            print(
                f"[*] Age: {age:.1f} mins"
            )

            # Check whether the latest log is recent
            if age < 15:
                print(
                    "[+] VERDICT: PASS"
                )

            else:
                print(
                    "[-] VERDICT: FAIL - file too old"
                )

        else:
            print(
                "[-] No logs found"
            )

    except Exception as e:
        # Show GCS communication errors
        print(
            f"[-] Error communicating with GCS: {e}"
        )


# Run all benchmark checks
def main():
    # Show benchmark header
    print(
        "=" * 60
    )

    print(
        " XDP BENCHMARK TOOL"
    )

    print(
        "=" * 60
    )

    # Create command-line argument parser
    parser = argparse.ArgumentParser()

    # Add option for running the full benchmark
    parser.add_argument(
        "--all",
        action="store_true"
    )

    # Read command-line arguments
    args = parser.parse_args()

    # Run SoftIRQ check
    check_softirq(
        duration=5 if not args.all else 30
    )

    # Check BPF blacklist map
    check_bpfmap()

    # Check Telegram API latency
    check_latency()

    # Check GCS logs
    check_gcs()

    # Show completion message
    print(
        "\n" + "=" * 60
    )

    print(
        "[+] FINISH!"
    )

    print(
        "=" * 60
    )


# Start the benchmark program
if __name__ == "__main__":
    main()