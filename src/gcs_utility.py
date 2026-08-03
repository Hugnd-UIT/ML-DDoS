import csv
import io
import os
import threading
import time
from collections import Counter


# Check whether Google Cloud Storage is available
try:
    from google.cloud import storage as gcs

    GCS_AVAILABLE = True

except ImportError:
    GCS_AVAILABLE = False

    print(
        "[-] google-cloud-storage not installed. "
        "GCS upload skipped."
    )


# Configure the GCS bucket and log directory
GCS_BUCKET_NAME = os.environ.get(
    "GCS_BUCKET_NAME",
    ""
)

GCS_LOG_PREFIX = os.environ.get(
    "GCS_LOG_PREFIX",
    "ddos-logs/"
)

GCS_FLUSH_INTERVAL = int(
    os.environ.get(
        "GCS_FLUSH_INTERVAL",
        "300"
    )
)


# Configure local storage limits
MAX_ROWS_PER_FILE = 100_000

LOCAL_LOG_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "dirty_flows"
)


# Define metadata fields for administrators
METADATA_FIELDNAMES = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "dst_port",
    "pps",
    "fwd_len_mean",
    "reason",
    "signature_key",
    "blocked_at_epoch"
]


# Define the 19 AI feature fields
FEATURE_FIELDNAMES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Down/Up Ratio",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Total",
    "Protocol",
    "SYN Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward"
]


# Combine metadata and AI feature columns
CSV_FIELDNAMES = (
    METADATA_FIELDNAMES
    + FEATURE_FIELDNAMES
)


# Store information about a malicious network flow
class DirtyFlowEvent:

    # Create a new malicious flow event
    def __init__(
        self,
        src_ip,
        dst_ip,
        protocol,
        dst_port,
        pps,
        fwd_len_mean,
        reason,
        signature_key,
        blocked_at,
        features=None
    ):
        # Store the event timestamp in UTC
        self.timestamp = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(
                time.time()
            )
        )

        # Store basic flow metadata
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.pps = pps
        self.fwd_len_mean = fwd_len_mean

        # Store detection information
        self.reason = reason
        self.signature_key = signature_key

        # Store the block timestamp
        self.blocked_at_epoch = (
            blocked_at
            or time.time()
        )


        # Store the 19 AI features when available
        if (
            features is not None
            and len(features)
            == len(FEATURE_FIELDNAMES)
        ):
            for col_name, value in zip(
                FEATURE_FIELDNAMES,
                features
            ):
                setattr(
                    self,
                    col_name,
                    value
                )


    # Convert the event into a CSV-compatible dictionary
    def to_row(self):
        return self.__dict__


# Upload CSV content to Google Cloud Storage
def upload_to_gcs(
    csv_content,
    gcs_path
):
    # Skip upload when GCS is not configured
    if (
        not GCS_AVAILABLE
        or not GCS_BUCKET_NAME
    ):
        print(
            "[-] GCS upload skipped - "
            "missing SDK or configuration"
        )

        return False


    # Upload the generated CSV file
    try:
        client = gcs.Client()

        bucket = client.bucket(
            GCS_BUCKET_NAME
        )

        blob = bucket.blob(
            gcs_path
        )


        # Upload the CSV content as UTF-8 text
        blob.upload_from_string(
            csv_content.encode("utf-8"),
            content_type="text/csv"
        )


        # Show the uploaded GCS path
        print(
            f"[+] Uploaded to GCS: "
            f"gs://{GCS_BUCKET_NAME}/"
            f"{gcs_path}"
        )

        return True


    # Handle GCS upload failures
    except Exception as exc:
        print(
            f"[-] GCS upload error: {exc}"
        )

        return False


# Save CSV content as a local backup
def save_local_backup(
    csv_content,
    filename
):
    # Create the local log directory when needed
    os.makedirs(
        LOCAL_LOG_DIR,
        exist_ok=True
    )

    # Build the local output path
    path = os.path.join(
        LOCAL_LOG_DIR,
        filename
    )


    # Write the CSV backup to disk
    try:
        with open(
            path,
            "w",
            encoding="utf-8",
            newline=""
        ) as file:
            file.write(
                csv_content
            )


        # Show the local backup path
        print(
            f"[+] Saved local backup: "
            f"{path}"
        )


    # Handle local file errors
    except Exception as exc:
        print(
            f"[-] Local backup error: {exc}"
        )


    return path


# Collect malicious flows and periodically upload them
class DirtyFlowCollector:

    # Initialize the collector state
    def __init__(self):
        self.buffer = []
        self.lock = threading.Lock()
        self.running = False

        self.window_blocked = 0
        self.window_ips = Counter()


    # Start the background flush thread
    def start(self):
        # Avoid starting the collector more than once
        if self.running:
            return

        self.running = True

        threading.Thread(
            target=self.flush_loop,
            daemon=True
        ).start()

        print(
            f"[*] Collector started - "
            f"interval: {GCS_FLUSH_INTERVAL}s"
        )


    # Stop the collector and flush remaining data
    def stop(self):
        self.running = False

        print(
            "[*] Stopping collector "
            "and flushing data..."
        )

        self.do_flush()


    # Record a blocked IP from an attack signature
    def record_from_signature(
        self,
        sig,
        dst_ip="",
        features=None
    ):
        batch = None

        # Protect the shared buffer from concurrent access
        with self.lock:
            event = DirtyFlowEvent(
                src_ip=sig.src_ip,
                dst_ip=dst_ip,
                protocol=sig.protocol,
                dst_port=sig.dst_port,
                pps=sig.pps,
                fwd_len_mean=sig.fwd_len_mean,
                reason=sig.reason,
                signature_key=sig.signature_key,
                blocked_at=time.time(),
                features=features
            )

            # Add the event to the memory buffer
            self.buffer.append(
                event
            )

            # Update the current statistics
            self.window_blocked += 1

            self.window_ips[
                event.src_ip
            ] += 1


            # Flush immediately when the buffer reaches its limit
            if len(self.buffer) >= MAX_ROWS_PER_FILE:
                print(
                    f"[!] Buffer full, "
                    f"flushing {len(self.buffer)} rows."
                )

                batch = self.buffer[:]

                self.buffer.clear()


        # Flush outside the lock
        if batch is not None:
            self.flush_batch(
                batch
            )


    # Run the periodic background flush loop
    def flush_loop(self):
        while self.running:
            # Wait until the next flush interval
            time.sleep(
                GCS_FLUSH_INTERVAL
            )

            # Flush only when the collector is still active
            if self.running:
                self.do_flush()


    # Flush the current buffer and send a digest alert
    def do_flush(self):
        # Safely extract the current batch
        with self.lock:
            if not self.buffer:
                return

            batch = self.buffer[:]

            self.buffer.clear()


            # Capture statistics for the current window
            window_blocked = (
                self.window_blocked
            )

            top_ips = (
                self.window_ips
                .most_common(5)
            )


            # Reset the current statistics
            self.window_blocked = 0
            self.window_ips.clear()


        # Upload the collected batch
        self.flush_batch(
            batch
        )


    # Convert a batch of events into CSV and upload it
    def flush_batch(
        self,
        batch
    ):
        # Generate a timestamped CSV filename
        timestamp = time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime()
        )

        filename = (
            f"dirty_flows_{timestamp}.csv"
        )


        # Build the destination GCS path
        gcs_path = (
            f"{GCS_LOG_PREFIX}"
            f"{filename}"
        )


        # Create an in-memory CSV buffer
        output = io.StringIO()

        writer = csv.DictWriter(
            output,
            fieldnames=CSV_FIELDNAMES,
            extrasaction="ignore"
        )


        # Write the CSV header
        writer.writeheader()


        # Write every collected event
        for event in batch:
            writer.writerow(
                event.to_row()
            )


        # Get the generated CSV content
        content = output.getvalue()

        print(
            f"[*] Flushing {len(batch)} rows..."
        )


        # Upload to GCS and use local backup on failure
        if not upload_to_gcs(
            content,
            gcs_path
        ):
            save_local_backup(
                content,
                filename
            )


# Store the global collector instance
collector_instance = None


# Return the shared collector instance
def get_collector():
    global collector_instance

    # Create and start the collector when needed
    if collector_instance is None:
        collector_instance = (
            DirtyFlowCollector()
        )

        collector_instance.start()

    return collector_instance


# Convenience wrapper for logging attack events to GCS
def log_attack(sig):
    collector = get_collector()
    features = getattr(sig, "features", None)
    collector.record_from_signature(sig, features=features)
