import csv
import io
import os
import threading
import time
import uuid

from features import FEATURE_NAMES


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
        "60"
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


# Define metadata fields for administrators.
#
# has_features cho biết dòng này CÓ vector đặc trưng hợp lệ hay không. Tuyến
# rate limiter có thể chặn một flow quá nhỏ để mô tả (features=None), và khi
# đó DictWriter ghi ô rỗng. Nếu dashboard cứ fillna(0) rồi đưa vào model thì
# nó vẫn trả về một nhãn nào đó — tức là bịa ra loại tấn công. Cột này để
# app.py phân biệt được hai trường hợp.
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
    "blocked_at_epoch",
    "has_features"
]


# AI feature columns, shared with the training pipeline and the extractor
FEATURE_FIELDNAMES = list(FEATURE_NAMES)


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


        # Store the AI feature vector when available
        has_features = (
            features is not None
            and len(features) == len(FEATURE_FIELDNAMES)
        )

        self.has_features = int(has_features)

        if has_features:
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
        self._stop_event = threading.Event()


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
        self._stop_event.set()

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

            # Flush immediately when the buffer reaches its limit
            if len(self.buffer) >= MAX_ROWS_PER_FILE:
                print(
                    f"[!] Buffer full, "
                    f"flushing {len(self.buffer)} rows."
                )

                batch = self.buffer[:]

                self.buffer.clear()


        # Flush ngoài lock VÀ ngoài luồng gọi.
        #
        # record_from_signature() được enforcer.block_ip() gọi đồng bộ ngay
        # trong vòng bắt gói của gatekeeper. Nếu upload GCS chạy tại chỗ thì
        # một lần flush chậm (100 000 dòng, mạng kém) sẽ treo toàn bộ khâu
        # phát hiện tấn công.
        if batch is not None:
            threading.Thread(
                target=self.flush_batch,
                args=(batch,),
                daemon=True,
                name="gcs-flush"
            ).start()


    # Run the periodic background flush loop
    def flush_loop(self):
        while self.running:
            # Wait until the next flush interval, nhưng tỉnh dậy ngay khi
            # stop() được gọi thay vì ngủ hết chu kỳ
            self._stop_event.wait(GCS_FLUSH_INTERVAL)

            # Flush only when the collector is still active
            if self.running:
                self.do_flush()


    # Flush the current buffer
    def do_flush(self):
        # Safely extract the current batch
        with self.lock:
            if not self.buffer:
                return

            batch = self.buffer[:]

            self.buffer.clear()

        # Upload the collected batch
        self.flush_batch(
            batch
        )


    # Convert a batch of events into CSV and upload it
    def flush_batch(
        self,
        batch
    ):
        # Generate a timestamped CSV filename.
        #
        # Hậu tố ngẫu nhiên là bắt buộc: tên file cũ chỉ có độ phân giải giây,
        # nên một lần flush theo chu kỳ trùng giây với một lần flush do đầy
        # buffer sẽ GHI ĐÈ lên nhau trên GCS và mất trắng một lô log.
        timestamp = time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime()
        )

        filename = (
            f"dirty_flows_{timestamp}_{uuid.uuid4().hex[:8]}.csv"
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

# Bảo vệ khâu khởi tạo singleton. Không có lock thì hai luồng cùng gọi
# get_collector() lần đầu sẽ tạo ra HAI collector, mỗi cái một buffer và một
# luồng flush riêng — log bị chia đôi ngẫu nhiên giữa hai cái.
_collector_lock = threading.Lock()


# Return the shared collector instance
def get_collector():
    global collector_instance

    if collector_instance is not None:
        return collector_instance

    with _collector_lock:
        # Kiểm tra lại bên trong lock (double-checked locking)
        if collector_instance is None:
            instance = DirtyFlowCollector()
            instance.start()

            collector_instance = instance

    return collector_instance


# Convenience wrapper for logging attack events to GCS
def log_attack(sig):
    collector = get_collector()
    features = getattr(sig, "features", None)
    collector.record_from_signature(sig, features=features)
