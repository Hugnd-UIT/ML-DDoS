import csv
import io
import os
import threading
import time
from collections import Counter

try:
    from google.cloud import storage as gcs
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    print("[-] google-cloud-storage not installed. GCS upload skipped.")

# Cấu hình GCS bucket và thư mục log
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME", "")
GCS_LOG_PREFIX = os.environ.get("GCS_LOG_PREFIX", "ddos-logs/")
GCS_FLUSH_INTERVAL = int(os.environ.get("GCS_FLUSH_INTERVAL", "300"))
MAX_ROWS_PER_FILE = 100_000
LOCAL_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs", "dirty_flows")

CSV_FIELDNAMES = [
    "timestamp", "src_ip", "dst_ip", "protocol", "dst_port",
    "pps", "fwd_len_mean", "reason", "signature_key", "blocked_at_epoch",
]

class DirtyFlowEvent:
    # Đối tượng lưu trữ thông tin của một flow độc hại
    def __init__(self, src_ip, dst_ip, protocol, dst_port, pps, fwd_len_mean, reason, signature_key, blocked_at):
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.pps = pps
        self.fwd_len_mean = fwd_len_mean
        self.reason = reason
        self.signature_key = signature_key
        self.blocked_at_epoch = blocked_at or time.time()
        
    def to_row(self):
        return self.__dict__

def upload_to_gcs(csv_content, gcs_path):
    # Đẩy dữ liệu file CSV lên Google Cloud Storage
    if not GCS_AVAILABLE or not GCS_BUCKET_NAME:
        print("[-] GCS upload skipped - missing SDK or config")
        return False
    try:
        client = gcs.Client()
        bucket = client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(gcs_path)
        blob.upload_from_string(csv_content.encode("utf-8"), content_type="text/csv")
        print(f"[+] Uploaded to GCS: gs://{GCS_BUCKET_NAME}/{gcs_path}")
        return True
    except Exception as e:
        print(f"[-] GCS upload error: {e}")
        return False

def save_local_backup(csv_content, filename):
    # Lưu file CSV dự phòng vào thư mục logs máy ảo
    os.makedirs(LOCAL_LOG_DIR, exist_ok=True)
    path = os.path.join(LOCAL_LOG_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_content)
        print(f"[+] Saved local backup: {path}")
    except Exception as e:
        print(f"[-] Local backup error: {e}")
    return path

class DirtyFlowCollector:
    # Thu thập luồng độc hại vào bộ nhớ và đẩy lên GCS mỗi chu kỳ
    def __init__(self):
        self.buffer = []
        self.lock = threading.Lock()
        self.running = False
        self.window_blocked = 0
        self.window_ips = Counter()

    def start(self):
        # Bắt đầu luồng chạy ngầm đẩy dữ liệu định kỳ
        if self.running: 
            return
        self.running = True
        threading.Thread(target=self.flush_loop, daemon=True).start()
        print(f"[*] Collector started - interval: {GCS_FLUSH_INTERVAL}s")

    def stop(self):
        # Dừng luồng đẩy dữ liệu
        self.running = False
        print("[*] Stopping collector and flushing data...")
        self.do_flush()

    def record_from_signature(self, sig, dst_ip=""):
        # Ghi nhận IP bị khóa từ chữ ký tấn công
        batch = None
        with self.lock:
            event = DirtyFlowEvent(
                sig.src_ip, dst_ip, sig.protocol, sig.dst_port,
                sig.pps, sig.fwd_len_mean, sig.reason, sig.signature_key, time.time()
            )
            self.buffer.append(event)
            self.window_blocked += 1
            self.window_ips[event.src_ip] += 1
            if len(self.buffer) >= MAX_ROWS_PER_FILE:
                print(f"[!] Buffer full, flushing {len(self.buffer)} rows.")
                batch = self.buffer[:]
                self.buffer.clear()
        
        if batch is not None:
            self.flush_batch(batch)

    def flush_loop(self):
        # Vòng lặp ngủ đông và tự động đẩy dữ liệu
        while self.running:
            time.sleep(GCS_FLUSH_INTERVAL)
            if self.running:
                self.do_flush()

    def do_flush(self):
        # Thu thập các IP bị chặn và tiến hành flush batch
        with self.lock:
            if not self.buffer: 
                return
            batch = self.buffer[:]
            self.buffer.clear()
            w_blocked = self.window_blocked
            top = self.window_ips.most_common(5)
            self.window_blocked = 0
            self.window_ips.clear()

        self.flush_batch(batch)
        if w_blocked > 0:
            try:
                import notifier
                notifier.send_digest_alert(w_blocked, top, f"{GCS_FLUSH_INTERVAL//60} phut")
            except Exception as e:
                print(f"[-] Digest alert error: {e}")

    def flush_batch(self, batch):
        # Tạo file CSV từ buffer hiện tại và đẩy lên GCS
        filename = f"dirty_flows_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.csv"
        gcs_path = f"{GCS_LOG_PREFIX}{filename}"
        
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for evt in batch:
            writer.writerow(evt.to_row())
            
        content = out.getvalue()
        print(f"[*] Flushing {len(batch)} rows...")
        if not upload_to_gcs(content, gcs_path):
            save_local_backup(content, filename)

collector_instance = None
def get_collector():
    # Lấy instance duy nhất của collector
    global collector_instance
    if collector_instance is None:
        collector_instance = DirtyFlowCollector()
        collector_instance.start()
    return collector_instance
