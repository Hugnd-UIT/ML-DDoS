import argparse
import json
import os
import subprocess
import time
import socket
import struct

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from google.cloud import storage as gcs
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

# Cấu hình môi trường
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME", "")
GCS_LOG_PREFIX = os.environ.get("GCS_LOG_PREFIX", "ddos-logs/")

def read_softirq(cpu="cpu"):
    # Đọc thông số SoftIRQ từ proc stat
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith(cpu):
                    parts = line.split()
                    while len(parts) < 11: 
                        parts.append("0")
                    vals = [int(x) for x in parts[1:10]]
                    return sum(vals), vals[6] 
    except FileNotFoundError:
        return None, None
    return None, None

def check_softirq(duration=30):
    # Đo lường SoftIRQ trong một khoảng thời gian
    print(f"\n[*] Monitoring SoftIRQ for {duration}s...")
    tot1, siq1 = read_softirq()
    
    if tot1 is None:
        print("[-] Error: /proc/stat not found - requires Linux")
        return
        
    time.sleep(duration)
    tot2, siq2 = read_softirq()
    
    dtot = tot2 - tot1
    dsiq = siq2 - siq1
    
    if dtot > 0:
        pct = (dsiq / dtot) * 100
        print(f"[*] Avg SoftIRQ: {pct:.2f}%")
        if pct < 10: 
            print("[+] VERDICT: PASS - <10%")
        else: 
            print("[-] VERDICT: FAIL - >=10%")

def check_bpfmap(map_name="blacklist_map"):
    # Kiểm tra BPF Map bằng bpftool
    print(f"\n[*] Dumping BPF Map: {map_name}...")
    try:
        res = subprocess.run(["bpftool", "map", "dump", "name", map_name, "--json"], capture_output=True, text=True)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            print(f"[*] Found {len(data)} blocked IPs")
            for i, entry in enumerate(data[:10]):
                val = entry.get('key', {}).get('value', 0)
                ip = socket.inet_ntoa(struct.pack("I", val))
                print(f"  {i+1}. {ip}")
            if len(data) > 10: 
                print("  ...")
            
            if len(data) > 0:
                print("[+] VERDICT: PASS")
            else:
                print("[-] VERDICT: EMPTY")
        else:
            print("[-] bpftool error or map not found")
    except Exception as e:
        print(f"[-] Error parsing bpftool output: {e}")

def check_latency(probes=5):
    # Kiểm tra độ trễ của Telegram API
    print(f"\n[*] Testing Telegram Latency - {probes} probes...")
    if not REQUESTS_AVAILABLE or not TG_BOT_TOKEN:
        print("[-] Skipping: missing requests library or TG_BOT_TOKEN")
        return
        
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": "[BENCHMARK] Latency test"}
    lats = []
    
    for i in range(probes):
        t0 = time.time()
        try:
            r = requests.post(url, json=payload, timeout=5)
            t1 = time.time()
            if r.status_code == 200:
                lats.append((t1-t0)*1000)
                print(f"  Probe {i+1}: {lats[-1]:.1f} ms")
            else:
                print(f"  Probe {i+1}: HTTP {r.status_code}")
        except Exception as e:
            print(f"  Probe {i+1}: Failed - {e}")
            
    if lats:
        avg = sum(lats) / len(lats)
        print(f"[*] Avg Latency: {avg:.1f} ms")
        if avg < 1000: 
            print("[+] VERDICT: PASS - <1000ms")
        else: 
            print("[-] VERDICT: FAIL")

def check_gcs():
    # Kiểm tra logs đã được upload lên GCS chưa
    print(f"\n[*] Checking GCS Bucket: {GCS_BUCKET_NAME}...")
    if not GCS_AVAILABLE or not GCS_BUCKET_NAME:
        print("[-] Skipping: missing google-cloud-storage SDK or GCS_BUCKET_NAME")
        return
        
    try:
        client = gcs.Client()
        blobs = list(client.list_blobs(GCS_BUCKET_NAME, prefix=GCS_LOG_PREFIX))
        if blobs:
            latest = sorted(blobs, key=lambda b: b.updated)[-1]
            age = (time.time() - latest.updated.timestamp()) / 60
            print(f"[*] Latest log: {latest.name} - {latest.size} bytes")
            print(f"[*] Age: {age:.1f} mins")
            
            if age < 15: 
                print("[+] VERDICT: PASS")
            else: 
                print("[-] VERDICT: FAIL - file too old")
        else:
            print("[-] No logs found")
    except Exception as e:
        print(f"[-] Error communicating with GCS: {e}")

def main():
    print("="*60)
    print(" XDP BENCHMARK TOOL")
    print("="*60)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    
    check_softirq(duration=5 if not args.all else 30)
    check_bpfmap()
    check_latency()
    check_gcs()
    
    print("\n" + "="*60)
    print("[+] FINISH!")
    print("="*60)

if __name__ == "__main__":
    main()
