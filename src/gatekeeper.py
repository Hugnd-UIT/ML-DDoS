import os
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib
import time
from enforcer import TokenBucketEnforcer

try:
    from nfstream import NFStreamer
except ImportError:
    print("[!] 'nfstream' library not found. Please install it: pip install nfstream")
    NFStreamer = None

warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
warnings.filterwarnings("ignore", category=FutureWarning)

# Sau tung nay giay, cho phep bao dong lai cho cung 1 rule (thay vi im
# lang vinh vien sau lan bao dau tien)
ALERT_COOLDOWN_SECONDS = 300  # 5 phut

# Neu so luong flow can chay qua pipeline ML trong 1 giay vuot qua muc
# nay, he thong tam thoi bo qua buoc tinh feature + model.predict (ton
# CPU nhat) va coi nhu nghi ngo mac dinh, de tranh chinh he thong phong
# thu tu ha guc CPU cua no truoc khi kip phan loai (self-DoS).
MAX_ML_FLOWS_PER_SECOND = 200

def get_args():
    parser = argparse.ArgumentParser(description="Gatekeeper - Inline IPS System using ML and nfstream")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on (default: eth0)")
    parser.add_argument("-m", "--model", default="./models/binary.pkl", help="Path to the trained XGBoost model")
    return parser.parse_args()

def map_nfstream_to_cic(flow):
    duration_ms = getattr(flow, 'bidirectional_duration_ms', 0)
    duration_s = duration_ms / 1000.0 if duration_ms > 0 else 0.001
    
    src2dst_bytes = getattr(flow, 'src2dst_bytes', 0)
    dst2src_bytes = getattr(flow, 'dst2src_bytes', 0)
    
    features = {
        'Flow Duration': duration_ms * 1000,
        'Flow Bytes/s': getattr(flow, 'bidirectional_bytes', 0) / duration_s,
        'Flow Packets/s': getattr(flow, 'bidirectional_packets', 0) / duration_s,
        'Total Fwd Packets': getattr(flow, 'src2dst_packets', 0),
        'Total Backward Packets': getattr(flow, 'dst2src_packets', 0),
        'Down/Up Ratio': dst2src_bytes / src2dst_bytes if src2dst_bytes > 0 else 0,
        'Total Length of Fwd Packets': src2dst_bytes,
        'Total Length of Bwd Packets': dst2src_bytes,
        'Fwd Packet Length Max': getattr(flow, 'src2dst_max_ps', 0),
        'Fwd Packet Length Min': getattr(flow, 'src2dst_min_ps', 0),
        'Fwd Packet Length Mean': getattr(flow, 'src2dst_mean_ps', 0),
        'Bwd Packet Length Mean': getattr(flow, 'dst2src_mean_ps', 0),
        'Flow IAT Mean': getattr(flow, 'bidirectional_mean_piat_ms', 0) * 1000,
        'Flow IAT Std': getattr(flow, 'bidirectional_stddev_piat_ms', 0) * 1000,
        'Fwd IAT Total': getattr(flow, 'src2dst_duration_ms', 0) * 1000,
        'Protocol': getattr(flow, 'protocol', 0),
        'SYN Flag Count': getattr(flow, 'bidirectional_syn_packets', 0),
        'ACK Flag Count': getattr(flow, 'bidirectional_ack_packets', 0),
        'Init_Win_bytes_forward': getattr(flow, 'src2dst_init_win_bytes', 0)
    }
    
    feature_columns = [
        'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets', 
        'Total Backward Packets', 'Down/Up Ratio', 'Total Length of Fwd Packets', 
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow IAT Mean', 'Flow IAT Std', 
        'Fwd IAT Total', 'Protocol', 'SYN Flag Count', 'ACK Flag Count', 'Init_Win_bytes_forward'
    ]
    
    df = pd.DataFrame([features], columns=feature_columns)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    return df

def print_banner():
    banner = """
   _____       _       _                     
  / ____|     | |     | |                    
 | |  __  __ _| |_ ___| | _____  ___ _ __   ___ _ __ 
 | | |_ |/ _` | __/ _ \ |/ / _ \/ _ \ '_ \ / _ \ '__|
 | |__| | (_| | ||  __/   <  __/  __/ |_) |  __/ |   
  \_____|\__,_|\__\___|_|\_\___|\___| .__/ \___|_|   
                                    | |              
                                    |_|              
======================================================
    Inline IPS eBPF - Realtime DDoS Detection Engine
======================================================
    """
    print(banner)

def main():
    print_banner()
    args = get_args()
    
    model_path = args.model
    try:
        print(f"[*] Loading model from: {model_path} ...")
        if not os.path.exists(model_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            alt_path = os.path.join(base_dir, '..', 'models', 'binary.pkl')
            if os.path.exists(alt_path):
                model_path = alt_path
            
        model = joblib.load(model_path)
        print("[+] Model loaded successfully!")
    except Exception as e:
        print(f"[-] Critical Error: Could not load the ML model. Reason: {e}")
        return

    if NFStreamer is None:
        return

    print(f"[*] Initializing NFStreamer on interface '{args.interface}' ...")
    print("[*] Gatekeeper is listening for traffic. Press Ctrl+C to stop.\n")
    
    blocked_rules = {}  # rule_key -> thoi diem canh bao gan nhat (time.time())
    enforcer = TokenBucketEnforcer(max_pps_threshold=100.0, burst_capacity=150.0)
    start_time = time.time()

    # Trang thai cho circuit breaker chong self-DoS CPU
    ml_window_start = time.time()
    ml_flows_in_window = 0
    try:
        streamer = NFStreamer(source=args.interface, active_timeout=1, idle_timeout=1, statistical_analysis=True)
        for flow in streamer:
            # --- Circuit breaker chong self-DoS CPU ---
            # Neu so flow/giay dang can ML xu ly vuot qua nguong an toan,
            # bo qua buoc tinh feature (map_nfstream_to_cic) + model.predict
            # (2 buoc ton CPU nhat) va coi flow do la nghi ngo mac dinh
            # (fail-safe: tha cho Token Bucket xu ly tiep, khong de ML
            # inference lam nghen CPU cua chinh he thong phong thu).
            now_ml = time.time()
            if now_ml - ml_window_start >= 1.0:
                ml_window_start = now_ml
                ml_flows_in_window = 0
            ml_flows_in_window += 1

            if ml_flows_in_window > MAX_ML_FLOWS_PER_SECOND:
                prediction = 1  # qua tai -> mac dinh nghi ngo, khong chay ML
            else:
                df_features = map_nfstream_to_cic(flow)
                prediction = model.predict(df_features)[0]

            if prediction == 1:
                protocol = str(getattr(flow, 'protocol', 'TCP'))
                dst_port = int(getattr(flow, 'dst_port', 0))
                fwd_len_mean = float(getattr(flow, 'src2dst_mean_ps', 0.0))
                total_pkts = float(getattr(flow, 'bidirectional_packets', 1))

                result = enforcer.evaluate_traffic(
                    ai_label=prediction,
                    protocol=protocol,
                    dst_port=dst_port,
                    fwd_len_mean=fwd_len_mean,
                    packet_count=total_pkts
                )

                if result.action == "DROP_RATE_LIMIT_EXCEEDED":
                    rule_key = (protocol, dst_port)
                    now_alert = time.time()
                    last_alert = blocked_rules.get(rule_key, 0)
                    # Chi im lang trong khoang ALERT_COOLDOWN_SECONDS, sau do
                    # bao dong lai neu rule van con bi drop (khong mu vinh vien)
                    if now_alert - last_alert >= ALERT_COOLDOWN_SECONDS:
                        print(f"[!] REAL-TIME ALERT: DDoS Rate Limit Exceeded => {result.signature_key}")
                        print(f"RULE_DROP => {result.signature_key}")
                        blocked_rules[rule_key] = now_alert
                elif result.action == "PASS_SUSTAINED_LOW_AND_SLOW":
                    print(f"[?] WARNING: Sustained low-and-slow pattern detected (van duoi nguong tuc thoi) => {result.signature_key}")
                
    except KeyboardInterrupt:
        print("\n[*] Gatekeeper stopped by user. Exiting gracefully...")
    except PermissionError:
        print("\n[-] Permission Denied. Please run the script as Root/Administrator to sniff packets.")
    except Exception as e:
        print(f"\n[-] Unexpected error occurred: {e}")

if __name__ == "__main__":
    main()