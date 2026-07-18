import os
import time
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib
from collections import defaultdict

class AlertAggregator:
    def __init__(self, interval=2.0):
        self.interval = interval
        self.last_flush = time.time()
        self.drop_stats = defaultdict(int)

    def log_drop(self, proto, port):
        self.drop_stats[(proto, port)] += 1
        current_time = time.time()
        if current_time - self.last_flush >= self.interval:
            self.flush()
            self.last_flush = current_time

    def flush(self):
        if not self.drop_stats:
            return
        print(f"\n[+] === GATEKEEPER ALERT ({time.strftime('%H:%M:%S')}) ===")
        for (proto, port), count in self.drop_stats.items():
            print(f"[!] DROPPED {count} packets => PROTO:{proto} | DST_PORT:{port}")
        print("[+] =========================================\n")
        self.drop_stats.clear()

try:
    from nfstream import NFStreamer
except ImportError:
    print("[!] 'nfstream' library not found. Please install it: pip install nfstream")
    NFStreamer = None

# Disable warnings to keep terminal clean
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
warnings.filterwarnings("ignore", category=FutureWarning)

def get_args():
    parser = argparse.ArgumentParser(description="Gatekeeper - Inline IPS System using ML and nfstream")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on (default: eth0)")
    parser.add_argument("-m", "--model", default="./models/binary.pkl", help="Path to the trained XGBoost model")
    return parser.parse_args()

def map_nfstream_to_cic(flow):
    """
    Extract and convert attributes from the `flow` object (nfstream)
    into a dictionary/DataFrame containing CICDDoS2019 features.
    Safely fill with 0 or NaN if attributes are missing.
    """
    
    # Safe calculation to avoid Division by Zero and Mathematical Flaws
    duration_ms = getattr(flow, 'bidirectional_duration_ms', 0)
    bidirectional_bytes = getattr(flow, 'bidirectional_bytes', 0)
    bidirectional_packets = getattr(flow, 'bidirectional_packets', 0)
    
    if duration_ms == 0:
        flow_bytes_s = 0.0
        flow_packets_s = 0.0
    else:
        duration_s = duration_ms / 1000.0
        flow_bytes_s = bidirectional_bytes / duration_s
        flow_packets_s = bidirectional_packets / duration_s

    src2dst_bytes = getattr(flow, 'src2dst_bytes', 0)
    dst2src_bytes = getattr(flow, 'dst2src_bytes', 0)
    
    # Map features
    features = {
        'Flow Duration': duration_ms * 1000,
        'Flow Bytes/s': flow_bytes_s,
        'Flow Packets/s': flow_packets_s,
        'Total Fwd Packets': getattr(flow, 'src2dst_packets', 0),
        'Total Backward Packets': getattr(flow, 'dst2src_packets', 0),
        'Down/Up Ratio': dst2src_bytes / src2dst_bytes if src2dst_bytes > 0 else 0,
        'Total Length of Fwd Packets': src2dst_bytes,
        'Total Length of Bwd Packets': dst2src_bytes,
        'Fwd Packet Length Max': getattr(flow, 'src2dst_max_bytes', 0),
        'Fwd Packet Length Min': getattr(flow, 'src2dst_min_bytes', 0),
        'Fwd Packet Length Mean': getattr(flow, 'src2dst_mean_bytes', 0),
        'Bwd Packet Length Mean': getattr(flow, 'dst2src_mean_bytes', 0),
        'Flow IAT Mean': getattr(flow, 'bidirectional_mean_ms', 0) * 1000,
        'Flow IAT Std': getattr(flow, 'bidirectional_stddev_ms', 0) * 1000,
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
    
    # Return DataFrame (single row)
    df = pd.DataFrame([features], columns=feature_columns)
    
    # Fill NaN/Inf values (if any) with 0 to prevent inference errors on live traffic
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
    
    # 1. Load XGBoost Model
    model_path = args.model
    try:
        print(f"[*] Loading model from: {model_path} ...")
        # Handle path based on where script is run
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
    
    aggregator = AlertAggregator(interval=2.0)
    
    # 2. Event Loop to capture Live Traffic
    try:
        # Optimize stream capture: Push flows almost instantly for Real-time IPS
        streamer = NFStreamer(source=args.interface, active_timeout=1, idle_timeout=2)
        for flow in streamer:
            # 3. Extract Feature Map
            df_features = map_nfstream_to_cic(flow)
            
            # 4. Inference
            prediction = model.predict(df_features)[0]
            
            # 5. Stateless Extraction & eBPF interaction
            if prediction == 1:
                # Sanity check: Ignore if flow has too few packets (background noise)
                if getattr(flow, 'bidirectional_packets', 0) < 10:
                    continue
                    
                protocol = getattr(flow, 'protocol', 0)
                dst_port = getattr(flow, 'dst_port', 0)
                max_len = getattr(flow, 'src2dst_max_bytes', 0)
                
                # Print specific format for eBPF to read
                aggregator.log_drop(proto=protocol, port=dst_port)
                
    except KeyboardInterrupt:
        print("\n[*] Gatekeeper stopped by user. Exiting gracefully...")
    except PermissionError:
        print("\n[-] Permission Denied. Please run the script as Root/Administrator to sniff packets.")
    except Exception as e:
        print(f"\n[-] Unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
