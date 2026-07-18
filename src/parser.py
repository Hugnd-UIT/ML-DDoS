import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.preprocessing import LabelEncoder

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'CICDDoS2019')
TRAIN_DIR = os.path.join(DATA_DIR, 'training')
TEST_DIR = os.path.join(DATA_DIR, 'testing')

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
os.makedirs(MODELS_DIR, exist_ok=True) 

FEATURES = [
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets', 'Total Backward Packets', 'Down/Up Ratio',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Total',
    'Protocol', 'SYN Flag Count', 'ACK Flag Count', 'Init_Win_bytes_forward',
    'Label'
]

def clean_data(folder, dataset="DATASET"):
    print(f"\n[*] Scanning for CSV files in {dataset} day:")
    files = glob.glob(os.path.join(folder, '*.csv'))
    
    if not files:
        print(f"[-] No CSV files found in {dataset} folder.")
        return None

    data_frame_list = []

    for file in files:
        print(f"[*] Processing: {os.path.basename(file)}")
        chunk_iterator = pd.read_csv(file, chunksize=100000, low_memory=False)
        
        for chunk in chunk_iterator:
            chunk.columns = chunk.columns.str.strip()
            missing_cols = [col for col in FEATURES if col not in chunk.columns]
            if missing_cols:
                continue
                
            df_chunk = chunk[FEATURES].copy()
            
            cols_numeric = ['Flow Bytes/s', 'Flow Packets/s']
            for col in cols_numeric:
                if col in df_chunk.columns:
                    df_chunk[col] = pd.to_numeric(df_chunk[col], errors='coerce')

            df_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            df_chunk.dropna(inplace=True)
            
            if not df_chunk.empty:
                data_frame_list.append(df_chunk)

    if not data_frame_list:
        return None
        
    print(f"[*] Merging {dataset} chunks...")
    return pd.concat(data_frame_list, ignore_index=True)

def save_data(df_train, df_test):
    # ! Binary
    print("[!] Encoding Binary labels...")
    df_train_bin = df_train.copy()
    df_test_bin = df_test.copy()
    
    df_train_bin['Label'] = df_train_bin['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    df_test_bin['Label'] = df_test_bin['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    train_bin_path = os.path.join(OUTPUT_DIR, 'train_binary.csv')
    test_bin_path = os.path.join(OUTPUT_DIR, 'test_binary.csv')

    df_train_bin.to_csv(train_bin_path, index=False)
    df_test_bin.to_csv(test_bin_path, index=False)
    
    print(f"[+] Saved: {train_bin_path}")
    print(f"[+] Saved: {test_bin_path}")

    # ! Multi-class
    print("[!] Encoding Multi-class labels...")
    df_train_multi = df_train.copy()
    df_test_multi = df_test.copy()
    
    label = LabelEncoder()
    df_train_multi['Label'] = label.fit_transform(df_train_multi['Label'])
    
    knowledge = set(label.classes_)
    df_test_multi = df_test_multi[df_test_multi['Label'].isin(knowledge)]
    df_test_multi['Label'] = label.transform(df_test_multi['Label'])
    
    train_multi_path = os.path.join(OUTPUT_DIR, 'train_multiclass.csv')
    test_multi_path = os.path.join(OUTPUT_DIR, 'test_multiclass.csv')

    df_train_multi.to_csv(train_multi_path, index=False)
    df_test_multi.to_csv(test_multi_path, index=False)

    print(f"[+] Saved: {train_multi_path}")
    print(f"[+] Saved: {test_multi_path}")

    path = os.path.join(MODELS_DIR, 'label.pkl')
    joblib.dump(label, path)

def main():
    print("="*60)
    
    # Quét folder training
    df_train = clean_data(TRAIN_DIR, "training")
    if df_train is None:
        print("[-] Fatal Error: Training data not found. Aborting.")
        return

    # Quét folder testing
    df_test = clean_data(TEST_DIR, "testing")
    if df_test is None:
        print("[-] Fatal Error: Testing data not found. Aborting.")
        return

    print(f"\n[*] Raw Training samples: {len(df_train):,}")
    print(f"[*] Raw Testing samples : {len(df_test):,}")

    save_data(df_train, df_test)
    
    print("\n" + "="*60)
    print("[+] FINISH!")
    print("="*60)

if __name__ == "__main__":
    main()