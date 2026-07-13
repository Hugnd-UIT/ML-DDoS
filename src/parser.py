import pandas as pd
import numpy as np
import glob
import os
from sklearn.preprocessing import LabelEncoder

# ! Cấu hình đường dẫn
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'CICDDoS2019')
BINARY_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'binary.csv')
MULTI_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'multiclass.csv')

# ! Các features cần lọc
FEATURES = [
    # ! Cường độ và lưu lượng - Volumetric
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets', 'Total Backward Packets', 'Down/Up Ratio',

    # ! Kích thước gói tin - Payload size
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    
    # ! Nhịp điệu thời gian - IAT
    'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Total',

    # ! Vân tay - Fingerprinting
    'Protocol', 'SYN Flag Count', 'ACK Flag Count', 'Init_Win_bytes_forward',
    
    # ! Nhãn hệ thống - Mandatory
    'Label'
]

def clean_data():
    # ! Chọn các file CSV
    print("[*] Scanning for CSV files...")
    files = glob.glob(os.path.join(DATA_DIR, '*.csv'))
    
    if not files:
        print("[-] No CSV files found.")
        return None

    data_frame_list = []

    for file in files:
        print(f"[*] Processing: {os.path.basename(file)}")
        
        # ! Đọc chunk kích thước 100.000 dòng để không tràn RAM
        chunk_iterator = pd.read_csv(file, chunksize=100000, low_memory=False)
        
        for chunk in chunk_iterator:
            chunk.columns = chunk.columns.str.strip()
            
            # ! Kiểm tra đủ 20 cột cốt lõi không
            missing_cols = [col for col in FEATURES if col not in chunk.columns]
            if missing_cols:
                # ! Nếu thiếu cột, bỏ qua chunk này
                continue
                
            # ! Ép xuống 20 cột
            df_chunk = chunk[FEATURES].copy()
            
            # ! Xử lý ép dữ liệu cho 2 cột có thể có giá trị inf
            cols_numeric = ['Flow Bytes/s', 'Flow Packets/s']
            for col in cols_numeric:
                if col in df_chunk.columns:
                    df_chunk[col] = pd.to_numeric(df_chunk[col], errors='coerce')

            # ! Dọn dẹp rác đổi Infinity thành NaN, sau đó drop toàn bộ dòng chứa NaN
            df_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            df_chunk.dropna(inplace=True)
            
            if not df_chunk.empty:
                data_frame_list.append(df_chunk)

    if not data_frame_list:
        return None
        
    print("[*] Merging datasets...")
    master_df = pd.concat(data_frame_list, ignore_index=True)
    return master_df

def clean_labels(df):
    print("[*] Encoding labels...")
    
    # ! Binary
    # * Nhãn gốc 'BENIGN' -> 0 *
    # * Mọi loại tấn công khác -> 1 *
    df_binary = df.copy()
    df_binary['Label'] = df_binary['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    # ! Multi-class
    df_multi = df.copy()
    le = LabelEncoder()
    df_multi['Label'] = le.fit_transform(df_multi['Label'])
    
    print("[+] Multi-class label mapping:")
    for index, label_name in enumerate(le.classes_):
        print(f"    {index} : {label_name}")
        
    return df_binary, df_multi

def check_results():
    print("\n" + "=" * 60)
    print("[*] Dataset Validation Report (Fast Mode)")
    print("=" * 60)

    for path in [BINARY_PATH, MULTI_PATH]:
        label_type = "Binary" if "binary" in path else "Multi-class"
        df_sample = pd.read_csv(path, nrows=1000)
        
        print(f"[+] {label_type} labels: {sorted(df_sample['Label'].unique())}")
        
        has_nan = False
        for chunk in pd.read_csv(path, chunksize=100000):
            if chunk.isnull().values.any():
                has_nan = True
                break
        
        status = "PASSED" if not has_nan else "FAILED - Missing values detected"
        print(f"[+] {label_type} Validation : {status}")

    print("=" * 60)

def main():
    df = clean_data()
    
    if df is not None:
        df_binary, df_multi = clean_labels(df)
        
        print("[*] Saving binary dataset...")
        df_binary.to_csv(BINARY_PATH, index=False)
        print(f"[+] Saved -> {BINARY_PATH}")
        
        print("[*] Saving multi-class dataset...")
        df_multi.to_csv(MULTI_PATH, index=False)
        print(f"[+] Saved -> {MULTI_PATH}")

        check_results()
        
        print("[+] Dataset preprocessing completed successfully.")

if __name__ == "__main__":
    main()