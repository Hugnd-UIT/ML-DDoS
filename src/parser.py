import pandas as pd
import numpy as np
import glob
import os
import joblib

from sklearn.preprocessing import LabelEncoder

from features import FEATURE_NAMES


# Set data paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'CICDDoS2019')
TRAIN_DIR = os.path.join(DATA_DIR, 'training')
TEST_DIR = os.path.join(DATA_DIR, 'testing')

# Set output paths
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

# Create model folder if it does not exist
os.makedirs(MODELS_DIR, exist_ok=True)


# CICDDoS2019 labels the SAME attack differently on each capture day:
# day 1 (training/) uses the "DrDoS_" prefix, day 2 (testing/) does not.
# Without this mapping the two days share only BENIGN and Syn, so the
# day-2 set collapses from ~19.5M rows to ~4.6M and 11 of 13 classes
# are silently dropped by the isin() filter in save_data().
LABEL_CANON = {
    'DrDoS_DNS': 'DNS',
    'DrDoS_LDAP': 'LDAP',
    'DrDoS_MSSQL': 'MSSQL',
    'DrDoS_NTP': 'NTP',
    'DrDoS_NetBIOS': 'NetBIOS',
    'DrDoS_SNMP': 'SNMP',
    'DrDoS_SSDP': 'SSDP',
    'DrDoS_UDP': 'UDP',
    'UDP-lag': 'UDPLag',
    'UDPLag': 'UDPLag',
}


# Normalize a label column so both capture days use the same vocabulary
def canonicalize_labels(series):
    return series.astype(str).str.strip().replace(LABEL_CANON)


# Columns pulled from the raw CSVs: the model's feature contract plus the
# label. FEATURE_NAMES lives in features.py so the training pipeline and the
# live extractor in gatekeeper.py cannot drift apart.
FEATURES = FEATURE_NAMES + ['Label']


# Clean and merge CSV files from a folder
def clean_data(folder, dataset="DATASET"):
    # Show the current dataset being scanned
    print(f"\n[*] Scanning for CSV files in {dataset} day:")

    # Find all CSV files
    files = glob.glob(os.path.join(folder, '*.csv'))

    # Stop if no CSV files are found
    if not files:
        print(f"[-] No CSV files found in {dataset} folder.")
        return None

    # Store cleaned data chunks
    data_frame_list = []

    # Đếm số file bị bỏ hoàn toàn vì thiếu cột
    skipped_files = []

    # Process each CSV file
    for file in files:
        # Show the current file
        print(f"[*] Processing: {os.path.basename(file)}")

        # Read the file in chunks to reduce memory usage
        chunk_iterator = pd.read_csv(
            file,
            chunksize=100000,
            low_memory=False
        )

        kept_rows = 0

        # Process each chunk
        for chunk in chunk_iterator:
            # Remove spaces from column names
            chunk.columns = chunk.columns.str.strip()

            # Check for missing required columns
            missing_cols = [
                col for col in FEATURES
                if col not in chunk.columns
            ]

            # Skip chunks with missing columns.
            #
            # Bản cũ `continue` trong im lặng, nên một file CSV có header khác
            # (đổi tên cột, thêm dấu cách, bản CICFlowMeter khác) sẽ biến mất
            # khỏi dataset mà không để lại dấu vết nào. Nay báo rõ.
            if missing_cols:
                if file not in skipped_files:
                    skipped_files.append(file)

                    print(
                        f"[!] BỎ QUA {os.path.basename(file)} — "
                        f"thiếu {len(missing_cols)} cột: "
                        f"{missing_cols[:5]}"
                        f"{' ...' if len(missing_cols) > 5 else ''}"
                    )

                continue

            # Keep only required features
            df_chunk = chunk[FEATURES].copy()

            # Align label vocabulary across both capture days
            df_chunk['Label'] = canonicalize_labels(
                df_chunk['Label']
            )

            # Convert numeric columns to numbers
            cols_numeric = [
                'Flow Bytes/s',
                'Flow Packets/s'
            ]

            # Process each numeric column
            for col in cols_numeric:
                # Convert invalid values to NaN
                if col in df_chunk.columns:
                    df_chunk[col] = pd.to_numeric(
                        df_chunk[col],
                        errors='coerce'
                    )

            # Replace infinite values with NaN
            df_chunk.replace(
                [np.inf, -np.inf],
                np.nan,
                inplace=True
            )

            # Remove rows containing missing values
            df_chunk.dropna(inplace=True)

            # Save non-empty chunks
            if not df_chunk.empty:
                data_frame_list.append(df_chunk)
                kept_rows += len(df_chunk)

        if kept_rows:
            print(f"    → giữ lại {kept_rows:,} dòng")

    # Tổng kết các file bị loại, để không ai vô tình train trên nửa dataset
    if skipped_files:
        print(
            f"\n[!] {len(skipped_files)}/{len(files)} file trong {dataset} "
            f"bị bỏ hoàn toàn vì header không khớp feature contract:"
        )

        for path in skipped_files:
            print(f"    - {os.path.basename(path)}")

    # Stop if no valid data was found
    if not data_frame_list:
        return None

    # Merge all cleaned chunks
    print(f"[*] Merging {dataset} chunks...")

    return pd.concat(
        data_frame_list,
        ignore_index=True
    )


# Convert labels and save processed datasets
def save_data(df_train, df_test):
    # Create binary label datasets
    print("[!] Encoding Binary labels...")

    df_train_bin = df_train.copy()
    df_test_bin = df_test.copy()

    # Convert BENIGN to zero and attacks to one
    df_train_bin['Label'] = df_train_bin['Label'].apply(
        lambda x: 0 if x == 'BENIGN' else 1
    )

    # Convert BENIGN to zero and attacks to one
    df_test_bin['Label'] = df_test_bin['Label'].apply(
        lambda x: 0 if x == 'BENIGN' else 1
    )

    # Set binary output paths
    train_bin_path = os.path.join(
        OUTPUT_DIR,
        'train_binary.csv'
    )

    test_bin_path = os.path.join(
        OUTPUT_DIR,
        'test_binary.csv'
    )

    # Save binary datasets
    df_train_bin.to_csv(train_bin_path, index=False)
    df_test_bin.to_csv(test_bin_path, index=False)

    # Show saved binary files
    print(f"[+] Saved: {train_bin_path}")
    print(f"[+] Saved: {test_bin_path}")

    # Create multi-class label datasets
    print("[!] Encoding Multi-class labels...")

    df_train_multi = df_train.copy()
    df_test_multi = df_test.copy()

    # Create label encoder
    label = LabelEncoder()

    # Encode training labels
    df_train_multi['Label'] = label.fit_transform(
        df_train_multi['Label']
    )

    # Get labels available in the training dataset
    knowledge = set(label.classes_)

    # Report which test labels cannot be evaluated before dropping them.
    # This filter used to remove ~15M rows silently because the two capture
    # days named the same attacks differently; canonicalize_labels() now
    # aligns them, so only genuinely train-absent classes are dropped.
    test_labels = set(df_test_multi['Label'].unique())
    unseen = sorted(test_labels - knowledge)

    print(f"[*] Train classes ({len(knowledge)}): {sorted(knowledge)}")
    print(f"[*] Test classes  ({len(test_labels)}): {sorted(test_labels)}")

    if unseen:
        dropped = df_test_multi['Label'].isin(unseen).sum()

        print(
            f"[!] Dropping {dropped:,} test rows "
            f"({dropped / len(df_test_multi) * 100:.2f}%) "
            f"with train-absent labels: {unseen}"
        )

        print(
            "[!] These are unseen attack types. They stay in the BINARY "
            "set and are a useful zero-day generalization test there."
        )

    # Keep only known labels in the testing dataset.
    # .copy() là bắt buộc: nếu không, phép gán Label bên dưới chạy trên một
    # view và pandas ném SettingWithCopyWarning, với hành vi không đảm bảo
    # giữa các phiên bản.
    df_test_multi = df_test_multi[
        df_test_multi['Label'].isin(knowledge)
    ].copy()

    # Show the surviving evaluation set
    print(
        f"[+] Multiclass test set: {len(df_test_multi):,} rows, "
        f"{df_test_multi['Label'].nunique()} classes"
    )

    # Encode testing labels
    df_test_multi['Label'] = label.transform(
        df_test_multi['Label']
    )

    # Set multi-class output paths
    train_multi_path = os.path.join(
        OUTPUT_DIR,
        'train_multiclass.csv'
    )

    test_multi_path = os.path.join(
        OUTPUT_DIR,
        'test_multiclass.csv'
    )

    # Save multi-class datasets
    df_train_multi.to_csv(train_multi_path, index=False)
    df_test_multi.to_csv(test_multi_path, index=False)

    # Show saved multi-class files
    print(f"[+] Saved: {train_multi_path}")
    print(f"[+] Saved: {test_multi_path}")

    # Save the label encoder
    path = os.path.join(
        MODELS_DIR,
        'label.pkl'
    )

    joblib.dump(label, path)


# Run the complete data processing pipeline
def main():
    # Show process header
    print("=" * 60)

    # Clean training data
    df_train = clean_data(
        TRAIN_DIR,
        "training"
    )

    # Stop if training data is missing
    if df_train is None:
        print("[-] Fatal Error: Training data not found. Aborting.")
        return

    # Clean testing data
    df_test = clean_data(
        TEST_DIR,
        "testing"
    )

    # Stop if testing data is missing
    if df_test is None:
        print("[-] Fatal Error: Testing data not found. Aborting.")
        return

    # Show raw dataset sizes
    print(f"\n[*] Raw Training samples: {len(df_train):,}")
    print(f"[*] Raw Testing samples : {len(df_test):,}")

    # Save processed datasets
    save_data(
        df_train,
        df_test
    )

    # Show completion message
    print("\n" + "=" * 60)
    print("[+] FINISH!")
    print("=" * 60)


# Start the program
if __name__ == "__main__":
    main()