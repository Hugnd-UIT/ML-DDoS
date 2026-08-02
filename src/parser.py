import pandas as pd
import numpy as np
import glob
import os
import joblib

from sklearn.preprocessing import LabelEncoder


# Set data paths
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'CICDDoS2019')
TRAIN_DIR = os.path.join(DATA_DIR, 'training')
TEST_DIR = os.path.join(DATA_DIR, 'testing')

# Set output paths
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

# Create model folder if it does not exist
os.makedirs(MODELS_DIR, exist_ok=True)


# Select features used by the model
FEATURES = [
    'Flow Duration',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Down/Up Ratio',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Total',
    'Protocol',
    'SYN Flag Count',
    'ACK Flag Count',
    'Init_Win_bytes_forward',
    'Label'
]


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

        # Process each chunk
        for chunk in chunk_iterator:
            # Remove spaces from column names
            chunk.columns = chunk.columns.str.strip()

            # Check for missing required columns
            missing_cols = [
                col for col in FEATURES
                if col not in chunk.columns
            ]

            # Skip chunks with missing columns
            if missing_cols:
                continue

            # Keep only required features
            df_chunk = chunk[FEATURES].copy()

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

    # Keep only known labels in the testing dataset
    df_test_multi = df_test_multi[
        df_test_multi['Label'].isin(knowledge)
    ]

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