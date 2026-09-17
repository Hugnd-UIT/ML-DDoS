import os
import sys
import glob
import time
import shutil
import joblib
import traceback
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from collections import Counter
from sklearn.preprocessing import LabelEncoder


BASE_DIR = (
    '/content/drive/MyDrive/ML-DDoS'
    if os.path.exists('/content/drive/MyDrive/ML-DDoS')
    else os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..'
        )
        if '__file__' in globals()
        else '.'
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    'data'
)

DOS_DIR = os.path.join(
    DATA_DIR,
    'raw',
    'CIC-DoS2017'
)

DDOS_DIR = os.path.join(
    DATA_DIR,
    'raw',
    'CIC-DDoS2019'
)

if not os.path.exists(DOS_DIR):
    fallback_dos = os.path.join(DATA_DIR, 'CIC-DoS2017')
    if os.path.exists(fallback_dos):
        DOS_DIR = fallback_dos

if not os.path.exists(DDOS_DIR):
    fallback_ddos = os.path.join(DATA_DIR, 'CIC-DDoS2019')
    if os.path.exists(fallback_ddos):
        DDOS_DIR = fallback_ddos

DIVIDED_DIR = os.path.join(
    DATA_DIR,
    'divided'
)

PARSED_DIR = os.path.join(
    DATA_DIR,
    'parsed'
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    'models'
)

os.makedirs(DIVIDED_DIR, exist_ok=True)
os.makedirs(PARSED_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'FIN Flag Count',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'Active Mean',
    'Idle Mean',
    'Destination Port'
]

LABELS = {
    'BENIGN': 'Benign',
    'Benign': 'Benign',
    'DoS Hulk': 'Hulk',
    'Hulk': 'Hulk',
    'DoS GoldenEye': 'GoldenEye',
    'GoldenEye': 'GoldenEye',
    'DoS slowloris': 'Slowloris',
    'Slowloris': 'Slowloris',
    'DoS Slowhttptest': 'Slowhttptest',
    'Slowhttptest': 'Slowhttptest',
    'DoS RUDY': 'RUDY',
    'RUDY': 'RUDY',
    'Slowbody': 'Slowbody',
    'Slowheaders': 'Slowheaders',
    'Slowread': 'Slowread',
    'DDoS': 'DDoS',
    'PortScan': 'PortScan',
    'Bot': 'Botnet',
    'Botnet': 'Botnet',
    'FTP-Patator': 'Brute_Force',
    'SSH-Patator': 'Brute_Force',
    'Web Attack - Brute Force': 'Brute_Force',
    'Web Attack - XSS': 'Web_Attack',
    'Web Attack - Sql Injection': 'Web_Attack',
    'WebDDoS': 'DDoS',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed',
    'DrDoS_DNS': 'DNS',
    'DNS': 'DNS',
    'DrDoS_LDAP': 'LDAP',
    'LDAP': 'LDAP',
    'DrDoS_MSSQL': 'MSSQL',
    'MSSQL': 'MSSQL',
    'DrDoS_NTP': 'NTP',
    'NTP': 'NTP',
    'DrDoS_NetBIOS': 'NetBIOS',
    'NetBIOS': 'NetBIOS',
    'DrDoS_SNMP': 'SNMP',
    'SNMP': 'SNMP',
    'DrDoS_SSDP': 'SSDP',
    'SSDP': 'SSDP',
    'DrDoS_UDP': 'UDP',
    'UDP': 'UDP',
    'Syn': 'SYN',
    'SYN': 'SYN',
    'TFTP': 'TFTP',
    'Portmap': 'PortMap',
    'PORTMAP': 'PortMap',
    'UDP-lag': 'UDP-Lag',
    'UDPLag': 'UDP-Lag'
}


def clean(folder, name="DATASET", out_file=None):
    print(f"\n[*] Scanning for CSV files in {name}:")

    files = glob.glob(
        os.path.join(folder, '**', '*.csv'),
        recursive=True
    )
    if not files:
        files = glob.glob(os.path.join(folder, '*.csv'))

    if not files:
        print(f"[-] No CSV files found in {name} folder.")
        return 0

    needed = FEATURES + ['Label']
    needed_set = set(needed)
    written = 0

    for f in sorted(files):
        print(f"[*] Processing: {os.path.basename(f)}")

        try:
            chunks = pd.read_csv(
                f,
                usecols=lambda c: c.strip() in needed_set,
                chunksize=1000000,
                low_memory=False,
                encoding_errors='replace'
            )
        except Exception:
            continue

        for chunk in chunks:
            chunk.columns = chunk.columns.str.strip()

            missing = [
                col for col in needed
                if col not in chunk.columns
            ]

            if missing:
                continue

            df_chunk = chunk[needed].copy()

            for col in FEATURES:
                df_chunk[col] = pd.to_numeric(
                    df_chunk[col],
                    errors='coerce'
                )

            df_chunk.replace(
                [np.inf, -np.inf],
                np.nan,
                inplace=True
            )

            df_chunk.dropna(inplace=True)

            clean_label = (
                df_chunk['Label']
                .astype(str)
                .str.strip()
                .str.replace('\ufffd', '-', regex=False)
                .str.replace('–', '-', regex=False)
                .str.replace('—', '-', regex=False)
            )

            df_chunk['Label'] = (
                clean_label
                .map(LABELS)
                .fillna(clean_label)
            )

            if not df_chunk.empty:
                first = not os.path.exists(out_file) or os.path.getsize(out_file) == 0
                df_chunk.to_csv(
                    out_file,
                    mode='a',
                    header=first,
                    index=False
                )
                written += len(df_chunk)

    if written > 0:
        print(f"[*] Merging {name} chunks...")

    return written


def merge(dos2017_dir, ddos2019_dir):
    out_file = os.path.join(PARSED_DIR, 'dataset.csv')
    if os.path.exists(out_file):
        os.remove(out_file)

    folders = [
        (dos2017_dir, 'DoS2017'),
        (ddos2019_dir, 'DDoS2019')
    ]

    total = 0
    for path, name in folders:
        count = clean(path, name, out_file)
        total += count

    if total == 0 or not os.path.exists(out_file):
        return None

    label_counts = Counter()
    for chunk in pd.read_csv(out_file, usecols=['Label'], chunksize=1000000, low_memory=False):
        for k, v in chunk['Label'].value_counts().items():
            label_counts[k] += v

    print("\n[*] Label distribution:")
    s = pd.Series(label_counts, name="count").sort_values(ascending=False)
    s.index.name = "Label"
    print(s)

    return out_file


def compute(df):
    path = os.path.join(
        MODELS_DIR,
        'stats.pkl'
    )
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print(f"[*] Found existing stats.pkl. Skipping stats scan!")
        return joblib.load(path)

    stats = {}
    mins = {col: float('inf') for col in FEATURES}
    maxs = {col: float('-inf') for col in FEATURES}
    sums = {col: 0.0 for col in FEATURES}
    sum_sqs = {col: 0.0 for col in FEATURES}
    reservoirs = {col: [] for col in FEATURES}
    total = 0

    for chunk in pd.read_csv(df, chunksize=1000000, low_memory=False):
        total += len(chunk)
        for col in FEATURES:
            s = pd.to_numeric(chunk[col], errors='coerce').dropna()
            vals = s.values
            if len(vals) == 0:
                continue
            mins[col] = min(mins[col], float(np.min(vals)))
            maxs[col] = max(maxs[col], float(np.max(vals)))
            sums[col] += float(np.sum(vals))
            sum_sqs[col] += float(np.sum(vals ** 2))
            if len(reservoirs[col]) < 50000:
                sample_size = min(500, len(vals))
                reservoirs[col].extend(np.random.choice(vals, size=sample_size, replace=False))

    for col in FEATURES:
        mean_v = sums[col] / max(total, 1)
        var_v = (sum_sqs[col] / max(total, 1)) - (mean_v ** 2)
        std_v = float(np.sqrt(max(var_v, 0.0)))
        med_v = float(np.median(reservoirs[col])) if reservoirs[col] else 0.0
        stats[col] = {
            'max': maxs[col],
            'min': mins[col],
            'median': med_v,
            'mean': float(mean_v),
            'std': std_v
        }

    joblib.dump(stats, path)
    print(f"[+] Saved stats: {path}")

    return stats


def split(df):
    try:
        le_path = os.path.join(
            MODELS_DIR,
            'labels.pkl'
        )

        if os.path.exists(le_path) and os.path.getsize(le_path) > 0:
            print(f"[*] Found existing labels.pkl. Skipping label scan!")
            le = joblib.load(le_path)
            valid_labels = set(le.classes_)
        else:
            label_counts = Counter()
            for chunk in pd.read_csv(df, usecols=['Label'], chunksize=1000000, low_memory=False):
                for k, v in chunk['Label'].value_counts().items():
                    label_counts[k] += v

            labels_list = sorted([lbl for lbl, cnt in label_counts.items() if cnt >= 2])
            le = LabelEncoder()
            le.fit(labels_list)
            valid_labels = set(le.classes_)

            joblib.dump(le, le_path)
            print(f"[+] Saved encoder: {le_path}")

        train_path = os.path.join(
            DIVIDED_DIR,
            'train.csv'
        )

        test_path = os.path.join(
            DIVIDED_DIR,
            'test.csv'
        )

        temp_dir = '/content' if os.path.exists('/content') and os.path.isdir('/content') else ('/tmp' if os.path.exists('/tmp') and os.path.isdir('/tmp') else DIVIDED_DIR)
        local_train = os.path.join(temp_dir, 'train.csv') if temp_dir != DIVIDED_DIR else train_path
        local_test = os.path.join(temp_dir, 'test.csv') if temp_dir != DIVIDED_DIR else test_path

        for p in [train_path, test_path, local_train, local_test]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

        first_train = True
        first_test = True
        train_count = 0
        test_count = 0

        for i, chunk in enumerate(pd.read_csv(df, chunksize=1000000, low_memory=False)):
            try:
                chunk = chunk[chunk['Label'].isin(valid_labels)].copy()
                if chunk.empty:
                    continue

                for col in FEATURES:
                    chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
                chunk.dropna(subset=FEATURES, inplace=True)
                if chunk.empty:
                    continue

                chunk['Label'] = le.transform(chunk['Label'])

                rng = np.random.RandomState(42 + i)
                mask = rng.rand(len(chunk)) < 0.8

                train_chunk = chunk[mask]
                test_chunk = chunk[~mask]

                if not train_chunk.empty:
                    train_chunk.to_csv(
                        local_train,
                        mode='a',
                        header=first_train,
                        index=False
                    )
                    first_train = False
                    train_count += len(train_chunk)

                if not test_chunk.empty:
                    test_chunk.to_csv(
                        local_test,
                        mode='a',
                        header=first_test,
                        index=False
                    )
                    first_test = False
                    test_count += len(test_chunk)

                print(f"[*] Chunk {i+1:2d} | Train: {train_count:>10,} | Test: {test_count:>9,}")

            except Exception as e:
                print(f"\n[!] Error in chunk {i}: {e}")
                traceback.print_exc()
                raise e

        if local_train != train_path:
            shutil.move(local_train, train_path)
        if local_test != test_path:
            shutil.move(local_test, test_path)

        print(f"[+] Saved train: {train_path} ({train_count:,} rows)")
        print(f"[+] Saved test: {test_path} ({test_count:,} rows)")

    except Exception as e:
        print(f"\n[!] Error in split: {e}")
        traceback.print_exc()
        raise e


def main():
    print("=" * 40)

    out_file = os.path.join(PARSED_DIR, 'dataset.csv')
    if os.path.exists(out_file) and os.path.getsize(out_file) > 1000000000:
        print(f"[*] Found existing dataset.csv {os.path.getsize(out_file) / (1024*1024*1024):.2f} GB. Skipping raw scan!")
        df = out_file
    else:
        df = merge(
            DOS_DIR,
            DDOS_DIR
        )

    if df is None:
        print("[-] Fatal Error: No data found. Aborting.")
        return

    compute(df)
    split(df)

    print("\n" + "=" * 40)
    print("[+] FINISH!")
    print("=" * 40)


if __name__ == "__main__":
    main()