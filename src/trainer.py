import os
import gc
import time
import joblib

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import xgboost as xgb

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report


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
    'data',
    'divided'
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    'models'
)

os.makedirs(MODELS_DIR, exist_ok=True)

TRAIN_PATH = (
    os.path.join(DATA_DIR, 'train.parquet')
    if os.path.exists(os.path.join(DATA_DIR, 'train.parquet'))
    else os.path.join(DATA_DIR, 'train.csv')
)

TEST_PATH = (
    os.path.join(DATA_DIR, 'test.parquet')
    if os.path.exists(os.path.join(DATA_DIR, 'test.parquet'))
    else os.path.join(DATA_DIR, 'test.csv')
)

try:
    import torch
    DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'
except Exception:
    DEVICE = 'cpu'


def stream_data(path, chunksize=5000000):
    if path.endswith('.parquet'):
        pf = pq.ParquetFile(path)
        for batch in pf.iter_batches(batch_size=chunksize):
            yield batch.to_pandas()
    else:
        sample = pd.read_csv(path, nrows=1)
        dtypes = {
            col: np.float32
            for col in sample.columns
            if col != 'Label'
        }
        dtypes['Label'] = np.int16
        chunks = pd.read_csv(
            path,
            chunksize=chunksize,
            dtype=dtypes,
            low_memory=False
        )
        for chunk in chunks:
            yield chunk


def load_balanced(cap=200000):
    print("\n" + "=" * 60)
    print(f"[*] Loading dataset...")
    print("=" * 60)

    t = time.time()
    df_labels = pd.read_parquet(TRAIN_PATH, columns=['Label'])
    total_rows = len(df_labels)
    selected_mask = np.zeros(total_rows, dtype=bool)

    for label in sorted(df_labels['Label'].unique()):
        idx = np.where(df_labels['Label'].values == label)[0]
        if len(idx) > cap:
            chosen = np.random.choice(idx, size=cap, replace=False)
        else:
            chosen = idx
        selected_mask[chosen] = True
        print(f"[*] Class {label:2d}: {len(chosen):>7,} flows")

    del df_labels
    gc.collect()

    sampled_chunks = []
    current_offset = 0

    pf = pq.ParquetFile(TRAIN_PATH)
    for batch in pf.iter_batches(batch_size=2000000):
        batch_len = len(batch)
        batch_mask = selected_mask[current_offset:current_offset + batch_len]

        if np.any(batch_mask):
            local_indices = np.where(batch_mask)[0]
            batch_df = batch.take(local_indices).to_pandas()
            sampled_chunks.append(batch_df)
            del batch_df

        current_offset += batch_len

    del selected_mask
    gc.collect()

    df = pd.concat(sampled_chunks, ignore_index=True)
    del sampled_chunks
    gc.collect()

    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    y = df.pop('Label').values
    X = df

    print(f"[+] Dataset: {len(X):,} flows | {len(np.unique(y))} classes")
    print(f"[+] Loaded in {time.time() - t:.2f}s")

    return X, y


def train_xgboost(num_class):
    print("\n" + "=" * 60)
    print("[*] Training: XGBoost")
    print(f"[*] Device: {DEVICE.upper()}")
    print("=" * 60)

    t = time.time()
    X_train, y_train = load_balanced(cap=200000)

    dtrain = xgb.DMatrix(
        X_train,
        label=y_train
    )

    del X_train, y_train
    gc.collect()

    params = {
        'objective': 'multi:softprob',
        'num_class': num_class,
        'max_depth': 8,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'tree_method': 'hist',
        'device': DEVICE,
        'eval_metric': 'mlogloss',
        'seed': 42
    }

    print("[*] Fitting XGBoost booster...")
    booster = xgb.train(
        params,
        dtrain,
        num_boost_round=400
    )

    del dtrain
    gc.collect()

    model_path = os.path.join(
        MODELS_DIR,
        'XGBoost.pkl'
    )

    joblib.dump(
        booster,
        model_path
    )

    print(f"[+] Saved model: {model_path}")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    return booster


def train_isolation_forest():
    print("\n" + "=" * 60)
    print("[*] Training: Isolation Forest")
    print("=" * 60)

    t = time.time()
    df_labels = pd.read_parquet(TRAIN_PATH, columns=['Label'])
    benign_idx = np.where(df_labels['Label'].values == 0)[0]

    if len(benign_idx) > 100000:
        chosen = np.random.choice(benign_idx, size=100000, replace=False)
    else:
        chosen = benign_idx

    selected_mask = np.zeros(len(df_labels), dtype=bool)
    selected_mask[chosen] = True
    del df_labels
    gc.collect()

    benign_chunks = []
    current_offset = 0
    pf = pq.ParquetFile(TRAIN_PATH)
    cols = [c.name for c in pf.schema if c.name != 'Label']

    for batch in pf.iter_batches(batch_size=2000000, columns=cols):
        batch_len = len(batch)
        batch_mask = selected_mask[current_offset:current_offset + batch_len]

        if np.any(batch_mask):
            local_indices = np.where(batch_mask)[0]
            benign_chunks.append(batch.take(local_indices).to_pandas())

        current_offset += batch_len

    del selected_mask
    gc.collect()

    X_benign = pd.concat(benign_chunks, ignore_index=True)
    del benign_chunks
    gc.collect()

    print(f"[+] Total Benign flows: {len(X_benign):,}")
    print("[*] Fitting Isolation Forest...")

    model = IsolationForest(
        n_estimators=200,
        contamination='auto',
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_benign)

    scores_benign = model.score_samples(X_benign)
    model.offset_ = float(np.percentile(scores_benign, 10))

    del X_benign, scores_benign
    gc.collect()

    model_path = os.path.join(
        MODELS_DIR,
        'IsolationForest.pkl'
    )

    joblib.dump(
        model,
        model_path
    )

    print(f"[+] Saved model: {model_path}")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    return model


def evaluate(model, name='XGBoost'):
    print("\n" + "=" * 60)
    print(f"[*] Evaluating: {name}")
    print("=" * 60)

    t = time.time()
    preds = []
    y_true = []

    for chunk in stream_data(TEST_PATH, chunksize=2000000):
        y_chunk = chunk.pop('Label').values
        X_chunk = chunk

        if name == 'XGBoost':
            dtest = xgb.DMatrix(X_chunk)
            pred_probs = model.predict(dtest)
            pred_chunk = np.argmax(pred_probs, axis=1)
            preds.extend(pred_chunk)
            y_true.extend(y_chunk)
            del dtest, pred_probs
        else:
            pred_chunk = model.predict(X_chunk)
            preds.extend(pred_chunk)
            y_true.extend(np.where(y_chunk == 0, 1, -1))

        del X_chunk, y_chunk, chunk, pred_chunk
        gc.collect()

    print(f"[+] Total evaluated: {len(y_true):,} test flows")
    if name == 'XGBoost':
        print(classification_report(y_true, preds, zero_division=0))
    else:
        print(classification_report(y_true, preds, target_names=['Anomaly', 'Normal'], zero_division=0))

    print(f"[+] Completed in {time.time() - t:.2f}s")

    del preds, y_true
    gc.collect()


def main():
    total_start = time.time()

    labels_path = os.path.join(
        MODELS_DIR,
        'labels.pkl'
    )

    if os.path.exists(labels_path):
        le = joblib.load(labels_path)
        num_class = len(le.classes_)
    else:
        num_class = 24

    print(f"[*] Train Path: {TRAIN_PATH}")
    print(f"[*] Test Path:  {TEST_PATH}")
    print(f"[*] Number of Classes: {num_class}")

    xgb_model = train_xgboost(num_class)
    evaluate(xgb_model, name='XGBoost')

    iso_model = train_isolation_forest()
    evaluate(iso_model, name='Isolation Forest')

    print("\n" + "=" * 60)
    print("[+] FINISH!")
    print(f"[+] Total time: {time.time() - total_start:.2f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
