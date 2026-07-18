import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_sample_weight
import os
import time


def train_binary():
    print("\n" + "=" * 60)
    print("[*] Starting BINARY training process")
    print("=" * 60)
    start_time = time.time()

    train_path = './data/train_binary.csv'
    test_path = './data/test_binary.csv'

    print("[*] Loading and merging data...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    
    # Gộp chung tập train và test
    df_merged = pd.concat([df_train, df_test], ignore_index=True)
    
    X = df_merged.drop(columns=['Label'])
    y = df_merged['Label']

    print(f"[+] Total flows after merging: {X.shape[0]:,}")

    print("[*] Training binary model on 100% data...")
    model = XGBClassifier(
        n_estimators=150,
        max_depth=7,
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )

    model.fit(X, y)

    joblib.dump(model, './models/binary.pkl')

    print(f"\n[+] Training completed. binary.pkl is ready.")
    print(f"[+] Time: {time.time() - start_time:.2f}s.")


def train_multiclass():
    print("\n" + "=" * 60)
    print("[*] Starting MULTICLASS training process")
    print("=" * 60)
    start_time = time.time()

    train_path = './data/train_multiclass.csv'
    test_path = './data/test_multiclass.csv'

    print("[*] Loading and merging data...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    
    # Gộp chung tập train và test
    df_merged = pd.concat([df_train, df_test], ignore_index=True)

    X = df_merged.drop(columns=['Label'])
    y = df_merged['Label']

    num_class = len(np.unique(y))

    print(f"[+] Total flows after merging: {X.shape[0]:,}")
    print(f"[+] Number of classes: {num_class}")

    print("[*] Computing sample weights to handle class imbalance...")
    sample_weights = compute_sample_weight(class_weight='balanced', y=y)

    print("[*] Training multiclass model on 100% data...")
    model = XGBClassifier(
        objective='multi:softprob',
        num_class=num_class,
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method='hist',
        eval_metric='mlogloss',
        random_state=42,
        n_jobs=-1
    )

    model.fit(
        X, y,
        sample_weight=sample_weights
    )

    joblib.dump(model, './models/multiclass.pkl')

    print(f"\n[+] Training completed. multiclass.pkl is ready.")
    print(f"[+] Time: {time.time() - start_time:.2f}s.")


def main():
    total_start = time.time()
    train_binary()
    train_multiclass()
    print("\n" + "=" * 60)
    print("[+] ALL TRAINING FINISHED!")
    print(f"[+] Total time: {time.time() - total_start:.2f}s.")
    print("=" * 60)


if __name__ == "__main__":
    main()