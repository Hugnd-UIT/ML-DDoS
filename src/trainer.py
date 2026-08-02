import os
import time
import joblib

import numpy as np
import pandas as pd

from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_sample_weight


# Train binary classification model
def train_binary():
    # Show training header
    print("\n" + "=" * 60)
    print("[*] Starting BINARY training process")
    print("=" * 60)

    # Start training timer
    start_time = time.time()

    # Set dataset paths
    train_path = './data/train_binary.csv'
    test_path = './data/test_binary.csv'

    # Load training and testing data
    print("[*] Loading and merging data...")

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # Merge training and testing data
    df_merged = pd.concat(
        [df_train, df_test],
        ignore_index=True
    )

    # Separate features and labels
    X = df_merged.drop(
        columns=['Label']
    )

    y = df_merged['Label']

    # Show total number of flows
    print(
        f"[+] Total flows after merging: {X.shape[0]:,}"
    )

    # Create binary classification model
    print("[*] Training binary model on 100% data...")

    model = XGBClassifier(
        n_estimators=150,
        max_depth=7,
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )

    # Train binary model
    model.fit(X, y)

    # Save binary model
    joblib.dump(
        model,
        './models/binary.pkl'
    )

    # Show training result
    print(
        "\n[+] Training completed. binary.pkl is ready."
    )

    # Show training time
    print(
        f"[+] Time: {time.time() - start_time:.2f}s."
    )


# Train multiclass classification model
def train_multiclass():
    # Show training header
    print("\n" + "=" * 60)
    print("[*] Starting MULTICLASS training process")
    print("=" * 60)

    # Start training timer
    start_time = time.time()

    # Set dataset paths
    train_path = './data/train_multiclass.csv'
    test_path = './data/test_multiclass.csv'

    # Load training and testing data
    print("[*] Loading and merging data...")

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # Merge training and testing data
    df_merged = pd.concat(
        [df_train, df_test],
        ignore_index=True
    )

    # Separate features and labels
    X = df_merged.drop(
        columns=['Label']
    )

    y = df_merged['Label']

    # Count the number of classes
    num_class = len(
        np.unique(y)
    )

    # Show dataset information
    print(
        f"[+] Total flows after merging: {X.shape[0]:,}"
    )

    print(
        f"[+] Number of classes: {num_class}"
    )

    # Calculate sample weights for class imbalance
    print(
        "[*] Computing sample weights to handle class imbalance..."
    )

    sample_weights = compute_sample_weight(
        class_weight='balanced',
        y=y
    )

    # Create multiclass classification model
    print(
        "[*] Training multiclass model on 100% data..."
    )

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

    # Train multiclass model
    model.fit(
        X,
        y,
        sample_weight=sample_weights
    )

    # Save multiclass model
    joblib.dump(
        model,
        './models/multiclass.pkl'
    )

    # Show training result
    print(
        "\n[+] Training completed. multiclass.pkl is ready."
    )

    # Show training time
    print(
        f"[+] Time: {time.time() - start_time:.2f}s."
    )


# Run all training processes
def main():
    # Start total training timer
    total_start = time.time()

    # Train binary model
    train_binary()

    # Train multiclass model
    train_multiclass()

    # Show final training result
    print("\n" + "=" * 60)
    print("[+] ALL TRAINING FINISHED!")

    # Show total training time
    print(
        f"[+] Total time: {time.time() - total_start:.2f}s."
    )

    print("=" * 60)


# Start the training program
if __name__ == "__main__":
    main()