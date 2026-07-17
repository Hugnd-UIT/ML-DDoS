import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import classification_report, f1_score, confusion_matrix
import os
import time


def train_binary():
    print("\n" + "=" * 60)
    print("[*] Starting BINARY training process")
    print("=" * 60)
    start_time = time.time()

    train_path = './data/train_binary.csv'
    test_path = './data/test_binary.csv'

    print("[*] Loading data...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    X_train = df_train.drop(columns=['Label'])
    y_train = df_train['Label']
    X_test = df_test.drop(columns=['Label'])
    y_test = df_test['Label']

    print(f"[+] Loaded {X_train.shape[0]:,} train flows, {X_test.shape[0]:,} test flows.")

    print("[*] Training binary model...")
    model = XGBClassifier(
        n_estimators=150,
        max_depth=7,
        tree_method='hist',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
        early_stopping_rounds=20
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    print("\n[*] Evaluating on test set...")
    y_pred = model.predict(X_test)

    f1 = f1_score(y_test, y_pred)
    print(f"[+] F1-Score: {f1:.4f}")
    print("\n[*] Classification report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK'], digits=4))

    cm = confusion_matrix(y_test, y_pred)
    print("[*] Confusion matrix (rows=actual, cols=predicted):")
    print(cm)

    os.makedirs('./models', exist_ok=True)
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
    label_encoder_path = './models/label.pkl'

    print("[*] Loading data...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    X_train = df_train.drop(columns=['Label'])
    y_train = df_train['Label']
    X_test = df_test.drop(columns=['Label'])
    y_test = df_test['Label']

    label_encoder = joblib.load(label_encoder_path)
    num_class = len(label_encoder.classes_)

    print(f"[+] Loaded {X_train.shape[0]:,} train flows, {X_test.shape[0]:,} test flows.")
    print(f"[+] Number of classes: {num_class}")

    print("[*] Computing sample weights to handle class imbalance...")
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

    class_counts = pd.Series(y_train).value_counts().sort_index()
    print("[*] Class distribution (train):")
    for cls_idx, count in class_counts.items():
        cls_name = label_encoder.inverse_transform([cls_idx])[0]
        print(f"    - {cls_name} (idx {cls_idx}): {count:,}")

    print("[*] Training multiclass model...")
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
        n_jobs=-1,
        early_stopping_rounds=20
    )

    model.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    print("\n[*] Evaluating on test set...")
    y_pred = model.predict(X_test)

    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_weighted = f1_score(y_test, y_pred, average='weighted')
    print(f"[+] F1-Score (macro)   : {f1_macro:.4f}")
    print(f"[+] F1-Score (weighted): {f1_weighted:.4f}")

    target_names = [str(c) for c in label_encoder.classes_]
    present_labels = sorted(set(y_test) | set(y_pred))
    print("\n[*] Classification report:")
    print(classification_report(
        y_test, y_pred,
        labels=present_labels,
        target_names=[target_names[i] for i in present_labels],
        digits=4,
        zero_division=0
    ))

    cm = confusion_matrix(y_test, y_pred, labels=present_labels)
    print("[*] Confusion matrix (rows=actual, cols=predicted):")
    print(cm)

    os.makedirs('./models', exist_ok=True)
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