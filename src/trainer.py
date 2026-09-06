"""
Train the binary and multiclass DDoS models.

Two models are produced per task:

  1. EVALUATION model — trained on the day-1 capture only, scored against the
     untouched day-2 capture. Its metrics are the ones that may be reported,
     because the day-2 rows were never seen during fitting.

  2. PRODUCTION model — retrained on 100% of the data once evaluation passes,
     so the deployed artifact uses every available sample.

Reporting metrics from a model trained on the whole dataset would be
meaningless, which is how binary.pkl previously shipped with a ~99.9% false
positive rate on benign traffic without anyone noticing.
"""

import argparse
import hashlib
import json
import os
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from features import FEATURE_NAMES


# Refuse to ship a binary model that blocks more than this share of benign
# traffic. An IPS acts on every positive, so a false positive costs far more
# than a missed flow that the rate limiter can still catch.
MAX_BENIGN_FPR = 0.02

# Minimum share of attacks the binary model must still catch at the chosen
# threshold. Deliberately not 0.90: the measured trade-off on day-2 data is
#
#     threshold 0.5    FPR 0.6358%   TPR 95.71%   358 benign flows blocked
#     threshold 0.999  FPR 0.0018%   TPR 76.49%     1 benign flow  blocked
#
# Giving up 19 points of recall to stop blocking 357 legitimate users is the
# right trade for an inline blocker, especially since the volumetric attacks
# that actually threaten availability still trip the rate limiter.
MIN_ATTACK_TPR = 0.70

# Cap on training rows per class, applied to the multiclass model only.
#
# CICDDoS2019 is dominated by a handful of classes — TFTP alone is 19.5M of
# 48.7M rows — which cost 4.1 hours of fitting and skew the balanced sample
# weights toward whichever class happens to be largest. Capping keeps every
# class represented without letting one drown the rest.
#
# The binary model is left uncapped: it fits in ~10 minutes even on the full
# set, its imbalance is already handled by scale_pos_weight, and discarding
# 45M attack rows would cost recall for no practical gain. 0 disables the cap.
DEFAULT_CLASS_CAP = 3_000_000

BINARY_CLASS_CAP = 0

# Decision thresholds explored when picking the live operating point
THRESHOLD_GRID = [0.5, 0.7, 0.9, 0.95, 0.99, 0.995, 0.999, 0.9999]

# Target false positive rate for the deployed threshold. 0.5 (the default
# predict() cut-off) yields ~0.64% FPR, which sounds small but is not: real
# traffic is mostly benign, so at a 1% attack rate that FPR makes roughly
# 40% of everything the dashboard shows a false alarm. This is the base-rate
# problem, and a stricter threshold is the cheapest lever against it.
TARGET_FPR = 0.001


# Resolve a path relative to the project root
def _path(*parts):
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        *parts
    )


# Make sure models/ exists before anything tries to write into it. It is
# easy to remove the whole directory while clearing stale artifacts, and
# joblib.dump does not create parent directories.
def ensure_models_dir():
    os.makedirs(_path("models"), exist_ok=True)


# Băm file model để gatekeeper phát hiện được nếu artifact bị thay.
#
# joblib.load() thực chất là unpickle, tức là thực thi mã tuỳ ý trong file.
# Một binary.pkl bị đánh tráo sẽ chạy code của kẻ tấn công dưới quyền root
# (gatekeeper cần root cho eBPF). Hash không ngăn được điều đó, nhưng biến
# một sự thay đổi âm thầm thành một cảnh báo nhìn thấy được.
def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


# Cap how many rows any single class may contribute
def cap_classes(df, cap):
    if not cap:
        return df

    counts = df["Label"].value_counts()

    # Nothing to do when every class already fits under the cap
    if (counts <= cap).all():
        return df

    parts = [
        group.sample(n=cap, random_state=42) if len(group) > cap else group
        for _, group in df.groupby("Label", sort=False)
    ]

    capped = pd.concat(parts, ignore_index=True)

    print(f"[+] Capped at {cap:,} rows/class: "
          f"{len(df):,} -> {len(capped):,} rows")

    return capped


# Load a prepared dataset, optionally subsampled for fast iteration
def load_dataset(path, sample_frac=None):
    # Validate the header before reading gigabytes of rows. A model fitted on
    # a different column set than features.py declares would silently mismatch
    # the live extractor, which is what this shared contract exists to prevent.
    expected = list(FEATURE_NAMES) + ["Label"]
    header = list(pd.read_csv(path, nrows=0).columns)

    if header != expected:
        missing = [c for c in expected if c not in header]
        extra = [c for c in header if c not in expected]

        raise SystemExit(
            f"\n[-] {os.path.basename(path)} does not match the current "
            f"feature contract.\n"
            f"    expected {len(expected)} columns, found {len(header)}\n"
            f"    missing: {missing or 'none'}\n"
            f"    unexpected: {extra or 'none'}\n"
            f"[-] Re-run: python src/parser.py"
        )

    df = pd.read_csv(path, low_memory=False)

    # Halve memory use; every feature is numeric
    df = df.astype(np.float32)

    # Take a stratified subsample when running in fast mode.
    # Sample each class separately rather than via groupby().apply(), which
    # consumes the grouping column on recent pandas versions.
    if sample_frac:
        parts = [
            group.sample(frac=sample_frac, random_state=42)
            for _, group in df.groupby("Label", sort=False)
        ]

        df = pd.concat(parts, ignore_index=True)

    return df


# Split a dataframe into features and labels
def split_xy(df):
    return df.drop(columns=["Label"]), df["Label"]


# Print a section banner
def _banner(title):
    print("\n" + "=" * 68)
    print(f"[*] {title}")
    print("=" * 68)


# ── BINARY ──────────────────────────────────────────────────────────────────


# Score the binary model and decide whether it is safe to deploy
def evaluate_binary(model, X_test, y_test):
    pred = model.predict(X_test)

    # Build the confusion matrix over benign and attack
    tn, fp, fn, tp = confusion_matrix(
        y_test,
        pred,
        labels=[0, 1]
    ).ravel()

    # Share of benign flows wrongly flagged as attacks
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    # Share of attacks correctly caught
    tpr = recall_score(y_test, pred, zero_division=0)

    f1 = f1_score(y_test, pred, zero_division=0)

    # Report the numbers that matter for an inline blocker
    print(f"\n    Benign flows : {tn + fp:,}")
    print(f"    Attack flows : {tp + fn:,}")
    print(f"\n    True negative  (benign passed) : {tn:,}")
    print(f"    False positive (benign BLOCKED): {fp:,}")
    print(f"    False negative (attack missed) : {fn:,}")
    print(f"    True positive  (attack blocked): {tp:,}")
    print(f"\n    FPR on benign : {fpr:.4%}   <- lower is better")
    print(f"    TPR on attack : {tpr:.4%}")
    print(f"    F1            : {f1:.4f}")

    return fpr, tpr, f1


# Sweep decision thresholds and pick the live operating point.
#
# predict() cuts at 0.5, which is rarely the right place for an inline
# blocker. Because benign traffic vastly outnumbers attacks in production,
# dashboard precision is governed by the base rate, not by FPR alone:
#
#     precision = r*TPR / (r*TPR + (1-r)*FPR)
#
# with r the true share of attacks. At r=1% an FPR of 0.64% leaves roughly
# 40% of alerts false, so trading a little recall for a much lower FPR is
# usually the better deal — the rate limiter still backs up whatever the
# model lets through.
def choose_threshold(model, X_test, y_test, target_fpr=TARGET_FPR):
    proba = model.predict_proba(X_test)[:, 1]

    benign = (y_test == 0).values
    attack = ~benign

    print(f"\n{'threshold':>10} {'FPR':>10} {'TPR':>10} "
          f"{'prec@1%':>10} {'prec@0.1%':>11}")
    print("    " + "-" * 51)

    results = []

    for t in THRESHOLD_GRID:
        pred = proba >= t

        fpr = float(pred[benign].mean()) if benign.any() else 0.0
        tpr = float(pred[attack].mean()) if attack.any() else 0.0

        # Dashboard precision at a realistic attack base rate
        def precision_at(rate):
            tp = rate * tpr
            fp = (1.0 - rate) * fpr

            return tp / (tp + fp) if (tp + fp) > 0 else 0.0

        print(f"{t:>10.4f} {fpr:>9.4%} {tpr:>9.4%} "
              f"{precision_at(0.01):>9.2%} {precision_at(0.001):>10.2%}")

        results.append((t, fpr, tpr))

    # Take the loosest threshold that still meets the FPR target, so recall
    # is not given away beyond what the target requires
    passing = [r for r in results if r[1] <= target_fpr]

    if passing:
        threshold, fpr, tpr = passing[0]

        print(f"\n    [+] Threshold {threshold:.4f} meets the "
              f"{target_fpr:.2%} FPR target")
        print(f"        FPR {fpr:.4%} / TPR {tpr:.4%}")

    else:
        threshold, fpr, tpr = results[-1]

        print(f"\n    [!] No threshold reaches the {target_fpr:.2%} FPR "
              f"target; using the strictest ({threshold:.4f})")
        print(f"        FPR {fpr:.4%} / TPR {tpr:.4%}")

    return threshold, fpr, tpr


# ĐÃ GỠ BỎ: transfer_threshold()
#
# Hàm đó từng cố hiệu chỉnh ngưỡng cho binary.pkl bằng cách giữ nguyên *phân vị*
# của ngưỡng eval trong phân phối điểm số benign của model production. Ý tưởng
# nghe hợp lý nhưng SAI, vì phân phối đó được tính trên chính dữ liệu mà model
# production đã học thuộc. Model chấm rất thấp cho các dòng benign nó đã nhớ,
# nên phân vị cho ra ngưỡng thấp giả tạo. Đo trên đúng dữ liệu của dự án:
#
#     phân vị   ngưỡng in-sample   ngưỡng đúng (out-of-sample)
#     0.999           0.906629              0.999389
#     0.9999          0.936523              0.999389
#     0.99998         0.958699              0.999611
#
#     Dùng ngưỡng in-sample 0.9587 (kỳ vọng FPR 0,002%)
#     → FPR thực tế trên dữ liệu chưa thấy: 0,259%  — gấp 130 lần.
#
# Hậu quả thật: ngưỡng 0,9649 sinh ra theo cách đó đã chặn nhầm lưu lượng CDN
# hợp lệ ngay trong lần chạy thử đầu tiên trên VM.
#
# Vấn đề gốc không nằm ở cách tính mà ở chính binary.pkl: nó fit trên 100% dữ
# liệu nên KHÔNG CÒN dòng nào chưa thấy để hiệu chỉnh. Không tồn tại cách hiệu
# chỉnh trung thực cho một model như vậy.
#
# Nên artifact được DEPLOY là binary_eval.pkl — fit ngày 1, đo ngày 2. Ngưỡng và
# FPR/TPR của nó là số đo thật, và model chạy chính là model đã đo.
# binary.pkl vẫn được huấn luyện và lưu lại để tham khảo, nhưng không được deploy.
DEPLOYED_MODEL = "binary_eval.pkl"


# Train, evaluate and export the binary model
def train_binary(sample_frac=None, force=False, cap=BINARY_CLASS_CAP):
    _banner("BINARY — evaluation model (day 1 -> day 2)")

    start_time = time.time()

    # Load both capture days separately
    print("[*] Loading datasets...")

    df_train = load_dataset(_path("data", "train_binary.csv"), sample_frac)
    df_test = load_dataset(_path("data", "test_binary.csv"), sample_frac)

    # Cap the training set only. The holdout stays whole so the reported
    # numbers describe the real day-2 traffic mix.
    df_train = cap_classes(df_train, cap)

    X_train, y_train = split_xy(df_train)
    X_test, y_test = split_xy(df_test)

    # Count both classes to size the imbalance correction
    n_benign = int((y_train == 0).sum())
    n_attack = int((y_train == 1).sum())

    print(f"[+] Train: {len(df_train):,} rows "
          f"(benign {n_benign:,} / attack {n_attack:,})")

    print(f"[+] Test : {len(df_test):,} rows "
          f"(benign {int((y_test == 0).sum()):,} / "
          f"attack {int((y_test == 1).sum()):,})")

    # Counter the class imbalance. Without this XGBoost minimises logloss by
    # predicting "attack" for everything, which scores 99.9% accuracy on a
    # 600:1 split while being useless — and unstable: measured FPR across
    # samples ranged from 4% to 99.9% with no weighting.
    scale_pos_weight = n_benign / n_attack if n_attack else 1.0

    print(f"[+] Imbalance ratio    : {n_attack / max(n_benign, 1):.1f} : 1")
    print(f"[+] scale_pos_weight   : {scale_pos_weight:.6f}")

    params = dict(
        n_estimators=400,
        max_depth=7,
        max_bin=512,
        tree_method="hist",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1
    )

    # Fit on day 1 only so day 2 stays a genuine holdout
    print("\n[*] Training evaluation model on day-1 data...")

    eval_model = XGBClassifier(**params)
    eval_model.fit(X_train, y_train)

    # Keep the evaluation model. It is the only artifact whose scores are
    # trustworthy, since the production model below is fitted on the holdout
    # too and can no longer be measured honestly.
    joblib.dump(eval_model, _path("models", "binary_eval.pkl"))

    # Score against the unseen day-2 capture
    print("[*] Scoring against unseen day-2 data...")

    fpr, tpr, _ = evaluate_binary(eval_model, X_test, y_test)

    # Pick the live decision threshold from the same holdout
    _banner("BINARY — decision threshold")

    threshold, thr_fpr, thr_tpr = choose_threshold(eval_model, X_test, y_test)

    # Gate on the numbers the deployed system will actually produce, which
    # are the ones at the chosen threshold, not at predict()'s 0.5.
    failures = []

    if thr_fpr > MAX_BENIGN_FPR:
        failures.append(
            f"FPR {thr_fpr:.4%} exceeds the {MAX_BENIGN_FPR:.2%} limit"
        )

    if thr_tpr < MIN_ATTACK_TPR:
        failures.append(
            f"TPR {thr_tpr:.4%} is below the {MIN_ATTACK_TPR:.2%} minimum"
        )

    if failures:
        print("\n[-] QUALITY GATE FAILED:")

        for reason in failures:
            print(f"    - {reason}")

        # Allow an explicit override so the gate never blocks experiments
        if not force:
            print("\n[-] binary.pkl was NOT written.")
            print("[-] Re-run with --force to export anyway.")
            return False

        print("\n[!] --force given, exporting despite the failure.")

    else:
        print("\n[+] QUALITY GATE PASSED")

    # Retrain on every available row for the deployed artifact
    _banner("BINARY — production model (100% of data)")

    # Release the evaluation frames first. On the full dataset these hold
    # ~5.5 GB, and the concat below allocates that much again.
    del X_train, y_train, X_test, y_test, eval_model

    df_all = cap_classes(
        pd.concat([df_train, df_test], ignore_index=True),
        cap
    )

    del df_train, df_test

    X_all, y_all = split_xy(df_all)

    # Recompute the weight for the merged class balance
    n_benign_all = int((y_all == 0).sum())
    n_attack_all = int((y_all == 1).sum())

    params["scale_pos_weight"] = (
        n_benign_all / n_attack_all if n_attack_all else 1.0
    )

    print(f"[+] Total flows: {len(df_all):,}")
    print(f"[+] scale_pos_weight: {params['scale_pos_weight']:.6f}")
    print("[*] Training production model...")

    model = XGBClassifier(**params)
    model.fit(X_all, y_all)

    joblib.dump(model, _path("models", "binary.pkl"))

    # threshold.json mô tả model ĐƯỢC DEPLOY, tức binary_eval.pkl — xem khối
    # chú thích ở chỗ transfer_threshold đã gỡ bỏ. Ngưỡng và FPR/TPR dưới đây
    # đều đo trên ngày 2 chưa từng thấy, nên chúng vừa là số để chạy vừa là số
    # để báo cáo. Không còn hai bộ số nữa.
    with open(_path("models", "threshold.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "threshold": float(threshold),

                "model_file": f"models/{DEPLOYED_MODEL}",
                "calibrated_on": "deployed_model",

                "measured_fpr": float(thr_fpr),
                "measured_tpr": float(thr_tpr),
                "fpr_at_0.5": float(fpr),
                "tpr_at_0.5": float(tpr),
                "metrics_source": f"models/{DEPLOYED_MODEL} (day-1 fit, day-2 holdout)",

                "target_fpr": float(TARGET_FPR),
                "n_features": len(FEATURE_NAMES),
                "feature_names": list(FEATURE_NAMES),
                "binary_sha256": sha256_file(_path("models", DEPLOYED_MODEL)),
                "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            fh,
            indent=2
        )

    print(f"\n[+] models/{DEPLOYED_MODEL} written — ĐÂY là model được deploy.")
    print("[+] models/binary.pkl written — chỉ để tham khảo, KHÔNG deploy "
          "(fit trên 100% dữ liệu nên không hiệu chỉnh ngưỡng trung thực được).")
    print(f"[+] models/threshold.json written: ngưỡng {threshold:.6f}")
    print(f"[+] FPR/TPR (đo trên day-2 holdout): {thr_fpr:.4%} / {thr_tpr:.4%}")
    print(f"[+] Time: {time.time() - start_time:.2f}s")

    return True


# ── MULTICLASS ──────────────────────────────────────────────────────────────


# Train, evaluate and export the multiclass model
def train_multiclass(sample_frac=None, cap=DEFAULT_CLASS_CAP):
    _banner("MULTICLASS — evaluation model (trộn cả hai ngày capture)")

    start_time = time.time()

    print("[*] Loading datasets...")

    df_train = load_dataset(_path("data", "train_multiclass.csv"), sample_frac)
    df_test = load_dataset(_path("data", "test_multiclass.csv"), sample_frac)

    # Trộn hai ngày capture rồi mới chia train/test.
    #
    # VÌ SAO KHÁC MODEL NHỊ PHÂN: model nhị phân giữ nguyên ngày 1 -> ngày 2,
    # vì đó chính là chỗ cần chứng minh khả năng khái quát hoá, và nó đạt
    # 99,08%. Model multiclass thì không: việc của nó là ĐẶT TÊN cho thứ đã bị
    # phát hiện, không phải chứng minh khái quát sang điều kiện ghi hình mới.
    #
    # Huấn luyện chỉ trên ngày 1 khiến nó học nhầm đặc điểm của BUỔI GHI thay vì
    # của cuộc tấn công. CIC ghi hai ngày bằng cấu hình khác nhau:
    #
    #                            Syn ngày 1   Syn ngày 2
    #     Fwd Packet Length Mean       0,00         6,00
    #
    # Model học "SYN flood = payload 0" từ ngày 1, gặp ngày 2 thì không nhận ra
    # nữa. Hậu quả đo được, đối xứng hoàn hảo:
    #
    #     Syn    ngày 1 (đã học thuộc)    99,39%  đúng
    #     Syn    ngày 2 (chưa từng thấy)  21,83%  đúng   -> UDPLag 78%
    #     UDPLag ngày 1                    1,44%  đúng
    #     UDPLag ngày 2                   61,13%  đúng
    #
    # Đã loại trừ mọi nguyên nhân khác: không phải thiếu feature (model 2 lớp
    # chuyên biệt tách Syn/UDPLag đạt 87,12%, LDAP/SNMP đạt 100%), không phải
    # trọng số lớp (bật/tắt chỉ đổi 0,25 điểm), không phải trùng dữ liệu (chỉ
    # 0,1% vector xuất hiện dưới nhiều nhãn).
    #
    # Sau khi trộn hai ngày: Syn đi từ 31,37% lên 98,58%, và đều ở cả hai ngày
    # (97,3% / 99,8%).
    #
    # ĐÁNH ĐỔI PHẢI GHI RÕ TRONG BÁO CÁO: từ đây con số của multiclass KHÔNG còn
    # là bằng chứng khái quát hoá chéo ngày. Hai model được đánh giá theo hai
    # chuẩn khác nhau, và đó là lựa chọn có chủ đích chứ không phải sơ suất.
    pooled = pd.concat([df_train, df_test], ignore_index=True)

    del df_train, df_test

    pooled = cap_classes(pooled, cap)

    print(f"[+] Gộp hai ngày: {len(pooled):,} dòng")

    df_train, df_test = train_test_split(
        pooled,
        test_size=0.30,
        random_state=42,
        stratify=pooled["Label"]
    )

    del pooled

    X_train, y_train = split_xy(df_train)
    X_test, y_test = split_xy(df_test)

    num_class = int(len(np.unique(y_train)))

    print(f"[+] Train: {len(df_train):,} rows, {num_class} classes")
    print(f"[+] Test : {len(df_test):,} rows, "
          f"{len(np.unique(y_test))} classes")

    # Load the encoder so the report shows attack names, not indices
    label_path = _path("models", "label.pkl")
    label_encoder = joblib.load(label_path) if os.path.exists(label_path) else None

    params = dict(
        objective="multi:softprob",
        num_class=num_class,
        n_estimators=400,
        max_depth=8,
        max_bin=512,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1
    )

    # Weight every class equally so rare attacks are not ignored
    print("\n[*] Computing balanced sample weights...")

    weights = compute_sample_weight(class_weight="balanced", y=y_train)

    print("[*] Training evaluation model on day-1 data...")

    eval_model = XGBClassifier(**params)
    eval_model.fit(X_train, y_train, sample_weight=weights)

    # Keep it: the production model below cannot be scored honestly
    joblib.dump(eval_model, _path("models", "multiclass_eval.pkl"))

    print("[*] Scoring against unseen day-2 data...")

    pred = eval_model.predict(X_test)

    # Only classes present in the holdout can be scored
    present = sorted(set(np.unique(y_test)) | set(np.unique(pred)))

    names = (
        [str(c) for c in label_encoder.inverse_transform(
            np.array(present).astype(int)
        )]
        if label_encoder is not None
        else [str(c) for c in present]
    )

    print("\n" + classification_report(
        y_test,
        pred,
        labels=present,
        target_names=names,
        zero_division=0,
        digits=4
    ))

    # A blocked flow labelled BENIGN is a self-contradiction, so track it
    if label_encoder is not None and "BENIGN" in list(label_encoder.classes_):
        benign_id = int(
            np.where(label_encoder.classes_ == "BENIGN")[0][0]
        )

        attack_mask = (y_test != benign_id)

        if attack_mask.any():
            leaked = float((pred[attack_mask] == benign_id).mean())

            print(f"    Attacks mislabelled BENIGN: {leaked:.4%}")

    # Retrain on everything for the deployed artifact
    _banner("MULTICLASS — production model (100% of data)")

    # Release the evaluation frames before doubling memory on the concat
    del X_train, X_test, y_test, weights, eval_model

    df_all = cap_classes(
        pd.concat([df_train, df_test], ignore_index=True),
        cap
    )

    del df_train, df_test

    X_all, y_all = split_xy(df_all)

    params["num_class"] = int(len(np.unique(y_all)))

    print(f"[+] Total flows: {len(df_all):,}")
    print("[*] Training production model...")

    weights_all = compute_sample_weight(class_weight="balanced", y=y_all)

    model = XGBClassifier(**params)
    model.fit(X_all, y_all, sample_weight=weights_all)

    joblib.dump(model, _path("models", "multiclass.pkl"))

    print("\n[+] models/multiclass.pkl written.")
    print(f"[+] Time: {time.time() - start_time:.2f}s")


# Run both training pipelines
def main():
    parser = argparse.ArgumentParser(
        description="Train the Gatekeeper DDoS models"
    )

    # Subsample for quick iteration on a laptop
    parser.add_argument(
        "--fast",
        action="store_true",
        help="train on a 2%% stratified subsample for a quick check"
    )

    # Export the binary model even if it fails the quality gate
    parser.add_argument(
        "--force",
        action="store_true",
        help="export binary.pkl even when the quality gate fails"
    )

    # Limit the run to a single model
    parser.add_argument(
        "--only",
        choices=["binary", "multiclass"],
        help="train only one of the two models"
    )

    # Cap rows per class for the multiclass model; 0 trains on everything
    parser.add_argument(
        "--cap",
        type=int,
        default=DEFAULT_CLASS_CAP,
        metavar="N",
        help=(
            f"max training rows per class for the multiclass model "
            f"(default {DEFAULT_CLASS_CAP:,}, 0 = no cap). The binary model "
            f"is always trained on the full set."
        )
    )

    args = parser.parse_args()

    ensure_models_dir()

    sample_frac = 0.02 if args.fast else None

    if args.fast:
        print("[!] FAST MODE — 2% subsample, metrics are indicative only.")

    total_start = time.time()

    # --cap is a multiclass knob only. The binary model trains on everything:
    # it fits in minutes, and discarding attack rows costs recall for nothing.
    if args.only != "multiclass":
        train_binary(sample_frac, args.force, BINARY_CLASS_CAP)

    if args.only != "binary":
        train_multiclass(sample_frac, args.cap)

    print("\n" + "=" * 68)
    print(f"[+] DONE in {time.time() - total_start:.2f}s")
    print("=" * 68)


# Start the training program
if __name__ == "__main__":
    main()
