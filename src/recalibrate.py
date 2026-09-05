"""
Sinh lại models/threshold.json mà KHÔNG huấn luyện lại model.

Vì sao cần script này:

    trainer.py là đường đầy đủ — nó fit lại binary_eval.pkl rồi fit lại
    binary.pkl, sau đó mới ghi threshold.json. Nhưng khi model trên đĩa đã
    đúng và chỉ riêng threshold.json là lỗi thời (định dạng cũ, thiếu
    binary_sha256 / feature_names / ngưỡng hiệu chỉnh theo model production),
    thì chạy lại toàn bộ trainer vừa tốn hàng chục phút vừa GHI ĐÈ hai file
    .pkl — làm mọi con số FPR/TPR đã đưa vào báo cáo không còn mô tả đúng
    artifact đang nằm trên đĩa nữa.

    Script này dùng lại đúng binary_eval.pkl và binary.pkl hiện có, chỉ tính
    lại phần hiệu chỉnh ngưỡng và ghi threshold.json theo định dạng mới.

Nó làm đúng ba việc trainer.py làm ở khâu cuối:

  1. choose_threshold  — quét ngưỡng trên binary_eval.pkl với dữ liệu ngày 2
                         chưa từng thấy. Đây là nguồn của FPR/TPR TRUNG THỰC.
  2. transfer_threshold — chuyển ngưỡng đó sang binary.pkl theo PHÂN VỊ, vì
                         hai model có calibration khác nhau.
  3. sha256_file        — băm binary.pkl để gatekeeper phát hiện được đánh tráo.

Đọc dữ liệu theo chunk: test_binary.csv ~1,9 GB và train_binary.csv ~5 GB,
nạp thẳng vào RAM sẽ vượt quá bộ nhớ của phần lớn máy. Với model production
chỉ cần các dòng benign (khoảng 0,2% tổng số dòng) nên phần đó rất nhẹ.
"""

import json
import os
import time
import warnings

import joblib
import numpy as np
import pandas as pd

from features import FEATURE_NAMES
from trainer import (
    MAX_BENIGN_FPR,
    MIN_ATTACK_TPR,
    TARGET_FPR,
    THRESHOLD_GRID,
    _path,
    sha256_file,
)


# Số dòng đọc mỗi lượt. 1 triệu dòng × 19 cột ≈ 150 MB ở float32.
CHUNK_ROWS = 1_000_000


# Đọc một CSV theo chunk và trả về điểm số của model, tách benign / attack.
#
# Chỉ giữ lại mảng xác suất (float32, 4 byte mỗi dòng) chứ không giữ khung dữ
# liệu, nên bộ nhớ đỉnh chỉ bằng một chunk cộng với hai mảng điểm số.
def score_csv(model, path, label, keep_benign_only=False):
    expected = list(FEATURE_NAMES) + ["Label"]

    proba_benign = []
    proba_attack = []

    rows_seen = 0
    t0 = time.time()

    reader = pd.read_csv(path, chunksize=CHUNK_ROWS, low_memory=False)

    for chunk in reader:
        if list(chunk.columns) != expected:
            raise SystemExit(
                f"\n[-] {os.path.basename(path)} không khớp feature contract.\n"
                f"    Chạy lại: python src/parser.py"
            )

        y = chunk["Label"].to_numpy()

        if keep_benign_only:
            chunk = chunk[y == 0]
            y = y[y == 0]

            if chunk.empty:
                rows_seen += CHUNK_ROWS
                continue

        X = chunk[FEATURE_NAMES].astype(np.float32)

        proba = model.predict_proba(X)[:, 1].astype(np.float32)

        proba_benign.append(proba[y == 0])

        if not keep_benign_only:
            proba_attack.append(proba[y == 1])

        rows_seen += len(chunk)

        print(
            f"    {label}: {rows_seen:,} dòng "
            f"({time.time() - t0:.0f}s)",
            end="\r"
        )

    print(" " * 70, end="\r")

    benign = (
        np.concatenate(proba_benign)
        if proba_benign
        else np.array([], dtype=np.float32)
    )

    attack = (
        np.concatenate(proba_attack)
        if proba_attack
        else np.array([], dtype=np.float32)
    )

    return benign, attack


# Quét lưới ngưỡng trên điểm số đã tính sẵn.
#
# Giống choose_threshold() của trainer.py, nhưng nhận thẳng mảng xác suất thay
# vì (model, X, y) để không phải giữ khung dữ liệu trong bộ nhớ.
def sweep(proba_benign, proba_attack, target_fpr=TARGET_FPR):
    print(f"\n{'threshold':>10} {'FPR':>10} {'TPR':>10} "
          f"{'prec@1%':>10} {'prec@0.1%':>11}")
    print("    " + "-" * 51)

    results = []

    for t in THRESHOLD_GRID:
        fpr = float((proba_benign >= t).mean()) if proba_benign.size else 0.0
        tpr = float((proba_attack >= t).mean()) if proba_attack.size else 0.0

        def precision_at(rate):
            tp = rate * tpr
            fp = (1.0 - rate) * fpr

            return tp / (tp + fp) if (tp + fp) > 0 else 0.0

        print(f"{t:>10.4f} {fpr:>9.4%} {tpr:>9.4%} "
              f"{precision_at(0.01):>9.2%} {precision_at(0.001):>10.2%}")

        results.append((t, fpr, tpr))

    # Ngưỡng lỏng nhất vẫn đạt mục tiêu FPR, để không cho đi recall quá mức cần
    passing = [r for r in results if r[1] <= target_fpr]

    if passing:
        threshold, fpr, tpr = passing[0]

        print(f"\n    [+] Ngưỡng {threshold:.4f} đạt mục tiêu FPR "
              f"{target_fpr:.2%}")

    else:
        threshold, fpr, tpr = results[-1]

        print(f"\n    [!] Không ngưỡng nào đạt {target_fpr:.2%}; "
              f"dùng ngưỡng chặt nhất ({threshold:.4f})")

    print(f"        FPR {fpr:.4%} / TPR {tpr:.4%}")

    return threshold, fpr, tpr


def main():
    warnings.filterwarnings("ignore")

    binary_path = _path("models", "binary.pkl")
    eval_path = _path("models", "binary_eval.pkl")

    for path in (binary_path, eval_path):
        if not os.path.exists(path):
            raise SystemExit(
                f"\n[-] Thiếu {path}.\n"
                f"[-] Chưa từng huấn luyện, hãy chạy: python src/trainer.py"
            )

    print("=" * 68)
    print("[*] HIỆU CHỈNH LẠI NGƯỠNG (không huấn luyện lại)")
    print("=" * 68)

    eval_model = joblib.load(eval_path)
    prod_model = joblib.load(binary_path)

    # Chặn ngay nếu model trên đĩa không còn khớp hợp đồng feature: ghi ra một
    # threshold.json mô tả sai model là tệ hơn là không ghi gì.
    for name, model in (("binary_eval.pkl", eval_model), ("binary.pkl", prod_model)):
        n = getattr(model, "n_features_in_", None)

        if n is not None and int(n) != len(FEATURE_NAMES):
            raise SystemExit(
                f"\n[-] {name} nhận {int(n)} feature nhưng features.py khai "
                f"báo {len(FEATURE_NAMES)}.\n"
                f"[-] Model đã cũ — phải huấn luyện lại: python src/trainer.py"
            )

    print(f"[+] Nạp model xong, cả hai đều {len(FEATURE_NAMES)} feature.")

    # ── 1. Số liệu TRUNG THỰC trên model đánh giá + dữ liệu ngày 2 ───────────
    print("\n[*] Chấm binary_eval.pkl trên dữ liệu ngày 2 (chưa từng thấy)...")

    benign_eval, attack_eval = score_csv(
        eval_model,
        _path("data", "test_binary.csv"),
        "test_binary"
    )

    print(f"[+] Ngày 2: {benign_eval.size:,} dòng benign / "
          f"{attack_eval.size:,} dòng attack")

    fpr_05 = float((benign_eval >= 0.5).mean()) if benign_eval.size else 0.0
    tpr_05 = float((attack_eval >= 0.5).mean()) if attack_eval.size else 0.0

    eval_threshold, eval_fpr, eval_tpr = sweep(benign_eval, attack_eval)

    # Cùng cổng chất lượng mà trainer.py áp dụng
    failures = []

    if eval_fpr > MAX_BENIGN_FPR:
        failures.append(f"FPR {eval_fpr:.4%} vượt trần {MAX_BENIGN_FPR:.2%}")

    if eval_tpr < MIN_ATTACK_TPR:
        failures.append(f"TPR {eval_tpr:.4%} dưới mức tối thiểu {MIN_ATTACK_TPR:.2%}")

    if failures:
        print("\n[-] CỔNG CHẤT LƯỢNG KHÔNG ĐẠT:")

        for reason in failures:
            print(f"    - {reason}")

        print("\n[-] Model trên đĩa không đủ tốt để deploy. "
              "Huấn luyện lại: python src/trainer.py")

        raise SystemExit(1)

    print("\n[+] CỔNG CHẤT LƯỢNG ĐẠT")

    # ── 2. Chuyển ngưỡng sang model production theo phân vị ──────────────────
    print("\n[*] Đọc các dòng benign của TOÀN BỘ dữ liệu để hiệu chỉnh "
          "model production...")

    benign_parts = []

    for name in ("train_binary.csv", "test_binary.csv"):
        part, _ = score_csv(
            prod_model,
            _path("data", name),
            name,
            keep_benign_only=True
        )

        print(f"[+] {name}: {part.size:,} dòng benign")

        benign_parts.append(part)

    benign_prod = np.concatenate(benign_parts)

    if benign_prod.size == 0:
        raise SystemExit("\n[-] Không tìm thấy dòng benign nào để hiệu chỉnh.")

    quantile = min(max(1.0 - float(eval_fpr), 0.0), 1.0)

    prod_threshold = float(np.quantile(benign_prod, quantile))
    prod_threshold = min(max(prod_threshold, 0.5), 1.0 - 1e-9)

    achieved = float((benign_prod >= prod_threshold).mean())

    print(f"\n    Ngưỡng eval model       : {eval_threshold:.6f} "
          f"(FPR {eval_fpr:.4%})")
    print(f"    Phân vị benign tương ứng: {quantile:.6f}")
    print(f"    Ngưỡng model production : {prod_threshold:.6f} "
          f"(FPR in-sample {achieved:.4%})")
    print("    [!] FPR in-sample là lạc quan — model đã thấy dữ liệu này.")
    print("    [!] Số liệu để BÁO CÁO phải lấy từ binary_eval.pkl.")

    # ── 3. Ghi threshold.json theo đúng định dạng trainer.py sinh ra ─────────
    payload = {
        "threshold": float(prod_threshold),
        "calibrated_on": "production_model",

        "eval_threshold": float(eval_threshold),
        "measured_fpr": float(eval_fpr),
        "measured_tpr": float(eval_tpr),
        "fpr_at_0.5": float(fpr_05),
        "tpr_at_0.5": float(tpr_05),
        "metrics_source": "models/binary_eval.pkl (day-1 fit, day-2 holdout)",

        "target_fpr": float(TARGET_FPR),
        "n_features": len(FEATURE_NAMES),
        "feature_names": list(FEATURE_NAMES),
        "binary_sha256": sha256_file(binary_path),
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "recalibrated_without_retrain": True,
    }

    out_path = _path("models", "threshold.json")

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print("\n" + "=" * 68)
    print(f"[+] Đã ghi {out_path}")
    print(f"[+] Ngưỡng gatekeeper sẽ dùng : {prod_threshold:.6f}")
    print(f"[+] FPR/TPR để ĐƯA VÀO BÁO CÁO: {eval_fpr:.4%} / {eval_tpr:.4%}")
    print(f"[+] sha256 binary.pkl         : {payload['binary_sha256'][:16]}...")
    print("=" * 68)


if __name__ == "__main__":
    main()
