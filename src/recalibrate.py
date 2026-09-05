"""
Sinh lại models/threshold.json mà KHÔNG huấn luyện lại.

Model được deploy là models/binary_eval.pkl — fit trên dữ liệu ngày 1, chấm trên
ngày 2 chưa từng thấy. Script này đo lại nó trên ngày 2, chọn ngưỡng theo mục
tiêu FPR, rồi ghi threshold.json.

VÌ SAO KHÔNG DÙNG binary.pkl:

    binary.pkl được fit trên 100% dữ liệu (cả hai ngày), nên không còn một dòng
    nào chưa thấy để hiệu chỉnh ngưỡng cho nó. Mọi ngưỡng gán cho nó đều không
    kiểm chứng được.

    Bản trước của script này cố lách bằng cách giữ nguyên *phân vị*: lấy ngưỡng
    của model production tại đúng phân vị mà ngưỡng eval chiếm trong phân phối
    điểm số benign. Nhưng phân phối đó được tính trên chính dữ liệu model đã học
    thuộc. Model chấm điểm rất thấp cho các dòng benign nó đã nhớ, nên phân vị
    cho ra ngưỡng thấp giả tạo. Đo trên đúng dữ liệu của dự án:

        phân vị   ngưỡng in-sample   ngưỡng đúng (out-of-sample)
        0.999           0.906629              0.999389
        0.9999          0.936523              0.999389
        0.99998         0.958699              0.999611

        Dùng ngưỡng in-sample 0.9587 (kỳ vọng FPR 0,002%)
        → FPR thực tế trên dữ liệu chưa thấy: 0,259%  — gấp 130 lần.

    Hậu quả thật: ngưỡng 0,9649 sinh ra theo cách đó đã chặn nhầm lưu lượng CDN
    hợp lệ ngay trong lần chạy thử đầu tiên trên VM.

    Không có cách nào hiệu chỉnh trung thực cho một model đã nhìn thấy toàn bộ
    dữ liệu. Nên deploy đúng model đã đo được: binary_eval.pkl.

Đọc dữ liệu theo chunk vì test_binary.csv khoảng 1,9 GB.
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

# File model được deploy và được mô tả bởi threshold.json
DEPLOYED_MODEL = "binary_eval.pkl"

# Mục tiêu FPR cho riêng nhánh TCP.
#
# Lỏng hơn TARGET_FPR chung một cách có chủ đích. Lớp Syn được model chấm điểm
# thấp hơn hẳn các lớp phản xạ UDP (trung vị 0,68 so với ~1,0), nên ép nó vào
# cùng mục tiêu FPR đồng nghĩa với bỏ lọt gần hết SYN flood:
#
#     ngưỡng TCP   bắt Syn    FPR benign TCP
#        0,90       96,54%        0,4944%
#        0,95       55,00%        0,3304%
#        0,99       49,51%        0,1896%
#        0,9999     28,47%        0,0000%
#
# Chi phí này không rơi xuống người dùng cuối, vì gatekeeper chỉ chặn sau
# VERDICTS_TO_BAN phán quyết trên cùng một IP. Ở K=5, FPR 0,4944% mỗi flow
# tương ứng 4,30e-08 mỗi IP — thấp hơn kiến trúc cũ khoảng 8.400 lần.
TARGET_FPR_TCP = float(
    os.environ.get("TARGET_FPR_TCP", "0.005")
)


# Chấm điểm một CSV theo chunk, trả về xác suất tách riêng benign / attack.
#
# Chỉ giữ mảng xác suất (float32) chứ không giữ khung dữ liệu, nên bộ nhớ đỉnh
# chỉ bằng một chunk cộng hai mảng điểm số.
def score_csv(model, path):
    expected = list(FEATURE_NAMES) + ["Label"]

    parts_benign = []
    parts_attack = []

    # Tách riêng theo giao thức để hiệu chỉnh ngưỡng TCP độc lập
    parts_benign_tcp = []
    parts_attack_tcp = []

    rows = 0
    t0 = time.time()

    for chunk in pd.read_csv(path, chunksize=CHUNK_ROWS, low_memory=False):
        if list(chunk.columns) != expected:
            raise SystemExit(
                f"\n[-] {os.path.basename(path)} không khớp feature contract.\n"
                f"[-] Chạy lại: python src/parser.py"
            )

        y = chunk["Label"].to_numpy()

        proba = model.predict_proba(
            chunk[FEATURE_NAMES].astype(np.float32)
        )[:, 1].astype(np.float32)

        parts_benign.append(proba[y == 0])
        parts_attack.append(proba[y == 1])

        tcp = chunk["Protocol"].to_numpy() == 6

        parts_benign_tcp.append(proba[(y == 0) & tcp])
        parts_attack_tcp.append(proba[(y == 1) & tcp])

        rows += len(chunk)

        print(f"    đã chấm {rows:,} dòng ({time.time() - t0:.0f}s)", end="\r")

    print(" " * 70, end="\r")

    return (
        np.concatenate(parts_benign),
        np.concatenate(parts_attack),
        np.concatenate(parts_benign_tcp),
        np.concatenate(parts_attack_tcp),
    )


# Quét lưới ngưỡng trên điểm số đã tính sẵn.
def sweep(proba_benign, proba_attack, target_fpr=TARGET_FPR):
    print(f"\n{'ngưỡng':>10} {'FPR':>10} {'TPR':>10} "
          f"{'prec@1%':>10} {'prec@0.1%':>11}")
    print("    " + "-" * 51)

    results = []

    for t in THRESHOLD_GRID:
        fpr = float((proba_benign >= t).mean()) if proba_benign.size else 0.0
        tpr = float((proba_attack >= t).mean()) if proba_attack.size else 0.0

        # Độ chính xác của dashboard ở tỉ lệ tấn công thực tế
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

        print(f"\n    [+] Ngưỡng {threshold:.4f} đạt mục tiêu FPR {target_fpr:.2%}")

    else:
        threshold, fpr, tpr = results[-1]

        print(f"\n    [!] Không ngưỡng nào đạt {target_fpr:.2%}; "
              f"dùng ngưỡng chặt nhất ({threshold:.4f})")

    print(f"        FPR {fpr:.4%} / TPR {tpr:.4%}")

    return threshold, fpr, tpr


def main():
    warnings.filterwarnings("ignore")

    model_path = _path("models", DEPLOYED_MODEL)

    if not os.path.exists(model_path):
        raise SystemExit(
            f"\n[-] Thiếu {model_path}.\n"
            f"[-] Chưa từng huấn luyện, hãy chạy: python src/trainer.py"
        )

    print("=" * 68)
    print("[*] HIỆU CHỈNH LẠI NGƯỠNG (không huấn luyện lại)")
    print(f"[*] Model được deploy: models/{DEPLOYED_MODEL}")
    print("=" * 68)

    model = joblib.load(model_path)

    # Chặn ngay nếu model trên đĩa không còn khớp hợp đồng feature: ghi ra một
    # threshold.json mô tả sai model là tệ hơn là không ghi gì.
    n = getattr(model, "n_features_in_", None)

    if n is not None and int(n) != len(FEATURE_NAMES):
        raise SystemExit(
            f"\n[-] {DEPLOYED_MODEL} nhận {int(n)} feature nhưng features.py "
            f"khai báo {len(FEATURE_NAMES)}.\n"
            f"[-] Model đã cũ — phải huấn luyện lại: python src/trainer.py"
        )

    print(f"[+] Nạp model xong, {len(FEATURE_NAMES)} feature.")

    # Chấm trên ngày 2 — dữ liệu model CHƯA từng thấy. Đây là toàn bộ lý do
    # những con số dưới đây đáng tin.
    print("\n[*] Chấm trên dữ liệu ngày 2 (chưa từng thấy)...")

    benign, attack, benign_tcp, attack_tcp = score_csv(
        model, _path("data", "test_binary.csv")
    )

    print(f"[+] Ngày 2: {benign.size:,} dòng benign / {attack.size:,} dòng attack")
    print(f"[+] Riêng TCP: {benign_tcp.size:,} benign / {attack_tcp.size:,} attack")

    fpr_05 = float((benign >= 0.5).mean()) if benign.size else 0.0
    tpr_05 = float((attack >= 0.5).mean()) if attack.size else 0.0

    threshold, fpr, tpr = sweep(benign, attack)

    # Ngưỡng riêng cho TCP.
    #
    # Một ngưỡng chung không phục vụ được cả hai họ tấn công. Các lớp phản xạ
    # UDP (MSSQL/UDP/NetBIOS/LDAP) được model chấm ~1,0 nên ngưỡng rất chặt
    # không tốn gì, bắt được 99,3–99,97%. Lớp Syn có trung vị điểm số chỉ 0,68,
    # nên cùng ngưỡng đó chỉ bắt được 28,47% — tức là tuyến AI gần như không
    # phát hiện được SYN flood.
    #
    # Sai số mỗi flow tăng lên được VERDICTS_TO_BAN bù lại: gatekeeper chỉ chặn
    # sau K phán quyết trên cùng một IP, nên FPR 0,4944% mỗi flow tương ứng
    # 4,30e-08 mỗi IP ở K=5.
    print("\n[*] Hiệu chỉnh ngưỡng RIÊNG cho TCP (nơi chứa SYN flood)...")

    threshold_tcp, fpr_tcp, tpr_tcp = sweep(
        benign_tcp, attack_tcp, target_fpr=TARGET_FPR_TCP
    )

    # Cùng cổng chất lượng mà trainer.py áp dụng
    failures = []

    if fpr > MAX_BENIGN_FPR:
        failures.append(f"FPR {fpr:.4%} vượt trần {MAX_BENIGN_FPR:.2%}")

    if tpr < MIN_ATTACK_TPR:
        failures.append(f"TPR {tpr:.4%} dưới mức tối thiểu {MIN_ATTACK_TPR:.2%}")

    if failures:
        print("\n[-] CỔNG CHẤT LƯỢNG KHÔNG ĐẠT:")

        for reason in failures:
            print(f"    - {reason}")

        print("\n[-] Model trên đĩa không đủ tốt để deploy. "
              "Huấn luyện lại: python src/trainer.py")

        raise SystemExit(1)

    print("\n[+] CỔNG CHẤT LƯỢNG ĐẠT")

    payload = {
        "threshold": float(threshold),

        # Ngưỡng riêng cho TCP — nơi duy nhất chứa SYN flood. Xem TARGET_FPR_TCP.
        "threshold_tcp": float(threshold_tcp),
        "measured_fpr_tcp": float(fpr_tcp),
        "measured_tpr_tcp": float(tpr_tcp),
        "target_fpr_tcp": float(TARGET_FPR_TCP),

        # Model nào được mô tả bởi file này. gatekeeper.py nạp đúng file này.
        "model_file": f"models/{DEPLOYED_MODEL}",
        "calibrated_on": "deployed_model",

        # Đo trên ngày 2 chưa từng thấy — CHÍNH LÀ số để đưa vào báo cáo, và
        # cũng chính là model đang chạy. Không còn khoảng cách giữa hai thứ.
        "measured_fpr": float(fpr),
        "measured_tpr": float(tpr),
        "fpr_at_0.5": float(fpr_05),
        "tpr_at_0.5": float(tpr_05),
        "metrics_source": f"models/{DEPLOYED_MODEL} (day-1 fit, day-2 holdout)",

        "target_fpr": float(TARGET_FPR),
        "n_features": len(FEATURE_NAMES),
        "feature_names": list(FEATURE_NAMES),
        "binary_sha256": sha256_file(model_path),
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "recalibrated_without_retrain": True,
    }

    out_path = _path("models", "threshold.json")

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print("\n" + "=" * 68)
    print(f"[+] Đã ghi {out_path}")
    print(f"[+] Model deploy   : models/{DEPLOYED_MODEL}")
    print(f"[+] Ngưỡng UDP/khác: {threshold:.6f}")
    print(f"[+] Ngưỡng TCP     : {threshold_tcp:.6f}")
    print(f"[+] FPR / TPR THẬT : {fpr:.4%} / {tpr:.4%}  (đo trên ngày 2)")
    print(f"[+] FPR / TPR TCP  : {fpr_tcp:.4%} / {tpr_tcp:.4%}")
    print(f"[+] sha256         : {payload['binary_sha256'][:16]}...")
    print("=" * 68)


if __name__ == "__main__":
    main()
