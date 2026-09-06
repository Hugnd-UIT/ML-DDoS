"""
Kiểm tra model có nhận đúng và đủ các loại tấn công trong CICDDoS2019 không.

Nạp dữ liệu THẬT từ tập kiểm tra, chạy qua đúng đường ống đang deploy
(binary_eval.pkl quyết định chặn + multiclass_eval.pkl đặt tên), rồi in bảng
nhận diện theo từng lớp.

    python src/test_classes.py

Đây là cách kiểm tra trung thực nhất: hping3 không tái hiện được các họ tấn công
phản xạ UDP vì chúng được nhận diện qua cổng dịch vụ giả của phòng lab.
"""

import json
import os
import sys
from collections import defaultdict

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from features import FEATURE_NAMES

BASE = os.path.join(os.path.dirname(__file__), "..")


def _p(*parts):
    return os.path.join(BASE, *parts)


def main():
    binary = joblib.load(_p("models", "binary_eval.pkl"))
    multi = joblib.load(_p("models", "multiclass_eval.pkl"))
    label = joblib.load(_p("models", "label.pkl"))
    names = list(label.classes_)

    meta = json.load(open(_p("models", "threshold.json"), encoding="utf-8"))
    t_other = meta["threshold"]
    t_tcp = meta.get("threshold_tcp", t_other)

    print(f"[*] Ngưỡng chặn: TCP {t_tcp} / khác {t_other}")
    print(f"[*] Các lớp model biết: {names}\n")

    tot = defaultdict(int)
    blocked = defaultdict(int)
    named = defaultdict(int)
    wrong = defaultdict(lambda: defaultdict(int))

    rng = np.random.default_rng(0)
    path = _p("data", "test_multiclass.csv")

    for chunk in pd.read_csv(path, chunksize=1_000_000, low_memory=False):
        # Lấy mẫu 20% cho nhanh; bỏ dòng này nếu muốn chạy toàn bộ
        chunk = chunk.iloc[rng.random(len(chunk)) < 0.20]

        if not len(chunk):
            continue

        X = chunk[FEATURE_NAMES].astype(np.float32)
        y = chunk["Label"].to_numpy()

        proba = binary.predict_proba(X)[:, 1]
        limit = np.where(chunk["Protocol"].to_numpy() == 6, t_tcp, t_other)
        is_blocked = proba >= limit
        pred = multi.predict(X)

        for a, b, q in zip(y, is_blocked, pred):
            a = int(a)
            tot[a] += 1

            if b:
                blocked[a] += 1

            if int(q) == a:
                named[a] += 1
            else:
                wrong[a][int(q)] += 1

    print(f"{'loại':<10} {'số dòng':>10} {'AI CHẶN':>9} {'ĐẶT TÊN':>9}  nhầm sang")
    print("-" * 74)

    atk_tot = atk_block = atk_name = 0

    for k in sorted(tot, key=lambda x: -tot[x]):
        name = names[k]

        if name == "BENIGN":
            continue

        atk_tot += tot[k]
        atk_block += blocked[k]
        atk_name += named[k]

        top = sorted(((v, c) for c, v in wrong[k].items()), reverse=True)[:2]
        ws = ", ".join(f"{names[c]} {v / tot[k]:.0%}" for v, c in top) or "-"

        print(f"{name:<10} {tot[k]:>10,} {blocked[k] / tot[k]:>8.1%} "
              f"{named[k] / tot[k]:>8.1%}  {ws}")

    benign = [x for x in tot if names[x] == "BENIGN"]

    if benign:
        k = benign[0]

        print(f"\n{'BENIGN':<10} {tot[k]:>10,} {blocked[k] / tot[k]:>8.1%} "
              f"{'':>8}  <- CHẶN nghĩa là báo động nhầm")

    print(f"\n[+] Tổng tấn công bị chặn: {atk_block / atk_tot:.2%}")
    print(f"[+] Tổng đặt tên đúng    : {atk_name / atk_tot:.2%}")


if __name__ == "__main__":
    main()
