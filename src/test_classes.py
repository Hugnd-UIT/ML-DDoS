"""
Kiểm tra model nhận đúng và đủ các loại tấn công trong CICDDoS2019 tới đâu.

    python src/test_classes.py

Chấm trên data/holdout_multiclass.csv — phần dữ liệu trainer.py tách ra và
KHÔNG dùng để huấn luyện. Đây là điểm khác quan trọng so với bản trước: bản đó
chấm trên nguyên data/test_multiclass.csv, mà sau khi trainer trộn hai ngày
capture rồi chia ngẫu nhiên thì khoảng 70% số dòng ấy nằm trong chính tập huấn
luyện. Con số in ra khi đó có phần là học thuộc chứ không phải khái quát hoá.

MỘT ĐIỀU PHẢI HIỂU KHI ĐỌC KẾT QUẢ. Cột "ĐẶT TÊN" dưới đây chỉ đo phần MÔ HÌNH,
tức khả năng phân loại dựa trên HÌNH DẠNG luồng. Nó không đo hệ thống đầy đủ.
Ngoài thực tế, họ tấn công phản xạ được định danh bằng CỔNG DỊCH VỤ NGUỒN theo
luật tất định trong app.py — và luật đó không kiểm chứng được trên CICDDoS2019,
vì cột cổng của dataset là cổng giả của phòng lab (DNS bắn từ 564 chứ không phải
53). Xem khối chú thích ở app.py và features.py.

Vài lớp có trần rất thấp và đó là giới hạn của DỮ LIỆU, không phải của model:
DNS và LDAP đều là gói lấp đầy MTU 1472 byte, SSDP và UDP đều 375 byte. Ở tầng
thống kê luồng chúng trùng khít nhau.
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

# Hai cặp lớp trùng khít nhau ở tầng thống kê luồng. Nhầm lẫn TRONG một cặp là
# giới hạn vật lý của dữ liệu, nên được thống kê riêng thay vì tính là lỗi.
INSEPARABLE = [{"DNS", "LDAP"}, {"SSDP", "UDP"}]


def _p(*parts):
    return os.path.join(BASE, *parts)


# Chọn tập chấm điểm, ưu tiên holdout thật
def pick_dataset():
    holdout = _p("data", "holdout_multiclass.csv")

    if os.path.exists(holdout):
        return holdout, True

    print("[!] Chưa có data/holdout_multiclass.csv — chạy lại "
          "`python src/trainer.py` để sinh ra nó.")

    print("[!] Tạm chấm trên data/test_multiclass.csv, nhưng phần lớn số dòng "
          "đó model ĐÃ HỌC, nên con số sẽ cao hơn thực tế.\n")

    return _p("data", "test_multiclass.csv"), False


def main():
    binary = joblib.load(_p("models", "binary_eval.pkl"))
    multi = joblib.load(_p("models", "multiclass_eval.pkl"))
    label = joblib.load(_p("models", "label.pkl"))
    names = list(label.classes_)

    meta = json.load(open(_p("models", "threshold.json"), encoding="utf-8"))
    t_other = meta["threshold"]
    t_tcp = meta.get("threshold_tcp", t_other)

    path, honest = pick_dataset()

    print(f"[*] Tập chấm : {os.path.basename(path)}"
          f"{' (model CHƯA từng thấy)' if honest else ''}")

    print(f"[*] Feature   : {len(FEATURE_NAMES)} cột, không có cổng")
    print(f"[*] Ngưỡng chặn: TCP {t_tcp} / khác {t_other}")
    print(f"[*] Lớp model biết: {names}\n")

    tot = defaultdict(int)
    blocked = defaultdict(int)
    named = defaultdict(int)
    twin = defaultdict(int)
    wrong = defaultdict(lambda: defaultdict(int))

    for chunk in pd.read_csv(path, chunksize=1_000_000, low_memory=False,
                             usecols=list(FEATURE_NAMES) + ["Label"]):
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

                # Nhầm sang lớp song sinh không tách được thì đếm riêng
                pair = {names[a], names[int(q)]}

                if any(pair <= grp for grp in INSEPARABLE):
                    twin[a] += 1

    print(f"{'loại':<10} {'số dòng':>9} {'AI CHẶN':>9} {'ĐẶT TÊN':>9} "
          f"{'+song sinh':>11}  nhầm sang")
    print("-" * 82)

    atk_tot = atk_block = atk_name = atk_twin = 0

    for k in sorted(tot, key=lambda x: -tot[x]):
        name = names[k]

        if name == "BENIGN":
            continue

        atk_tot += tot[k]
        atk_block += blocked[k]
        atk_name += named[k]
        atk_twin += twin[k]

        top = sorted(((v, c) for c, v in wrong[k].items()), reverse=True)[:2]
        ws = ", ".join(f"{names[c]} {v / tot[k]:.0%}" for v, c in top) or "-"

        print(f"{name:<10} {tot[k]:>9,} {blocked[k] / tot[k]:>8.1%} "
              f"{named[k] / tot[k]:>8.1%} "
              f"{(named[k] + twin[k]) / tot[k]:>10.1%}  {ws}")

    benign = [x for x in tot if names[x] == "BENIGN"]

    if benign:
        k = benign[0]

        print(f"\n{'BENIGN':<10} {tot[k]:>9,} {blocked[k] / tot[k]:>8.1%} "
              f"{'':>19}  <- CHẶN nghĩa là báo động nhầm")

    print(f"\n[+] Tấn công bị chặn        : {atk_block / atk_tot:.2%}")
    print(f"[+] Mô hình đặt đúng tên    : {atk_name / atk_tot:.2%}")
    print(f"[+] Đúng tên hoặc lớp song sinh: "
          f"{(atk_name + atk_twin) / atk_tot:.2%}")

    print("\n[*] Cột '+song sinh' gộp DNS<->LDAP và SSDP<->UDP, hai cặp trùng")
    print("    khít nhau ở tầng thống kê luồng. Ngoài thực tế cổng dịch vụ")
    print("    nguồn tách chúng ra, và app.py làm việc đó bằng luật tất định.")


if __name__ == "__main__":
    main()
