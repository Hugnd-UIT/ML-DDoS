"""
╔══════════════════════════════════════════════════════════════════╗
║         GATEKEEPER IPS — HYBRID AI + eBPF/XDP CONTROL PLANE      ║
╚══════════════════════════════════════════════════════════════════╝

Sửa lỗi đã ghi nhận:
  - Thêm GlobalFloodDetector: bản cũ chỉ cộng dồn theo TỪNG src_ip, nên một
    trận SYN flood với source giả mạo ngẫu nhiên (mỗi IP 1-2 gói) không chạm
    ngưỡng nào cả — đúng kịch bản DDoS phổ biến nhất lại là điểm mù.
  - Không còn bỏ qua IPv6: trước đây `continue` khi thấy ':' trong src_ip,
    trong khi XDP cũng PASS mọi gói IPv6 → bypass hoàn toàn.
  - Kiểm tra khớp số feature giữa model và features.py ngay lúc khởi động.
    Trước đây model lệch feature làm predict_proba ném lỗi ở MỌI flow, bị
    handler nuốt, và hệ thống âm thầm tụt xuống chỉ còn rate limiter.
"""

import argparse
import fcntl
import hashlib
import json
import os
import socket
import struct
import time
import warnings

from collections import Counter, deque

import joblib
import numpy as np

from nfstream import NFStreamer

from enforcer import XDPEnforcer, AttackSignature
from features import (
    extract_features,
    FEATURE_NAMES,
    MIN_PACKETS_FOR_INFERENCE,
    N_FEATURES,
)


# Map IANA protocol numbers to readable protocol names
PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}


# Convert a protocol number into a readable name
def proto_name(proto_num):
    return PROTO_NAMES.get(
        int(proto_num),
        str(proto_num)
    )


# Model nhị phân được deploy.
#
# CỐ Ý dùng binary_eval.pkl chứ KHÔNG phải binary.pkl.
#
# binary.pkl được fit trên 100% dữ liệu (cả ngày 1 lẫn ngày 2), nên không còn
# một dòng nào chưa thấy để hiệu chỉnh ngưỡng cho nó. Mọi ngưỡng gán cho nó đều
# không kiểm chứng được. Bản trước cố lách bằng cách lấy phân vị trên chính dữ
# liệu nó đã học — nhưng model chấm điểm rất thấp cho các dòng benign nó đã nhớ,
# nên ngưỡng thu được thấp giả tạo. Đo thực tế trên đúng dữ liệu của dự án:
#
#     phân vị 0.99998  ngưỡng in-sample 0.9587  |  ngưỡng đúng 0.9996
#     FPR kỳ vọng 0.002%          FPR thực tế 0.259%   (gấp 130 lần)
#
# binary_eval.pkl fit ngày 1, chấm ngày 2 chưa từng thấy. Ngưỡng và FPR/TPR của
# nó là số đo thật, và model được deploy chính là model đã đo — không còn khoảng
# cách nào giữa con số trong báo cáo và thứ đang chạy.
MODEL_FILE = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "..",
    "models",
    "binary_eval.pkl"
)

THRESHOLD_FILE = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "..",
    "models",
    "threshold.json"
)


# Cửa sổ trượt, dùng cho sổ phán quyết của AI và cho bộ đếm telemetry
WINDOW_SECONDS = 5

# Sàn thời lượng khi BÁO CÁO pps lên log/dashboard.
#
# Khác MIN_DURATION_S (1 µs) vốn dùng cho vector đưa vào model: con số đó khớp
# độ phân giải của CICDDoS2019 nên đúng cho feature. Nhưng NFStream chỉ đo tới
# mili-giây, nên chia cho 1 µs là bịa ra độ chính xác gấp 1000 lần thực tế.
MIN_REPORTED_DURATION_S = 1e-3


# ── AI LÀ BÊN DUY NHẤT RA QUYẾT ĐỊNH CHẶN ───────────────────────────────────
#
# Bản trước có hai tuyến song song: AI, và một rate limiter đếm gói theo IP
# (200 SYN / 1000 UDP / 3000 gói mỗi 5 giây). Đo lại thì rate limiter làm gần
# như toàn bộ việc chặn, còn tuyến AI hầu như không bắn:
#
#   - MIN_PACKETS_FOR_AI = 10 loại bỏ 90,32% flow thuộc lớp Syn trước khi AI
#     kịp chấm, vì flow SYN flood có trung vị đúng 2 gói.
#   - Ngưỡng 0,9999 được hiệu chỉnh theo các lớp dễ (MSSQL/UDP/LDAP/NetBIOS
#     đều chấm ~1,0) rồi áp chung cho lớp Syn, vốn có trung vị điểm số 0,68.
#     Trong 9,68% flow lọt qua cửa trên, chỉ 28,47% vượt được ngưỡng.
#
#   => tuyến AI bắt được khoảng 2,8% số cuộc SYN flood.
#
# Rate limiter nhặt phần còn lại nên hệ thống nhìn bên ngoài vẫn hoạt động,
# che mất việc trọng tâm đã hỏng. Nó cũng chính là thứ đã ban nhầm Fastly CDN
# lúc máy chủ chạy `pip install` (xem TRUST_EPHEMERAL_REPLIES bên dưới).
#
# Kiến trúc hiện tại: AI chấm MỌI flow đủ 2 gói, không còn ngưỡng đếm gói nào.
# Thứ được đếm là PHÁN QUYẾT của AI, không phải lưu lượng — nên kẻ tấn công
# chậm vẫn bị bắt, còn host lành tính tải nhanh không bao giờ bị đụng tới.


# Số phán quyết "tấn công" mà AI phải đưa ra cho cùng một IP trước khi chặn.
#
# Đây KHÔNG phải rate limiter: nó không nhìn số gói, không nhìn pps, chỉ đếm
# số lần model kết luận tấn công. Tác dụng là biến sai số trên mỗi flow thành
# sai số trên mỗi IP. Đo trên tập kiểm tra, với ngưỡng TCP 0,90:
#
#     K=1  xác suất ban nhầm một IP lành tính  9,44e-02
#     K=2                                      4,38e-03
#     K=3                                      1,29e-04
#     K=5                                      4,30e-08     <- đang dùng
#
# Kẻ tấn công sinh ~200 flow/giây nên chạm K=5 sau khoảng 26 ms.
VERDICTS_TO_BAN = int(
    os.environ.get("VERDICTS_TO_BAN", "5")
)

# Cửa sổ tích luỹ phán quyết. Quá hạn thì sổ của IP đó được xoá.
VERDICT_WINDOW_S = int(
    os.environ.get("VERDICT_WINDOW_S", "60")
)

# Số flow gom lại trước khi gọi predict_proba một lần.
#
# XGBoost chấm từng dòng rất phí: đo trên chính model này, chấm lẻ đạt 2.074
# flow/giây, gom lô 128 đạt 199.424 flow/giây — nhanh gấp 96 lần. Khi AI phải
# chấm mọi flow thay vì 9,68% như trước, chênh lệch này là bắt buộc.
AI_BATCH_SIZE = int(
    os.environ.get("AI_BATCH_SIZE", "128")
)

# Thời gian tối đa giữ một lô chưa đầy trước khi chấm, tính bằng giây. Không có
# nó thì flow cuối cùng của một đợt tấn công có thể nằm chờ vô hạn.
AI_BATCH_MAX_WAIT_S = float(
    os.environ.get("AI_BATCH_MAX_WAIT_S", "0.25")
)


# ── Lưu lượng trả về cho kết nối do CHÍNH MÁY NÀY mở ra ─────────────────────
#
# NFStream gán hướng flow theo gói ĐẦU TIÊN nó bắt được. Gatekeeper gắn vào
# giữa chừng, nên với một kết nối đi ra (pip install, apt update, đọc GCS) gói
# đầu tiên nó thấy thường là gói máy chủ từ xa trả về — và máy chủ đó bị ghi
# nhận thành bên khởi tạo. Kiểm tra `src_ip in local_ips` vì thế không bắt được
# trường hợp này.
#
# Dấu hiệu đáng tin hơn là CỔNG ĐÍCH trên máy ta. Kết nối do ta mở ra luôn dùng
# cổng nguồn ephemeral, nên gói trả về đi tới một cổng ephemeral. Ngược lại,
# DDoS nhắm vào cổng dịch vụ (80, 443, 53...) vì mục tiêu là làm cạn dịch vụ;
# gói bắn vào cổng ephemeral ngẫu nhiên nơi không có gì lắng nghe chỉ khiến
# kernel trả RST với chi phí không đáng kể.
#
# Sự cố thật đã xảy ra: `pip install -r requirements.txt` trên VM1 kéo gói từ
# Fastly CDN ở 1385 pps. Nhân với WINDOW_SECONDS=5 ra 6928 gói, vượt
# TOTAL_THRESHOLD=3000, và 151.101.0.223 bị ban dù model đã phán đúng là BENIGN.
# Mọi lượt tải nhanh hơn ~600 gói/giây đều dính lỗi này.
TRUST_EPHEMERAL_REPLIES = os.environ.get(
    "TRUST_EPHEMERAL_REPLIES", "1"
).strip().lower() in ("1", "true", "yes", "on")

# Dải cổng ephemeral, đọc từ kernel để khớp đúng máy đang chạy
EPHEMERAL_PORT_MIN = 32768
EPHEMERAL_PORT_MAX = 60999


# ── Ngưỡng volumetric TOÀN CỤC (cộng dồn qua MỌI source) ────────────────────
#
# CHỈ LÀ TELEMETRY. Bộ đếm này KHÔNG được tham gia bất kỳ quyết định chặn nào —
# nó chỉ trả lời câu hỏi "hiện có đang bị bão không" để báo Telegram và vẽ
# dashboard. Toàn bộ việc chặn thuộc về AI.
#
# Bản trước dùng nó để hạ ngưỡng rate limiter xuống 1/10, tức là để nó gián
# tiếp ban IP. Cơ chế đó đã bị gỡ cùng với rate limiter.
GLOBAL_SYN_THRESHOLD = int(
    os.environ.get("GLOBAL_SYN_THRESHOLD", "2000")
)

GLOBAL_PACKET_THRESHOLD = int(
    os.environ.get("GLOBAL_PACKET_THRESHOLD", "20000")
)

GLOBAL_SOURCE_THRESHOLD = int(
    os.environ.get("GLOBAL_SOURCE_THRESHOLD", "500")
)

# Số giây yên ắng liên tục trước khi thoát FLOOD MODE (chống dao động bật/tắt)
FLOOD_EXIT_GRACE_S = 15

# Trần cứng cho hàng đợi sự kiện của bộ đếm toàn cục
MAX_FLOOD_EVENTS = 500_000


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Gatekeeper IPS — "
            "Hybrid AI XGBoost + eBPF/XDP"
        ),
        formatter_class=(
            argparse.RawDescriptionHelpFormatter
        )
    )

    # Define the protected network interface
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        metavar="IFACE",
        help=(
            "Network interface to protect "
            "for example ens4 or eth0"
        )
    )

    return parser.parse_args()


# Đọc dải cổng ephemeral thật của kernel, để không đoán sai trên máy đã chỉnh
# net.ipv4.ip_local_port_range. Thất bại thì giữ mặc định Linux.
def load_ephemeral_range():
    global EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX

    try:
        with open(
            "/proc/sys/net/ipv4/ip_local_port_range", encoding="utf-8"
        ) as fh:
            low, high = fh.read().split()

        EPHEMERAL_PORT_MIN = int(low)
        EPHEMERAL_PORT_MAX = int(high)

    except Exception:
        pass

    return EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX


# True nếu flow là lưu lượng trả về cho một kết nối do máy này chủ động mở.
#
# Điều kiện: cổng đích (phía ta) nằm trong dải ephemeral, còn cổng nguồn (phía
# đối phương) thì không — tức đó là một cổng dịch vụ. Cả hai cùng ephemeral thì
# không kết luận được nên trả về False, thà kiểm tra thừa còn hơn bỏ lọt.
def is_reply_to_local_client(flow):
    # Chỉ TCP và UDP mới có khái niệm cổng
    if int(flow.protocol) not in (6, 17):
        return False

    dst_port = int(getattr(flow, "dst_port", 0))
    src_port = int(getattr(flow, "src_port", 0))

    if not (EPHEMERAL_PORT_MIN <= dst_port <= EPHEMERAL_PORT_MAX):
        return False

    return not (EPHEMERAL_PORT_MIN <= src_port <= EPHEMERAL_PORT_MAX)


# Get all IP addresses assigned to the interface (cả IPv4 lẫn IPv6)
def get_all_local_ips(ifname):
    import subprocess

    # Store detected local addresses
    ips = set()

    # Try to detect addresses using the ip command
    for family_flag in ("-4", "-6"):
        try:
            result = subprocess.run(
                [
                    "ip",
                    family_flag,
                    "addr",
                    "show",
                    ifname
                ],
                capture_output=True,
                text=True,
                timeout=3
            )

            # Parse addresses from command output
            for line in result.stdout.splitlines():
                line = line.strip()

                if line.startswith("inet ") or line.startswith("inet6 "):
                    ip = line.split()[1]
                    ip = ip.split("/")[0]

                    ips.add(ip)

        except Exception:
            pass

    # Use ioctl as a fallback when ip command fails
    if not ips:
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            try:
                # Request the interface IPv4 address
                address = fcntl.ioctl(
                    sock.fileno(),
                    0x8915,
                    struct.pack(
                        "256s",
                        bytes(
                            ifname[:15],
                            "utf-8"
                        )
                    )
                )

                # Convert the returned address to IPv4
                ip = socket.inet_ntoa(
                    address[20:24]
                )

                ips.add(ip)

            finally:
                # Close the fallback socket
                sock.close()

        except Exception:
            pass

    # Always ignore loopback traffic
    ips.add("127.0.0.1")
    ips.add("::1")

    return ips


# Đối chiếu sha256 của binary.pkl với giá trị trainer.py đã ghi.
#
# PHẢI chạy TRƯỚC load_ai_model(): joblib.load() là unpickle, tức là thực thi
# mã tuỳ ý chứa trong file, và gatekeeper chạy dưới quyền root vì eBPF đòi hỏi
# thế. Kiểm tra sau khi đã load thì đã muộn. Hash không ngăn được kẻ sửa được
# cả hai file, nhưng biến một vụ đánh tráo âm thầm thành cảnh báo nhìn thấy được.
def verify_model_integrity():
    try:
        with open(THRESHOLD_FILE, encoding="utf-8") as fh:
            expected = json.load(fh).get("binary_sha256")

    except Exception:
        expected = None

    if not expected:
        print(
            "  [!] threshold.json chưa có binary_sha256; "
            "bỏ qua bước kiểm tra toàn vẹn (chạy lại trainer.py để bật)."
        )

        return

    digest = hashlib.sha256()

    try:
        with open(MODEL_FILE, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(block)

    except Exception as exc:
        print(f"  [!] Không đọc được model để băm: {exc}")

        return

    actual = digest.hexdigest()

    if actual != expected:
        print(
            "  [✗] CẢNH BÁO BẢO MẬT: sha256 của binary.pkl KHÔNG khớp "
            "giá trị trainer.py đã ghi."
        )

        print(f"      mong đợi : {expected}")
        print(f"      thực tế  : {actual}")

        print(
            "  [✗] File model đã bị thay đổi sau khi huấn luyện. "
            "joblib.load() sẽ chạy mã tuỳ ý dưới quyền root."
        )

        print(
            "  [✗] Đặt GATEKEEPER_SKIP_INTEGRITY=1 nếu bạn CHẮC CHẮN "
            "file này là của mình (ví dụ vừa retrain trên máy khác)."
        )

        if os.environ.get(
            "GATEKEEPER_SKIP_INTEGRITY", ""
        ).strip().lower() not in ("1", "true", "yes", "on"):
            import sys

            sys.exit(1)

        print("  [!] GATEKEEPER_SKIP_INTEGRITY đang bật — vẫn nạp model.")

    else:
        print("  [+] Model integrity: sha256 khớp")


# Load the trained XGBoost model
def load_ai_model():
    try:
        # Suppress model loading warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            model = joblib.load(
                MODEL_FILE
            )

        # Show the loaded model information
        print(
            f"  [+] Model loaded: "
            f"{type(model).__name__}"
        )

        print(
            f"      Path: {MODEL_FILE}"
        )

        return model

    except Exception as exc:
        # Stop the system when the model cannot be loaded
        print(
            f"  [✗] Unable to load model: {exc}"
        )

        print(
            "  [✗] A valid model file is required."
        )

        print(
            "  [✗] Exiting system..."
        )

        import sys

        sys.exit(1)


# Đối chiếu số feature của model với hợp đồng feature trong features.py.
#
# Nếu binary.pkl là bản cũ (ví dụ 19 feature) còn features.py đã rút xuống 18,
# thì predict_proba() ném exception ở MỌI flow. Handler per-flow nuốt lỗi, in
# vài dòng rồi chạy tiếp, nên hệ thống vẫn "chạy" nhưng thực chất chỉ còn rate
# limiter — không ai nhận ra AI đã chết. Thà dừng hẳn lúc khởi động.
def validate_model_contract(model):
    n_model = getattr(model, "n_features_in_", None)

    if n_model is None:
        try:
            booster = model.get_booster()
            n_model = len(booster.feature_names or []) or None

        except Exception:
            n_model = None

    if n_model is None:
        print(
            "  [!] Không xác định được số feature của model; "
            "bỏ qua bước đối chiếu."
        )

        return

    if int(n_model) != N_FEATURES:
        print(
            f"  [✗] FATAL: model nhận {int(n_model)} feature nhưng "
            f"features.py khai báo {N_FEATURES}."
        )

        print(
            "  [✗] Model và feature contract lệch nhau — mọi lần suy luận "
            "sẽ thất bại và hệ thống chỉ còn rate limiter."
        )

        print("  [✗] Chạy lại: python3 src/parser.py && python3 src/trainer.py")

        import sys

        sys.exit(1)

    print(f"  [+] Feature contract khớp: {N_FEATURES} feature")


# Load the decision threshold chosen during training.
#
# trainer.py picks it on the held-out day-2 capture to hit a target false
# positive rate, then writes it beside the model. Falling back to 0.5 keeps
# the system runnable with an older model directory, but 0.5 is the value
# that made benign traffic a large share of everything the dashboard shows.
def load_threshold():
    try:
        with open(THRESHOLD_FILE, encoding="utf-8") as fh:
            meta = json.load(fh)

        threshold = float(meta["threshold"])

        print(f"  [+] Decision threshold: {threshold:.4f}")

        print(
            f"      Measured on day-2 holdout: "
            f"FPR {meta.get('measured_fpr', 0):.4%} / "
            f"TPR {meta.get('measured_tpr', 0):.4%}"
        )

        # Đối chiếu số feature ghi trong threshold.json với features.py
        n_declared = meta.get("n_features")

        if n_declared is not None and int(n_declared) != N_FEATURES:
            print(
                f"  [!] threshold.json ghi {int(n_declared)} feature nhưng "
                f"features.py có {N_FEATURES}. threshold.json đã cũ."
            )

        # Cảnh báo theo hướng NGƯỢC LẠI: chỉ im lặng khi có bằng chứng rõ ràng
        # rằng ngưỡng đã được hiệu chỉnh trên model production.
        #
        # Bản trước chỉ cảnh báo khi calibrated_on == "eval_model", nên đúng
        # cái file nguy hiểm nhất — threshold.json cũ, KHÔNG có trường này,
        # chứa ngưỡng lấy nguyên từ eval model — lại chạy hoàn toàn im lặng.
        if meta.get("calibrated_on") != "deployed_model":
            print(
                "  [!] threshold.json không xác nhận đã hiệu chỉnh trên chính "
                "model đang deploy (calibrated_on="
                f"{meta.get('calibrated_on') or 'thiếu'})."
            )

            print(
                "  [!] Ngưỡng có thể được suy ra từ một model khác, nên FPR/TPR "
                "thực tế có thể khác xa số ghi ở trên. "
                "Chạy lại src/recalibrate.py."
            )

        # threshold.json phải mô tả ĐÚNG file model đang được nạp. Nếu lệch thì
        # ngưỡng thuộc về một model khác — chính là lớp lỗi đã khiến hệ thống
        # chặn nhầm lưu lượng CDN hợp lệ trong lần chạy thử đầu tiên.
        declared_model = meta.get("model_file")

        if declared_model:
            if os.path.basename(declared_model) != os.path.basename(MODEL_FILE):
                print(
                    f"  [✗] threshold.json mô tả {declared_model} nhưng "
                    f"gatekeeper đang nạp {os.path.basename(MODEL_FILE)}."
                )

                print("  [✗] Ngưỡng này thuộc về một model khác. Dừng.")

                import sys

                sys.exit(1)

        # Đối chiếu cả TÊN feature, không chỉ số lượng: hai bộ 18 feature khác
        # thứ tự vẫn đếm ra 18 mà vector đưa vào model thì sai hoàn toàn.
        declared_names = meta.get("feature_names")

        if declared_names and list(declared_names) != list(FEATURE_NAMES):
            print(
                "  [✗] Tên/thứ tự feature trong threshold.json khác "
                "features.py — model đang được nạp sai vector."
            )

            print("  [✗] Chạy lại: python3 src/parser.py && python3 src/trainer.py")

            import sys

            sys.exit(1)

        # Ngưỡng riêng cho TCP.
        #
        # Một ngưỡng chung không phục vụ được cả hai họ tấn công. Đo trên tập
        # kiểm tra: các lớp phản xạ UDP (MSSQL/UDP/NetBIOS/LDAP) đều được chấm
        # điểm ~1,0 nên ngưỡng 0,9999 không tốn gì, bắt 99,3–99,97%. Lớp Syn
        # có trung vị điểm số chỉ 0,68, nên cùng ngưỡng đó chỉ bắt được 28,47%.
        #
        #     ngưỡng TCP   bắt Syn    FPR benign TCP
        #        0,90       96,54%        0,4944%      <- mặc định
        #        0,95       55,00%        0,3304%
        #        0,99       49,51%        0,1896%
        #        0,9999     28,47%        0,0000%
        #
        # Sai số 0,49% mỗi flow được VERDICTS_TO_BAN chuyển thành 4,3e-08 mỗi
        # IP, nên đánh đổi này không làm tăng số IP bị ban nhầm.
        tcp_threshold = meta.get("threshold_tcp")

        if tcp_threshold is None:
            tcp_threshold = threshold

            print(
                "  [!] threshold.json chưa có threshold_tcp — dùng chung "
                f"{threshold:.4f} cho TCP. Tuyến AI sẽ bỏ lọt phần lớn SYN "
                "flood. Chạy lại: python3 src/recalibrate.py"
            )

        else:
            tcp_threshold = float(tcp_threshold)

            print(f"  [+] Ngưỡng riêng cho TCP: {tcp_threshold:.4f}")

        return threshold, tcp_threshold

    except Exception as exc:
        print(
            f"  [!] No usable models/threshold.json ({exc}); "
            f"falling back to 0.5"
        )

        print(
            "  [!] Re-run src/trainer.py to generate a tuned threshold."
        )

        return 0.5, 0.5


# Bộ đếm volumetric toàn cục.
#
# Cộng dồn SYN, tổng gói và SỐ SOURCE KHÁC NHAU trên toàn interface trong một
# cửa sổ trượt. Đây là thứ duy nhất nhìn thấy được flood phân tán/giả mạo, vì
# theo định nghĩa loại flood đó không có source nào nổi bật.
class VerdictLedger:
    """Sổ phán quyết của AI, tính theo từng IP nguồn.

    Đây là thứ thay thế rate limiter, và khác nó ở chỗ căn bản: rate limiter
    đếm GÓI, sổ này đếm số lần MODEL kết luận "tấn công". Hệ quả:

      - Kẻ tấn công chậm vẫn bị bắt, vì mỗi flow độc hại đều tính một phán
        quyết bất kể nó gửi nhanh hay chậm.
      - Host lành tính tải rất nhanh không bao giờ bị đụng tới, vì AI không
        kết luận gì về nó. Đúng ca `pip install` từ Fastly đã bị ban nhầm.

    Tác dụng định lượng là biến sai số trên mỗi flow thành sai số trên mỗi IP.
    Với ngưỡng TCP 0,90 (FPR 0,4944% mỗi flow), xác suất một IP lành tính bị
    ban rơi từ 9,44e-02 ở K=1 xuống 4,30e-08 ở K=5.
    """

    def __init__(self, need=VERDICTS_TO_BAN, window_s=VERDICT_WINDOW_S):
        self.need = max(1, int(need))
        self.window_s = float(window_s)

        # src_ip -> danh sách thời điểm các phán quyết còn hiệu lực
        self.hits = {}

    # Ghi nhận một phán quyết "tấn công" cho src_ip.
    # Trả về (đủ_để_chặn, số_phán_quyết_hiện_có).
    def record(self, src_ip, now):
        stamps = self.hits.get(src_ip)

        if stamps is None:
            stamps = []
            self.hits[src_ip] = stamps

        stamps.append(now)

        # Bỏ các phán quyết đã quá hạn cửa sổ
        cutoff = now - self.window_s

        while stamps and stamps[0] < cutoff:
            stamps.pop(0)

        if len(stamps) >= self.need:
            del self.hits[src_ip]

            return True, self.need

        return False, len(stamps)

    # Xoá sổ của một IP, gọi sau khi IP đó đã bị chặn
    def forget(self, src_ip):
        self.hits.pop(src_ip, None)

    # Dọn các IP không còn phán quyết nào trong cửa sổ.
    #
    # Không có bước này thì `hits` lớn dần vô hạn trước một cuộc tấn công giả
    # mạo source — đúng lớp lỗi mà FIX-26 đã sửa cho ban_registry.
    def prune(self, now):
        cutoff = now - self.window_s

        dead = [
            ip for ip, stamps in self.hits.items()
            if not stamps or stamps[-1] < cutoff
        ]

        for ip in dead:
            del self.hits[ip]

        return len(dead)


class FlowBatcher:
    """Gom flow lại rồi chấm điểm một lượt.

    Khi AI phải chấm mọi flow thay vì 9,68% như kiến trúc cũ, chi phí gọi
    predict_proba từng dòng trở thành nút cổ chai. Đo trên chính model này:

        chấm lẻ (batch 1)     2.074 flow/giây
        gom lô 128          199.424 flow/giây     — nhanh gấp 96 lần

    Lô được chấm khi đầy, hoặc khi flow cũ nhất đã chờ quá AI_BATCH_MAX_WAIT_S
    để flow cuối của một đợt tấn công không nằm chờ vô hạn.
    """

    def __init__(self, size=AI_BATCH_SIZE, max_wait_s=AI_BATCH_MAX_WAIT_S):
        self.size = max(1, int(size))
        self.max_wait_s = float(max_wait_s)

        self.vectors = []
        self.payloads = []
        self.opened_at = None

    def add(self, vector, payload, now):
        if not self.vectors:
            self.opened_at = now

        self.vectors.append(vector)
        self.payloads.append(payload)

    # True khi lô đã sẵn sàng để chấm
    def ready(self, now):
        if not self.vectors:
            return False

        return (
            len(self.vectors) >= self.size
            or now - self.opened_at >= self.max_wait_s
        )

    # Lấy nội dung lô ra và làm rỗng nó
    def drain(self):
        vectors = np.vstack(self.vectors)
        payloads = self.payloads

        self.vectors = []
        self.payloads = []
        self.opened_at = None

        return vectors, payloads


class GlobalFloodDetector:

    def __init__(
        self,
        window_s=WINDOW_SECONDS,
        syn_limit=GLOBAL_SYN_THRESHOLD,
        packet_limit=GLOBAL_PACKET_THRESHOLD,
        source_limit=GLOBAL_SOURCE_THRESHOLD
    ):
        self.window_s = window_s
        self.syn_limit = syn_limit
        self.packet_limit = packet_limit
        self.source_limit = source_limit

        self._events = deque()
        self._sources = Counter()

        self._syn_total = 0
        self._packet_total = 0

        self.active = False
        self._last_exceed = 0.0
        self.trigger_reason = ""

    # Loại bỏ một sự kiện cũ nhất và trừ lại các bộ đếm
    def _pop_oldest(self):
        _, syn, packets, src_ip = self._events.popleft()

        self._syn_total -= syn
        self._packet_total -= packets

        self._sources[src_ip] -= 1

        if self._sources[src_ip] <= 0:
            del self._sources[src_ip]

    # Loại bỏ các sự kiện đã rơi ra ngoài cửa sổ
    def _trim(self, now):
        cutoff = now - self.window_s

        while self._events and self._events[0][0] < cutoff:
            self._pop_oldest()

        # Trần cứng: nếu đồng hồ hệ thống nhảy lùi thì điều kiện thời gian ở
        # trên không bao giờ đúng và deque sẽ phình vô hạn ngay giữa lúc bị
        # tấn công. Chính bộ đếm chống DDoS mà bị DoS thì hỏng cả hệ thống.
        while len(self._events) > MAX_FLOOD_EVENTS:
            self._pop_oldest()

    # Ghi nhận một flow và trả về True nếu đang trong FLOOD MODE
    def observe(self, now, syn, packets, src_ip):
        self._events.append((now, syn, packets, src_ip))

        self._syn_total += syn
        self._packet_total += packets
        self._sources[src_ip] += 1

        self._trim(now)

        reasons = []

        if self._syn_total > self.syn_limit:
            reasons.append(
                f"SYN {self._syn_total:,}/{self.window_s}s "
                f"> {self.syn_limit:,}"
            )

        if self._packet_total > self.packet_limit:
            reasons.append(
                f"packets {self._packet_total:,}/{self.window_s}s "
                f"> {self.packet_limit:,}"
            )

        if len(self._sources) > self.source_limit:
            reasons.append(
                f"distinct sources {len(self._sources):,}/{self.window_s}s "
                f"> {self.source_limit:,}"
            )

        if reasons:
            self._last_exceed = now
            self.trigger_reason = " | ".join(reasons)

            if not self.active:
                self.active = True

                return True, True  # (đang flood, vừa mới kích hoạt)

        elif self.active and now - self._last_exceed > FLOOD_EXIT_GRACE_S:
            self.active = False
            self.trigger_reason = ""

            print(
                f"  [~] FLOOD MODE OFF — "
                f"{FLOOD_EXIT_GRACE_S}s không còn vượt ngưỡng toàn cục"
            )

        return self.active, False

    # Số liệu hiện tại của cửa sổ, dùng cho log và cảnh báo
    def snapshot(self):
        return {
            "syn": self._syn_total,
            "packets": self._packet_total,
            "sources": len(self._sources),
        }


# Print a section banner
def _banner(
    title,
    width=65
):
    # Print the top border
    print(
        f"\n  {'─' * width}"
    )

    # Print the section title
    print(
        f"  {title}"
    )

    # Print the bottom border
    print(
        f"  {'─' * width}"
    )


# Cảnh báo khi vào FLOOD MODE. Tách riêng để không phụ thuộc notifier khi
# module đó chưa cấu hình Telegram.
def _announce_flood(detector):
    stats = detector.snapshot()

    print()
    print("  ╔" + "═" * 63 + "╗")
    print("  ║   ⚠  GLOBAL FLOOD MODE ACTIVATED                            ║")
    print("  ╚" + "═" * 63 + "╝")
    print(f"  [!] Trigger: {detector.trigger_reason}")
    print(
        f"  [!] Cửa sổ {detector.window_s}s: "
        f"{stats['syn']:,} SYN / {stats['packets']:,} gói / "
        f"{stats['sources']:,} source khác nhau"
    )
    print(
        "  [!] Đây là CẢNH BÁO, không phải lệnh chặn. Việc chặn vẫn hoàn toàn "
        f"do AI quyết định, mọi flow >= {MIN_PACKETS_FOR_INFERENCE} gói đều "
        "được chấm như bình thường."
    )
    print(
        "  [!] LƯU Ý: nếu source bị giả mạo thì chặn theo src IP là vô nghĩa "
        "về bản chất — tuyến phòng thủ ở đây là tcp_syncookies (đã bật trong "
        "scripts/setup.sh) và rp_filter, không phải blacklist."
    )
    print()

    try:
        from notifier import send_telegram_async

        send_telegram_async(
            "🌊 <b>[SOC] GLOBAL FLOOD MODE</b>\n\n"
            f"Trigger: <code>{detector.trigger_reason}</code>\n"
            f"Cửa sổ {detector.window_s}s: {stats['syn']:,} SYN / "
            f"{stats['packets']:,} gói / {stats['sources']:,} source\n\n"
            "Hệ thống đã hạ ngưỡng per-IP và mở rộng phạm vi suy luận AI.\n"
            "Nếu source bị spoof, hãy dựa vào syncookies + upstream scrubbing."
        )

    except Exception as exc:
        print(f"  [!] Không gửi được cảnh báo flood: {exc}")


# Start the Gatekeeper IPS
def main():
    # Parse command-line arguments
    args = parse_args()

    # Get the protected network interface
    interface = args.interface

    # Set the XDP source file path
    xdp_file = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "xdp_filter.c"
    )


    # Print the application header
    print()

    print(
        "  ╔" + "═" * 63 + "╗"
    )

    print(
        "  ║   GATEKEEPER IPS  —  AI XGBoost + eBPF/XDP          ║"
    )

    print(
        f"  ║   Interface : {interface:<47}║"
    )

    print(
        "  ╚" + "═" * 63 + "╝"
    )

    print()


    # Initialize the XDP data plane
    _banner(
        "1/4  INITIALIZING DATA PLANE eBPF/XDP"
    )

    enforcer = XDPEnforcer(
        interface,
        xdp_file
    )

    # Stop startup when XDP cannot be attached
    if not enforcer.load_and_attach():
        return


    # Synchronize the whitelist
    _banner(
        "WHITELIST SYNCHRONIZATION"
    )

    enforcer.load_whitelist()


    # Initialize user-space memory and state
    _banner(
        "2/4  INITIALIZING USER-SPACE MEMORY"
    )

    print(
        "  [+] Offense History initialized "
        "TTLCache 24h"
    )

    print(
        "  [+] Memory Manager daemon started"
    )


    # Initialize the AI engine
    _banner(
        "3/4  INITIALIZING AI ENGINE XGBoost"
    )

    # Kiểm tra toàn vẹn TRƯỚC khi unpickle
    verify_model_integrity()

    ai_model = load_ai_model()

    validate_model_contract(ai_model)

    ai_threshold, tcp_threshold = load_threshold()


    # Configure the egress traffic filter
    _banner(
        "4/4  CONFIGURING EGRESS FILTER"
    )

    local_ips = get_all_local_ips(
        interface
    )

    print(
        f"  [+] Local IPs detected: "
        f"{', '.join(sorted(local_ips))}"
    )

    print(
        "  [+] Traffic originating from these "
        "addresses will be ignored"
    )

    # Dải cổng ephemeral quyết định flow nào được coi là gói trả về
    eph_low, eph_high = load_ephemeral_range()

    if TRUST_EPHEMERAL_REPLIES:
        print(
            f"  [+] Bỏ qua lưu lượng trả về tới cổng ephemeral "
            f"{eph_low}-{eph_high} (pip, apt, GCS...)"
        )

    else:
        print(
            "  [!] TRUST_EPHEMERAL_REPLIES=0 — lượt tải ra ngoài "
            "có thể bị ban nhầm"
        )

    # Nói rõ trạng thái IPv6 thay vì âm thầm bỏ qua như bản cũ
    has_global_v6 = any(
        ":" in ip and not ip.startswith(("fe80", "::1"))
        for ip in local_ips
    )

    if has_global_v6 and enforcer.blacklist6_map is None:
        print(
            "  [✗] Interface có địa chỉ IPv6 global nhưng eBPF program "
            "không có map IPv6 — traffic IPv6 sẽ KHÔNG được chặn."
        )

        print(
            "  [✗] Biên dịch lại với src/xdp_filter.c mới nhất."
        )

    elif enforcer.blacklist6_map is not None:
        print("  [+] IPv6 enforcement: ENABLED")


    # Sổ phán quyết của AI — thứ duy nhất dẫn tới lệnh chặn
    ledger = VerdictLedger()

    # Bộ gom lô để chấm điểm hàng loạt
    batcher = FlowBatcher()

    print(
        f"  [+] Chặn khi AI kết luận tấn công {VERDICTS_TO_BAN} lần "
        f"trên cùng một IP trong {VERDICT_WINDOW_S}s"
    )

    print(
        f"  [+] Gom lô {AI_BATCH_SIZE} flow mỗi lượt chấm "
        f"(chờ tối đa {AI_BATCH_MAX_WAIT_S:.2f}s)"
    )

    # Bộ đếm volumetric toàn cục — TELEMETRY, không tham gia quyết định chặn
    flood = GlobalFloodDetector()

    print(
        f"  [+] Bộ đếm toàn cục (chỉ cảnh báo, không chặn): "
        f"{GLOBAL_SYN_THRESHOLD:,} SYN / "
        f"{GLOBAL_PACKET_THRESHOLD:,} gói / "
        f"{GLOBAL_SOURCE_THRESHOLD:,} source mỗi {WINDOW_SECONDS}s"
    )


    # Show that the system is ready
    print()

    print(
        "  ╔" + "═" * 63 + "╗"
    )

    print(
        "  ║   GATEKEEPER READY — MONITORING INGRESS TRAFFIC     ║"
    )

    print(
        "  ╚" + "═" * 63 + "╝"
    )

    print()

    # Vòng tiêu thụ flow, tách khỏi main() để supervisor bên dưới dựng lại
    # được NFStream mà vẫn giữ nguyên enforcer, whitelist, model và sổ ban.
    # Chấm điểm một lô flow rồi ra quyết định.
    #
    # Tách khỏi consume() vì nó được gọi từ hai chỗ: khi lô đầy, và khi lô chưa
    # đầy nhưng đã chờ quá lâu.
    def score_batch(vectors, payloads):
        # Một lần gọi cho cả lô. Chấm lẻ đạt 2.074 flow/giây, lô 128 đạt
        # 199.424 flow/giây trên chính model này.
        probabilities = ai_model.predict_proba(vectors)[:, 1]

        for probability, item in zip(probabilities, payloads):
            attack_proba = float(probability)

            # Ngưỡng riêng cho TCP. Các lớp phản xạ UDP được model chấm ~1,0
            # nên ngưỡng chặt không tốn gì; lớp Syn có trung vị 0,68 nên cùng
            # ngưỡng đó chỉ bắt được 28,47%.
            limit = (
                tcp_threshold
                if item["protocol_num"] == 6
                else ai_threshold
            )

            if attack_proba < limit:
                continue

            src_ip = item["src_ip"]

            if enforcer.is_whitelisted(src_ip) or enforcer.is_banned(src_ip):
                continue

            # Tích luỹ phán quyết thay vì chặn ngay. Đây là chỗ sai số trên mỗi
            # flow được chuyển thành sai số trên mỗi IP: 0,4944% -> 4,30e-08.
            enough, seen = ledger.record(src_ip, item["now"])

            if not enough:
                continue

            sig = AttackSignature(
                src_ip       = src_ip,
                protocol     = item["protocol"],
                dst_port     = item["dst_port"],
                fwd_len_mean = item["fwd_len_mean"],
                pps          = item["pps"],
                reason       = "AI_INFERENCE (Binary Model)",
                features     = item["features"]
            )

            count, ttl_secs = enforcer.block_ip(sig)

            if count:
                ttl_label = (
                    f"{ttl_secs // 3600}h"
                    if ttl_secs >= 3600
                    else f"{ttl_secs // 60}m"
                )

                print(
                    f"  [BLOCK] {src_ip:<20} "
                    f"AI_INFERENCE (Binary) "
                    f"│ p={attack_proba:.4f} "
                    f"│ {seen} phán quyết "
                    f"│ ban {ttl_label:<4} "
                    f"│ offense #{count}"
                )


    # Vòng tiêu thụ flow, tách khỏi main() để supervisor bên dưới dựng lại
    # được NFStream mà vẫn giữ nguyên enforcer, whitelist, model và sổ ban.
    #
    # KIẾN TRÚC: AI là bên duy nhất ra quyết định chặn, XDP chỉ thi hành.
    # Không còn tuyến rate limiter nào — xem chú thích ở VERDICTS_TO_BAN.
    def consume(streamer):
        last_prune = time.time()

        # Process each detected network flow
        for flow in streamer:
            try:
                now = time.time()

                # Dọn sổ phán quyết định kỳ. Không có bước này thì `hits` lớn
                # dần vô hạn trước một cuộc tấn công giả mạo source.
                if now - last_prune >= VERDICT_WINDOW_S:
                    ledger.prune(now)

                    last_prune = now

                # Chấm lô đang chờ nếu nó đã quá hạn, kể cả khi flow hiện tại
                # không được đưa vào lô.
                if batcher.ready(now):
                    score_batch(*batcher.drain())

                # Ignore traffic originating from local IPs
                if flow.src_ip in local_ips:
                    continue


                # Ignore IPs that are already banned
                if enforcer.is_banned(
                    flow.src_ip
                ):
                    continue


                # Bộ đếm toàn cục — TELEMETRY THUẦN.
                #
                # Nó chỉ trả lời "hiện có đang bị bão không" để báo Telegram và
                # vẽ dashboard. Bản trước dùng kết quả này để hạ ngưỡng rate
                # limiter xuống 1/10, tức là để nó gián tiếp ban IP; cơ chế đó
                # đã bị gỡ cùng rate limiter. Giá trị trả về không được dùng
                # cho bất kỳ quyết định chặn nào.
                _, flood_just_started = flood.observe(
                    now,
                    flow.bidirectional_syn_packets,
                    flow.bidirectional_packets,
                    flow.src_ip
                )

                if flood_just_started:
                    _announce_flood(flood)


                # Bỏ qua lưu lượng trả về cho kết nối do chính máy này mở ra.
                #
                # Đặt SAU flood.observe() là có chủ đích: những gói này vẫn phải
                # được cộng vào bộ đếm toàn cục, nếu không hệ thống sẽ mù trước
                # tấn công vắt kiệt băng thông nhắm vào cổng ephemeral. Chỉ miễn
                # cho nó khỏi tuyến AI, vì đó là chỗ ra quyết định ban.
                if TRUST_EPHEMERAL_REPLIES and is_reply_to_local_client(flow):
                    continue


                # ── AI XGBoost: BÊN DUY NHẤT PHÁT HIỆN ──────────────────────
                #
                # Mọi flow đủ 2 gói đều được chấm. Bản trước đặt cửa
                # MIN_PACKETS_FOR_AI = 10 ở đây, loại bỏ 90,32% flow thuộc lớp
                # Syn trước khi AI kịp nhìn — flow SYN flood có trung vị đúng
                # 2 gói. Ngưỡng dưới đây là ngưỡng của extract_features(), tức
                # là giới hạn thật của dữ liệu chứ không phải một lựa chọn.
                features = extract_features(flow)

                # extract_features trả None cho flow dưới 2 gói: không có thông
                # tin liên gói nào để mô tả. Kiến trúc này không có tuyến thứ
                # hai để đỡ, nên những flow đó được bỏ qua — hạn chế đã biết,
                # ghi rõ trong report.md.
                if features is None:
                    continue

                # Sàn thời lượng dùng để BÁO CÁO pps, khác sàn dùng cho feature.
                #
                # MIN_DURATION_S là 1 µs vì đó là độ phân giải của CICDDoS2019
                # — đúng cho vector đưa vào model. Nhưng NFStream chỉ đo được
                # tới mili-giây, nên mọi flow dưới 1 ms về đây với duration = 0.
                # Chia cho 1 µs là bịa ra độ chính xác gấp 1000 lần thực tế:
                # một flow 3 gói hiện thành 3.000.000 pps trên dashboard, trong
                # khi kẻ tấn công chỉ bắn 1.000 gói/giây.
                #
                # Dùng sàn 1 ms để con số báo cáo là cận trên thật sự đo được.
                duration_s = max(
                    float(flow.bidirectional_duration_ms) / 1000.0,
                    MIN_REPORTED_DURATION_S
                )

                batcher.add(
                    features,
                    {
                        "src_ip":       flow.src_ip,
                        "protocol":     proto_name(flow.protocol),
                        "protocol_num": int(flow.protocol),
                        "dst_port":     int(getattr(flow, "dst_port", 0)),
                        "fwd_len_mean": float(getattr(flow, "src2dst_mean_ps", 0.0)),
                        "pps":          float(flow.bidirectional_packets) / duration_s,
                        "features":     features[0].tolist(),
                        "now":          now,
                    },
                    now
                )

                if batcher.ready(now):
                    score_batch(*batcher.drain())


            # Handle errors from individual flows
            except Exception as flow_err:
                # Đọc src_ip trong try riêng: nếu chính việc truy cập thuộc
                # tính flow là thứ đã ném lỗi thì handler cũ sẽ ném lần hai.
                try:
                    who = flow.src_ip

                except Exception:
                    who = "unknown"

                print(
                    f"  [-] Flow error "
                    f"({who}): {flow_err}"
                )

        # Chấm nốt lô còn dở khi luồng flow kết thúc
        if batcher.vectors:
            score_batch(*batcher.drain())



    # Supervisor: dựng lại NFStream khi nó chết.
    #
    # Bản trước để `for flow in streamer` trần trong một try duy nhất, nên bất
    # kỳ exception nào thoát ra từ NFStream — libpcap mất interface, hết bộ
    # nhớ, một gói dị dạng làm rơi luồng — đều rơi thẳng xuống `finally`, gỡ
    # XDP và thoát. Nghĩa là ĐÚNG lúc bị tấn công nặng nhất, máy chủ không chỉ
    # mất bộ phát hiện mà mất luôn cả tầng chặn ở kernel: những IP đang bị ban
    # bỗng đi qua được. Một sự cố nhỏ ở tầng bắt gói trở thành gỡ bỏ toàn bộ
    # hàng phòng thủ.
    try:
        backoff_s = 1
        restarts = 0

        while True:
            started_at = time.time()

            try:
                streamer = NFStreamer(
                    source=interface,
                    active_timeout=1,
                    idle_timeout=1,
                    statistical_analysis=True
                )

                consume(streamer)

                cause = "NFStream đã đóng luồng"

            except KeyboardInterrupt:
                raise

            except Exception as exc:
                cause = f"NFStream lỗi: {exc}"

            uptime = time.time() - started_at

            # Chạy được một lúc rồi mới chết → coi như sự cố nhất thời, thử
            # lại ngay. Chết liên tiếp → giãn dần để không quay tít CPU.
            if uptime > 60:
                backoff_s = 1

            restarts += 1

            print(
                f"\n  [✗] {cause}"
            )

            print(
                f"  [~] XDP VẪN đang gắn và tiếp tục chặn "
                f"({len(enforcer.ban_registry):,} IP trong sổ ban)."
            )

            print(
                f"  [~] Khởi động lại bộ bắt gói sau {backoff_s}s "
                f"(lần thứ {restarts})..."
            )

            enforcer.print_stats()

            time.sleep(backoff_s)

            backoff_s = min(backoff_s * 2, 30)


    # Handle manual shutdown
    except KeyboardInterrupt:
        print(
            "\n  [~] Ctrl+C received "
            "— cleaning up..."
        )


    # Always detach XDP before exiting
    finally:
        # In số liệu data plane TRƯỚC khi gỡ XDP: sau detach thì map biến mất
        # cùng chương trình và không còn gì để đọc.
        try:
            enforcer.print_stats()
        except Exception as e:
            print(f"  [-] Không đọc được XDP counters: {e}")

        try:
            from gcs_utility import get_collector
            get_collector().stop()
        except Exception as e:
            print(f"  [-] Lỗi dừng GCS collector: {e}")

        enforcer.detach()


# Start the Gatekeeper application
if __name__ == "__main__":
    main()
