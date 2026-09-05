"""
Single source of truth for the model's feature contract.

The same ordered list previously lived in four files — parser.py, gatekeeper.py,
gcs_utility.py and app.py — with no mechanism keeping them aligned. Import
FEATURE_NAMES from here instead of redeclaring it.

Training features come from CICFlowMeter (the CICDDoS2019 CSVs); live features
come from NFStream. The two tools do not agree on units, resolution, or which
fields exist at all, so extract_features() maps NFStream onto the CICFlowMeter
convention rather than reading fields off verbatim.

Measured on the CICDDoS2019 training set:

    Flow Duration    minimum 1 us, never 0        (microsecond resolution)
    Flow Bytes/s     saturates at ~2.94e9
    Flow Packets/s   saturates at ~4.0e6
    Flow IAT Std     0 for 99.6% of attack rows, 16% of benign rows

Init_Win_bytes_forward is deliberately absent: NFStream exposes no TCP window
field, so it was always 0 at inference while training data had 253 (benign
median) and -1 (attack median). A feature that is constant in production is
worse than no feature, because the model still allocates split weight to it.
"""

import numpy as np


# Ordered feature vector. Order is significant: the model indexes by position.
FEATURE_NAMES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Down/Up Ratio",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Total",
    "Protocol",
    "SYN Flag Count",
    "ACK Flag Count",

    # Cổng nguồn và cổng đích.
    #
    # Thiếu hai cột này là nguyên nhân chính khiến model không phân biệt được
    # các họ tấn công phản xạ UDP. Toàn bộ DNS/LDAP/SNMP/SSDP/MSSQL/NetBIOS/NTP
    # đều là phản xạ UDP, và thứ duy nhất phân biệt chúng ngoài đời là cổng
    # dịch vụ bị lợi dụng. Đo trên 937.614 dòng, 12 lớp cân bằng:
    #
    #     18 feature (không cổng)          62,84%
    #     + Source Port, Destination Port  75,24%    (+12,40 điểm)
    #     + 9 thống kê khác nữa            75,42%    (+0,18 — không đáng)
    #
    # Riêng NetBIOS đi từ 8,70% lên 77,10%, DNS từ 36,02% lên 74,81%.
    #
    # Không phải bảng tra: dùng RIÊNG hai cột cổng chỉ đạt 47,59%, nên chúng
    # mang thông tin bổ sung thật chứ không thay thế các feature còn lại.
    #
    # HẠN CHẾ PHẢI NÊU TRONG BÁO CÁO: CICDDoS2019 dùng cổng tổng hợp của phòng
    # lab — DNS bắn từ 564/634 chứ không phải 53, LDAP từ 900 chứ không phải
    # 389. Model học cổng theo dữ liệu này sẽ KHÔNG nhận ra tấn công phản xạ
    # thật ngoài đời, vốn đến từ cổng dịch vụ chuẩn.
    "Source Port",
    "Destination Port",
]

N_FEATURES = len(FEATURE_NAMES)


# CICDDoS2019 never records a flow shorter than 1 us. NFStream reports
# duration in whole milliseconds, so every sub-millisecond flow arrives as 0.
# Clamping to the dataset's own floor keeps derived rates inside the
# distribution the model was fitted on; the previous 1e-9 floor was a
# nanosecond, inflating every rate by 1000x.
MIN_DURATION_S = 1e-6

# Upper bounds observed in the training set. NFStream can exceed these on
# very short flows, which would place the sample outside anything the model
# has seen.
MAX_FLOW_BYTES_PER_S = 2.94e9
MAX_FLOW_PACKETS_PER_S = 4.0e6

# A flow needs at least two packets for inter-arrival statistics to exist.
# Single-packet flows are left to the rate limiter.
#
# Đã kiểm chứng: trong 22 triệu dòng huấn luyện KHÔNG có dòng nào <= 1 gói, nên
# ngưỡng 2 này khớp đúng phân bố dữ liệu. Đừng hạ xuống 1.
MIN_PACKETS_FOR_INFERENCE = 2


# Chi phí header phải TRỪ khỏi kích thước gói của NFStream.
#
# CICFlowMeter (nguồn của CICDDoS2019) đo "Packet Length" là độ dài PAYLOAD.
# NFStream đo `*_ps` là kích thước CẢ KHUNG, gồm Ethernet + IP + L4. Hai bên
# cùng tên cột nhưng khác đơn vị đo, và chênh lệch cố định ~54 byte đủ để đẩy
# vector ra ngoài phân bố huấn luyện.
#
# Đây không phải suy đoán. Nhóm feature độ dài gói chiếm 47,74% tổng importance
# của multiclass.pkl, và mô phỏng trên dữ liệu thật cho thấy chỉ riêng việc cộng
# nhầm 54 byte làm độ chính xác rơi từ 74,91% xuống 49,88%.
#
# Bằng chứng rõ nhất: lớp tấn công "Syn" trong tập huấn luyện có
# Fwd Packet Length Mean median = 0,00 — gói SYN không có payload. Nếu NFStream
# đo cả khung thì con số tương ứng phải là 54+, không đời nào bằng 0.
ETH_IP_TCP_OVERHEAD = 54   # 14 Ethernet + 20 IPv4 + 20 TCP
ETH_IP_UDP_OVERHEAD = 42   # 14 Ethernet + 20 IPv4 +  8 UDP


# Trừ header khỏi kích thước khung để ra độ dài payload theo cách CICFlowMeter đo
def _payload_len(frame_len, overhead):
    return max(0.0, float(frame_len) - overhead)


# Read an attribute that older NFStream builds may not expose
def _get(flow, name, default=0.0):
    try:
        value = getattr(flow, name)

    except AttributeError:
        return default

    return default if value is None else value


# Convert an NFStream flow into the model's feature vector.
# Returns None when the flow carries too little information to describe,
# in which case the caller should skip inference rather than guess.
def extract_features(flow):
    total_packets = int(flow.bidirectional_packets)

    # Refuse to describe a flow that has no inter-arrival information
    if total_packets < MIN_PACKETS_FOR_INFERENCE:
        return None

    # CICFlowMeter measures duration in microseconds; NFStream in milliseconds
    duration_s = max(
        float(flow.bidirectional_duration_ms) / 1000.0,
        MIN_DURATION_S
    )

    duration_us = duration_s * 1_000_000.0

    # Derive rates, capped at the training distribution's ceiling
    flow_bytes_per_s = min(
        float(flow.bidirectional_bytes) / duration_s,
        MAX_FLOW_BYTES_PER_S
    )

    flow_packets_per_s = min(
        float(total_packets) / duration_s,
        MAX_FLOW_PACKETS_PER_S
    )

    # Directional totals
    fwd_packets = float(flow.src2dst_packets)
    bwd_packets = float(flow.dst2src_packets)
    fwd_bytes = float(flow.src2dst_bytes)
    bwd_bytes = float(flow.dst2src_bytes)

    down_up_ratio = (
        bwd_packets / fwd_packets
        if fwd_packets > 0
        else 0.0
    )

    # Packet size statistics, available because NFStreamer runs with
    # statistical_analysis=True.
    #
    # Phải TRỪ header: NFStream đo cả khung, CICFlowMeter đo payload.
    # Xem ETH_IP_TCP_OVERHEAD ở trên.
    overhead = (
        ETH_IP_UDP_OVERHEAD
        if int(flow.protocol) == 17
        else ETH_IP_TCP_OVERHEAD
    )

    fwd_len_max = _payload_len(_get(flow, "src2dst_max_ps"), overhead)
    fwd_len_min = _payload_len(_get(flow, "src2dst_min_ps"), overhead)
    fwd_len_mean = _payload_len(_get(flow, "src2dst_mean_ps"), overhead)
    bwd_len_mean = _payload_len(_get(flow, "dst2src_mean_ps"), overhead)

    # Tổng byte cũng phải trừ header của TỪNG gói, không phải trừ một lần
    fwd_bytes = max(0.0, fwd_bytes - overhead * fwd_packets)
    bwd_bytes = max(0.0, bwd_bytes - overhead * bwd_packets)

    # Inter-arrival statistics. NFStream reports these in milliseconds and
    # CICFlowMeter in microseconds, hence the 1000x conversion. Flow IAT Std
    # used to be hardcoded to 0, which matches 99.6% of attack rows but only
    # 16% of benign rows — a constant bias toward classifying traffic as an
    # attack.
    iat_mean_us = float(_get(flow, "bidirectional_mean_piat_ms")) * 1000.0
    iat_std_us = float(_get(flow, "bidirectional_stddev_piat_ms")) * 1000.0

    # Fall back to an even spread when NFStream withholds the mean
    if iat_mean_us <= 0.0 and total_packets > 1:
        iat_mean_us = duration_us / (total_packets - 1)

    fwd_iat_total_us = float(_get(flow, "src2dst_duration_ms")) * 1000.0

    # TCP flag features.
    #
    # HAI CỘT NÀY KHÔNG MANG Ý NGHĨA NHƯ TÊN GỌI. CICFlowMeter — công cụ sinh ra
    # CICDDoS2019 — không điền chúng theo cờ TCP thật. Đo trên dữ liệu gốc:
    #
    #   file gốc SYN-Flood.csv (capture của chính một cuộc SYN flood):
    #       SYN Flag Count   mean = 0,0002    <- gần như luôn 0
    #       ACK Flag Count   mean = 0,9996    <- gần như luôn 1
    #
    #   trên cả 11 file gốc:
    #       SYN Flag Count  ≈ 0 ở MỌI lớp (lớn nhất 0,0008) — cột chết, không
    #                       mang một bit thông tin nào
    #       ACK Flag Count  bám sát Protocol == 6:
    #                       SYN-Flood 0,9997 / 100,0% TCP
    #                       TFTP      0,9990 /  99,9% TCP
    #                       UDP-Lag   0,5626 /  57,8% TCP
    #                       DNS       0,0040 /   1,4% TCP
    #
    # Nói cách khác "ACK Flag Count" chỉ là bản sao của Protocol == 6.
    #
    # Bản FIX-32 tính ack_count theo nghĩa thật ("flow có gói ACK không"). Với
    # SYN flood bắn vào host không phản hồi thì không có gói ACK nào, nên
    # ack_count = 0 — trái ngược hẳn dữ liệu huấn luyện. Hậu quả đo được trên
    # 60.000 dòng thuộc lớp Syn:
    #
    #       nguyên bản dataset (SYN=0, ACK=1)   ->  nhận đúng Syn 40,84%
    #       chỉ đảo ACK về 0                    ->  nhận đúng Syn  0,00%
    #                                               98,4% bị gán BENIGN
    #       chỉ đảo SYN lên 1                   ->  nhận đúng Syn 42,48%
    #
    # Nên bám đúng ngữ nghĩa mà dataset thực sự ghi, không bám theo tên cột.
    # Cách gán dưới đây tái tạo đúng từng giá trị của dữ liệu huấn luyện.
    syn_count = 0.0
    ack_count = 1.0 if int(flow.protocol) == 6 else 0.0

    protocol = float(flow.protocol)

    # Cổng, lấy thẳng từ NFStream. Xem chú thích ở FEATURE_NAMES về vì sao hai
    # cột này quan trọng, và về hạn chế cổng tổng hợp của CICDDoS2019.
    src_port = float(_get(flow, "src_port"))
    dst_port = float(_get(flow, "dst_port"))

    features = np.array(
        [[
            duration_us,
            flow_bytes_per_s,
            flow_packets_per_s,
            fwd_packets,
            bwd_packets,
            down_up_ratio,
            fwd_bytes,
            bwd_bytes,
            fwd_len_max,
            fwd_len_min,
            fwd_len_mean,
            bwd_len_mean,
            iat_mean_us,
            iat_std_us,
            fwd_iat_total_us,
            protocol,
            syn_count,
            ack_count,
            src_port,
            dst_port,
        ]],
        dtype=np.float32
    )

    # Guard against any residual division artefacts
    return np.nan_to_num(
        features,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )
