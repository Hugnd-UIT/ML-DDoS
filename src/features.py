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
MIN_PACKETS_FOR_INFERENCE = 2


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
    # statistical_analysis=True
    fwd_len_max = float(_get(flow, "src2dst_max_ps"))
    fwd_len_min = float(_get(flow, "src2dst_min_ps"))
    fwd_len_mean = float(_get(flow, "src2dst_mean_ps"))
    bwd_len_mean = float(_get(flow, "dst2src_mean_ps"))

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

    # TCP flag counters
    syn_count = float(_get(flow, "bidirectional_syn_packets"))
    ack_count = float(_get(flow, "bidirectional_ack_packets"))

    protocol = float(flow.protocol)

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
