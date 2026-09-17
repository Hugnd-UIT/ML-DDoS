import argparse
import fcntl
import os
import socket
import struct
import sys
import time
import warnings

warnings.filterwarnings('ignore')

import joblib
import numpy as np
import xgboost as xgb

from nfstream import NFStreamer

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'FIN Flag Count',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'Active Mean',
    'Idle Mean',
    'Destination Port'
]

ROOT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..'
    )
)

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from prevent.enforcer import Enforcer, Signature
except ImportError:
    from enforcer import Enforcer, Signature


PROTO_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


def proto_name(proto_num):
    return PROTO_NAMES.get(
        int(proto_num),
        str(proto_num)
    )


MODELS_DIR = os.path.join(
    ROOT_DIR,
    'models'
)

XGB_PATH = os.path.join(
    MODELS_DIR,
    'XGBoost.pkl'
)

ISO_PATH = os.path.join(
    MODELS_DIR,
    'IsolationForest.pkl'
)

LABELS_PATH = os.path.join(
    MODELS_DIR,
    'labels.pkl'
)

XDP_PATH = os.path.join(
    ROOT_DIR,
    'prevent',
    'xdp.c'
)



def parse_args():
    parser = argparse.ArgumentParser(
        description='XGBoost + IsolationForest + eBPF/XDP',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-i',
        '--interface',
        required=True,
        metavar='IFACE',
        help='Network interface to protect (e.g. eth0, ens4)'
    )

    parser.add_argument(
        '--xdp',
        default=XDP_PATH,
        metavar='FILE',
        help=f'Path to XDP C source file (default: {XDP_PATH})'
    )

    return parser.parse_args()


def get_ips(ifname):
    import subprocess

    ips = set()

    try:
        res = subprocess.run(
            [
                'ip',
                '-4',
                'addr',
                'show',
                ifname
            ],
            capture_output=True,
            text=True,
            timeout=3
        )

        for line in res.stdout.splitlines():
            line = line.strip()

            if line.startswith('inet '):
                ip = line.split()[1]
                ip = ip.split('/')[0]

                ips.add(ip)

    except Exception:
        pass

    if not ips:
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            try:
                addr = fcntl.ioctl(
                    sock.fileno(),
                    0x8915,
                    struct.pack(
                        '256s',
                        bytes(
                            ifname[:15],
                            'utf-8'
                        )
                    )
                )

                ip = socket.inet_ntoa(
                    addr[20:24]
                )

                ips.add(ip)

            finally:
                sock.close()

        except Exception:
            pass

    ips.add('127.0.0.1')

    return ips


def load_models():
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')

            xgb_model = joblib.load(
                XGB_PATH
            )

            iso_model = joblib.load(
                ISO_PATH
            )

            label_encoder = joblib.load(
                LABELS_PATH
            )

        print(
            f"  [+] XGBoost model loaded: {type(xgb_model).__name__}"
        )
        print(
            f"      Path: {XGB_PATH}"
        )

        print(
            f"  [+] IsolationForest model loaded: {type(iso_model).__name__}"
        )
        print(
            f"      Path: {ISO_PATH}"
        )

        print(
            f"  [+] LabelEncoder loaded: {len(label_encoder.classes_)} classes"
        )
        print(
            f"      Path: {LABELS_PATH}"
        )

        return xgb_model, iso_model, label_encoder

    except Exception as exc:
        print(
            f"  [-] Unable to load models: {exc}"
        )
        print(
            "  [-] Valid models and label encoder are required."
        )
        print(
            "  [-] Exiting system..."
        )
        sys.exit(1)


def extract_features(flow):
    duration_ms = float(
        getattr(
            flow,
            'bidirectional_duration_ms',
            0.0
        )
    )

    duration_us = duration_ms * 1000.0

    duration_s = max(
        duration_ms / 1000.0,
        0.001
    )

    fwd_pkts = float(
        getattr(
            flow,
            'src2dst_packets',
            0
        )
    )

    bwd_pkts = float(
        getattr(
            flow,
            'dst2src_packets',
            0
        )
    )

    total_pkts = fwd_pkts + bwd_pkts

    fwd_bytes = float(
        getattr(
            flow,
            'src2dst_bytes',
            0
        )
    )

    bwd_bytes = float(
        getattr(
            flow,
            'dst2src_bytes',
            0
        )
    )

    total_bytes = fwd_bytes + bwd_bytes

    fwd_len_max = float(
        getattr(
            flow,
            'src2dst_max_ps',
            0.0
        )
    )

    fwd_len_min = float(
        getattr(
            flow,
            'src2dst_min_ps',
            0.0
        )
    )

    fwd_len_mean = float(
        getattr(
            flow,
            'src2dst_mean_ps',
            0.0
        )
    )

    bwd_len_max = float(
        getattr(
            flow,
            'dst2src_max_ps',
            0.0
        )
    )

    bwd_len_mean = float(
        getattr(
            flow,
            'dst2src_mean_ps',
            0.0
        )
    )

    flow_bytes_s = total_bytes / duration_s
    flow_packets_s = total_pkts / duration_s

    flow_iat_mean = (
        float(
            getattr(
                flow,
                'bidirectional_mean_piat_ms',
                0.0
            )
        )
        * 1000.0
    )

    if flow_iat_mean == 0.0 and total_pkts > 1:
        flow_iat_mean = duration_us / (total_pkts - 1)

    flow_iat_std = (
        float(
            getattr(
                flow,
                'bidirectional_stddev_piat_ms',
                0.0
            )
        )
        * 1000.0
    )

    fwd_iat_mean = (
        float(
            getattr(
                flow,
                'src2dst_mean_piat_ms',
                0.0
            )
        )
        * 1000.0
    )

    if fwd_iat_mean == 0.0 and fwd_pkts > 1:
        fwd_duration_ms = float(
            getattr(
                flow,
                'src2dst_duration_ms',
                0.0
            )
        )
        fwd_iat_mean = (fwd_duration_ms * 1000.0) / (fwd_pkts - 1)

    bwd_iat_mean = (
        float(
            getattr(
                flow,
                'dst2src_mean_piat_ms',
                0.0
            )
        )
        * 1000.0
    )

    if bwd_iat_mean == 0.0 and bwd_pkts > 1:
        bwd_duration_ms = float(
            getattr(
                flow,
                'dst2src_duration_ms',
                0.0
            )
        )
        bwd_iat_mean = (bwd_duration_ms * 1000.0) / (bwd_pkts - 1)

    syn_count = float(
        getattr(
            flow,
            'bidirectional_syn_packets',
            0
        )
    )

    rst_count = float(
        getattr(
            flow,
            'bidirectional_rst_packets',
            0
        )
    )

    psh_count = float(
        getattr(
            flow,
            'bidirectional_psh_packets',
            0
        )
    )

    ack_count = float(
        getattr(
            flow,
            'bidirectional_ack_packets',
            0
        )
    )

    fin_count = float(
        getattr(
            flow,
            'bidirectional_fin_packets',
            0
        )
    )

    init_win_fwd = float(
        getattr(
            flow,
            'src2dst_init_win',
            0
        )
    )

    init_win_bwd = float(
        getattr(
            flow,
            'dst2src_init_win',
            0
        )
    )

    active_mean = (
        float(
            getattr(
                flow,
                'bidirectional_mean_active_ms',
                0.0
            )
        )
        * 1000.0
    )

    idle_mean = (
        float(
            getattr(
                flow,
                'bidirectional_mean_idle_ms',
                0.0
            )
        )
        * 1000.0
    )

    dst_port = float(
        getattr(
            flow,
            'dst_port',
            0
        )
    )

    features = np.array(
        [[
            duration_us,
            fwd_pkts,
            bwd_pkts,
            fwd_bytes,
            bwd_bytes,
            fwd_len_max,
            fwd_len_min,
            fwd_len_mean,
            bwd_len_max,
            bwd_len_mean,
            flow_bytes_s,
            flow_packets_s,
            flow_iat_mean,
            flow_iat_std,
            fwd_iat_mean,
            bwd_iat_mean,
            syn_count,
            rst_count,
            psh_count,
            ack_count,
            fin_count,
            init_win_fwd,
            init_win_bwd,
            active_mean,
            idle_mean,
            dst_port
        ]],
        dtype=np.float32
    )

    features = np.nan_to_num(
        features,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )

    return features


def _banner(
    title,
    width=65
):
    print(
        f"\n  {'─' * width}"
    )
    print(
        f"  {title}"
    )
    print(
        f"  {'─' * width}"
    )


def main():
    args = parse_args()
    interface = args.interface

    print()
    print(
        "  ╔" + "═" * 65 + "╗"
    )
    print(
        f"  ║{'XGBoost + IsolationForest + eBPF/XDP':^65}║"
    )
    print(
        f"  ║{f'Interface : {interface}':^65}║"
    )
    print(
        "  ╚" + "═" * 65 + "╝"
    )
    print()

    _banner(
        "1/4  INITIALIZING eBPF/XDP..."
    )

    enforcer = Enforcer(
        interface,
        getattr(args, 'xdp', XDP_PATH)
    )

    if not enforcer.load_xdp():
        return

    _banner(
        "WHITELIST"
    )

    enforcer.load_whitelist()

    _banner(
        "2/4  INITIALIZING HISTORY..."
    )

    print(
        "  [+] History initialized"
    )

    _banner(
        "3/4  INITIALIZING MACHINE LEARNING..."
    )

    xgb_model, iso_model, label_encoder = load_models()

    benign_idx = None
    if 'Benign' in label_encoder.classes_:
        benign_idx = int(
            label_encoder.transform(['Benign'])[0]
        )

    _banner(
        "4/4  CONFIGURING EGRESS..."
    )

    local_ips = get_ips(
        interface
    )

    print(
        f"  [+] IPs: {', '.join(sorted(local_ips))}"
    )

    print()
    print(
        "  ╔" + "═" * 65 + "╗"
    )
    print(
        "  ║                         MONITORING...                           ║"
    )
    print(
        "  ╚" + "═" * 65 + "╝"
    )
    print()

    try:
        streamer = NFStreamer(
            source=interface,
            active_timeout=1,
            idle_timeout=1,
            statistical_analysis=True
        )

        for flow in streamer:
            try:
                if ":" in flow.src_ip:
                    continue

                if interface != 'lo' and flow.src_ip in local_ips:
                    continue

                if enforcer.check_blacklist(flow.src_ip):
                    continue

                features = extract_features(flow)

                if hasattr(xgb_model, 'predict') and 'Booster' in type(xgb_model).__name__:
                    dmat = xgb.DMatrix(
                        features,
                        feature_names=FEATURES
                    )
                    probs = xgb_model.predict(dmat)
                    pred_val = int(np.argmax(probs, axis=1)[0])
                else:
                    prediction = xgb_model.predict(features)
                    if isinstance(prediction, (list, np.ndarray)):
                        pred_val = int(prediction[0])
                    else:
                        pred_val = int(prediction)

                is_attack = False
                reason = ""

                if benign_idx is not None and pred_val != benign_idx:
                    is_attack = True
                    class_name = label_encoder.inverse_transform([pred_val])[0]
                    reason = str(class_name)
                elif benign_idx is None and pred_val != 0:
                    is_attack = True
                    reason = f"Class {pred_val}"

                if not is_attack and iso_model is not None:
                    score = float(
                        iso_model.score_samples(features)[0]
                    )

                    offset = float(
                        getattr(
                            iso_model,
                            'offset_',
                            -0.5
                        )
                    )

                    dur = max(
                        float(getattr(flow, 'bidirectional_duration_ms', 1.0)) / 1000.0,
                        0.001
                    )

                    rate = (
                        float(getattr(flow, 'bidirectional_packets', 1))
                        / dur
                    )

                    is_deep = bool(
                        score < (offset - 0.08)
                    )

                    has_flood = bool(
                        (getattr(flow, 'bidirectional_syn_packets', 0) > 10 and getattr(flow, 'bidirectional_ack_packets', 0) == 0)
                        or (getattr(flow, 'bidirectional_rst_packets', 0) > 20)
                        or (rate > 1500.0)
                    )

                    if is_deep and has_flood:
                        is_attack = True
                        reason = "Zero-Day"

                if is_attack:
                    if not enforcer.check_whitelist(flow.src_ip):
                        dur = max(
                            float(getattr(flow, 'bidirectional_duration_ms', 1.0)) / 1000.0,
                            0.001
                        )
                        fwd = float(getattr(flow, 'src2dst_packets', 0))
                        bwd = float(getattr(flow, 'dst2src_packets', 0))
                        bytes_total = float(getattr(flow, 'src2dst_bytes', 0)) + float(getattr(flow, 'dst2src_bytes', 0))
                        sig = Signature(
                            src_ip=flow.src_ip,
                            protocol=proto_name(flow.protocol),
                            dst_port=int(getattr(flow, "dst_port", 0)),
                            fwd_len_mean=float(getattr(flow, "src2dst_mean_ps", 0.0)),
                            pps=float(getattr(flow, 'bidirectional_packets', 1)) / dur,
                            reason=reason,
                            features=features[0].tolist(),
                            fwd_pkts=int(fwd),
                            bwd_pkts=int(bwd),
                            syn_count=int(getattr(flow, 'bidirectional_syn_packets', 0)),
                            ack_count=int(getattr(flow, 'bidirectional_ack_packets', 0)),
                            rst_count=int(getattr(flow, 'bidirectional_rst_packets', 0)),
                            flow_duration_ms=float(getattr(flow, 'bidirectional_duration_ms', 0.0)),
                            flow_bytes_s=bytes_total / dur
                        )

                        count, ttl_secs = enforcer.block_ip(sig)

                        ttl_label = (
                            f"{ttl_secs // 3600}h"
                            if ttl_secs >= 3600
                            else f"{ttl_secs // 60}m"
                        )

                        prefix = "[ZERO-DAY]" if reason == "Zero-Day" else "[BLOCK]"

                        print(
                            f"  {prefix:<10} {flow.src_ip:<16} "
                            f"{reason:<16} "
                            f"│ ban {ttl_label:<4} "
                            f"│ offense #{count}"
                        )

            except Exception as flow_err:
                print(
                    f"  [-] Flow error ({flow.src_ip}): {flow_err}"
                )

    except KeyboardInterrupt:
        print(
            "\n  [~] Cleaning up..."
        )

    except Exception as exc:
        print(
            f"\n  [✗] Fatal error: {exc}"
        )

    finally:
        print(
            "  [*] Shutting down..."
        )
        enforcer.detach_xdp()


if __name__ == "__main__":
    main()