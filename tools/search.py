import os
import json
import sys
import ipaddress

ROOT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..'
    )
)

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.storage import (
    history,
    subnet,
    LOG_PATH
)


def search_history(
    src_ip
):
    try:
        res = history(
            ip=src_ip
        )

        if res and res.get("offenses", 0) > 0:
            return json.dumps(
                res
            )

    except Exception:
        pass

    if not os.path.exists(LOG_PATH):
        return json.dumps({
            "src_ip": src_ip,
            "offenses": 0,
            "first_seen": None,
            "last_seen": None,
            "protocols": [],
            "reasons": [],
            "dst_ports": [],
            "avg_pps": 0.0,
            "total_bytes_across_offenses": 0
        })

    count = 0
    first_ts = None
    last_ts = None
    protocols = set()
    reasons = set()
    ports = set()
    pps_list = []
    bytes_total = 0

    try:
        with open(
            LOG_PATH,
            'r',
            encoding='utf-8'
        ) as stream:
            for line in stream:
                text = line.strip()
                if not text:
                    continue

                try:
                    entry = json.loads(
                        text
                    )

                    if entry.get("src_ip") == src_ip:
                        count += 1
                        ts = entry.get("timestamp")

                        if first_ts is None or (ts and ts < first_ts):
                            first_ts = ts

                        if last_ts is None or (ts and ts > last_ts):
                            last_ts = ts

                        if entry.get("protocol"):
                            protocols.add(entry["protocol"])

                        if entry.get("reason"):
                            reasons.add(entry["reason"])

                        if entry.get("dst_port"):
                            ports.add(entry["dst_port"])

                        pps = entry.get("pps")
                        if pps:
                            pps_list.append(float(pps))

                        sz = float(entry.get("avg_packet_size", 128.0) or 128.0)
                        dur_ms = float(entry.get("flow_duration_ms", 1000.0) or 1000.0)
                        dur = max(dur_ms / 1000.0, 0.001)
                        fwd = entry.get("fwd_pkts", 0) or 0
                        bwd = entry.get("bwd_pkts", 0) or 0
                        bytes_s = entry.get("flow_bytes_s", 0.0) or 0.0
                        pps_val = float(entry.get("pps", 0.0) or 0.0)

                        if bytes_s:
                            bytes_total += int(float(bytes_s) * dur)
                        elif fwd or bwd:
                            bytes_total += int((fwd + bwd) * sz)
                        else:
                            bytes_total += int(pps_val * dur * sz)

                except Exception:
                    pass

    except Exception as err:
        return json.dumps({
            "status": "error",
            "message": str(err)
        })

    avg_pps = (
        round(sum(pps_list) / len(pps_list), 2)
        if pps_list
        else 0.0
    )

    return json.dumps({
        "src_ip": src_ip,
        "offenses": count,
        "first_seen": first_ts,
        "last_seen": last_ts,
        "protocols": sorted(list(protocols)),
        "reasons": sorted(list(reasons)),
        "dst_ports": sorted(list(ports)),
        "avg_pps": avg_pps,
        "total_bytes_across_offenses": bytes_total
    })


def search_subnet(
    target
):
    try:
        res = subnet(
            cidr=target
        )

        if res and res.get("total_packets_recorded", 0) > 0:
            return json.dumps(
                res
            )

    except Exception:
        pass

    try:
        if "/" in target:
            net = ipaddress.ip_network(
                target,
                strict=False
            )
        else:
            net = ipaddress.ip_network(
                f"{target}/24",
                strict=False
            )

    except Exception as err:
        return json.dumps({
            "status": "error",
            "message": f"Invalid subnet: {err}"
        })

    matched = set()
    hits = 0
    reasons = set()
    ports = set()

    if os.path.exists(LOG_PATH):
        try:
            with open(
                LOG_PATH,
                'r',
                encoding='utf-8'
            ) as stream:
                for line in stream:
                    text = line.strip()
                    if not text:
                        continue

                    try:
                        entry = json.loads(
                            text
                        )

                        ip = entry.get(
                            "src_ip"
                        )

                        if ip:
                            addr = ipaddress.ip_address(
                                ip
                            )

                            if addr in net:
                                matched.add(
                                    ip
                                )

                                hits += 1

                                if entry.get("reason"):
                                    reasons.add(
                                        entry["reason"]
                                    )

                                if entry.get("dst_port"):
                                    ports.add(
                                        entry["dst_port"]
                                    )

                    except Exception:
                        pass

        except Exception as err:
            return json.dumps({
                "status": "error",
                "message": str(err)
            })

    is_bot = bool(len(matched) >= 3)

    return json.dumps({
        "subnet": str(net),
        "unique_bot_ips": sorted(list(matched)),
        "bot_count": len(matched),
        "total_packets_recorded": hits,
        "attack_reasons": sorted(list(reasons)),
        "targeted_ports": sorted(list(ports)),
        "is_distributed_cluster": is_bot
    })
