import os
import json
import ipaddress

LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    '..',
    'logs',
    'alerts.log'
)

def search_history(src_ip):
    if not os.path.exists(LOG_PATH):
        return json.dumps({"src_ip": src_ip, "offenses": 0, "first_seen": None, "last_seen": None})

    offenses = 0
    first_seen = None
    last_seen = None
    protocols = set()
    reasons = set()
    ports = set()
    pps_vals = []
    bytes_total = 0

    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                text = line.strip()
                if not text:
                    continue
                try:
                    entry = json.loads(text)
                    if entry.get("src_ip") == src_ip:
                        offenses += 1
                        ts = entry.get("timestamp")
                        if first_seen is None or (ts and ts < first_seen):
                            first_seen = ts
                        if last_seen is None or (ts and ts > last_seen):
                            last_seen = ts
                        if entry.get("protocol"):
                            protocols.add(entry["protocol"])
                        if entry.get("reason"):
                            reasons.add(entry["reason"])
                        if entry.get("dst_port"):
                            ports.add(entry["dst_port"])
                        pps = entry.get("pps")
                        if pps:
                            pps_vals.append(float(pps))
                        sz = float(entry.get("avg_packet_size", 128) or 128)
                        dur_ms = float(entry.get("flow_duration_ms", 1000.0) or 1000.0)
                        dur = max(dur_ms / 1000.0, 0.001)
                        fwd_p = entry.get("fwd_pkts", 0)
                        bwd_p = entry.get("bwd_pkts", 0)
                        flow_bs = entry.get("flow_bytes_s", 0)
                        p = float(entry.get("pps", 0) or 0)
                        if flow_bs:
                            bytes_total += int(float(flow_bs) * dur)
                        elif fwd_p or bwd_p:
                            bytes_total += int((fwd_p + bwd_p) * sz)
                        else:
                            bytes_total += int(p * dur * sz)
                except Exception:
                    pass
    except Exception as err:
        return json.dumps({"status": "error", "message": str(err)})

    avg_pps = round(sum(pps_vals) / len(pps_vals), 2) if pps_vals else None

    return json.dumps({
        "src_ip": src_ip,
        "offenses": offenses,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "protocols": list(protocols),
        "reasons": list(reasons),
        "dst_ports": list(ports),
        "avg_pps": avg_pps,
        "total_bytes_across_offenses": bytes_total
    })

def search_subnet(ip_or_cidr):
    try:
        if "/" in ip_or_cidr:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
        else:
            net = ipaddress.ip_network(f"{ip_or_cidr}/24", strict=False)
    except Exception as err:
        return json.dumps({"status": "error", "message": f"Invalid subnet: {err}"})

    matching_ips = set()
    total_hits = 0
    subnet_reasons = set()
    subnet_ports = set()

    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        entry = json.loads(text)
                        ip_str = entry.get("src_ip")
                        if ip_str:
                            addr = ipaddress.ip_address(ip_str)
                            if addr in net:
                                matching_ips.add(ip_str)
                                total_hits += 1
                                if entry.get("reason"):
                                    subnet_reasons.add(entry["reason"])
                                if entry.get("dst_port"):
                                    subnet_ports.add(entry["dst_port"])
                    except Exception:
                        pass
        except Exception as err:
            return json.dumps({"status": "error", "message": str(err)})

    is_botnet = len(matching_ips) >= 3

    return json.dumps({
        "subnet": str(net),
        "unique_bot_ips": list(matching_ips),
        "bot_count": len(matching_ips),
        "total_packets_recorded": total_hits,
        "attack_reasons": list(subnet_reasons),
        "targeted_ports": list(subnet_ports),
        "is_distributed_cluster": is_botnet
    })
