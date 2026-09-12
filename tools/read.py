import os
import json
import ipaddress

LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    '..',
    'logs',
    'alerts.log'
)

def read_alert(src_ip="", max_lines=20):
    if not os.path.exists(LOG_PATH):
        return json.dumps({"status": "empty", "alerts": []})

    records = []
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                text = line.strip()
                if not text:
                    continue
                try:
                    entry = json.loads(text)
                    if not src_ip or entry.get("src_ip") == src_ip:
                        records.append(entry)
                except Exception:
                    pass
    except Exception as err:
        return json.dumps({"status": "error", "message": str(err)})

    records = records[-max_lines:]
    return json.dumps({
        "status": "ok",
        "count": len(records),
        "alerts": records
    })

def read_flow(src_ip):
    res = read_alert(src_ip, max_lines=5)
    try:
        data = json.loads(res)
        alerts = data.get("alerts", [])
        if alerts:
            t = alerts[-1]
            pps = t.get("pps", 0) or 0
            avg_sz = t.get("avg_packet_size", 128) or 128
            dur_ms = t.get("flow_duration_ms", 1000.0) or 1000.0
            dur = max(float(dur_ms) / 1000.0, 0.001)
            fwd_pkts = t.get("fwd_pkts", 0)
            bwd_pkts = t.get("bwd_pkts", 0)
            syn_cnt = t.get("syn_count", 0)
            ack_cnt = t.get("ack_count", 0)
            rst_cnt = t.get("rst_count", 0)
            flow_bytes_s = t.get("flow_bytes_s", 0)

            total_pkts = (fwd_pkts + bwd_pkts) if (fwd_pkts or bwd_pkts) else (int(pps * dur) if pps > 0 else t.get("offense_count", 1))
            total_bytes = int(flow_bytes_s * dur) if flow_bytes_s else int(total_pkts * avg_sz)

            return json.dumps({
                "src_ip": t.get("src_ip"),
                "protocol": t.get("protocol"),
                "dst_port": t.get("dst_port"),
                "pps": pps,
                "avg_packet_size_bytes": avg_sz,
                "duration_secs": round(dur, 3),
                "flow_duration_ms": round(dur_ms, 2),
                "flow_bytes_s": flow_bytes_s,
                "fwd_pkts": fwd_pkts,
                "bwd_pkts": bwd_pkts,
                "syn_count": syn_cnt,
                "ack_count": ack_cnt,
                "rst_count": rst_cnt,
                "total_packets": total_pkts,
                "total_bytes": total_bytes,
                "ttl_secs": t.get("ttl_secs"),
                "reason": t.get("reason"),
                "offense_count": t.get("offense_count"),
                "recent_reasons": list({a.get("reason") for a in alerts if a.get("reason")})
            })
    except Exception:
        pass
    return json.dumps({"status": "not_found", "src_ip": src_ip})

def read_metrics():
    total_alerts = 0
    unique_ips = set()
    reasons = {}

    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        entry = json.loads(text)
                        total_alerts += 1
                        ip = entry.get("src_ip")
                        if ip:
                            unique_ips.add(ip)
                        r = entry.get("reason", "Unknown")
                        reasons[r] = reasons.get(r, 0) + 1
                    except Exception:
                        pass
        except Exception:
            pass

    return json.dumps({
        "total_alerts": total_alerts,
        "blocked_ips": len(unique_ips),
        "distribution": reasons
    })
