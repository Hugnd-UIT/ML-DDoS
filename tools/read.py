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
            dur = t.get("duration", 1.0) or 1.0
            total_pkts = int(pps * dur) if pps > 0 else t.get("offense_count", 1)
            return json.dumps({
                "src_ip": t.get("src_ip"),
                "protocol": t.get("protocol"),
                "dst_port": t.get("dst_port"),
                "pps": pps,
                "avg_packet_size_bytes": avg_sz,
                "duration_secs": dur,
                "total_packets": total_pkts,
                "total_bytes": int(total_pkts * avg_sz),
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
