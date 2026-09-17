import os
import json
import sys

ROOT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..'
    )
)

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.storage import (
    by_ip,
    connect,
    DB_PATH,
    LOG_PATH
)


def read_alert(
    src_ip="",
    max_lines=20
):
    try:
        records = by_ip(
            ip=src_ip,
            limit=max_lines
        )

        if records:
            return json.dumps({
                "status": "ok",
                "count": len(records),
                "alerts": records
            })

    except Exception:
        pass

    if not os.path.exists(LOG_PATH):
        return json.dumps({
            "status": "empty",
            "alerts": []
        })

    records = []

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

                    if not src_ip or entry.get("src_ip") == src_ip:
                        records.append(
                            entry
                        )

                except Exception:
                    pass

    except Exception as err:
        return json.dumps({
            "status": "error",
            "message": str(err)
        })

    records = records[-max_lines:]

    return json.dumps({
        "status": "ok",
        "count": len(records),
        "alerts": records
    })


def read_flow(
    src_ip
):
    raw = read_alert(
        src_ip=src_ip,
        max_lines=5
    )

    try:
        data = json.loads(
            raw
        )

        items = data.get(
            "alerts",
            []
        )

        if items:
            last = items[-1]

            pps = float(
                last.get("pps", 0.0) or 0.0
            )

            sz = float(
                last.get("avg_packet_size", 128.0) or 128.0
            )

            dur_ms = float(
                last.get("flow_duration_ms", 1000.0) or 1000.0
            )

            dur = max(
                dur_ms / 1000.0,
                0.001
            )

            fwd = int(
                last.get("fwd_pkts", 0) or 0
            )

            bwd = int(
                last.get("bwd_pkts", 0) or 0
            )

            syn = int(
                last.get("syn_count", 0) or 0
            )

            ack = int(
                last.get("ack_count", 0) or 0
            )

            rst = int(
                last.get("rst_count", 0) or 0
            )

            bytes_s = float(
                last.get("flow_bytes_s", 0.0) or 0.0
            )

            total_pkts = (
                fwd + bwd
                if (fwd or bwd)
                else (
                    int(pps * dur)
                    if pps > 0
                    else int(last.get("offense_count", 1) or 1)
                )
            )

            total_bytes = (
                int(bytes_s * dur)
                if bytes_s
                else int(total_pkts * sz)
            )

            return json.dumps({
                "src_ip": last.get("src_ip"),
                "protocol": last.get("protocol"),
                "dst_port": last.get("dst_port"),
                "pps": pps,
                "avg_packet_size_bytes": sz,
                "duration_secs": round(dur, 3),
                "flow_duration_ms": round(dur_ms, 2),
                "flow_bytes_s": bytes_s,
                "fwd_pkts": fwd,
                "bwd_pkts": bwd,
                "syn_count": syn,
                "ack_count": ack,
                "rst_count": rst,
                "total_packets": total_pkts,
                "total_bytes": total_bytes,
                "ttl_secs": last.get("ttl_secs"),
                "reason": last.get("reason"),
                "offense_count": last.get("offense_count"),
                "recent_reasons": list({
                    r.get("reason")
                    for r in items
                    if r.get("reason")
                })
            })

    except Exception:
        pass

    return json.dumps({
        "status": "not_found",
        "src_ip": src_ip
    })


def read_metrics():
    try:
        conn = connect(
            DB_PATH
        )

        cur = conn.cursor()

        cur.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT src_ip) FROM alerts;
            """
        )

        overview = cur.fetchone()

        total = overview[0] or 0
        ips = overview[1] or 0

        cur.execute(
            """
            SELECT reason, COUNT(*) FROM alerts GROUP BY reason;
            """
        )

        reasons = {
            r[0]: r[1]
            for r in cur.fetchall()
            if r[0]
        }

        cur.close()

        conn.close()

        return json.dumps({
            "total_alerts": total,
            "blocked_ips": ips,
            "distribution": reasons
        })

    except Exception:
        pass

    total = 0
    ips = set()
    reasons = {}

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

                        total += 1

                        ip = entry.get(
                            "src_ip"
                        )

                        if ip:
                            ips.add(
                                ip
                            )

                        reason = entry.get(
                            "reason",
                            "Unknown"
                        )

                        reasons[reason] = (
                            reasons.get(reason, 0) + 1
                        )

                    except Exception:
                        pass

        except Exception:
            pass

    return json.dumps({
        "total_alerts": total,
        "blocked_ips": len(ips),
        "distribution": reasons
    })
