import os
import json
import sqlite3
import threading
import ipaddress

ROOT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..'
    )
)

LOG_DIR = os.path.join(
    ROOT_DIR,
    'logs'
)

DB_PATH = os.path.join(
    LOG_DIR,
    'alerts.db'
)

LOG_PATH = os.path.join(
    LOG_DIR,
    'alerts.log'
)

LOCK = threading.RLock()


def connect(
    path=DB_PATH
):
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    conn = sqlite3.connect(
        path,
        timeout=15.0,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    cur = conn.cursor()

    cur.execute(
        "PRAGMA journal_mode = WAL;"
    )

    cur.execute(
        "PRAGMA synchronous = NORMAL;"
    )

    cur.execute(
        "PRAGMA busy_timeout = 10000;"
    )

    cur.close()

    return conn


def init(
    path=DB_PATH
):
    with LOCK:
        conn = connect(
            path
        )

        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                protocol TEXT,
                dst_port INTEGER,
                reason TEXT,
                pps REAL,
                ttl_secs INTEGER,
                offense_count INTEGER,
                avg_packet_size REAL,
                fwd_pkts INTEGER,
                bwd_pkts INTEGER,
                syn_count INTEGER,
                ack_count INTEGER,
                rst_count INTEGER,
                flow_duration_ms REAL,
                flow_bytes_s REAL,
                audit_decision TEXT,
                audit_classification TEXT,
                audit_corrected_attack TEXT,
                audit_reason TEXT,
                audit_steps INTEGER,
                audit_history TEXT,
                audit_payload TEXT,
                unbanned_processed INTEGER DEFAULT 0
            );
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip
            ON alerts(src_ip);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_audit_decision
            ON alerts(audit_decision);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_unbanned
            ON alerts(unbanned_processed);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_ip_ts
            ON alerts(src_ip, timestamp);
            """
        )

        conn.commit()

        cur.close()

        conn.close()


def sync(
    path=DB_PATH,
    log=LOG_PATH
):
    if not os.path.exists(log):
        return

    init(
        path
    )

    with LOCK:
        conn = connect(
            path
        )

        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM alerts;"
        )

        total = cur.fetchone()[0]

        if total > 0:
            cur.close()
            conn.close()
            return

        query = """
            INSERT INTO alerts (
                timestamp,
                src_ip,
                protocol,
                dst_port,
                reason,
                pps,
                ttl_secs,
                offense_count,
                avg_packet_size,
                fwd_pkts,
                bwd_pkts,
                syn_count,
                ack_count,
                rst_count,
                flow_duration_ms,
                flow_bytes_s,
                audit_decision,
                audit_classification,
                audit_corrected_attack,
                audit_reason,
                audit_steps,
                audit_history,
                audit_payload,
                unbanned_processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        records = []

        try:
            with open(
                log,
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

                        audit_obj = entry.get(
                            "audit",
                            {}
                        )

                        decision = audit_obj.get(
                            "decision"
                        )

                        cls_name = audit_obj.get(
                            "classification"
                        )

                        corrected = audit_obj.get(
                            "corrected_attack"
                        )

                        reason = audit_obj.get(
                            "reason"
                        )

                        steps = audit_obj.get(
                            "steps",
                            0
                        )

                        hist = (
                            json.dumps(
                                audit_obj.get(
                                    "history",
                                    []
                                )
                            )
                            if "history" in audit_obj
                            else None
                        )

                        payload = (
                            json.dumps(
                                audit_obj
                            )
                            if audit_obj
                            else None
                        )

                        flag = (
                            1
                            if decision == "UNBLOCK"
                            else 0
                        )

                        records.append((
                            float(entry.get("timestamp", 0.0) or 0.0),
                            str(entry.get("src_ip", "")),
                            str(entry.get("protocol", "UNKNOWN")),
                            int(entry.get("dst_port", 0) or 0),
                            str(entry.get("reason", "AI_INFERENCE")),
                            float(entry.get("pps", 0.0) or 0.0),
                            int(entry.get("ttl_secs", 300) or 300),
                            int(entry.get("offense_count", 1) or 1),
                            float(entry.get("avg_packet_size", 0.0) or 0.0),
                            int(entry.get("fwd_pkts", 0) or 0),
                            int(entry.get("bwd_pkts", 0) or 0),
                            int(entry.get("syn_count", 0) or 0),
                            int(entry.get("ack_count", 0) or 0),
                            int(entry.get("rst_count", 0) or 0),
                            float(entry.get("flow_duration_ms", 0.0) or 0.0),
                            float(entry.get("flow_bytes_s", 0.0) or 0.0),
                            decision,
                            cls_name,
                            corrected,
                            reason,
                            steps,
                            hist,
                            payload,
                            flag
                        ))

                    except Exception:
                        pass

            if records:
                cur.executemany(
                    query,
                    records
                )

                conn.commit()

        except Exception:
            pass

        finally:
            cur.close()
            conn.close()


def record(
    entry,
    path=DB_PATH,
    log=LOG_PATH
):
    init(
        path
    )

    with LOCK:
        conn = connect(
            path
        )

        cur = conn.cursor()

        query = """
            INSERT INTO alerts (
                timestamp,
                src_ip,
                protocol,
                dst_port,
                reason,
                pps,
                ttl_secs,
                offense_count,
                avg_packet_size,
                fwd_pkts,
                bwd_pkts,
                syn_count,
                ack_count,
                rst_count,
                flow_duration_ms,
                flow_bytes_s,
                audit_decision,
                audit_classification,
                audit_corrected_attack,
                audit_reason,
                audit_steps,
                audit_history,
                audit_payload,
                unbanned_processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        audit_obj = entry.get(
            "audit",
            {}
        )

        cur.execute(
            query,
            (
                float(entry.get("timestamp", 0.0) or 0.0),
                str(entry.get("src_ip", "")),
                str(entry.get("protocol", "UNKNOWN")),
                int(entry.get("dst_port", 0) or 0),
                str(entry.get("reason", "AI_INFERENCE")),
                float(entry.get("pps", 0.0) or 0.0),
                int(entry.get("ttl_secs", 300) or 300),
                int(entry.get("offense_count", 1) or 1),
                float(entry.get("avg_packet_size", 0.0) or 0.0),
                int(entry.get("fwd_pkts", 0) or 0),
                int(entry.get("bwd_pkts", 0) or 0),
                int(entry.get("syn_count", 0) or 0),
                int(entry.get("ack_count", 0) or 0),
                int(entry.get("rst_count", 0) or 0),
                float(entry.get("flow_duration_ms", 0.0) or 0.0),
                float(entry.get("flow_bytes_s", 0.0) or 0.0),
                audit_obj.get("decision"),
                audit_obj.get("classification"),
                audit_obj.get("corrected_attack"),
                audit_obj.get("reason"),
                audit_obj.get("steps", 0),
                json.dumps(audit_obj.get("history", [])) if "history" in audit_obj else None,
                json.dumps(audit_obj) if audit_obj else None,
                0
            )
        )

        conn.commit()

        cur.close()

        conn.close()

    try:
        os.makedirs(
            os.path.dirname(log),
            exist_ok=True
        )

        with open(
            log,
            'a',
            encoding='utf-8'
        ) as stream:
            stream.write(
                json.dumps(entry) + '\n'
            )

    except Exception:
        pass


def audit(
    ip,
    ts,
    data,
    path=DB_PATH
):
    init(
        path
    )

    with LOCK:
        conn = connect(
            path
        )

        cur = conn.cursor()

        decision = data.get(
            "decision",
            "KEEP_BLOCK"
        )

        cls_name = data.get(
            "classification",
            "MALICIOUS"
        )

        corrected = data.get(
            "corrected_attack"
        )

        reason = data.get(
            "reason",
            ""
        )

        steps = data.get(
            "steps",
            0
        )

        hist = json.dumps(
            data.get(
                "history",
                []
            )
        )

        payload = json.dumps(
            data
        )

        num_ts = float(
            ts or 0.0
        )

        if num_ts > 0:
            cur.execute(
                """
                UPDATE alerts
                SET audit_decision = ?,
                    audit_classification = ?,
                    audit_corrected_attack = ?,
                    audit_reason = ?,
                    audit_steps = ?,
                    audit_history = ?,
                    audit_payload = ?
                WHERE src_ip = ?
                  AND ABS(timestamp - ?) < 0.1;
                """,
                (
                    decision,
                    cls_name,
                    corrected,
                    reason,
                    steps,
                    hist,
                    payload,
                    ip,
                    num_ts
                )
            )

        else:
            cur.execute(
                """
                UPDATE alerts
                SET audit_decision = ?,
                    audit_classification = ?,
                    audit_corrected_attack = ?,
                    audit_reason = ?,
                    audit_steps = ?,
                    audit_history = ?,
                    audit_payload = ?
                WHERE id = (
                    SELECT id FROM alerts
                    WHERE src_ip = ?
                      AND audit_decision IS NULL
                    ORDER BY timestamp DESC
                    LIMIT 1
                );
                """,
                (
                    decision,
                    cls_name,
                    corrected,
                    reason,
                    steps,
                    hist,
                    payload,
                    ip
                )
            )

        conn.commit()

        cur.close()

        conn.close()


def alerts(
    limit=50,
    pending=False,
    path=DB_PATH
):
    init(
        path
    )

    conn = connect(
        path
    )

    cur = conn.cursor()

    if pending:
        cur.execute(
            """
            SELECT *
            FROM alerts
            WHERE audit_decision IS NULL
            ORDER BY timestamp ASC
            LIMIT ?;
            """,
            (limit,)
        )

    else:
        cur.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?;
            """,
            (limit,)
        )

    rows = cur.fetchall()

    records = []

    for row in rows:
        entry = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "src_ip": row["src_ip"],
            "protocol": row["protocol"],
            "dst_port": row["dst_port"],
            "reason": row["reason"],
            "pps": row["pps"],
            "ttl_secs": row["ttl_secs"],
            "offense_count": row["offense_count"],
            "avg_packet_size": row["avg_packet_size"],
            "fwd_pkts": row["fwd_pkts"],
            "bwd_pkts": row["bwd_pkts"],
            "syn_count": row["syn_count"],
            "ack_count": row["ack_count"],
            "rst_count": row["rst_count"],
            "flow_duration_ms": row["flow_duration_ms"],
            "flow_bytes_s": row["flow_bytes_s"]
        }

        if row["audit_payload"]:
            try:
                entry["audit"] = json.loads(
                    row["audit_payload"]
                )

            except Exception:
                entry["audit"] = {
                    "decision": row["audit_decision"],
                    "classification": row["audit_classification"],
                    "corrected_attack": row["audit_corrected_attack"],
                    "reason": row["audit_reason"]
                }

        elif row["audit_decision"]:
            entry["audit"] = {
                "decision": row["audit_decision"],
                "classification": row["audit_classification"],
                "corrected_attack": row["audit_corrected_attack"],
                "reason": row["audit_reason"]
            }

        records.append(entry)

    cur.close()

    conn.close()

    return records


def by_ip(
    ip,
    limit=20,
    path=DB_PATH
):
    init(
        path
    )

    conn = connect(
        path
    )

    cur = conn.cursor()

    if ip:
        cur.execute(
            """
            SELECT *
            FROM alerts
            WHERE src_ip = ?
            ORDER BY timestamp DESC
            LIMIT ?;
            """,
            (ip, limit)
        )

    else:
        cur.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?;
            """,
            (limit,)
        )

    rows = cur.fetchall()

    records = []

    for row in rows:
        entry = {
            "timestamp": row["timestamp"],
            "src_ip": row["src_ip"],
            "protocol": row["protocol"],
            "dst_port": row["dst_port"],
            "reason": row["reason"],
            "pps": row["pps"],
            "ttl_secs": row["ttl_secs"],
            "offense_count": row["offense_count"],
            "avg_packet_size": row["avg_packet_size"],
            "fwd_pkts": row["fwd_pkts"],
            "bwd_pkts": row["bwd_pkts"],
            "syn_count": row["syn_count"],
            "ack_count": row["ack_count"],
            "rst_count": row["rst_count"],
            "flow_duration_ms": row["flow_duration_ms"],
            "flow_bytes_s": row["flow_bytes_s"]
        }

        if row["audit_payload"]:
            try:
                entry["audit"] = json.loads(
                    row["audit_payload"]
                )

            except Exception:
                pass

        records.append(entry)

    cur.close()

    conn.close()

    return records


def unbans(
    path=DB_PATH
):
    init(
        path
    )

    conn = connect(
        path
    )

    cur = conn.cursor()

    cur.execute(
        """
        SELECT DISTINCT src_ip
        FROM alerts
        WHERE (audit_decision = 'UNBLOCK'
            OR audit_classification IN ('FALSE_POSITIVE', 'BENIGN'))
          AND unbanned_processed = 0;
        """
    )

    result = [
        row["src_ip"]
        for row in cur.fetchall()
    ]

    cur.close()

    conn.close()

    return result


def unbanned(
    ip,
    path=DB_PATH
):
    with LOCK:
        conn = connect(
            path
        )

        cur = conn.cursor()

        cur.execute(
            """
            UPDATE alerts
            SET unbanned_processed = 1
            WHERE src_ip = ?;
            """,
            (ip,)
        )

        conn.commit()

        cur.close()

        conn.close()


def history(
    ip,
    path=DB_PATH
):
    init(
        path
    )

    conn = connect(
        path
    )

    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            COUNT(*) AS total_offenses,
            MIN(timestamp) AS first_timestamp,
            MAX(timestamp) AS last_timestamp,
            AVG(pps) AS average_pps,
            SUM(CASE
                WHEN flow_bytes_s > 0 THEN flow_bytes_s * MAX(flow_duration_ms / 1000.0, 0.001)
                ELSE (fwd_pkts + bwd_pkts) * avg_packet_size
            END) AS total_bytes
        FROM alerts
        WHERE src_ip = ?;
        """,
        (ip,)
    )

    row = cur.fetchone()

    total = row["total_offenses"] or 0

    if total == 0:
        cur.close()
        conn.close()
        return {
            "src_ip": ip,
            "offenses": 0,
            "first_seen": None,
            "last_seen": None,
            "protocols": [],
            "reasons": [],
            "dst_ports": [],
            "avg_pps": 0.0,
            "total_bytes_across_offenses": 0
        }

    cur.execute(
        """
        SELECT DISTINCT protocol FROM alerts WHERE src_ip = ?;
        """,
        (ip,)
    )
    protocols = [
        r["protocol"]
        for r in cur.fetchall()
        if r["protocol"]
    ]

    cur.execute(
        """
        SELECT DISTINCT reason FROM alerts WHERE src_ip = ?;
        """,
        (ip,)
    )
    reasons = [
        r["reason"]
        for r in cur.fetchall()
        if r["reason"]
    ]

    cur.execute(
        """
        SELECT DISTINCT dst_port FROM alerts WHERE src_ip = ?;
        """,
        (ip,)
    )
    ports = [
        r["dst_port"]
        for r in cur.fetchall()
        if r["dst_port"]
    ]

    cur.close()

    conn.close()

    return {
        "src_ip": ip,
        "offenses": int(total),
        "first_seen": row["first_timestamp"],
        "last_seen": row["last_timestamp"],
        "protocols": sorted(protocols),
        "reasons": sorted(reasons),
        "dst_ports": sorted(ports),
        "avg_pps": round(float(row["average_pps"] or 0.0), 2),
        "total_bytes_across_offenses": int(row["total_bytes"] or 0)
    }


def subnet(
    cidr,
    path=DB_PATH
):
    init(
        path
    )

    try:
        net = ipaddress.ip_network(
            cidr,
            strict=False
        )

    except Exception:
        return {
            "subnet": cidr,
            "unique_bot_ips": [],
            "bot_count": 0,
            "total_packets_recorded": 0,
            "attack_reasons": [],
            "targeted_ports": [],
            "is_distributed_cluster": False
        }

    conn = connect(
        path
    )

    cur = conn.cursor()

    cur.execute(
        """
        SELECT src_ip, dst_port, reason, fwd_pkts, bwd_pkts, pps
        FROM alerts;
        """
    )

    matched = set()
    total_pkts = 0
    reasons = set()
    ports = set()

    for row in cur.fetchall():
        ip_str = row["src_ip"]
        try:
            addr = ipaddress.ip_address(
                ip_str
            )

            if addr in net:
                matched.add(ip_str)

                pkts = (
                    row["fwd_pkts"] + row["bwd_pkts"]
                    if (row["fwd_pkts"] or row["bwd_pkts"])
                    else 1
                )

                total_pkts += pkts

                if row["reason"]:
                    reasons.add(row["reason"])

                if row["dst_port"]:
                    ports.add(row["dst_port"])

        except Exception:
            pass

    cur.close()

    conn.close()

    count = len(matched)

    return {
        "subnet": cidr,
        "unique_bot_ips": sorted(list(matched)),
        "bot_count": count,
        "total_packets_recorded": total_pkts,
        "attack_reasons": sorted(list(reasons)),
        "targeted_ports": sorted(list(ports)),
        "is_distributed_cluster": bool(count >= 3)
    }
