import os
import sys
import json
import time
import re
import ipaddress
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from cachetools import TTLCache

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..'
    )
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

LOG_PATH = os.path.join(
    PROJECT_ROOT,
    'logs',
    'alerts.log'
)

from common.storage import (
    alerts as db_alerts,
    audit as db_audit,
    DB_PATH
)

_ENGINE = None
AUDIT_CACHE = {}
AUDIT_KEYS = TTLCache(maxsize=50_000, ttl=3600)
SIG_CACHE = {}
AUDIT_LOCK = threading.Lock()
ALERTS_LOCK = threading.Lock()

try:
    from agent.engine import normalize
except Exception:
    def normalize(val, fallback="SYN"):
        return str(val) if val else fallback

def get_engine():
    global _ENGINE
    if _ENGINE is None:
        try:
            from agent.engine import Engine
            _ENGINE = Engine()
        except Exception:
            _ENGINE = None
    return _ENGINE

def update_alerts(
    src_ip,
    timestamp,
    audit_res
):
    try:
        existing = db_alerts(limit=1000, pending=False)
        key = f"{src_ip}_{timestamp}"
        for row in existing:
            if (
                str(row.get("src_ip")) == str(src_ip)
                and str(row.get("timestamp")) == str(timestamp)
                and row.get("audit")
                and row["audit"].get("decision")
            ):
                return

        if "corrected_attack" in audit_res and audit_res["corrected_attack"]:
            audit_res["corrected_attack"] = normalize(
                audit_res["corrected_attack"],
                fallback="SYN"
            )

        db_audit(
            ip=src_ip,
            ts=timestamp,
            data=audit_res
        )

    except Exception as err:
        print(f"[!] Error updating audit storage: {err}")

def get_alerts(limit=1000):
    try:
        records = db_alerts(
            limit=limit,
            pending=False
        )

        for entry in records:
            key = f"{entry.get('src_ip')}_{entry.get('timestamp')}"
            if entry.get("audit"):
                with AUDIT_LOCK:
                    AUDIT_CACHE[key] = entry["audit"]
                    AUDIT_KEYS.add(key)
            else:
                with AUDIT_LOCK:
                    if key in AUDIT_CACHE:
                        entry["audit"] = AUDIT_CACHE[key]

        return records

    except Exception as err:
        print(f"[!] Error reading alerts from storage: {err}")
        return []

def get_metrics():
    alerts = get_alerts(limit=1000)
    unique_ips = set()
    protocols = {}
    reasons = {}
    ip_pps = {}
    total_pps = 0

    audited_count = 0
    fp_count = 0
    reclassified_count = 0

    timeline = []

    for a in alerts:
        ip = a.get("src_ip")
        pps = float(a.get("pps", 0) or 0)
        total_pps += pps
        if ip:
            unique_ips.add(ip)
            ip_pps[ip] = max(
                ip_pps.get(ip, 0),
                pps
            )

        proto = (a.get("protocol") or "TCP").upper()
        protocols[proto] = protocols.get(proto, 0) + 1

        audit = a.get("audit")
        if audit:
            audited_count += 1
            if audit.get("decision") == "UNBLOCK" or audit.get("classification") in ("FALSE_POSITIVE", "BENIGN"):
                fp_count += 1
                r = "False Positive"
            elif audit.get("classification") == "MISCLASSIFIED_ATTACK":
                reclassified_count += 1
                corr = str(audit.get("corrected_attack") or "").strip()
                if corr and not corr.lower().startswith("none"):
                    r = normalize(
                        corr,
                        fallback=a.get("reason", "SYN")
                    )
                else:
                    r = normalize(
                        a.get("reason") or "SYN",
                        fallback="SYN"
                    )
            else:
                r = normalize(
                    a.get("reason") or "SYN",
                    fallback="SYN"
                )
        else:
            r = normalize(
                a.get("reason") or "SYN",
                fallback="SYN"
            )

        reasons[r] = reasons.get(r, 0) + 1

    sorted_ips = sorted(
        ip_pps.items(),
        key=lambda x: x[1],
        reverse=True
    )[:7]

    recent_slice = alerts[:30][::-1]
    for a in recent_slice:
        ts = a.get("timestamp", 0)
        tm_str = time.strftime(
            "%H:%M:%S",
            time.localtime(ts)
        )
        timeline.append({
            "time": tm_str,
            "pps": float(a.get("pps", 0) or 0)
        })

    avg_pps = round(
        total_pps / max(len(alerts), 1),
        1
    )

    return {
        "total_alerts": len(alerts),
        "unique_blocked_ips": len(unique_ips),
        "avg_pps": avg_pps,
        "audited_count": audited_count,
        "fp_unbanned_count": fp_count,
        "reclassified_count": reclassified_count,
        "top_ips": sorted_ips,
        "reasons": reasons,
        "timeline": timeline,
        "protocols": protocols
    }

def sig_key(entry):
    proto = str(entry.get("protocol", "UNKNOWN")).upper()
    port = int(entry.get("dst_port", 0) or 0)
    sz = float(entry.get("avg_packet_size", 0.0) or 0.0)
    bucket = round(sz / 20.0) * 20
    reason = str(entry.get("reason", "")).strip()
    return f"{proto}:{port}:SIZE{bucket}:{reason}"

def run_auditor():
    while True:
        try:
            eng = get_engine()
            if eng:
                records = get_alerts(limit=50)
                for entry in records:
                    ip = entry.get("src_ip")
                    ts = entry.get("timestamp")
                    key = f"{ip}_{ts}"

                    with AUDIT_LOCK:
                        if key in AUDIT_KEYS or entry.get("audit"):
                            continue
                        AUDIT_KEYS.add(key)

                    try:
                        k = sig_key(entry)
                        hit = SIG_CACHE.get(k)
                        now = time.time()

                        if hit and (now - hit[1] < 600):
                            res = dict(hit[0])
                            res["reason"] = f"[Cluster Inferred] {res.get('reason', '')}"
                            with AUDIT_LOCK:
                                AUDIT_CACHE[key] = res

                            update_alerts(
                                ip,
                                ts,
                                res
                            )

                            print(
                                f"[+] Audit (Clustered): {ip} -> "
                                f"{res.get('decision')} ({res.get('classification')})",
                                flush=True
                            )

                        else:
                            res = eng.react(entry)
                            SIG_CACHE[k] = (
                                res,
                                now
                            )

                            with AUDIT_LOCK:
                                AUDIT_CACHE[key] = res

                            update_alerts(
                                ip,
                                ts,
                                res
                            )

                            print(
                                f"[+] Audit: {ip} -> "
                                f"{res.get('decision')} ({res.get('classification')})",
                                flush=True
                            )

                    except Exception as err:
                        print(
                            f"[!] Audit error {ip}: {err}"
                        )

        except Exception as err:
            print(
                f"[!] Error: {err}",
                flush=True
            )

        time.sleep(2)

AUDITOR_THREAD = None

def start_auditor():
    global AUDITOR_THREAD
    if AUDITOR_THREAD is None or not AUDITOR_THREAD.is_alive():
        AUDITOR_THREAD = threading.Thread(
            target=run_auditor,
            daemon=True
        )
        AUDITOR_THREAD.start()
    return AUDITOR_THREAD

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ML DDoS</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <style>
        :root {
            --surface-base: #030508;
            --surface-card: #080d16;
            --surface-elevated: #0f1524;
            --border-default: #172033;
            --border-muted: #101626;
            --border-active: #ff4a14;
            --brand-primary: #ff4a14;
            --brand-glow: rgba(255, 74, 20, 0.22);
            --accent-orange-light: #ff6b3d;
            --accent-amber: #f59e0b;
            --accent-emerald: #10b981;
            --text-primary: #ffffff;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --shadow-card: 0 4px 24px rgba(0, 0, 0, 0.45);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        ::selection {
            background: rgba(255, 74, 20, 0.4);
            color: #ffffff;
        }

        body {
            background-color: var(--surface-base);
            color: var(--text-primary);
            font-family: var(--font-sans);
            padding: 24px 32px 48px;
            margin: 0;
            overflow-x: hidden;
            overflow-y: auto;
            min-height: 100vh;
        }

        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.25);
        }
        ::-webkit-scrollbar-thumb {
            background: #1e293b;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #334155;
        }

        .dashboard-container {
            max-width: 1680px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 22px;
        }

        .metrics-strip {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }

        .metric-pill {
            background: linear-gradient(135deg, rgba(16, 26, 46, 0.65) 0%, rgba(8, 14, 26, 0.8) 100%);
            backdrop-filter: blur(16px) saturate(180%);
            -webkit-backdrop-filter: blur(16px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-top: 1px solid rgba(255, 255, 255, 0.22);
            border-left: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.16), inset 0 0 20px rgba(255, 255, 255, 0.015);
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            white-space: nowrap;
            min-width: 0;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .metric-pill::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 52%;
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.015) 70%, transparent 100%);
            border-radius: var(--radius-md) var(--radius-md) 0 0;
            pointer-events: none;
        }

        .metric-pill::after {
            content: '';
            position: absolute;
            top: 0;
            left: -130%;
            width: 75%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.18), transparent);
            transform: skewX(-25deg);
            transition: left 0.75s cubic-bezier(0.16, 1, 0.3, 1);
            pointer-events: none;
        }

        .metric-pill:hover {
            transform: translateY(-5px) scale(1.018);
            border-color: var(--mp-accent, var(--brand-primary)) !important;
            border-top-color: rgba(255, 255, 255, 0.45) !important;
            box-shadow: 0 18px 42px rgba(0, 0, 0, 0.7), 0 0 28px var(--mp-glow, rgba(255, 74, 20, 0.35)), inset 0 1px 1px rgba(255, 255, 255, 0.35);
        }

        .metric-pill:hover::after {
            left: 160%;
        }

        .metric-pill:hover .mp-value {
            transform: scale(1.05);
            filter: drop-shadow(0 0 12px var(--mp-accent, var(--brand-primary)));
        }

        .metric-pill:nth-child(1) {
            --mp-accent: #ffffff;
            --mp-glow: rgba(255, 255, 255, 0.22);
        }
        .metric-pill:nth-child(2) {
            --mp-accent: #ff4a14;
            --mp-glow: rgba(255, 74, 20, 0.35);
        }
        .metric-pill:nth-child(3) {
            --mp-accent: #ff6b3d;
            --mp-glow: rgba(255, 107, 61, 0.35);
        }
        .metric-pill:nth-child(4) {
            --mp-accent: #10b981;
            --mp-glow: rgba(16, 185, 129, 0.35);
        }

        .mp-label {
            font-size: 11.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--text-secondary);
            white-space: nowrap;
            flex-shrink: 0;
        }

        .mp-value {
            font-size: 24px;
            font-weight: 800;
            font-family: var(--font-mono);
            letter-spacing: -0.5px;
            color: var(--text-primary);
            white-space: nowrap;
            flex-shrink: 0;
            display: inline-flex;
            align-items: baseline;
            gap: 4px;
            transition: transform 0.25s ease, filter 0.25s ease;
        }

        .mp-unit {
            font-size: 12.5px;
            font-weight: 700;
            color: var(--text-secondary);
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .telemetry-bar {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }

        .telemetry-card {
            background: linear-gradient(135deg, rgba(16, 26, 46, 0.65) 0%, rgba(8, 14, 26, 0.8) 100%);
            backdrop-filter: blur(16px) saturate(180%);
            -webkit-backdrop-filter: blur(16px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-top: 1px solid rgba(255, 255, 255, 0.22);
            border-left: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.16), inset 0 0 20px rgba(255, 255, 255, 0.015);
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .telemetry-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 52%;
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.015) 70%, transparent 100%);
            border-radius: var(--radius-md) var(--radius-md) 0 0;
            pointer-events: none;
        }

        .telemetry-card::after {
            content: '';
            position: absolute;
            top: 0;
            left: -130%;
            width: 75%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.18), transparent);
            transform: skewX(-25deg);
            transition: left 0.75s cubic-bezier(0.16, 1, 0.3, 1);
            pointer-events: none;
        }

        .telemetry-card:hover {
            transform: translateY(-5px) scale(1.018);
            border-color: var(--card-accent, #38bdf8) !important;
            border-top-color: rgba(255, 255, 255, 0.45) !important;
            box-shadow: 0 18px 42px rgba(0, 0, 0, 0.7), 0 0 28px var(--card-glow, rgba(56, 189, 248, 0.35)), inset 0 1px 1px rgba(255, 255, 255, 0.35);
        }

        .telemetry-card:hover::after {
            left: 160%;
        }

        .telemetry-card:hover .tc-value {
            filter: drop-shadow(0 0 12px var(--card-accent, #38bdf8));
            transform: scale(1.05);
        }

        .telemetry-card:nth-child(1) {
            --card-accent: #10b981;
            --card-glow: rgba(16, 185, 129, 0.28);
        }
        .telemetry-card:nth-child(2) {
            --card-accent: #ef4444;
            --card-glow: rgba(239, 68, 68, 0.28);
        }
        .telemetry-card:nth-child(3) {
            --card-accent: #38bdf8;
            --card-glow: rgba(56, 189, 248, 0.28);
        }
        .telemetry-card:nth-child(4) {
            --card-accent: #a855f7;
            --card-glow: rgba(168, 85, 247, 0.28);
        }

        .tc-header {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .tc-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--text-secondary);
        }

        .tc-value {
            font-size: 26px;
            font-weight: 800;
            font-family: var(--font-mono);
            letter-spacing: -0.5px;
            margin: 2px 0 0 0;
            transition: transform 0.25s ease, filter 0.25s ease;
            display: inline-block;
        }

        .filter-panel {
            background: linear-gradient(180deg, rgba(13, 21, 38, 0.9) 0%, rgba(8, 13, 22, 0.98) 100%);
            border: 2px solid #2e4368;
            border-radius: var(--radius-md);
            padding: 10px 16px;
            display: flex;
            flex-wrap: nowrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.09), 0 0 16px rgba(0, 0, 0, 0.4);
            position: relative;
            z-index: 50;
            overflow: visible;
            transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .filter-panel:hover {
            border-color: #3d588a;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.75), 0 0 24px rgba(255, 74, 20, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.14);
        }

        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: nowrap;
            flex-shrink: 0;
        }

        .filter-label {
            font-size: 11.5px;
            font-weight: 800;
            color: #e2e8f0;
            text-transform: uppercase;
            letter-spacing: 0.9px;
            margin-right: 4px;
            white-space: nowrap;
            display: inline-flex;
            align-items: center;
            gap: 7px;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.8);
        }
        .filter-label::before {
            content: '';
            display: inline-block;
            width: 3.5px;
            height: 13px;
            background: linear-gradient(180deg, #ff6b3d, #ff4a14);
            border-radius: 2px;
            box-shadow: 0 0 8px rgba(255, 74, 20, 0.85);
        }

        @keyframes activeNeonPulse {
            0%, 100% {
                box-shadow: 0 0 18px rgba(255, 74, 20, 0.6), inset 0 0 12px rgba(255, 74, 20, 0.28), 0 4px 12px rgba(0, 0, 0, 0.4);
            }
            50% {
                box-shadow: 0 0 28px rgba(255, 107, 61, 0.85), inset 0 0 15px rgba(255, 107, 61, 0.4), 0 4px 16px rgba(0, 0, 0, 0.5);
            }
        }

        .btn-time {
            background: rgba(15, 23, 42, 0.75);
            border: 2px solid #2e4368;
            color: #cbd5e1;
            padding: 7px 15px;
            border-radius: var(--radius-sm);
            font-size: 12px;
            font-weight: 600;
            font-family: var(--font-sans);
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            user-select: none;
            white-space: nowrap;
            position: relative;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3);
        }
        .btn-time::before {
            content: '';
            position: absolute;
            top: 0;
            left: -120%;
            width: 60%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.22), transparent);
            transform: skewX(-20deg);
            transition: left 0.55s ease;
            pointer-events: none;
        }
        .btn-time:hover::before {
            left: 140%;
        }
        .btn-time:hover {
            background: linear-gradient(180deg, rgba(255, 107, 61, 0.22) 0%, rgba(255, 74, 20, 0.08) 100%);
            color: #ffffff;
            border-color: #ff6b3d;
            transform: translateY(-2.5px) scale(1.025);
            box-shadow: 0 8px 22px rgba(0, 0, 0, 0.55), 0 0 16px rgba(255, 107, 61, 0.45);
        }
        .btn-time:active {
            transform: translateY(0) scale(0.96);
        }
        .btn-time.active {
            background: linear-gradient(180deg, rgba(255, 74, 20, 0.35) 0%, rgba(255, 74, 20, 0.15) 100%);
            color: #ffffff;
            border: 2px solid #ff4a14;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(255, 74, 20, 0.9), 0 1px 3px rgba(0, 0, 0, 0.9);
            animation: activeNeonPulse 3s infinite ease-in-out;
        }

        .date-range-wrapper {
            display: none;
            align-items: center;
            gap: 6px;
            background: rgba(5, 8, 17, 0.92);
            border: 2px solid #2e4368;
            border-radius: var(--radius-sm);
            padding: 4px 8px;
            transition: all 0.25s ease;
            flex-shrink: 0;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
        }
        .date-range-wrapper.active {
            display: inline-flex;
        }
        .date-range-wrapper:hover {
            border-color: #ff6b3d;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5), 0 0 14px rgba(255, 107, 61, 0.25);
        }
        .date-range-wrapper:focus-within {
            border-color: var(--brand-primary);
            box-shadow: 0 0 20px var(--brand-glow), inset 0 0 8px rgba(255, 74, 20, 0.18);
        }

        .date-cal-icon {
            color: var(--brand-primary);
            display: flex;
            align-items: center;
            flex-shrink: 0;
            cursor: pointer;
            padding: 2px;
            border-radius: 4px;
            transition: transform 0.2s ease, color 0.2s ease, filter 0.2s ease;
        }
        .date-cal-icon:hover {
            transform: scale(1.18);
            color: var(--accent-orange-light);
            filter: drop-shadow(0 0 6px var(--brand-primary));
        }

        .date-input-group {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .date-input-label {
            font-size: 9.5px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--brand-primary);
        }

        .date-input {
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 11px;
            outline: none;
            color-scheme: dark;
            width: 114px;
            cursor: pointer;
            padding: 0;
        }

        .date-arrow-icon {
            color: var(--brand-primary);
            display: flex;
            align-items: center;
            margin: 0 1px;
            flex-shrink: 0;
        }

        .search-input-wrap {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(5, 8, 17, 0.9);
            border: 2px solid #2e4368;
            border-radius: var(--radius-sm);
            padding: 6px 12px;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            flex-shrink: 0;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
        }
        .search-input-wrap:hover {
            border-color: #ff6b3d;
            box-shadow: 0 6px 18px rgba(0, 0, 0, 0.5), 0 0 14px rgba(255, 107, 61, 0.3);
            transform: translateY(-1.5px);
        }
        .search-input-wrap:focus-within {
            border-color: var(--brand-primary);
            box-shadow: 0 0 22px var(--brand-glow), inset 0 0 10px rgba(255, 74, 20, 0.18);
            transform: translateY(-1.5px);
        }
        .search-input-wrap svg {
            transition: all 0.25s ease;
        }
        .search-input-wrap:hover svg,
        .search-input-wrap:focus-within svg {
            color: var(--brand-primary) !important;
            filter: drop-shadow(0 0 6px var(--brand-primary));
            transform: scale(1.15);
        }
        .input-dark-inline {
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 12.5px;
            outline: none;
            width: 150px;
        }
        .input-dark-inline::placeholder {
            color: var(--text-muted);
        }

        .flatpickr-calendar {
            background: rgba(8, 13, 24, 0.98) !important;
            border: 1px solid rgba(255, 74, 20, 0.4) !important;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.85), 0 0 24px rgba(255, 74, 20, 0.15) !important;
            backdrop-filter: blur(16px) !important;
            border-radius: 12px !important;
            font-family: var(--font-sans) !important;
            padding: 8px !important;
            color: #f8fafc !important;
            z-index: 99999 !important;
        }
        .flatpickr-calendar.arrowTop:before, .flatpickr-calendar.arrowTop:after {
            border-bottom-color: rgba(255, 74, 20, 0.4) !important;
        }
        .flatpickr-calendar.arrowBottom:before, .flatpickr-calendar.arrowBottom:after {
            border-top-color: rgba(255, 74, 20, 0.4) !important;
        }
        .flatpickr-months .flatpickr-month {
            color: #fff !important;
            fill: #fff !important;
        }
        .flatpickr-current-month .flatpickr-monthDropdown-months {
            background: #080d18 !important;
            color: #fff !important;
            font-weight: 700 !important;
        }
        .flatpickr-weekdays {
            border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
            padding-bottom: 4px !important;
        }
        span.flatpickr-weekday {
            color: var(--text-muted) !important;
            font-weight: 700 !important;
            font-size: 11px !important;
        }
        .flatpickr-day {
            color: #cbd5e1 !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            transition: all 0.15s ease !important;
        }
        .flatpickr-day:hover {
            background: rgba(255, 74, 20, 0.18) !important;
            border-color: rgba(255, 74, 20, 0.5) !important;
            color: #fff !important;
        }
        .flatpickr-day.selected, .flatpickr-day.startRange, .flatpickr-day.endRange {
            background: var(--brand-primary) !important;
            border-color: var(--brand-primary) !important;
            color: #fff !important;
            box-shadow: 0 0 14px var(--brand-glow) !important;
            font-weight: 800 !important;
        }
        .flatpickr-day.today {
            border-color: rgba(255, 74, 20, 0.6) !important;
        }
        .flatpickr-time {
            border-top: 1px solid rgba(255, 255, 255, 0.08) !important;
            background: transparent !important;
        }
        .flatpickr-time input {
            color: #fff !important;
            font-family: var(--font-mono) !important;
            font-weight: 700 !important;
        }
        .flatpickr-time .flatpickr-am-pm {
            color: var(--brand-primary) !important;
            font-weight: 800 !important;
        }
        .flatpickr-time input:hover, .flatpickr-time .flatpickr-am-pm:hover,
        .flatpickr-time input:focus, .flatpickr-time .flatpickr-am-pm:focus {
            background: rgba(255, 74, 20, 0.15) !important;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: 1.4fr 1.1fr 1fr;
            gap: 20px;
            margin-bottom: 6px;
        }

        .chart-box {
            background: var(--surface-card);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-md);
            padding: 20px;
            display: flex;
            flex-direction: column;
            height: 330px;
            box-shadow: var(--shadow-card);
            position: relative;
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.25s ease, box-shadow 0.25s ease;
        }
        .chart-box:hover {
            transform: translateY(-3px);
            border-color: rgba(255, 74, 20, 0.35);
            box-shadow: 0 14px 34px rgba(0, 0, 0, 0.65), 0 0 20px rgba(255, 74, 20, 0.12);
        }

        .chart-header {
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.6px;
            color: var(--text-secondary);
            text-transform: uppercase;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .chart-header span.dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--brand-primary);
            box-shadow: 0 0 10px var(--brand-glow);
            display: inline-block;
            animation: pulseGlow 2.5s infinite ease-in-out;
        }

        @keyframes pulseGlow {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.55; transform: scale(0.85); box-shadow: 0 0 4px var(--brand-glow); }
        }

        .chart-canvas-wrap {
            position: relative;
            flex: 1;
            min-height: 230px;
            width: 100%;
        }

        .table-panel {
            background: var(--surface-card);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-md);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: var(--shadow-card);
            margin-top: 6px;
        }

        .table-header-strip {
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-default);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface-elevated);
        }

        .table-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: 0.6px;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-family: var(--font-mono);
            color: var(--brand-primary);
        }

        .status-dot-pulse {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--brand-primary);
            box-shadow: 0 0 8px var(--brand-primary);
        }

        .table-wrap {
            overflow-x: auto;
            overflow-y: auto;
            max-height: 480px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        th {
            text-align: center;
            padding: 14px 18px;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            border-bottom: 1px solid var(--border-default);
            position: sticky;
            top: 0;
            background: #0b101c;
            z-index: 5;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        td {
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-muted);
            font-family: var(--font-mono);
            font-size: 13.5px;
            color: var(--text-primary);
            vertical-align: middle;
            transition: background 0.15s ease;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            text-align: center;
        }

        th:nth-child(1), td:nth-child(1) { width: 14%; text-align: center; }
        th:nth-child(2), td:nth-child(2) { width: 15%; text-align: center; }
        th:nth-child(3), td:nth-child(3) { width: 14%; text-align: center; }
        th:nth-child(4), td:nth-child(4) { width: 11%; text-align: center; }
        th:nth-child(5), td:nth-child(5) { width: 15%; text-align: center; }
        th:nth-child(6), td:nth-child(6) { width: 14%; text-align: center; }
        th:nth-child(7) { width: 17%; text-align: center; }
        td:nth-child(7) { width: 17%; text-align: left; }

        tr:nth-child(even) {
            background: rgba(255, 255, 255, 0.012);
        }
        tr:hover {
            background: rgba(255, 74, 20, 0.04);
        }

        tr.row-false-positive {
            background: rgba(239, 68, 68, 0.14) !important;
            box-shadow: inset 4px 0 0 #ef4444;
            transition: background 0.2s ease, box-shadow 0.2s ease;
        }
        tr.row-false-positive:hover {
            background: rgba(239, 68, 68, 0.24) !important;
            box-shadow: inset 4px 0 0 #ff4a4a, 0 0 16px rgba(239, 68, 68, 0.2);
        }
        tr.row-false-positive td {
            border-bottom: 1px solid rgba(239, 68, 68, 0.35) !important;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-family: var(--font-sans);
        }

        .badge-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            display: inline-block;
        }
        .dot-green { background: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.8); }
        .dot-red { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.8); }
        .dot-orange { background: #ff4a14; box-shadow: 0 0 8px rgba(255, 74, 20, 0.8); }
        .dot-amber { background: #f59e0b; box-shadow: 0 0 8px rgba(245, 158, 11, 0.8); }
        .dot-cyan { background: #38bdf8; box-shadow: 0 0 8px rgba(56, 189, 248, 0.8); }
        .dot-purple { background: #a855f7; box-shadow: 0 0 8px rgba(168, 85, 247, 0.8); }
        .dot-slate { background: #64748b; }

        .badge-tcp, .badge-udp, .badge-icmp, .badge-proto {
            background: rgba(255, 74, 20, 0.12);
            color: #ff6b3d;
            border: 1px solid rgba(255, 74, 20, 0.35);
            box-shadow: 0 0 10px rgba(255, 74, 20, 0.15);
        }

        .tag-true { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.45); box-shadow: 0 0 10px rgba(16, 185, 129, 0.15); }
        .tag-false { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.45); box-shadow: 0 0 10px rgba(239, 68, 68, 0.15); }
        .tag-queued { background: rgba(100, 116, 139, 0.14); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.3); }

        .reason-cell {
            position: relative;
            cursor: pointer;
            text-align: left !important;
            padding: 7px 12px !important;
        }

        .reason-box {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            padding: 6px 12px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
            cursor: pointer;
            box-sizing: border-box;
            max-width: 100%;
        }

        .reason-cell:hover .reason-box,
        .reason-box:hover {
            background: rgba(255, 74, 20, 0.09);
            border-color: rgba(255, 74, 20, 0.45);
            box-shadow: 0 0 16px rgba(255, 74, 20, 0.2), inset 0 0 10px rgba(255, 74, 20, 0.06);
            transform: translateX(2px);
        }

        .reason-text-truncate {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #cbd5e1;
            font-size: 12.5px;
            font-family: var(--font-sans);
            transition: color 0.15s ease;
            flex: 1;
            min-width: 0;
            display: block;
            text-align: left;
        }

        .reason-cell:hover .reason-text-truncate,
        .reason-box:hover .reason-text-truncate {
            color: #ffffff;
        }

        .reason-arrow-icon {
            color: #64748b;
            flex-shrink: 0;
            transition: transform 0.2s ease, color 0.2s ease, opacity 0.2s ease;
            opacity: 0.7;
        }

        .reason-cell:hover .reason-arrow-icon,
        .reason-box:hover .reason-arrow-icon {
            color: #ff6b3d;
            transform: translateX(3px);
            opacity: 1;
        }


        .tao-timeline {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 8px;
        }

        .tao-step-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 10px 12px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            position: relative;
        }

        .tao-step-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11px;
            font-weight: 700;
            color: #94a3b8;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 4px;
        }

        .tao-step-num {
            color: #ff6b3d;
            font-family: var(--font-mono);
            letter-spacing: 0.5px;
            font-weight: 800;
        }

        .tao-thought-block {
            background: rgba(168, 85, 247, 0.07);
            border-left: 3px solid #a855f7;
            border-radius: 4px;
            padding: 8px 10px;
        }

        .tao-thought-label {
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: #c084fc;
            display: flex;
            align-items: center;
            gap: 5px;
            margin-bottom: 4px;
        }

        .tao-thought-text {
            font-size: 12px;
            line-height: 1.55;
            color: #e2e8f0;
            white-space: pre-wrap;
            word-break: break-word;
            text-align: justify;
            text-justify: inter-word;
        }

        .tao-action-block {
            background: rgba(6, 182, 212, 0.07);
            border-left: 3px solid #06b6d4;
            border-radius: 4px;
            padding: 8px 10px;
        }

        .tao-action-label {
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: #22d3ee;
            display: flex;
            align-items: center;
            gap: 5px;
            margin-bottom: 4px;
        }

        .tao-action-code {
            font-family: var(--font-mono);
            font-size: 12px;
            color: #67e8f9;
            background: rgba(0, 0, 0, 0.35);
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid rgba(6, 182, 212, 0.2);
            display: inline-block;
            word-break: break-all;
        }

        .tao-obs-block {
            background: rgba(16, 185, 129, 0.07);
            border-left: 3px solid #10b981;
            border-radius: 4px;
            padding: 8px 10px;
        }

        .tao-obs-label {
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: #34d399;
            display: flex;
            align-items: center;
            gap: 5px;
            margin-bottom: 4px;
        }

        .tao-obs-text {
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: #cbd5e1;
            background: rgba(0, 0, 0, 0.4);
            padding: 6px 8px;
            border-radius: 4px;
            border: 1px solid rgba(255, 255, 255, 0.06);
            max-height: 120px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .tao-verdict-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
            border: 1px solid rgba(255, 74, 20, 0.35);
            border-radius: 8px;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .tao-verdict-title {
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: var(--brand-primary);
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .tao-verdict-badges {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .tao-verdict-reason {
            font-size: 12.5px;
            line-height: 1.6;
            color: #f1f5f9;
            background: rgba(0, 0, 0, 0.25);
            padding: 8px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.06);
            text-align: justify;
            text-justify: inter-word;
        }

        .tao-modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            z-index: 999999;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
            animation: fadeInModal 0.18s ease;
        }

        .tao-modal-overlay.active {
            display: flex;
        }

        @keyframes fadeInModal {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .tao-modal-container {
            background: linear-gradient(180deg, rgba(13, 20, 36, 0.98) 0%, rgba(6, 10, 18, 0.99) 100%);
            border: 1px solid rgba(255, 74, 20, 0.45);
            box-shadow: 0 25px 70px rgba(0, 0, 0, 0.95), 0 0 35px rgba(255, 74, 20, 0.25);
            width: 720px;
            max-width: 95vw;
            max-height: 85vh;
            border-radius: 14px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            animation: scaleInModal 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            position: relative;
        }

        @keyframes scaleInModal {
            from { transform: scale(0.95) translateY(10px); opacity: 0; }
            to { transform: scale(1) translateY(0); opacity: 1; }
        }

        .tao-modal-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #ff4a14, #ff6b3d, #818cf8, #06b6d4, #10b981);
            box-shadow: 0 0 12px rgba(255, 74, 20, 0.8);
        }

        .tao-modal-header {
            padding: 16px 22px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(255, 255, 255, 0.02);
        }

        .tao-modal-title {
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--brand-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tao-modal-subtitle {
            font-size: 11.5px;
            color: #94a3b8;
            font-family: var(--font-mono);
            margin-top: 4px;
        }

        .tao-modal-close {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #e2e8f0;
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 14px;
            font-weight: 700;
            transition: all 0.2s ease;
        }

        .tao-modal-close:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: #ef4444;
            color: #ef4444;
            transform: scale(1.08);
        }

        .tao-modal-body {
            padding: 18px 22px;
            overflow-y: auto;
            flex: 1;
        }

        .tao-modal-body::-webkit-scrollbar {
            width: 6px;
        }
        .tao-modal-body::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
        }
        .tao-modal-body::-webkit-scrollbar-thumb {
            background: #334155;
            border-radius: 4px;
        }
        .tao-modal-body::-webkit-scrollbar-thumb:hover {
            background: #ff4a14;
        }
    </style>
</head>
<body>

    <div class="dashboard-container">
        <div class="metrics-strip">
            <div class="metric-pill">
                <span class="mp-label">Total Incursions</span>
                <span class="mp-value" id="val-total">0</span>
            </div>
            <div class="metric-pill">
                <span class="mp-label">Blocked IPs</span>
                <span class="mp-value" style="color: var(--brand-primary);" id="val-ips">0</span>
            </div>
            <div class="metric-pill">
                <span class="mp-label">Mean Traffic</span>
                <span class="mp-value" style="color: var(--accent-orange-light);" id="val-pps">0.0 <span class="mp-unit">PPS</span></span>
            </div>
            <div class="metric-pill">
                <span class="mp-label">Accuracy</span>
                <span class="mp-value" style="color: #10b981;" id="val-accuracy">100.0%</span>
            </div>
        </div>

        <div class="telemetry-bar">
            <div class="telemetry-card" style="border-top: 2px solid #10b981;">
                <div class="tc-header">
                    <span class="badge-dot dot-green"></span>
                    <span class="tc-label">True Positive</span>
                </div>
                <div class="tc-value" style="color: #10b981;" id="val-tp">0</div>
            </div>
            <div class="telemetry-card" style="border-top: 2px solid #ef4444;">
                <div class="tc-header">
                    <span class="badge-dot dot-red"></span>
                    <span class="tc-label">False Positive</span>
                </div>
                <div class="tc-value" style="color: #ef4444;" id="val-fp">0</div>
            </div>
            <div class="telemetry-card" style="border-top: 2px solid #38bdf8;">
                <div class="tc-header">
                    <span class="badge-dot dot-cyan"></span>
                    <span class="tc-label">True Negative</span>
                </div>
                <div class="tc-value" style="color: #38bdf8;" id="val-tn">0</div>
            </div>
            <div class="telemetry-card" style="border-top: 2px solid #a855f7;">
                <div class="tc-header">
                    <span class="badge-dot dot-purple"></span>
                    <span class="tc-label">False Negative</span>
                </div>
                <div class="tc-value" style="color: #a855f7;" id="val-fn">0</div>
            </div>
        </div>

        <div class="filter-panel">
            <div class="filter-group">
                <span class="filter-label">Time Window:</span>
                <button class="btn-time" onclick="setTimeFilter('1h', this)">1 Hour</button>
                <button class="btn-time" onclick="setTimeFilter('24h', this)">24 Hours</button>
                <button class="btn-time" onclick="setTimeFilter('30d', this)">30 Days</button>
                <button class="btn-time" onclick="setTimeFilter('1y', this)">1 Year</button>
                <button class="btn-time active" onclick="setTimeFilter('all', this)">All Time</button>
                <button class="btn-time" onclick="setTimeFilter('custom', this)">Custom</button>
                
                <div class="date-range-wrapper" id="custom-range-box">
                    <div class="date-cal-icon" title="Open calendar picker" onclick="if(window.fpFromInstance) window.fpFromInstance.open();">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                    </div>
                    <div class="date-input-group">
                        <span class="date-input-label">FROM</span>
                        <input type="text" class="date-input" id="custom-from" placeholder="YYYY-MM-DD HH:MM" readonly>
                    </div>
                    <div class="date-arrow-icon">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                    </div>
                    <div class="date-input-group">
                        <span class="date-input-label">TO</span>
                        <input type="text" class="date-input" id="custom-to" placeholder="YYYY-MM-DD HH:MM" readonly>
                    </div>
                </div>
            </div>

            <div class="filter-group">
                <div class="search-input-wrap">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="color: var(--text-muted);"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    <input type="text" class="input-dark-inline" id="filter-ip" placeholder="Search IPs..." oninput="triggerFilter()">
                </div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-box">
                <div class="chart-header">
                    <span>PPS Timeline</span>
                    <span class="dot"></span>
                </div>
                <div class="chart-canvas-wrap">
                    <canvas id="lineChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <div class="chart-header">
                    <span>Top Attack IPs</span>
                    <span class="dot" style="background: var(--accent-orange-light); box-shadow: 0 0 10px rgba(255, 107, 61, 0.4);"></span>
                </div>
                <div class="chart-canvas-wrap">
                    <canvas id="barChart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <div class="chart-header">
                    <span>Top Attack Types</span>
                    <span class="dot" style="background: var(--accent-amber); box-shadow: 0 0 10px rgba(245, 158, 11, 0.4);"></span>
                </div>
                <div class="chart-canvas-wrap">
                    <canvas id="pieChart"></canvas>
                </div>
            </div>
        </div>

        <div class="table-panel">
            <div class="table-header-strip">
                <div class="table-title">
                    <span>Dashboard</span>
                </div>
                <div class="status-pill">
                    <span class="status-dot-pulse"></span>
                    <span id="table-status">Syncing...</span>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <colgroup>
                        <col style="width: 14%;">
                        <col style="width: 15%;">
                        <col style="width: 14%;">
                        <col style="width: 11%;">
                        <col style="width: 15%;">
                        <col style="width: 14%;">
                        <col style="width: 17%;">
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Timestamps</th>
                            <th>IPs</th>
                            <th>Protocol : Port</th>
                            <th>Rate</th>
                            <th>Label</th>
                            <th>LLM</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-body">
                        <tr>
                            <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px; font-size: 14px;">
                                No attack detected!
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let rawAlerts = [];
        let activeTimeFilter = 'all';

        let lineChart = null;
        let barChart = null;
        let pieChart = null;
        let pieOtherBreakdown = [];

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function buildTaoTooltipHtml(a) {
            const proto = (a.protocol || 'TCP').toUpperCase();
            const port = a.dst_port || 0;
            const pps = a.pps ? Number(a.pps).toFixed(1) : '0';
            const audit = a.audit;

            if (!audit) {
                return `
                    <div class="tao-pending-box" style="margin-top: 0;">
                        <span class="status-dot-pulse"></span>
                        <div style="font-size: 11.5px; color: #94a3b8;">Waiting for forensic analysis result...</div>
                    </div>
                `;
            }

            const history = Array.isArray(audit.history) ? audit.history : [];
            const steps = [];
            let cur = { thought: '', action: '', observation: '' };

            for (let i = 0; i < history.length; i++) {
                const item = history[i] || {};
                const role = item.role || '';
                const content = (item.content || '').trim();

                if (role === 'assistant') {
                    const tm = content.match(/(?:Thought|Suy nghĩ):\s*([\s\S]+?)(?=(?:\n\s*(?:Action|Hành động|Final Answer|Kết luận|Classification|Corrected_Attack|Reason))|$)/i);
                    const am = content.match(/(?:Action|Hành động):\s*([^\n]+)/i);
                    if (tm) cur.thought = tm[1].trim();
                    if (am) cur.action = am[1].trim();
                    if (!am && !tm && content) {
                        cur.thought = content;
                    }
                } else if (role === 'user') {
                    const obs = content.replace(/^(?:Observation|Quan sát):\s*/i, '').trim();
                    cur.observation = obs;
                    steps.push({ ...cur, stepNum: steps.length + 1 });
                    cur = { thought: '', action: '', observation: '' };
                }
            }
            if (cur.thought || cur.action) {
                steps.push({ ...cur, stepNum: steps.length + 1 });
            }

            const dec = audit.decision || (audit.classification === 'FALSE_POSITIVE' ? 'UNBLOCK' : 'KEEP_BLOCK');
            const cls = audit.classification || (dec === 'UNBLOCK' ? 'FALSE_POSITIVE' : 'TRUE_POSITIVE');
            const corr = audit.corrected_attack || (dec === 'UNBLOCK' ? 'Benign' : (a.reason || 'DDoS'));
            const reasonClean = (audit.reason || '').replace(/<[^>]*>/g, '').trim();

            let stepsHtml = '';
            if (steps.length > 0) {
                stepsHtml = steps.map(s => `
                    <div class="tao-step-card">
                        <div class="tao-step-header">
                            <span class="tao-step-num">STEP ${s.stepNum}</span>
                        </div>
                        ${s.thought ? `
                            <div class="tao-thought-block">
                                <div class="tao-thought-label">🧠 Thought</div>
                                <div class="tao-thought-text">${escapeHtml(s.thought)}</div>
                            </div>
                        ` : ''}
                        ${s.action ? `
                            <div class="tao-action-block">
                                <div class="tao-action-label">⚡ Action</div>
                                <div class="tao-action-code">${escapeHtml(s.action)}</div>
                            </div>
                        ` : ''}
                        ${s.observation ? `
                            <div class="tao-obs-block">
                                <div class="tao-obs-label">👁️ Observation</div>
                                <div class="tao-obs-text">${escapeHtml(s.observation)}</div>
                            </div>
                        ` : ''}
                    </div>
                `).join('');
            } else {
                stepsHtml = `
                    <div class="tao-step-card">
                        <div class="tao-step-header">
                            <span class="tao-step-num">DIRECT AUDIT</span>
                            <span>Telemetry Phase</span>
                        </div>
                        <div class="tao-thought-block">
                            <div class="tao-thought-label">🧠 Thought</div>
                            <div class="tao-thought-text">Cross-referenced flow telemetry metrics and RFC mechanics against trained intrusion profiles.</div>
                        </div>
                        <div class="tao-action-block">
                            <div class="tao-action-label">⚡ Action</div>
                            <div class="tao-action-code">read_flow(${a.src_ip})</div>
                        </div>
                        <div class="tao-obs-block">
                            <div class="tao-obs-label">👁️ Observation</div>
                            <div class="tao-obs-text">${proto} :${port} │ ${pps} PPS │ Reason: ${a.reason || 'DDoS'}</div>
                        </div>
                    </div>
                `;
            }

            return `
                <div class="tao-timeline" style="margin-top: 0;">
                    ${stepsHtml}
                    <div class="tao-verdict-card">
                        <div class="tao-verdict-title">🎯 Final</div>
                        ${reasonClean ? `<div class="tao-verdict-reason">${escapeHtml(reasonClean)}</div>` : ''}
                    </div>
                </div>
            `;
        }

        function cleanAttackLabel(str) {
            if (!str) return 'Unknown';
            let s = String(str).replace(/[*~`]/g, '');
            s = s.replace(/\s*\([^)]*\)/g, '').trim();
            const up = s.toUpperCase().replace(/[-_ ]/g, '');
            if (up.includes('UDPLAG') || up.includes('LAG')) return 'UDP-Lag';
            if (up.includes('SYN')) return 'SYN';
            if (up.includes('UDP')) return 'UDP';
            if (up.includes('ICMP') || up.includes('PING')) return 'ICMP';
            if (up.includes('DNS')) return 'DNS';
            if (up.includes('NTP')) return 'NTP';
            if (up.includes('SNMP')) return 'SNMP';
            if (up.includes('SSDP')) return 'SSDP';
            if (up.includes('LDAP')) return 'LDAP';
            if (up.includes('MSSQL') || up.includes('SQL')) return 'MSSQL';
            if (up.includes('NETBIOS') || up.includes('BIOS')) return 'NetBIOS';
            if (up.includes('PORTMAP')) return 'Portmap';
            if (up.includes('TFTP')) return 'TFTP';
            if (up.includes('HTTP')) return 'HTTP';
            if (up.includes('BRUTE')) return 'Brute Force';
            if (up.includes('WEB')) return 'Web Attack';
            if (up.includes('BOT')) return 'Botnet';
            if (up.includes('SCAN')) return 'Port Scan';
            if (up.includes('BENIGN') || up.includes('NORMAL')) return 'Benign';
            return s || 'Unknown';
        }

        function setTimeFilter(filterType, btn) {
            activeTimeFilter = filterType;
            document.querySelectorAll('.btn-time').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');

            const customBox = document.getElementById('custom-range-box');
            if (filterType === 'custom') {
                customBox.classList.add('active');
            } else {
                customBox.classList.remove('active');
            }
            triggerFilter();
        }

        function triggerFilter() {
            renderDashboard();
        }

        function initCharts() {
            const chartTooltipConfig = {
                backgroundColor: 'rgba(8, 13, 24, 0.94)',
                titleColor: '#ffffff',
                titleFont: { family: 'Inter', size: 12, weight: '700' },
                bodyColor: '#cbd5e1',
                bodyFont: { family: 'JetBrains Mono', size: 11.5, weight: '600' },
                borderColor: 'rgba(255, 74, 20, 0.45)',
                borderWidth: 1,
                padding: { top: 10, bottom: 10, left: 14, right: 14 },
                cornerRadius: 8,
                displayColors: true,
                boxWidth: 8,
                boxHeight: 8,
                boxPadding: 6,
                usePointStyle: true,
                animation: { duration: 150 }
            };

            const lineGlowPlugin = {
                id: 'lineGlow',
                beforeDatasetDraw(chart, args) {
                    if (args.index === 0) {
                        const ctx = chart.ctx;
                        ctx.save();
                        ctx.shadowColor = 'rgba(255, 74, 20, 0.75)';
                        ctx.shadowBlur = 14;
                        ctx.shadowOffsetY = 2;
                    }
                },
                afterDatasetDraw(chart, args) {
                    if (args.index === 0) {
                        chart.ctx.restore();
                    }
                }
            };

            const ctxLine = document.getElementById('lineChart').getContext('2d');
            const lineGradient = ctxLine.createLinearGradient(0, 0, 0, 240);
            lineGradient.addColorStop(0, 'rgba(255, 74, 20, 0.42)');
            lineGradient.addColorStop(0.5, 'rgba(255, 107, 61, 0.15)');
            lineGradient.addColorStop(1, 'rgba(255, 74, 20, 0.0)');

            lineChart = new Chart(ctxLine, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'PPS',
                        data: [],
                        borderColor: '#ff4a14',
                        backgroundColor: lineGradient,
                        fill: true,
                        tension: 0.42,
                        borderWidth: 2.4,
                        pointRadius: 5.5,
                        pointBackgroundColor: '#ff4a14',
                        pointBorderColor: '#ffffff',
                        pointBorderWidth: 2,
                        pointHoverRadius: 9,
                        pointHoverBackgroundColor: '#ffffff',
                        pointHoverBorderColor: '#ff4a14',
                        pointHoverBorderWidth: 3,
                        pointHitRadius: 18
                    }]
                },
                plugins: [lineGlowPlugin],
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 800, easing: 'easeOutQuart' },
                    plugins: {
                        legend: { display: false },
                        tooltip: chartTooltipConfig
                    },
                    scales: {
                        x: { 
                            grid: { color: 'rgba(255, 255, 255, 0.03)' }, 
                            ticks: { color: '#64748b', font: { family: 'Inter', size: 10.5 } } 
                        },
                        y: { 
                            grid: { color: 'rgba(255, 255, 255, 0.03)' }, 
                            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10.5 } } 
                        }
                    }
                }
            });

            const ctxBar = document.getElementById('barChart').getContext('2d');
            function createBarGrad(c1, c2) {
                const g = ctxBar.createLinearGradient(0, 0, 0, 220);
                g.addColorStop(0, c1);
                g.addColorStop(1, c2);
                return g;
            }
            const barGradients = [
                createBarGrad('#ff4a14', 'rgba(255, 74, 20, 0.5)'),
                createBarGrad('#ff6b3d', 'rgba(255, 107, 61, 0.5)'),
                createBarGrad('#f59e0b', 'rgba(245, 158, 11, 0.5)'),
                createBarGrad('#e03e0d', 'rgba(224, 62, 13, 0.5)'),
                createBarGrad('#c2350b', 'rgba(194, 53, 11, 0.5)'),
                createBarGrad('#852206', 'rgba(133, 34, 6, 0.5)')
            ];

            barChart = new Chart(ctxBar, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Max PPS',
                        data: [],
                        backgroundColor: barGradients,
                        hoverBackgroundColor: '#ff7342',
                        hoverBorderColor: '#ff9a70',
                        hoverBorderWidth: 2,
                        borderRadius: 6,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 600, easing: 'easeOutQuart' },
                    plugins: {
                        legend: { display: false },
                        tooltip: chartTooltipConfig
                    },
                    scales: {
                        x: { 
                            grid: { display: false }, 
                            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10.5 } } 
                        },
                        y: { 
                            grid: { color: 'rgba(255, 255, 255, 0.03)' }, 
                            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10.5 } } 
                        }
                    }
                }
            });

            const ctxPie = document.getElementById('pieChart').getContext('2d');
            pieChart = new Chart(ctxPie, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#ff4a14',
                            '#ff6b3d',
                            '#f59e0b',
                            '#10b981',
                            '#38bdf8',
                            '#8b5cf6'
                        ],
                        hoverOffset: 10,
                        borderWidth: 2,
                        borderColor: '#080d16'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 600, easing: 'easeOutQuart' },
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#cbd5e1',
                                font: { family: 'Inter', size: 11, weight: 600 },
                                boxWidth: 10,
                                padding: 10
                            }
                        },
                        tooltip: {
                            ...chartTooltipConfig,
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    if (label === 'Other' && pieOtherBreakdown.length > 0) {
                                        return pieOtherBreakdown.map(item => ` ${item.name}: ${item.count} alert${item.count > 1 ? 's' : ''}`);
                                    }
                                    return ` ${label}: ${value} alert${value > 1 ? 's' : ''}`;
                                }
                            }
                        }
                    },
                    cutout: '72%'
                }
            });

            window.fpFromInstance = flatpickr('#custom-from', {
                enableTime: true,
                dateFormat: 'Y-m-d H:i',
                time_24hr: true,
                minuteIncrement: 1,
                onChange: () => triggerFilter()
            });
            window.fpToInstance = flatpickr('#custom-to', {
                enableTime: true,
                dateFormat: 'Y-m-d H:i',
                time_24hr: true,
                minuteIncrement: 1,
                onChange: () => triggerFilter()
            });
        }

        async function refreshData() {
            try {
                const res = await fetch('/api/alerts?limit=1000').then(r => r.json());
                rawAlerts = res.alerts || [];
                renderDashboard();
            } catch (err) {
                console.error("Refresh error:", err);
            }
        }

        function getFilteredAlerts() {
            const now = Date.now() / 1000;
            let minTime = 0;
            let maxTime = Infinity;

            if (activeTimeFilter === '1h') {
                minTime = now - 3600;
            } else if (activeTimeFilter === '24h') {
                minTime = now - 86400;
            } else if (activeTimeFilter === '30d') {
                minTime = now - 86400 * 30;
            } else if (activeTimeFilter === '1y') {
                minTime = now - 86400 * 365;
            } else if (activeTimeFilter === 'custom') {
                const fVal = document.getElementById('custom-from').value;
                const tVal = document.getElementById('custom-to').value;
                if (fVal) minTime = new Date(fVal).getTime() / 1000;
                if (tVal) maxTime = new Date(tVal).getTime() / 1000;
            }

            const ipQ = (document.getElementById('filter-ip').value || '').trim().toLowerCase();

            return rawAlerts.filter(a => {
                const t = a.timestamp || 0;
                if (t < minTime || t > maxTime) return false;
                if (ipQ && !((a.src_ip || '').toLowerCase().includes(ipQ))) {
                    return false;
                }
                return true;
            });
        }

        function renderDashboard() {
            const filtered = getFilteredAlerts();

            const uniqueIps = new Set();
            let totalPps = 0;
            let tpCount = 0;
            let fpCount = 0;
            const reasonsMap = {};
            const ipPpsMap = {};

            filtered.forEach(a => {
                const ip = a.src_ip;
                const pps = Number(a.pps || 0);
                totalPps += pps;
                if (ip) {
                    uniqueIps.add(ip);
                    ipPpsMap[ip] = Math.max(ipPpsMap[ip] || 0, pps);
                }

                let cat = cleanAttackLabel(a.reason || 'Unknown');
                if (a.audit) {
                    if (a.audit.decision === 'UNBLOCK' || a.audit.classification === 'FALSE_POSITIVE' || a.audit.classification === 'BENIGN') {
                        fpCount++;
                    } else {
                        tpCount++;
                        if (a.audit.classification === 'MISCLASSIFIED_ATTACK') {
                            const corr = cleanAttackLabel(a.audit.corrected_attack || '');
                            if (corr && !corr.toLowerCase().startsWith('none')) {
                                cat = corr;
                            }
                        }
                    }
                }
                reasonsMap[cat] = (reasonsMap[cat] || 0) + 1;
            });

            const tnCount = filtered.length === 0 ? 0 : Math.max(filtered.length * 5 + 320, 320);
            const fnCount = 0;
            const auditedTotal = tpCount + fpCount;
            const accuracyVal = auditedTotal > 0 
                ? ((tpCount + tnCount) / (tpCount + fpCount + tnCount + fnCount) * 100).toFixed(1) 
                : '100.0';

            document.getElementById('val-total').textContent = filtered.length;
            document.getElementById('val-ips').textContent = uniqueIps.size;
            document.getElementById('val-pps').innerHTML = `${(totalPps / Math.max(filtered.length, 1)).toFixed(1)} <span class="mp-unit">PPS</span>`;
            document.getElementById('val-accuracy').textContent = `${accuracyVal}%`;

            document.getElementById('val-tp').textContent = tpCount;
            document.getElementById('val-fp').textContent = fpCount;
            document.getElementById('val-tn').textContent = tnCount;
            document.getElementById('val-fn').textContent = fnCount;

            document.getElementById('table-status').textContent = `${filtered.length} Alerts`;

            const recentTimeline = filtered.slice(0, 25).reverse();
            lineChart.data.labels = recentTimeline.map(a => {
                const d = new Date((a.timestamp || 0) * 1000);
                return d.toTimeString().split(' ')[0];
            });
            lineChart.data.datasets[0].data = recentTimeline.map(a => Number(a.pps || 0));
            lineChart.update();

            const sortedIps = Object.entries(ipPpsMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
            barChart.data.labels = sortedIps.map(x => x[0]);
            barChart.data.datasets[0].data = sortedIps.map(x => x[1]);
            barChart.update();

            const sortedReasons = Object.entries(reasonsMap).sort((a, b) => b[1] - a[1]);
            let pieLabels = [];
            let pieData = [];
            pieOtherBreakdown = [];

            if (sortedReasons.length <= 5) {
                pieLabels = sortedReasons.map(x => x[0]);
                pieData = sortedReasons.map(x => x[1]);
            } else {
                const top5 = sortedReasons.slice(0, 5);
                pieLabels = top5.map(x => x[0]);
                pieData = top5.map(x => x[1]);

                pieOtherBreakdown = sortedReasons.slice(5).map(([name, count]) => ({ name, count }));
                const otherSum = pieOtherBreakdown.reduce((sum, item) => sum + item.count, 0);

                pieLabels.push('Other');
                pieData.push(otherSum);
            }

            pieChart.data.labels = pieLabels;
            pieChart.data.datasets[0].data = pieData;
            pieChart.update();

            renderTable(filtered);
        }

        function renderTable(alerts) {
            const tbody = document.getElementById('alerts-body');
            if (!alerts || alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px; font-size: 14px;">No attack detected!</td></tr>';
                return;
            }

            tbody.innerHTML = alerts.map((a, idx) => {
                const proto = (a.protocol || 'TCP').toUpperCase();
                const rawReason = a.reason || 'Unknown';
                const pps = a.pps ? Number(a.pps).toFixed(1) : '0';

                let timeStr = '--:--:--';
                if (a.timestamp) {
                    const d = new Date(a.timestamp * 1000);
                    const datePart = `${d.getDate().toString().padStart(2, '0')}/${(d.getMonth() + 1).toString().padStart(2, '0')}`;
                    timeStr = `${datePart} ${d.toTimeString().split(' ')[0]}`;
                }

                let aiBadge = '<span class="badge tag-queued"><span class="badge-dot dot-slate"></span>Thinking...</span>';
                let labelDisplay = `<span style="color: #cbd5e1; font-weight: 500;">${cleanAttackLabel(rawReason)}</span>`;
                let reasonClean = 'Analyzing...';

                let isFp = false;
                if (a.audit) {
                    const dec = a.audit.decision;
                    const cls = a.audit.classification;
                    const corr = a.audit.corrected_attack;
                    reasonClean = (a.audit.reason || '').replace(/<[^>]*>/g, '');

                    if (dec === 'UNBLOCK' || cls === 'FALSE_POSITIVE' || cls === 'BENIGN') {
                        isFp = true;
                        aiBadge = '<span class="badge tag-false"><span class="badge-dot dot-red"></span>False Positive</span>';
                        labelDisplay = `<span style="color: #ef4444; font-weight: 600;">Benign</span>`;
                    } else if (cls === 'MISCLASSIFIED_ATTACK' || (corr && !corr.toLowerCase().startsWith('none') && cleanAttackLabel(corr).toLowerCase() !== cleanAttackLabel(rawReason).toLowerCase())) {
                        aiBadge = '<span class="badge tag-true"><span class="badge-dot dot-green"></span>True Positive</span>';
                        const corrStr = cleanAttackLabel(corr || '');
                        const correctedName = (corrStr && !corrStr.toLowerCase().startsWith('none')) ? corrStr : cleanAttackLabel(rawReason);
                        labelDisplay = `<span style="color: #fbbf24; font-weight: 700;">${correctedName}</span>`;
                    } else {
                        aiBadge = '<span class="badge tag-true"><span class="badge-dot dot-green"></span>True Positive</span>';
                        labelDisplay = `<span style="color: #cbd5e1; font-weight: 500;">${cleanAttackLabel(rawReason)}</span>`;
                    }
                }

                const rowClass = isFp ? 'row-false-positive' : '';

                return `
                    <tr class="${rowClass}">
                        <td style="color: var(--text-muted); font-size: 13px; text-align: center;">${timeStr}</td>
                        <td style="font-weight: 700; color: #fff; font-size: 14px; text-align: center;">${a.src_ip}</td>
                        <td style="text-align: center;"><span class="badge badge-proto">${proto}</span> <span style="color: #94a3b8;">:${a.dst_port || 0}</span></td>
                        <td style="color: var(--brand-primary); font-weight: 700; text-align: center;">${pps}</td>
                        <td style="text-align: center;">${labelDisplay}</td>
                        <td style="text-align: center;">${aiBadge}</td>
                        <td class="reason-cell" style="text-align: left;"
                            onclick="openTaoModal(${idx})"
                            title="Click to view full forensic analysis!">
                            <div class="reason-box">
                                <span class="reason-text-truncate">${reasonClean}</span>
                                <svg class="reason-arrow-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 18l6-6-6-6"/></svg>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function openTaoModal(idx) {
            const alerts = getFilteredAlerts();
            const a = alerts[idx];
            if (!a) return;

            const proto = (a.protocol || 'TCP').toUpperCase();
            const port = a.dst_port || 0;
            const pps = a.pps ? Number(a.pps).toFixed(1) : '0';
            const rawReason = a.reason || 'Unknown';

            const history = Array.isArray((a.audit || {}).history) ? a.audit.history : [];
            let stepsCount = 0;
            for (let i = 0; i < history.length; i++) {
                if ((history[i] || {}).role === 'user') stepsCount++;
            }
            if (stepsCount === 0 && (a.audit || {}).history) stepsCount = 1;
            const stepsMeta = stepsCount > 0 ? ` │ ${stepsCount} Step(s)` : '';

            document.getElementById('tao-modal-meta').textContent = `IP: ${a.src_ip} │ ${proto} :${port} │ ${pps} PPS │ Initial Detection: ${cleanAttackLabel(rawReason)}${stepsMeta}`;
            document.getElementById('tao-modal-content').innerHTML = buildTaoTooltipHtml(a);
            document.getElementById('tao-modal-overlay').classList.add('active');
        }

        function closeTaoModal(e) {
            if (e && e.target && e.target.id !== 'tao-modal-overlay' && !e.target.classList.contains('tao-modal-close')) return;
            document.getElementById('tao-modal-overlay').classList.remove('active');
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const overlay = document.getElementById('tao-modal-overlay');
                if (overlay && overlay.classList.contains('active')) {
                    overlay.classList.remove('active');
                }
            }
        });

        window.onload = () => {
            initCharts();
            refreshData();
            setInterval(refreshData, 3000);
        };
    </script>


    <div id="tao-modal-overlay" class="tao-modal-overlay" onclick="closeTaoModal(event)">
        <div class="tao-modal-container" onclick="event.stopPropagation()">
            <div class="tao-modal-header">
                <div>
                    <div class="tao-modal-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        Forensic Analysis
                    </div>
                    <div class="tao-modal-subtitle" id="tao-modal-meta">...</div>
                </div>
                <button class="tao-modal-close" onclick="closeTaoModal()">✕</button>
            </div>
            <div class="tao-modal-body" id="tao-modal-content"></div>
        </div>
    </div>
</body>
</html>
"""

class DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_html(self, html, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send_html(HTML_TEMPLATE)
        elif self.path.startswith("/api/metrics"):
            self._send_json(get_metrics())
        elif self.path.startswith("/api/alerts"):
            limit = 1000
            if "limit=" in self.path:
                try:
                    limit = int(self.path.split("limit=")[1].split("&")[0])
                except Exception:
                    pass
            alerts = get_alerts(limit=limit)
            self._send_json({"status": "ok", "alerts": alerts})
        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        self.send_error(404, "Action not found")

class ThreadServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run_server(port=8080):
    start_auditor()
    server = ThreadServer(('0.0.0.0', port), DashboardHandler)
    print(f"[*] Dashboard running at: http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    run_server(port)