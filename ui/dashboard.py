import os
import sys
import json
import time
import re
import ipaddress
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

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

_ENGINE = None

def get_engine():
    global _ENGINE
    if _ENGINE is None:
        try:
            from agent.engine import Engine
            _ENGINE = Engine()
        except Exception:
            _ENGINE = None
    return _ENGINE

def get_alerts(limit=50):
    if not os.path.exists(LOG_PATH):
        return []
    records = []
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    records.append(entry)
                except Exception:
                    pass
    except Exception as e:
        print(f"[ERROR] Reading alerts.log: {e}")
    return records[-limit:][::-1]

def get_metrics():
    alerts = get_alerts(limit=500)
    unique_ips = set()
    protocols = {}
    reasons = {}
    subnets = {}
    total_bytes = 0
    total_pps = 0

    for a in alerts:
        ip = a.get("src_ip")
        if ip:
            unique_ips.add(ip)
            try:
                sub = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                subnets[sub] = subnets.get(sub, 0) + 1
            except Exception:
                pass

        proto = a.get("protocol", "UNKNOWN")
        protocols[proto] = protocols.get(proto, 0) + 1

        r = a.get("reason", "Unknown")
        reasons[r] = reasons.get(r, 0) + 1

        pps = float(a.get("pps", 0) or 0)
        total_pps += pps
        sz = float(a.get("avg_packet_size", 128) or 128)
        dur = float(a.get("flow_duration_ms", 1000.0) or 1000.0) / 1000.0
        total_bytes += int(pps * dur * sz)

    avg_pps = round(total_pps / max(len(alerts), 1), 1)
    botnet_clusters = [s for s, count in subnets.items() if count >= 3]

    eng = get_engine()
    model_name = eng.model if eng else "Offline / Not Configured"

    return {
        "total_alerts": len(alerts),
        "unique_blocked_ips": len(unique_ips),
        "avg_pps": avg_pps,
        "total_bytes_analyzed": total_bytes,
        "protocols": protocols,
        "reasons": reasons,
        "botnet_clusters": botnet_clusters,
        "model_name": model_name,
        "status": "PROTECTED",
        "ebpf_status": "XDP_DRV_ACTIVE"
    }

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS-X | eBPF & AI Autonomous DDoS Defense SOC</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #07090e;
            --bg-secondary: #0d121d;
            --card-bg: rgba(16, 22, 36, 0.75);
            --card-border: rgba(56, 189, 248, 0.15);
            --card-hover: rgba(56, 189, 248, 0.25);
            --accent-cyan: #00f2fe;
            --accent-blue: #38bdf8;
            --accent-purple: #a855f7;
            --accent-rose: #f43f5e;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --font-sans: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 25%, rgba(168, 85, 247, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 50% 80%, rgba(244, 63, 94, 0.05) 0%, transparent 50%);
            color: var(--text-main);
            font-family: var(--font-sans);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        /* Glassmorphism scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(56, 189, 248, 0.3);
            border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-cyan);
        }

        /* Top Navigation */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 32px;
            border-bottom: 1px solid var(--card-border);
            backdrop-filter: blur(16px);
            background: rgba(7, 9, 14, 0.85);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-logo {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.4);
            font-weight: 800;
            font-size: 20px;
            color: #000;
        }

        .brand-text h1 {
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 0.5px;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text p {
            font-size: 11px;
            color: var(--accent-cyan);
            font-family: var(--font-mono);
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .nav-stats {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 12px;
            font-family: var(--font-mono);
            font-weight: 600;
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.3);
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
        }

        .status-badge .pulse {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-emerald);
            box-shadow: 0 0 10px var(--accent-emerald);
            animation: pulse-ring 1.8s infinite;
        }

        @keyframes pulse-ring {
            0% { transform: scale(0.9); opacity: 1; }
            50% { transform: scale(1.4); opacity: 0.5; }
            100% { transform: scale(0.9); opacity: 1; }
        }

        .model-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 12px;
            font-family: var(--font-mono);
            background: rgba(168, 85, 247, 0.1);
            color: var(--accent-purple);
            border: 1px solid rgba(168, 85, 247, 0.3);
        }

        .btn-refresh {
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid var(--card-border);
            color: var(--accent-cyan);
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn-refresh:hover {
            background: rgba(56, 189, 248, 0.25);
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.3);
        }

        /* Main Container */
        main {
            padding: 24px 32px;
            max-width: 1680px;
            margin: 0 auto;
            width: 100%;
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* Hero Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            padding: 20px;
            backdrop-filter: blur(12px);
            position: relative;
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .stat-card:hover {
            border-color: var(--card-hover);
            transform: translateY(-2px);
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.3);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
            opacity: 0.5;
        }

        .stat-label {
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            font-family: var(--font-mono);
            letter-spacing: -0.5px;
            color: #fff;
        }

        .stat-sub {
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 6px;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        /* Content Layout */
        .content-grid {
            display: grid;
            grid-template-columns: 1.15fr 0.85fr;
            gap: 24px;
            flex: 1;
        }

        @media (max-width: 1200px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Glass Panel */
        .panel {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            backdrop-filter: blur(16px);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--card-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255, 255, 255, 0.02);
        }

        .panel-title {
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .panel-title .icon {
            color: var(--accent-cyan);
        }

        /* Filter Controls */
        .filter-bar {
            padding: 12px 20px;
            display: flex;
            gap: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(0, 0, 0, 0.2);
        }

        .filter-input {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 6px 12px;
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 12px;
            flex: 1;
        }
        .filter-input:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0, 242, 254, 0.2);
        }

        /* Table */
        .table-container {
            overflow-y: auto;
            max-height: 580px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            text-align: left;
            padding: 12px 16px;
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--card-border);
            position: sticky;
            top: 0;
            background: #0b101b;
            z-index: 10;
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-main);
        }

        tr:hover {
            background: rgba(56, 189, 248, 0.05);
            cursor: pointer;
        }

        tr.selected {
            background: rgba(56, 189, 248, 0.12);
            border-left: 3px solid var(--accent-cyan);
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-tcp { background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); border: 1px solid rgba(56, 189, 248, 0.3); }
        .badge-udp { background: rgba(168, 85, 247, 0.15); color: var(--accent-purple); border: 1px solid rgba(168, 85, 247, 0.3); }
        .badge-icmp { background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
        
        .badge-attack { background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }
        .badge-benign { background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }

        .btn-audit {
            background: linear-gradient(135deg, rgba(0, 242, 254, 0.15), rgba(168, 85, 247, 0.15));
            border: 1px solid rgba(0, 242, 254, 0.4);
            color: var(--accent-cyan);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            font-family: var(--font-sans);
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-audit:hover {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            color: #000;
            box-shadow: 0 0 12px rgba(0, 242, 254, 0.4);
        }

        /* Right Tabs */
        .tabs-header {
            display: flex;
            border-bottom: 1px solid var(--card-border);
            background: rgba(0, 0, 0, 0.2);
        }

        .tab-btn {
            flex: 1;
            padding: 14px 12px;
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            font-family: var(--font-sans);
            cursor: pointer;
            transition: all 0.2s;
            border-bottom: 2px solid transparent;
            text-align: center;
        }

        .tab-btn.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
            background: rgba(56, 189, 248, 0.05);
        }

        .tab-btn:hover:not(.active) {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.02);
        }

        .tab-content {
            padding: 20px;
            flex: 1;
            overflow-y: auto;
            display: none;
        }
        .tab-content.active {
            display: block;
        }

        /* Audit Terminal / Log View */
        .terminal {
            background: #04060a;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 16px;
            font-family: var(--font-mono);
            font-size: 12px;
            line-height: 1.6;
            max-height: 480px;
            overflow-y: auto;
            color: #cbd5e1;
        }

        .terminal-step {
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .terminal-step:last-child {
            border-bottom: none;
            margin-bottom: 0;
        }

        .step-tag {
            font-weight: 700;
            display: inline-block;
            margin-right: 6px;
        }
        .tag-thought { color: var(--accent-blue); }
        .tag-action { color: var(--accent-purple); }
        .tag-observation { color: var(--accent-amber); }
        .tag-verdict-block { 
            color: var(--accent-rose); 
            font-size: 14px; 
            font-weight: 800; 
            background: rgba(244, 63, 94, 0.15);
            padding: 4px 10px;
            border-radius: 6px;
            display: inline-block;
            margin: 8px 0;
            border: 1px solid rgba(244, 63, 94, 0.3);
        }
        .tag-verdict-unblock { 
            color: var(--accent-emerald); 
            font-size: 14px; 
            font-weight: 800; 
            background: rgba(16, 185, 129, 0.15);
            padding: 4px 10px;
            border-radius: 6px;
            display: inline-block;
            margin: 8px 0;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .code-box {
            background: #020306;
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 8px;
            padding: 14px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: #38bdf8;
            position: relative;
            white-space: pre-wrap;
            margin-top: 10px;
        }

        .btn-copy {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #fff;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
        }
        .btn-copy:hover {
            background: var(--accent-cyan);
            color: #000;
        }

        .action-row {
            display: flex;
            gap: 10px;
            margin-top: 16px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            color: #000;
            font-weight: 700;
            padding: 10px 16px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-family: var(--font-sans);
            font-size: 13px;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .btn-primary:hover {
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.4);
            transform: translateY(-1px);
        }

        .btn-danger {
            background: rgba(244, 63, 94, 0.15);
            color: var(--accent-rose);
            border: 1px solid rgba(244, 63, 94, 0.3);
            font-weight: 600;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-family: var(--font-sans);
            font-size: 13px;
            transition: all 0.2s;
        }
        .btn-danger:hover {
            background: var(--accent-rose);
            color: #fff;
            box-shadow: 0 0 15px rgba(244, 63, 94, 0.4);
        }

        .btn-success {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.3);
            font-weight: 600;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-family: var(--font-sans);
            font-size: 13px;
            transition: all 0.2s;
        }
        .btn-success:hover {
            background: var(--accent-emerald);
            color: #fff;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.4);
        }

        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            border-top-color: var(--accent-cyan);
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Subnet Cluster Tag */
        .cluster-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(244, 63, 94, 0.1);
            border: 1px solid rgba(244, 63, 94, 0.25);
            color: var(--accent-rose);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-family: var(--font-mono);
            margin: 4px;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="brand-logo">🛡️</div>
            <div class="brand-text">
                <h1>AEGIS-X DEFENSE SOC</h1>
                <p>eBPF/XDP High-Speed Mitigation &bull; LLM ReAct Agent</p>
            </div>
        </div>
        <div class="nav-stats">
            <div class="status-badge">
                <span class="pulse"></span>
                <span>KERNEL XDP_PASS / DROP ACTIVE</span>
            </div>
            <div class="model-badge" id="model-display">
                <span>🤖 LLM: Loading...</span>
            </div>
            <button class="btn-refresh" onclick="refreshData()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                Sync Logs
            </button>
        </div>
    </header>

    <main>
        <!-- Hero Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">
                    <span>Total Alerts Logged</span>
                    <span style="color: var(--accent-blue)">⚡</span>
                </div>
                <div class="stat-value" id="val-total-alerts">--</div>
                <div class="stat-sub">Recent traffic window</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">
                    <span>Active Blacklist IPs</span>
                    <span style="color: var(--accent-rose)">🚫</span>
                </div>
                <div class="stat-value" style="color: var(--accent-rose);" id="val-blocked-ips">--</div>
                <div class="stat-sub">eBPF Kernel Array entries</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">
                    <span>Average Attack Velocity</span>
                    <span style="color: var(--accent-amber)">📈</span>
                </div>
                <div class="stat-value" id="val-avg-pps">-- PPS</div>
                <div class="stat-sub">Packets per second rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">
                    <span>Botnet Subnet Swarms</span>
                    <span style="color: var(--accent-purple)">🕸️</span>
                </div>
                <div class="stat-value" style="color: var(--accent-purple);" id="val-botnets">--</div>
                <div class="stat-sub">Coordinated /24 clusters</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="content-grid">
            <!-- Left: Realtime Alert Log -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <span class="icon">📡</span>
                        <span>Live Security Incursions & Blacklist Feed</span>
                    </div>
                    <span style="font-size: 11px; color: var(--text-dim);" id="alert-count-label">0 alerts</span>
                </div>
                <div class="filter-bar">
                    <input type="text" class="filter-input" id="search-filter" placeholder="Filter by IP, Protocol, Port, or Vector..." oninput="filterTable()">
                </div>
                <div class="table-container">
                    <table id="alerts-table">
                        <thead>
                            <tr>
                                <th>Source IP</th>
                                <th>Protocol</th>
                                <th>Dst Port</th>
                                <th>Rate (PPS)</th>
                                <th>Attack Vector</th>
                                <th>Offenses</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="alerts-body">
                            <tr>
                                <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 30px;">
                                    Loading live intrusion telemetry...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Right: AI Agent Audit & Tools -->
            <div class="panel">
                <div class="tabs-header">
                    <button class="tab-btn active" onclick="switchTab('audit')">🧠 AI ReAct Audit</button>
                    <button class="tab-btn" onclick="switchTab('explain')">🔬 Forensic Explain</button>
                    <button class="tab-btn" onclick="switchTab('mitigate')">🛡️ Mitigation Gen</button>
                    <button class="tab-btn" onclick="switchTab('subnets')">🌐 Botnet Map</button>
                </div>

                <!-- Tab 1: AI ReAct Audit -->
                <div class="tab-content active" id="tab-audit">
                    <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <h3 style="font-size: 14px; font-weight: 700;">Autonomous Decision Audit</h3>
                            <p style="font-size: 12px; color: var(--text-muted);" id="selected-ip-label">Select an IP from the table to inspect</p>
                        </div>
                        <button class="btn-primary" id="btn-run-audit" onclick="runAudit()" style="display: none;">
                            <span>Audit with Agent</span>
                        </button>
                    </div>

                    <div class="terminal" id="audit-terminal">
                        <div style="color: var(--text-dim); text-align: center; padding: 40px 0;">
                            💡 Click <strong>"Audit"</strong> on any alert entry in the table to execute the LLM ReAct Agent cycle.<br>
                            The agent will gather evidence using eBPF tools, inspect RFC mechanisms, and issue a verified verdict.
                        </div>
                    </div>

                    <div class="action-row" id="audit-actions" style="display: none;">
                        <button class="btn-success" onclick="applyUnban()">
                            ✓ Unban IP (Mark False Positive)
                        </button>
                        <button class="btn-danger" onclick="applyExtend()">
                            🔒 Extend Ban Duration (7200s)
                        </button>
                    </div>
                </div>

                <!-- Tab 2: Explain Attack -->
                <div class="tab-content" id="tab-explain">
                    <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 6px;">Deep Technical Attack Analysis</h3>
                    <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
                        Prompts LLM to analyze packet telemetry, protocol headers, and RFC RFC specifications.
                    </p>
                    <button class="btn-primary" id="btn-run-explain" onclick="runExplain()">
                        <span>Generate Forensic Analysis</span>
                    </button>
                    <div class="code-box" id="explain-box" style="margin-top: 14px; min-height: 200px;">
                        Ready. Click above to generate explanation for the selected alert.
                    </div>
                </div>

                <!-- Tab 3: Mitigation Generator -->
                <div class="tab-content" id="tab-mitigate">
                    <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 6px;">Multi-Layer Defense Rule Synthesis</h3>
                    <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
                        Generates exact firewall and traffic shaping configurations tailored to this attack vector.
                    </p>
                    <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                        <button class="btn-audit" onclick="runMitigate('iptables')">iptables</button>
                        <button class="btn-audit" onclick="runMitigate('ebpf')">eBPF / XDP</button>
                        <button class="btn-audit" onclick="runMitigate('tc')">Linux tc (HTB)</button>
                        <button class="btn-audit" onclick="runMitigate('cisco')">Cisco ACL</button>
                    </div>
                    <div class="code-box" id="mitigate-box" style="min-height: 180px;">
                        <button class="btn-copy" onclick="copyCode('mitigate-code')">Copy</button>
                        <pre id="mitigate-code">Select a target firewall or traffic control platform above.</pre>
                    </div>
                </div>

                <!-- Tab 4: Subnets & Botnets -->
                <div class="tab-content" id="tab-subnets">
                    <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 6px;">Distributed Botnet Correlation</h3>
                    <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
                        Identifies subnets with &ge; 3 coordinated attacking nodes attacking identical destination ports.
                    </p>
                    <div id="botnet-list" style="margin-top: 10px;">
                        <p style="color: var(--text-dim);">Scanning subnet topology...</p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        let allAlerts = [];
        let selectedAlert = null;

        async function refreshData() {
            try {
                const [metricsRes, alertsRes] = await Promise.all([
                    fetch('/api/metrics').then(r => r.json()),
                    fetch('/api/alerts?limit=100').then(r => r.json())
                ]);

                // Update metrics
                document.getElementById('val-total-alerts').textContent = metricsRes.total_alerts || 0;
                document.getElementById('val-blocked-ips').textContent = metricsRes.unique_blocked_ips || 0;
                document.getElementById('val-avg-pps').textContent = `${metricsRes.avg_pps || 0} PPS`;
                document.getElementById('val-botnets').textContent = (metricsRes.botnet_clusters || []).length;
                document.getElementById('model-display').innerHTML = `<span>🤖 LLM: ${metricsRes.model_name || 'Ready'}</span>`;

                // Update botnet tab
                const botnetDiv = document.getElementById('botnet-list');
                if (metricsRes.botnet_clusters && metricsRes.botnet_clusters.length > 0) {
                    botnetDiv.innerHTML = metricsRes.botnet_clusters.map(sub => 
                        `<div class="cluster-tag">⚠️ Botnet Swarm Detected: <strong>${sub}</strong></div>`
                    ).join('');
                } else {
                    botnetDiv.innerHTML = '<p style="color: var(--accent-emerald);">✓ No active botnet subnet clusters detected.</p>';
                }

                allAlerts = alertsRes.alerts || [];
                document.getElementById('alert-count-label').textContent = `${allAlerts.length} entries`;
                renderTable(allAlerts);

                if (!selectedAlert && allAlerts.length > 0) {
                    selectAlert(allAlerts[0]);
                }
            } catch (err) {
                console.error("Sync error:", err);
            }
        }

        function renderTable(alerts) {
            const tbody = document.getElementById('alerts-body');
            if (!alerts || alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 30px;">No incursions recorded in log.</td></tr>';
                return;
            }

            tbody.innerHTML = alerts.map((a, i) => {
                const proto = (a.protocol || 'TCP').toUpperCase();
                const pClass = proto === 'TCP' ? 'badge-tcp' : (proto === 'UDP' ? 'badge-udp' : 'badge-icmp');
                const reason = a.reason || 'DDoS';
                const isSelected = selectedAlert && selectedAlert.src_ip === a.src_ip && selectedAlert.timestamp === a.timestamp;
                const pps = a.pps ? Number(a.pps).toFixed(1) : '0';

                return `
                    <tr class="${isSelected ? 'selected' : ''}" onclick="selectAlertByIndex(${i})">
                        <td style="font-weight: 600;">${a.src_ip}</td>
                        <td><span class="badge ${pClass}">${proto}</span></td>
                        <td>${a.dst_port || 0}</td>
                        <td>${pps}</td>
                        <td><span class="badge badge-attack">${reason}</span></td>
                        <td><span style="color: var(--accent-amber); font-weight: 700;">${a.offense_count || 1}x</span></td>
                        <td>
                            <button class="btn-audit" onclick="event.stopPropagation(); selectAlertByIndex(${i}); switchTab('audit'); runAudit();">
                                Audit
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function filterTable() {
            const q = document.getElementById('search-filter').value.toLowerCase();
            const filtered = allAlerts.filter(a => {
                return (a.src_ip && a.src_ip.toLowerCase().includes(q)) ||
                       (a.protocol && a.protocol.toLowerCase().includes(q)) ||
                       (a.reason && a.reason.toLowerCase().includes(q)) ||
                       (a.dst_port && String(a.dst_port).includes(q));
            });
            renderTable(filtered);
        }

        function selectAlertByIndex(idx) {
            if (allAlerts[idx]) {
                selectAlert(allAlerts[idx]);
            }
        }

        function selectAlert(a) {
            selectedAlert = a;
            document.getElementById('selected-ip-label').innerHTML = 
                `Target: <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${a.src_ip}</strong> &bull; Port: ${a.dst_port} &bull; Vector: ${a.reason}`;
            document.getElementById('btn-run-audit').style.display = 'inline-flex';

            // Re-render highlight
            const rows = document.querySelectorAll('#alerts-body tr');
            rows.forEach(r => r.classList.remove('selected'));
        }

        function switchTab(name) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.textContent.toLowerCase().includes(name.toLowerCase()));
            if (btn) btn.classList.add('active');

            const content = document.getElementById(`tab-${name}`);
            if (content) content.classList.add('active');
        }

        async function runAudit() {
            if (!selectedAlert) return;
            const term = document.getElementById('audit-terminal');
            const actions = document.getElementById('audit-actions');
            actions.style.display = 'none';

            term.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px; color: var(--accent-cyan);">
                    <div class="loading-spinner"></div>
                    <span>Invoking LLM ReAct Agent cycle for <strong>${selectedAlert.src_ip}</strong>...</span>
                </div>
            `;

            try {
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(selectedAlert)
                }).then(r => r.json());

                if (res.status === 'error') {
                    term.innerHTML = `<div style="color: var(--accent-rose);">❌ Error executing audit: ${res.message}</div>`;
                    return;
                }

                let html = `<div style="margin-bottom: 12px; color: var(--accent-cyan); font-weight: 700;">>>> REASONING CHAIN FOR ${selectedAlert.src_ip} (${res.steps} steps):</div>`;

                if (res.history && res.history.length > 0) {
                    for (let item of res.history) {
                        const content = item.content || '';
                        if (item.role === 'assistant') {
                            const thoughtMatch = content.match(/Thought:\\s*(.+)/);
                            const actionMatch = content.match(/Action:\\s*(.+)/);
                            if (thoughtMatch) {
                                html += `<div class="terminal-step"><span class="step-tag tag-thought">Thought:</span> ${thoughtMatch[1]}</div>`;
                            }
                            if (actionMatch) {
                                html += `<div class="terminal-step"><span class="step-tag tag-action">Action:</span> <code>${actionMatch[1]}</code></div>`;
                            }
                        } else if (item.role === 'user' && content.startsWith('Observation:')) {
                            const obsText = content.replace('Observation:', '').trim();
                            html += `<div class="terminal-step" style="background: rgba(245, 158, 11, 0.05); padding: 8px; border-radius: 6px;"><span class="step-tag tag-observation">Observation:</span> ${obsText}</div>`;
                        }
                    }
                }

                const isKeep = res.decision === 'KEEP_BLOCK';
                const verdictClass = isKeep ? 'tag-verdict-block' : 'tag-verdict-unblock';
                const verdictIcon = isKeep ? '🛡️ KEEP_BLOCK (True Positive Attack)' : '✅ UNBLOCK (False Positive Anomaly)';

                html += `
                    <div style="margin-top: 16px; padding-top: 14px; border-top: 1px dashed var(--card-border);">
                        <div>VERDICT:</div>
                        <div class="${verdictClass}">${verdictIcon}</div>
                        <div style="margin-top: 8px; line-height: 1.5; color: #e2e8f0;">
                            <strong>Reasoning:</strong> ${res.reason || 'No reasoning provided.'}
                        </div>
                    </div>
                `;

                term.innerHTML = html;
                actions.style.display = 'flex';

            } catch (err) {
                term.innerHTML = `<div style="color: var(--accent-rose);">❌ Connection error: ${err}</div>`;
            }
        }

        async function runExplain() {
            if (!selectedAlert) return;
            const box = document.getElementById('explain-box');
            box.innerHTML = '<div class="loading-spinner"></div> Analyzing RFC mechanics and traffic heuristics...';

            try {
                const res = await fetch('/api/explain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ alert: selectedAlert })
                }).then(r => r.json());

                box.textContent = res.explanation || 'No explanation returned.';
            } catch (err) {
                box.textContent = `Error: ${err}`;
            }
        }

        async function runMitigate(device) {
            if (!selectedAlert) return;
            const codeEl = document.getElementById('mitigate-code');
            codeEl.textContent = `Synthesizing ${device} defense rules...`;

            try {
                const res = await fetch('/api/mitigate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ alert: selectedAlert, device: device })
                }).then(r => r.json());

                codeEl.textContent = res.rules || 'No rules synthesized.';
            } catch (err) {
                codeEl.textContent = `Error: ${err}`;
            }
        }

        async function applyUnban() {
            if (!selectedAlert) return;
            if (!confirm(`Confirm lifting block for ${selectedAlert.src_ip}?`)) return;
            try {
                const res = await fetch('/api/unban', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ src_ip: selectedAlert.src_ip })
                }).then(r => r.json());
                alert(`Unban result: ${JSON.stringify(res)}`);
                refreshData();
            } catch (err) {
                alert(`Error: ${err}`);
            }
        }

        async function applyExtend() {
            if (!selectedAlert) return;
            try {
                const res = await fetch('/api/extend', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ src_ip: selectedAlert.src_ip, ttl_seconds: 7200 })
                }).then(r => r.json());
                alert(`Extended ban for ${selectedAlert.src_ip} (TTL: 7200s): ${JSON.stringify(res)}`);
                refreshData();
            } catch (err) {
                alert(`Error: ${err}`);
            }
        }

        function copyCode(id) {
            const text = document.getElementById(id).textContent;
            navigator.clipboard.writeText(text);
            alert("Configuration copied to clipboard!");
        }

        // Initial load and periodic refresh
        refreshData();
        setInterval(refreshData, 4000);
    </script>
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
            limit = 50
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
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8')
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        eng = get_engine()

        if self.path == "/api/audit":
            if not eng:
                self._send_json({"status": "error", "message": "Agent Engine not configured."}, 500)
                return
            try:
                alert = payload
                res = eng.react(alert)
                self._send_json({
                    "status": "ok",
                    "decision": res.get("decision"),
                    "classification": res.get("classification"),
                    "corrected_attack": res.get("corrected_attack"),
                    "reason": res.get("reason"),
                    "steps": res.get("steps"),
                    "history": res.get("history")
                })
            except Exception as err:
                self._send_json({"status": "error", "message": str(err)}, 500)

        elif self.path == "/api/explain":
            if not eng:
                self._send_json({"status": "error", "message": "Agent Engine not configured."}, 500)
                return
            try:
                alert = payload.get("alert", {})
                explanation = eng.explain(alert)
                self._send_json({"status": "ok", "explanation": explanation})
            except Exception as err:
                self._send_json({"status": "error", "message": str(err)}, 500)

        elif self.path == "/api/mitigate":
            if not eng:
                self._send_json({"status": "error", "message": "Agent Engine not configured."}, 500)
                return
            try:
                alert = payload.get("alert", {})
                device = payload.get("device", "iptables")
                rules = eng.mitigate(alert, device=device)
                self._send_json({"status": "ok", "rules": rules})
            except Exception as err:
                self._send_json({"status": "error", "message": str(err)}, 500)

        elif self.path == "/api/unban":
            from tools.execute import execute_unban
            src_ip = payload.get("src_ip", "")
            res_str = execute_unban(src_ip)
            self._send_json(json.loads(res_str))

        elif self.path == "/api/extend":
            from tools.execute import execute_extend
            src_ip = payload.get("src_ip", "")
            ttl = payload.get("ttl_seconds", 3600)
            res_str = execute_extend(src_ip, ttl_seconds=ttl)
            self._send_json(json.loads(res_str))

        else:
            self.send_error(404, "Action not found")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run_server(port=8080):
    server = ThreadedHTTPServer(('0.0.0.0', port), DashboardHandler)
    print(f"http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()

if __name__ == '__main__':
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    run_server(port)
