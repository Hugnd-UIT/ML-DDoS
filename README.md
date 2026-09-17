<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->
<div align="center">

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC_BY--NC_4.0-lightgrey.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Linux Kernel](https://img.shields.io/badge/Linux-Kernel_5.15%2B-orange.svg?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![eBPF / XDP](https://img.shields.io/badge/eBPF-XDP_Line--Rate-red.svg?style=flat-square)](https://ebpf.io/)
[![ML](https://img.shields.io/badge/ML-XGBoost_2.0-yellow.svg?style=flat-square)](https://xgboost.readthedocs.io/)
[![Agent](https://img.shields.io/badge/Agent-ReAct_LLM-purple.svg?style=flat-square)](https://arxiv.org/abs/2210.03629)
[![DDoS Coverage](https://img.shields.io/badge/Coverage-17%2F17_DDoS_Classes-brightgreen.svg?style=flat-square)](#empirical-results)

</div>

<!-- PROJECT TITLE -->
<div align="center">
  <h3>ML-LLM-DDoS</h3>
  <p align="center">
    <strong>Autonomous eBPF/XDP DDoS Prevention & Cognitive LLM Forensics Engine</strong>
    <br />
    Line-rate kernel packet filtering combined with explainable AI forensics and automatic false-positive elimination.
    <br />
    <br />
    <a href="https://github.com/Hugnd-UIT/ML-LLM-DDoS/issues">Report Bug</a>
    ·
    <a href="https://github.com/Hugnd-UIT/ML-LLM-DDoS/issues">Request Feature</a>
  </p>
</div>

---

## Overview

**ML-LLM-DDoS** is a closed-loop network intrusion defense system built on a **Dual-Plane architecture**:

- **Fast-Path Data Plane (Kernel Space):** In-driver **eBPF/XDP** packet dropping (`< 0.6 ms`). Packets matching malicious flow signatures are dropped directly at the NIC layer (`XDP_DROP`) before touching Linux socket buffers (`sk_buff`).
- **Cognitive Forensics Plane (User Space):** An **Autonomous ReAct LLM Agent** audits alerts in the background. It calls forensic tools (`read_flow`, `search_subnet`, `lookup_mechanism`) to verify attack mechanics against RFC standards and automatically lifts false-positive bans.

---

## Key Features

- **Driver-Level Packet Drop:** Native eBPF/XDP filter program ([`prevent/xdp.c`](prevent/xdp.c)) dropping malicious IPs at line rate.
- **Dual ML Classifier:** XGBoost (17 attack types) + Isolation Forest (unsupervised Zero-Day novelty detection).
- **Autonomous Forensic Agent:** Multi-turn ReAct loop analyzing flow telemetry, subnet clustering, and RFC amplification factors.
- **Dynamic Signature Clustering:** Groups high-frequency attacks by `Proto:Port:Size:Reason`, reducing LLM API calls by **> 80%**.
- **Real-Time SOC Console:** Dark-mode glassmorphism dashboard with live attack feeds, geographic analytics, and forensic audit logs.

---

## Empirical Results

Tested directly on the Linux Kernel via eBPF/XDP using real micro-flow vectors from the **CIC-DDoS2019** & **CIC-DoS2017** datasets (10.6M records):

| # | Attack Vector | Protocol / Target | ML Detect % | XDP Drop % | Avg Latency | Status |
| :-: | :--- | :--- | :-: | :-: | :-: | :-: |
| 1 | **SYN Flood** | TCP / 80 | **100.0%** | **100.0%** | 0.28 ms | ✅ Blocked |
| 2 | **UDP Volumetric** | UDP / 80 | **100.0%** | **100.0%** | 0.22 ms | ✅ Blocked |
| 3 | **UDP-Lag** | UDP / 80 | **100.0%** | **100.0%** | 0.28 ms | ✅ Blocked |
| 4 | **DNS Amplification** | UDP / 53 | **100.0%** | **100.0%** | 0.43 ms | ✅ Blocked |
| 5 | **NTP Amplification** | UDP / 123 | **100.0%** | **100.0%** | 0.39 ms | ✅ Blocked |
| 6 | **SNMP Amplification** | UDP / 161 | **100.0%** | **100.0%** | 0.37 ms | ✅ Blocked |
| 7 | **SSDP Amplification** | UDP / 1900 | **100.0%** | **100.0%** | 0.44 ms | ✅ Blocked |
| 8 | **LDAP Amplification** | UDP / 389 | **100.0%** | **100.0%** | 0.38 ms | ✅ Blocked |
| 9 | **MSSQL Amplification**| UDP / 1434 | **100.0%** | **100.0%** | 0.41 ms | ✅ Blocked |
| 10 | **NetBIOS Amplification** | UDP / 137 | **100.0%** | **100.0%** | 0.33 ms | ✅ Blocked |
| 11 | **PortMap Amplification** | UDP / 111 | **100.0%** | **100.0%** | 0.38 ms | ✅ Blocked |
| 12 | **TFTP Reflection** | UDP / 69 | **100.0%** | **100.0%** | 0.28 ms | ✅ Blocked |
| 13 | **PortScan Recon** | TCP/UDP Probes | **100.0%** | **100.0%** | 0.24 ms | ✅ Blocked |
| 14 | **Web Attack (Layer 7)** | TCP / 80, 443 | **96.0%** | **100.0%** | 0.24 ms | ✅ Blocked |
| 15 | **Botnet Cluster** | TCP/UDP Distributed | **97.0%** | **100.0%** | 0.42 ms | ✅ Blocked |
| 16 | **Brute Force** | TCP / 22, 80 | **100.0%** | **100.0%** | 0.57 ms | ✅ Blocked |
| 17 | **DDoS Generic** | TCP/UDP Floods | **100.0%** | **100.0%** | 0.49 ms | ✅ Blocked |
| -- | **Benign (Normal)** | Mixed Client Traffic | **100.0% Spec** | **0.0% (Pass)** | 0.15 ms | 🛡️ Protected |

---

## Repository Structure

```
ML-DDoS/
├── agent/                    # ReAct cognitive engine & forensic prompt templates
├── common/                   # Concurrency-safe SQLite WAL database & storage
├── configs/                  # Global system configuration (config.yaml)
├── data/                     # Datasets and training partitions
│   ├── raw/                  # Original raw files (CIC-DDoS2019 & CIC-DoS2017)
│   ├── parsed/               # Cleaned tabular dataset (dataset.csv)
│   └── divided/              # Optimized train/test splits (Parquet format)
├── detect/                   # Real-time NFStream flow capture & ML gatekeeper
├── docs/                     # Research papers & architectural notes
├── logs/                     # SQLite alerts database & JSONL audit stream
├── models/                   # Pre-trained XGBoost, Isolation Forest & encoders
├── prevent/                  # eBPF/XDP native C kernel filter & ban lifecycle manager
├── scripts/                  # 16-in-1 raw socket DDoS simulation suite (simulate.sh)
├── src/                      # Dataset parsing, feature engineering & model trainer
├── tools/                    # ReAct agent tools (read, search, rag, execute)
├── ui/                       # Real-time glassmorphism Web console (dashboard.py)
├── requirements.txt          # Python dependencies
├── LICENSE                   # Non-Commercial License (CC BY-NC 4.0)
└── README.md
```

---

## Quick Start

### 1. Prerequisites (Linux / WSL2)

```bash
sudo apt-get update && sudo apt-get install -y \
    clang llvm libelf-dev bpfcc-tools python3-bpfcc \
    linux-headers-$(uname -r) libpcap-dev iptables iproute2 python3-pip
```

### 2. Installation

```bash
git clone https://github.com/Hugnd-UIT/ML-LLM-DDoS.git
cd ML-LLM-DDoS

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # Configure LLM_API_KEY (Mistral/OpenAI) and NETWORK_INTERFACE
```

### 3. Usage Commands

```bash
# 1. Start Security Operations Dashboard (:8080)
python3 ui/dashboard.py 8080

# 2. Start Kernel eBPF/XDP Gatekeeper (Requires root)
sudo python3 detect/gatekeeper.py --interface eth0

# 3. Simulate DDoS Attacks (16 attack vectors)
sudo bash scripts/simulate.sh
```

Open **`http://localhost:8080`** in your browser to inspect live traffic telemetry, active kernel drops, and real-time forensic explanations.

---

## License

Distributed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**.

> **Non-Commercial Restriction:** You are free to share, copy, and adapt this work for educational, academic, and research purposes. **Commercial use, closed-source monetization, sublicensing, and resale are strictly prohibited.**

See [`LICENSE`](LICENSE) for complete legal terms.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
