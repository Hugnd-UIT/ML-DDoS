# Autonomous eBPF/XDP Intrusion Prevention System with LLM-Assisted Forensics

An automated, closed-loop network intrusion prevention and forensic auditing platform combining **kernel-space eBPF/XDP packet filtering**, **machine learning traffic classification (XGBoost + Isolation Forest)**, and an **autonomous ReAct LLM Agent** for deep forensic investigation.

---

## 1. System Requirements

### Operating System & Kernel
* **OS:** Linux (Ubuntu 22.04 LTS / 24.04 LTS or WSL2 with kernel headers)
* **Kernel:** Linux >= 5.15 with eBPF and XDP driver support
* **Privileges:** `root` or `sudo` access required for loading eBPF/XDP bytecode and configuring network filter rules (`iptables` / `tc`)

### System Packages (Linux / WSL2)
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    libpcap-dev \
    iptables \
    iproute2 \
    python3-pip \
    python3-dev
```

### Python Environment
* **Python:** >= 3.10
* **Dependencies:** Installed via [`requirements.txt`](requirements.txt)

```bash
pip install -r requirements.txt
```

---

## 2. Python Dependencies ([`requirements.txt`](requirements.txt))

| Package | Minimum Version | Purpose |
| :--- | :--- | :--- |
| `numpy` | `>= 1.24.0` | Numerical arrays and feature tensor operations |
| `pandas` | `>= 2.0.0` | Dataframe manipulation and dataset processing |
| `scikit-learn` | `>= 1.3.0` | Feature preprocessing and Isolation Forest anomaly detection |
| `xgboost` | `>= 2.0.0` | Multi-class gradient boosted decision tree classifier |
| `joblib` | `>= 1.3.0` | Serialization of trained ML pipelines and encoders |
| `pyarrow` | `>= 14.0.0` | High-throughput Parquet dataset ingestion |
| `nfstream` | `>= 6.5.0` | High-speed real-time network flow extraction |
| `dpkt` | `>= 1.9.8` | Fast packet parsing and protocol analysis |
| `requests` | `>= 2.31.0` | HTTP communication with LLM inference endpoints |
| `pyyaml` | `>= 6.0` | Configuration loading (`configs/config.yaml`) |
| `cachetools` | `>= 5.3.0` | TTL memory caching for IP blocks and rate limiters |
| `python-dotenv` | `>= 1.0.0` | Environment variable management (`.env`) |
| `psutil` | `>= 5.9.0` | System metrics and resource telemetry |
| `rich` | `>= 13.0.0` | Formatted terminal output and CLI diagnostics |

---

## 3. Architecture Overview

```
                        [ Inbound Traffic ]
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   eBPF / XDP Filter   │ ◄─── Kernel Fast Path
                     └───────────┬───────────┘       (Drop Blacklisted IPs)
                                 │ Pass
                                 ▼
                     ┌───────────────────────┐
                     │   NFStream Extractor  │ ───► Real-time Flow Telemetry
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ ML Gatekeeper Pipeline│
                     │  • XGBoost Classifier │
                     │  • Isolation Forest   │
                     └───────────┬───────────┘
                                 │ Alert Triggered
                                 ▼
                     ┌───────────────────────┐
                     │   Automated Enforcer  │ ───► eBPF Map Blacklist + Alert Log
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ ReAct Forensic Agent  │ ◄─── Autonomous Tool Calling
                     │  • Telemetry Audit    │      (read_alert, search_subnet,
                     │  • RFC Mechanics RAG  │       lookup_mechanism, unban)
                     │  • Precision Verdict  │
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ Web Security Console  │ ───► Real-time Telemetry & Forensics
                     └───────────────────────┘
```

---

## 4. Quick Start

### 1. Configuration
Create `.env` from example:
```bash
cp .env.example .env
```
Configure your LLM endpoint (e.g. OpenAI, OpenRouter, or local Ollama/vLLM) in `.env` or `configs/config.yaml`.

### 2. Run the Web Dashboard
```bash
python3 ui/dashboard.py 8080
```
Open [http://localhost:8080](http://localhost:8080) to view the live dashboard.

### 3. Run the ML Gatekeeper Detector
```bash
sudo python3 detect/gatekeeper.py --interface eth0
```

### 4. Simulate Attack Traffic
```bash
bash scripts/simulate.sh
```
Select the attack vector (SYN Flood, UDP, NTP Amplification, DNS, MSSQL, Port Scan, etc.) to evaluate real-time mitigation and autonomous forensic auditing.
