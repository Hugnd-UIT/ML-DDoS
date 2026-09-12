# ML-DDoS -- System Architecture and Implementation Plan

## Overview

Two-tier DDoS defense system.

**Tier 1 -- Fast Path (Data Plane):**
XGBoost + Isolation Forest classify each completed NetFlow in user-space.
On a positive detection, Enforcer writes the attacker IP into the XDP eBPF
blacklist map, dropping subsequent packets in the kernel before they reach the
TCP/IP stack. Latency target: <5 ms per block decision.

**Tier 2 -- LLM Audit Agent (Control Plane):**
Every block event is enqueued asynchronously. A ReAct agent pulls events from
the queue, reasons over the flow telemetry, checks logs and enforcer state, and
decides whether to keep or revoke the block. This layer exists solely to reduce
false positives -- it never sits in the hot path.

**Rationale (from papers):**
- ShieldGPT shows that LLMs produce actionable, accurate mitigation commands
  when given structured flow context. Used here for the verify prompt.
- DrLLM Knowledge Prompt primes the LLM with global baseline statistics,
  improving per-flow reasoning without fine-tuning.
- Explainable NIDS paper confirms that ML-only systems miss the explainability
  required for human operators; the LLM audit fills that gap.

---

## Directory Layout (current)

```
ML-DDoS/
+-- configs/
|   +-- config.yaml            -- url, model, api_key, thresholds
+-- detect/
|   +-- gatekeeper.py          -- main loop: NFStreamer -> XGBoost -> IsoForest -> Enforcer
+-- prevent/
|   +-- xdp.c                  -- eBPF XDP kernel program (blacklist map)
|   +-- enforcer.py            -- Enforcer: load_xdp, block_ip, unblock_ip, check_blacklist
+-- agent/
|   +-- prompt.py              -- build_knowledge_prompt, build_explanation_prompt,
|   |                             build_mitigation_prompt, build_verify_prompt, get_fallback_commands
|   +-- engine.py              -- LLMEngine: query, explain, mitigate, review
|   +-- auditor.py             -- [NEW] ReAct audit loop: queue consumer, tool calls, unban logic
+-- models/
|   +-- XGBoost.pkl
|   +-- IsolationForest.pkl
|   +-- labels.pkl
+-- notebooks/
|   +-- 01_EDA.ipynb
|   +-- 02_Train_XGBoost.ipynb
|   +-- 03_Train_IsolationForest.ipynb
+-- data/
|   +-- raw/
|   |   +-- CIC-DoS2017/
|   |   +-- CIC-DDoS2019/
|   +-- processed/merged_clean.csv
|   +-- splits/train.csv, test.csv
+-- requirements.txt
```

---

## Data Flow

```
[Network Interface]
       |
       v  (NFStreamer, active_timeout=1s)
[gatekeeper.py  -- Tier 1]
       |
       |--(already blacklisted?)--> skip
       |
       |--(XGBoost predict)------> Benign? --(IsolationForest)--> normal? --> BENIGN (no action)
       |
       +--(attack detected)
              |
              v
         Enforcer.block_ip(Signature)
              |
              +--> XDP blacklist map write  (kernel drop, <1 us per packet)
              |
              +--> audit_queue.put(event)   (non-blocking, never delays Tier 1)
                        |
                        v  (background thread)
              [auditor.py  -- Tier 2 ReAct Agent]
                        |
                        +--(Thought) Is confidence high? Is the IP known bad?
                        +--(Action)  tool: check_log(src_ip)
                        +--(Obs)     log entries for that IP
                        +--(Action)  tool: check_enforcer_state(src_ip)
                        +--(Obs)     current TTL, offense count
                        +--(Thought) Flow metrics normal? Low offense history?
                        +--(Action)  tool: unblock_ip(src_ip)  [if false positive]
                        |            OR   tool: extend_ban(src_ip, ttl) [if confirmed]
                        |
                        +--> LLMEngine.review(flow_dict, attack_label) [explanation + commands]
```

---

## Phase 0 -- Setup

### 0.1 config.yaml fields

```yaml
# LLM endpoint -- OpenAI-compatible (Groq, LM Studio, etc.)
url: "https://api.groq.com/openai/v1/chat/completions"
model: "llama-3.3-70b-versatile"
api_key: ""           # or set env var API_KEY / LLM_API_KEY

# Detection thresholds
confidence_threshold: 0.70
syn_threshold: 200
udp_icmp_threshold: 1000
total_threshold: 3000
window_seconds: 5

# Audit agent
audit_queue_maxsize: 1000
audit_workers: 2
```

### 0.2 requirements.txt

```
nfstream
xgboost
scikit-learn
joblib
numpy
cachetools
pyyaml
requests
```

---

## Phase 1 -- Dataset and Preprocessing

### Datasets

| Dataset | Attacks | Size |
|---|---|---|
| CIC-DoS2017 | GoldenEye, Hulk, RUDY, Slowloris, Slowbody, Slowheaders, Slowread | ~400 MB |
| CIC-DDoS2019 | LDAP, MSSQL, NetBIOS, PortMap, SYN, UDP, UDP-Lag | ~800 MB |

Download CSVs only, upload to Google Drive for Colab access.

### Feature Set (26 features -- exact order used by gatekeeper.py extract_features)

| # | Feature | NFStreamer field |
|---|---|---|
| 1 | Flow Duration (us) | bidirectional_duration_ms * 1000 |
| 2 | Total Fwd Packets | src2dst_packets |
| 3 | Total Bwd Packets | dst2src_packets |
| 4 | Total Fwd Bytes | src2dst_bytes |
| 5 | Total Bwd Bytes | dst2src_bytes |
| 6 | Fwd Packet Length Max | src2dst_max_ps |
| 7 | Fwd Packet Length Min | src2dst_min_ps |
| 8 | Fwd Packet Length Mean | src2dst_mean_ps |
| 9 | Bwd Packet Length Max | dst2src_max_ps |
| 10 | Bwd Packet Length Mean | dst2src_mean_ps |
| 11 | Flow Bytes/s | derived |
| 12 | Flow Packets/s | derived |
| 13 | Flow IAT Mean (us) | bidirectional_mean_piat_ms * 1000 |
| 14 | Flow IAT Std (us) | bidirectional_stddev_piat_ms * 1000 |
| 15 | Fwd IAT Mean (us) | src2dst_mean_piat_ms * 1000 |
| 16 | Bwd IAT Mean (us) | dst2src_mean_piat_ms * 1000 |
| 17 | SYN Flag Count | bidirectional_syn_packets |
| 18 | RST Flag Count | bidirectional_rst_packets |
| 19 | PSH Flag Count | bidirectional_psh_packets |
| 20 | ACK Flag Count | bidirectional_ack_packets |
| 21 | FIN Flag Count | bidirectional_fin_packets |
| 22 | Init Win Fwd | src2dst_init_win |
| 23 | Init Win Bwd | dst2src_init_win |
| 24 | Active Mean (us) | bidirectional_mean_active_ms * 1000 |
| 25 | Idle Mean (us) | bidirectional_mean_idle_ms * 1000 |
| 26 | Destination Port | dst_port |

Training notebooks must produce arrays in this exact column order.
The feature extraction in gatekeeper.py:extract_features already implements this
mapping -- the models must match it.

### Preprocessing steps

1. Load CSVs, strip whitespace from column names.
2. Normalize label strings (Benign, SYN, UDP, Hulk, GoldenEye, ...).
3. Replace inf/-inf with NaN, drop NaN rows, drop duplicates.
4. Keep only the 25 features + Label column.
5. Stratified 80/20 train/test split.
6. Save train.csv, test.csv, labels.pkl (LabelEncoder), global_stats.pkl.

global_stats.pkl stores {feature: {min, max, mean, std}} over training set.
This dict is passed to build_knowledge_prompt to prime the LLM.

---

## Phase 2 -- Model Training (Colab T4)

### XGBoost (02_Train_XGBoost.ipynb)

```
objective:         multi:softprob
num_class:         15
n_estimators:      500
learning_rate:     0.05
max_depth:         8
subsample:         0.8
colsample_bytree:  0.8
early_stopping:    50 rounds on test set
```

Target: macro F1 > 0.98 across all 15 classes.
Save as models/XGBoost.pkl.

### Isolation Forest (03_Train_IsolationForest.ipynb)

Train on Benign-only rows from train.csv.

```
n_estimators:  200
contamination: 0.01
random_state:  42
```

Target: benign recall > 99%, attack anomaly recall > 60%.
Save as models/IsolationForest.pkl.

### Combined detection logic (gatekeeper.py)

```
flow with >= 10 packets arrives:
    pred = XGBoost.predict(features)
    if pred != Benign:
        -> ATTACK (known class)
    else:
        score = IsolationForest.predict(features)
        if score == -1:
            -> ATTACK (zero-day / Unknown)
        else:
            -> BENIGN (no action)
```

---

## Phase 3 -- Enforcer (prevent/enforcer.py) -- DONE

Enforcer responsibilities:
- load_xdp(interface) -- compile xdp.c via BCC and attach to interface
- block_ip(sig: Signature) -- write src_ip into eBPF blacklist map with TTL;
  increment offense counter; compute exponential TTL (base 5 min, doubles per
  repeat offense, capped at 24h)
- unblock_ip(src_ip) -- remove IP from blacklist map (called by auditor)
- check_blacklist(src_ip) -- O(1) lookup, called per flow in fast path
- check_whitelist(src_ip) -- skip blocking for trusted IPs
- _memory_manager() -- background thread, expires stale blacklist entries

Signature dataclass: src_ip, protocol, dst_port, fwd_len_mean, pps, reason,
features (list of 25 floats).

---

## Phase 4 -- LLM Agent (agent/)

### 4.1 prompt.py -- DONE

- build_knowledge_prompt(global_stats)
  DrLLM-style: injects baseline traffic statistics as system context.

- build_explanation_prompt(flow_dict, attack_label, global_stats)
  ShieldGPT-style: provides flow telemetry + attack mechanism description,
  requests 3-5 bullet technical analysis.

- build_mitigation_prompt(flow_dict, attack_label, device)
  Tiered defense: Tier 1 rate limit, Tier 2 specific filter, Tier 3 drop.
  Commands must be in a bash code block.

- build_verify_prompt(flow_dict, attack_label, confidence, log_entries)
  Used by the audit agent. Presents evidence and asks: KEEP_BLOCK or UNBLOCK?

- get_fallback_commands(attack_label, device, src_ip)
  Static templates for when LLM API is unavailable.

### 4.2 engine.py -- DONE

LLMEngine:
- Reads url, model, api_key from configs/config.yaml.
- query(prompt, system_prompt) -- POST to any OpenAI-compatible endpoint,
  result cached by prompt hash to avoid duplicate API calls.
- explain(flow_dict, attack_label, global_stats) -- knowledge + explanation prompts.
- mitigate(flow_dict, attack_label, device) -- mitigation prompt, parses bash
  blocks, falls back to get_fallback_commands.
- review(flow_dict, attack_label, confidence, device) -- runs explain + mitigate,
  returns dict: {explanation, strategy, commands, latency_ms}.

### 4.3 auditor.py -- TO BUILD

The ReAct audit agent. Runs in background thread(s) consuming from a queue
that gatekeeper.py writes to after each block_ip call.

**ReAct loop:**

```python
def worker_loop(audit_queue, enforcer, llm_engine):
    while True:
        event = audit_queue.get()
        run_react(event, enforcer, llm_engine)

def run_react(event, enforcer, llm_engine, max_steps=5):
    context = [build_initial_context(event)]
    for _ in range(max_steps):
        prompt = build_react_prompt(context)
        response = llm_engine.query(prompt)
        action = parse_action(response)   # regex: Action: tool(args)
        if action is None:
            break                         # LLM issued Final Answer
        obs = execute_tool(action, event, enforcer)
        context.append(f"Observation: {obs}")
    decision = parse_decision(response)
    if decision == "UNBLOCK":
        enforcer.unblock_ip(event["src_ip"])
        print(f"  [AUDIT] UNBLOCK {event['src_ip']} -- false positive")
    else:
        print(f"  [AUDIT] CONFIRMED {event['src_ip']} -- {event['attack_label']}")
```

**Tool registry:**

| Tool | Signature | Returns |
|---|---|---|
| check_log | check_log(src_ip) | Last 20 log lines for this IP |
| check_enforcer_state | check_enforcer_state(src_ip) | TTL remaining, offense count, block reason |
| get_flow_stats | get_flow_stats(src_ip) | pps, byte_rate, protocol from the block event |
| unblock_ip | unblock_ip(src_ip) | "done" |
| extend_ban | extend_ban(src_ip, ttl_seconds) | "done" |

**ReAct system prompt:**

```
You are a network security auditor reviewing an automated block decision.
Determine whether the block is a true positive or a false positive.

Tools:
  check_log(src_ip)                  -- recent log lines for this IP
  check_enforcer_state(src_ip)       -- TTL, offense count, block reason
  get_flow_stats(src_ip)             -- pps, byte_rate, protocol
  unblock_ip(src_ip)                 -- removes block
  extend_ban(src_ip, ttl_seconds)    -- increases ban duration

Block event:
  src_ip:        {src_ip}
  attack_label:  {attack_label}
  confidence:    {confidence}
  reason:        {reason}
  pps:           {pps}
  byte_rate:     {byte_rate}

Respond using this format:
  Thought: <reasoning>
  Action: <tool_name>(<args>)

When done:
  Final Answer: KEEP_BLOCK
  Reason: <one sentence>

  OR

  Final Answer: UNBLOCK
  Reason: <one sentence>

Thought:
```

**Integration point in gatekeeper.py** (to be added after block_ip call):

```python
try:
    audit_queue.put_nowait({
        "src_ip": flow.src_ip,
        "attack_label": class_name,
        "confidence": float(proba.max()),
        "reason": reason,
        "flow_dict": {
            "src_ip": flow.src_ip,
            "protocol": proto_name(flow.protocol),
            "dst_port": int(getattr(flow, "dst_port", 0)),
            "Flow Packets/s": flow_packets_s,
            "Flow Bytes/s": flow_bytes_s,
            "SYN Flag Count": syn_count,
        },
        "features": features[0].tolist()
    })
except queue.Full:
    pass   # drop oldest implicitly -- queue is bounded
```

Queue is bounded by audit_queue_maxsize from config. If full during a
sustained volumetric attack, new events are dropped (not queued), so Tier 1
performance is never impacted.

---

## Phase 5 -- Integration and Testing

### 5.1 Smoke test

```
sudo python detect/gatekeeper.py -i lo
```

Expected:
- XDP attaches to loopback
- NFStreamer starts listening
- Audit thread prints ready message
- Simulate attack: hping3 -S --flood -p 80 127.0.0.1
- See [BLOCK] line, then [AUDIT] decision within ~15 seconds

### 5.2 False positive test

1. Manually call enforcer.block_ip with a known-benign IP.
2. Send benign traffic from that IP.
3. Confirm audit agent calls check_log and check_enforcer_state.
4. Confirm agent outputs Final Answer: UNBLOCK.
5. Confirm enforcer.unblock_ip is called.

### 5.3 Metrics targets

| Metric | Target |
|---|---|
| XGBoost Macro F1 | > 0.98 |
| Per-class F1 | > 0.95 |
| ML False Positive Rate | < 1% |
| Zero-day recall (IsoForest) | > 60% |
| Block latency Tier 1 | < 5 ms |
| Audit latency Tier 2 | < 30 s (async, not in hot path) |
| Post-audit false positive reduction | > 50% of ML FPs resolved |

### 5.4 LLM output quality checks (manual, 10 flows per class)

- Explanation cites specific telemetry values from the flow dict
- Explanation is 3-5 bullet points
- Mitigation commands are syntactically valid for the target device
- Verify prompt returns KEEP_BLOCK for true attacks
- Verify prompt returns UNBLOCK for planted false positives

---

## Phase 6 -- Report Outline

**Chapter 1: Introduction**
- DDoS frequency and impact growth (Imperva 2024)
- Limitations: static rules have no context; ML-only has no explainability
- Contribution: eBPF fast-path + async ReAct LLM audit; $0 cost; no GPU

**Chapter 2: Related Work**
- ShieldGPT -- LLM-generated mitigation commands from structured flow context
- DrLLM -- Knowledge Prompt for zero-shot DDoS classification
- Explainable NIDS -- XAI for operator trust in network intrusion systems
- Gap: no existing system combines eBPF data-plane enforcement + ReAct audit

**Chapter 3: System Design**
- Architecture diagram: two-tier, fast path vs. audit path
- Fast path: NFStreamer -> XGBoost -> IsoForest -> XDP eBPF blacklist
- Audit path: queue -> ReAct agent -> tool calls -> unblock decision
- Prompt engineering: Knowledge Prompt, Explanation Prompt, Verify Prompt
- ReAct design: why async, tool selection rationale, max_steps bound

**Chapter 4: Experiments**
- Datasets: CIC-DoS2017, CIC-DDoS2019, class distribution table
- XGBoost: classification report, confusion matrix, feature importance
- IsoForest: benign recall, anomaly recall on held-out samples
- Audit agent: false positive reduction rate, example ReAct traces
- Latency: Tier 1 block latency distribution, Tier 2 audit latency distribution

**Chapter 5: Conclusion**
- Results summary
- Future: RAG with CVE database for zero-day context, small fine-tuned LLM
  for on-premise inference, federated learning across network nodes

---

## Implementation Checklist

### Data and Training
- [ ] Download CIC-DoS2017 and CIC-DDoS2019 CSVs
- [ ] 01_EDA.ipynb -- verify feature alignment with extract_features
- [ ] 02_Train_XGBoost.ipynb -- macro F1 > 0.98, save XGBoost.pkl
- [ ] 03_Train_IsolationForest.ipynb -- save IsolationForest.pkl
- [ ] Save labels.pkl and global_stats.pkl

### Tier 1 -- Fast Path (DONE)
- [x] prevent/xdp.c -- eBPF XDP blacklist map
- [x] prevent/enforcer.py -- Enforcer, Signature, block_ip, unblock_ip, TTL
- [x] detect/gatekeeper.py -- NFStreamer loop, extract_features, block logic

### Tier 2 -- LLM Audit (PARTIAL)
- [x] agent/prompt.py -- all prompt builders, fallback commands
- [x] agent/engine.py -- LLMEngine, configurable endpoint, caching
- [ ] agent/auditor.py -- ReAct loop, tool registry, queue consumer
- [ ] gatekeeper.py -- add audit_queue.put_nowait after block_ip
- [ ] auditor.py -- receive enforcer reference for unblock_ip calls

### Config
- [x] configs/config.yaml -- url, model, api_key
- [ ] Add: audit_queue_maxsize, audit_workers, confidence_threshold

### Testing
- [ ] Unit: extract_features shape matches model input (26,)
- [ ] Unit: engine.py fallback triggers when API returns empty string
- [ ] Unit: auditor parse_decision("Final Answer: UNBLOCK") returns UNBLOCK
- [ ] Integration: block -> queue -> audit -> unblock round trip
- [ ] Stress: 10,000 flows, block latency < 5 ms, no queue overflow

### Documentation
- [ ] README.md -- setup, run, config reference
- [ ] Chapters 1-5 report
- [ ] Architecture diagram (two-tier data flow)
