SYSTEM_PROMPT = """You are a network security analyst inside an eBPF/XDP Intrusion Prevention System.

ROLE

Audit each automated IP block.
Decide True Positive (real attack) or False Positive (benign), using tools as evidence before answering.


TOOLS

- read_alert(src_ip): recorded alert entries
- read_flow(src_ip): live flow stats (protocol, port, pps, reason)
- search_history(src_ip): repeat-offense count and timeline
- search_subnet(ip_or_cidr): check /24 peers for botnet signal
- lookup_mechanism(attack_name) / lookup_description(attack_name): RFC attack mechanics
- execute_unban(src_ip): lift block for confirmed FP
- execute_extend(src_ip, ttl_seconds): extend block for confirmed persistent attacker


ALLOWED LABELS (use only these, never invent new names)

DDoS:  SYN, UDP, UDP-Lag, ICMP, DNS, NTP, SNMP, SSDP, LDAP, MSSQL, NetBIOS, Portmap, TFTP, HTTP
Other: Brute Force, Web Attack, Botnet, Port Scan
Benign: Benign


METHOD

1. Inspect flow telemetry (protocol, port, PPS, packet size, byte volume, duration, TCP flags).
2. Cross-check against RFC mechanics via lookup_mechanism/lookup_description.
3. Verify with read_alert, search_history, search_subnet for repeat offenses or botnet clusters.


VERDICTS

KEEP_BLOCK — malicious pattern confirmed (flood, amplification, anomalous packet shape, botnet cluster, repeat offense).

  - ML label matches telemetry
    -> Classification: TRUE_POSITIVE
    -> Corrected_Attack: NONE

  - ML label wrong or imprecise
    -> Classification: MISCLASSIFIED_ATTACK
    -> Corrected_Attack: <one allowed label>

UNBLOCK — clean bidirectional flow, completed handshakes, normal query rate, clean history, no botnet peers.

  - Classification: FALSE_POSITIVE
  - Corrected_Attack: Benign


RULES

1. Call at least 2 tools before Final Answer.

2. Every non-final reply must be exactly:

   Thought: <one reasoning step>
   Action: tool_name(argument)

3. One action per reply. Never fabricate observations — wait for the real result.

4. Final reply format:

   Final Answer: KEEP_BLOCK | UNBLOCK
   Classification: TRUE_POSITIVE | MISCLASSIFIED_ATTACK | FALSE_POSITIVE
   Corrected_Attack: NONE | Benign | <one allowed label>
   Reason: <one sentence>
"""


def _tc_block(alert, packets=None):
    ip = alert.get("src_ip", "?")
    proto = alert.get("protocol", "?")
    port = alert.get("dst_port", 0)
    pps = float(alert.get("pps", 0))
    reason = alert.get("reason", "?")
    count = alert.get("offense_count", 1)
    avg_sz = float(alert.get("avg_packet_size", 128))
    dur_ms = float(alert.get("flow_duration_ms", 0))
    dur_s = max(dur_ms / 1000.0, 0.001)
    flow_bytes_s = float(alert.get("flow_bytes_s", 0))

    fwd_pkts = alert.get("fwd_pkts", None)
    bwd_pkts = alert.get("bwd_pkts", None)
    syn_count = alert.get("syn_count", None)
    ack_count = alert.get("ack_count", None)
    rst_count = alert.get("rst_count", None)

    if fwd_pkts is not None:
        total_pkts = int(fwd_pkts) + int(bwd_pkts or 0)
    else:
        total_pkts = int(pps * dur_s) if pps > 0 else int(count)

    total_bytes = (
        int(total_pkts * avg_sz)
        if flow_bytes_s == 0
        else int(flow_bytes_s * dur_s)
    )

    interval = round(1.0 / pps, 6) if pps > 0 else 0.0

    lines = [
        "[ Traffic Characteristics ]",
        f"Source IP: {ip}",
        f"Protocol: {proto}  Destination port: {port}",
        f"Total packets: {total_pkts}  Total bytes: {total_bytes}",
        f"Fwd packets: {fwd_pkts if fwd_pkts is not None else '?'}  Bwd packets: {bwd_pkts if bwd_pkts is not None else '?'}",
        f"Average packet size: {avg_sz:.1f} bytes",
        f"Average packet interval: {interval} s",
        f"Flow duration: {dur_ms:.1f} ms",
        f"Packet rate: {pps:.1f} PPS  Flow bytes/s: {flow_bytes_s:.1f}",
        f"Offense count: {count}",
        f"Detected label: {reason}",
    ]

    if syn_count is not None:
        lines.append(f"TCP flags — SYN: {syn_count}  ACK: {ack_count}  RST: {rst_count}")

    lines.append("[ First 5 Packets ]")

    if packets and isinstance(packets, list):
        for i, pkt in enumerate(packets[:5]):
            lines.append(f"  pkt{i+1}: {pkt}")
    else:
        flag = "SYN" if proto.upper() == "TCP" else "DATA"
        for i in range(1, 6):
            lines.append(f"  pkt{i}: src={ip} dst_port={port} proto={proto} len={int(avg_sz)} flags={flag}")

    return "\n".join(lines)


def build_react_prompt(alert):
    tc = _tc_block(alert)
    ip = alert.get("src_ip", "?")

    return (
        f"{tc}\n\n"
        f"Task: determine whether the automated block of {ip} is a TP or FP.\n"
        f"Required: call read_alert and search_history at minimum before issuing Final Answer.\n"
        f"Use additional tools if findings are ambiguous. Then issue Final Answer."
    )


def build_explain_prompt(alert, description="", packets=None):
    tc = _tc_block(alert, packets)
    attack = alert.get("reason", "DDoS")
    desc = description or "High-rate anomalous traffic exhausting server resources."

    return (
        f"{tc}\n\n"
        f"[ Attack Description ]\n{desc}\n\n"
        f"You are an experienced cybersecurity expert. "
        f"You've gathered the traffic statistical characteristics above and the first 5 packets' original information of the {{{attack}}} attack.\n"
        f"Analyze the traffic and explain step by step why it is a {{{attack}}} attack.\n"
        f"Provide a professional yet easy-to-understand explanation."
    )


def build_mitigation_prompt(alert, description="", device="iptables", packets=None):
    tc = _tc_block(alert, packets)
    attack = alert.get("reason", "DDoS")
    desc = description or "High-rate anomalous traffic exhausting server resources."

    return (
        f"{tc}\n\n"
        f"[ Attack Description ]\n{desc}\n\n"
        f"The above are traffic statistical characteristics and the first 5 packets' original data of the {{{attack}}} attack.\n"
        f"Suppose you are at {{{device}}}. Propose defense strategies to mitigate this {{{attack}}} attack.\n"
        f"Be as specific as possible. Detailed configuration commands are required."
    )