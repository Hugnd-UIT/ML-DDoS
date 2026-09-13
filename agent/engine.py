import os
import re
import sys
import time
import json
import yaml
import requests

from agent.prompt import (
    SYSTEM_PROMPT,
    build_react_prompt,
    build_explain_prompt,
    build_mitigation_prompt
)

from tools.read import read_alert, read_flow, read_metrics
from tools.search import search_history, search_subnet
from tools.rag import lookup_mechanism, lookup_mitigation, lookup_description
from tools.execute import execute_unban, execute_extend, execute_command

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    '..',
    'configs',
    'config.yaml'
)

ENV_PATH = os.path.join(
    os.path.dirname(__file__),
    '..',
    '.env'
)

def normalize_attack_label(
    val,
    fallback="SYN"
):
    if not val:
        return fallback
    clean = str(val).replace('*', '').replace('`', '').strip()
    paren_match = re.search(
        r'\(([^)]+)\)',
        clean
    )
    if paren_match:
        inner = paren_match.group(1).upper()
        if "UDPLAG" in inner or "LAG" in inner:
            return "UDP-Lag"
        if "NTP" in inner:
            return "NTP"
        if "DNS" in inner:
            return "DNS"
        if "SNMP" in inner:
            return "SNMP"
        if "SSDP" in inner:
            return "SSDP"
        if "LDAP" in inner:
            return "LDAP"
        if "MSSQL" in inner or "SQL" in inner:
            return "MSSQL"
        if "NETBIOS" in inner or "BIOS" in inner:
            return "NetBIOS"
        if "PORTMAP" in inner:
            return "Portmap"
        if "TFTP" in inner:
            return "TFTP"
        if "HTTP" in inner:
            return "HTTP"
        if "ICMP" in inner or "PING" in inner:
            return "ICMP"
        if "SCAN" in inner:
            return "Port Scan"
        if "BRUTE" in inner:
            return "Brute Force"
        if "WEB" in inner:
            return "Web Attack"
        if "BOT" in inner:
            return "Botnet"
        if "SYN" in inner:
            return "SYN"
        if "UDP" in inner:
            return "UDP"
    clean_no_prefix = re.sub(
        r'^(?:DDOS|ATTACK|TRAFFIC)[\s:\-_/]+',
        '',
        clean,
        flags=re.IGNORECASE
    ).strip()
    up = clean_no_prefix.upper().replace('-', '').replace('_', '').replace(' ', '')
    if "UDPLAG" in up or "LAG" in up:
        return "UDP-Lag"
    if "NTP" in up:
        return "NTP"
    if "DNS" in up:
        return "DNS"
    if "SNMP" in up:
        return "SNMP"
    if "SSDP" in up:
        return "SSDP"
    if "LDAP" in up:
        return "LDAP"
    if "MSSQL" in up or "SQL" in up:
        return "MSSQL"
    if "NETBIOS" in up or "BIOS" in up:
        return "NetBIOS"
    if "PORTMAP" in up:
        return "Portmap"
    if "TFTP" in up:
        return "TFTP"
    if "HTTP" in up:
        return "HTTP"
    if "ICMP" in up or "PING" in up:
        return "ICMP"
    if "SCAN" in up:
        return "Port Scan"
    if "BRUTE" in up:
        return "Brute Force"
    if "WEB" in up:
        return "Web Attack"
    if "BOT" in up:
        return "Botnet"
    if "SYN" in up:
        return "SYN"
    if "UDP" in up:
        return "UDP"
    if "DDOS" in up:
        return "DDoS"
    if "BENIGN" in up or "NORMAL" in up:
        return "Benign"
    return fallback


class Engine:

    def __init__(self, config_file=None):
        self.cfg_file = config_file or CONFIG_PATH
        self.url = ""
        self.model = ""
        self.api_key = ""
        self.timeout = 60
        self.tools = {
            "read_alert": read_alert,
            "read_flow": read_flow,
            "read_metrics": read_metrics,
            "search_history": search_history,
            "search_subnet": search_subnet,
            "lookup_mechanism": lookup_mechanism,
            "lookup_description": lookup_description,
            "lookup_mitigation": lookup_mitigation,
            "execute_unban": execute_unban,
            "execute_extend": execute_extend,
            "execute_command": execute_command
        }
        self.load_config()

    def load_config(self):
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    text = line.strip()
                    if text and "=" in text and not text.startswith("#"):
                        key, val = text.split("=", 1)
                        os.environ[key.strip()] = val.strip().strip('"').strip("'")

        if os.path.exists(self.cfg_file):
            try:
                with open(self.cfg_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                llm_cfg = data.get("llm", {})
                self.url = llm_cfg.get("url") or data.get("url", "")
                self.model = llm_cfg.get("model") or data.get("model", "")
                self.api_key = llm_cfg.get("api_key") or data.get("api_key", "")
            except Exception:
                pass

        if not self.url:
            self.url = os.environ.get("LLM_URL")
        if not self.model:
            self.model = os.environ.get("LLM_MODEL")
        if not self.api_key:
            self.api_key = os.environ.get("LLM_API_KEY")

        if not self.api_key:
            raise RuntimeError("LLM_API_KEY is not configured in environment or configs/config.yaml")

        if not self.url:
            raise RuntimeError("LLM_URL endpoint is not specified.")

        if not self.model:
            raise RuntimeError("LLM_MODEL is not configured.")

        if self.url and not self.url.endswith("/chat/completions"):
            self.url = self.url.rstrip("/") + "/chat/completions"

    def query(self, prompt, system=SYSTEM_PROMPT, messages=None):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        if messages is None:
            msgs = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        else:
            msgs = messages

        payload = {
            "model": self.model,
            "messages": msgs,
            "temperature": 0.1
        }

        resp = None
        for attempt in range(5):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=self.timeout)
                if resp.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(2)

        if not resp or resp.status_code != 200:
            err_msg = resp.text if resp else "No response"
            code = resp.status_code if resp else 0
            raise RuntimeError(f"LLM API request failed [{code}]: {err_msg}")

        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("LLM API returned empty choices list.")

        return choices[0]["message"]["content"].strip()

    def dispatch(self, action_name, action_input):
        func = self.tools.get(action_name)
        if not func:
            return f"Error: Tool '{action_name}' is not recognized. Valid tools: {list(self.tools.keys())}"

        clean_arg = action_input.strip().strip("'").strip('"')
        try:
            if "," in clean_arg:
                parts = []
                for p in clean_arg.split(","):
                    val = p.strip().strip("'").strip('"')
                    if "=" in val:
                        val = val.split("=", 1)[1].strip().strip("'").strip('"')
                    parts.append(val)
                return func(*parts)
            elif clean_arg:
                val = clean_arg
                if "=" in val:
                    val = val.split("=", 1)[1].strip().strip("'").strip('"')
                return func(val)
            else:
                return func()
        except Exception as err:
            return f"Error executing tool '{action_name}': {err}"

    def react(self, alert, max_steps=5):
        decision = "KEEP_BLOCK"
        reason = ""
        history = []

        user_prompt = build_react_prompt(alert)
        msgs = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]

        for step in range(1, max_steps + 1):
            response = self.query("", messages=msgs)

            match_action = re.search(r"Action:\s*[`'\"]?([a-zA-Z0-9_]+)[`'\"]?\s*(?:\((.*?)\)|:\s*([^\n]+))", response)
            tool_calls_count = len([h for h in history if h.get("role") == "user" and h.get("content", "").startswith("Observation:")])

            if match_action:
                action_name = match_action.group(1).strip()
                action_input = (match_action.group(2) or match_action.group(3) or "").strip()
                obs = self.dispatch(action_name, action_input)

                history.append({"role": "assistant", "content": response})
                history.append({"role": "user", "content": f"Observation: {obs}"})
                msgs.append({"role": "assistant", "content": response})
                msgs.append({"role": "user", "content": f"Observation: {obs}"})
                continue

            if "Final Answer:" in response:
                if tool_calls_count < 2 and step < max_steps:
                    msgs.append({"role": "assistant", "content": response})
                    msgs.append({"role": "user", "content": "Observation: Rule violation - you must call at least 2 tools (e.g. read_alert, search_history) before issuing Final Answer. Please call a tool now."})
                    continue

                match_ans = re.search(
                    r"Final Answer:\s*[*_]*([A-Z_]+)",
                    response
                )
                if match_ans:
                    decision = match_ans.group(1).strip()

                classification = "TRUE_POSITIVE" if decision == "KEEP_BLOCK" else "FALSE_POSITIVE"
                match_class = re.search(
                    r"Classification:\s*[*_]*([A-Z_]+)",
                    response
                )
                if match_class:
                    classification = match_class.group(1).strip()

                corrected_attack = "Benign" if decision == "UNBLOCK" else alert.get("reason", "SYN")
                match_attack = re.search(
                    r"Corrected_Attack:\s*[*_]*([^\n*]+)",
                    response
                )
                if match_attack:
                    val = match_attack.group(1).strip().replace('*', '').strip()
                    if val.upper() != "NONE":
                        corrected_attack = val

                if decision == "UNBLOCK":
                    corrected_attack = "Benign"
                else:
                    corrected_attack = normalize_attack_label(
                        corrected_attack,
                        fallback=alert.get("reason", "SYN")
                    )

                match_reason = re.search(
                    r"Reason:\s*([\s\S]+?)(?=\n\s*(?:Final Answer|Classification|Corrected_Attack|Action|Thought)|$)",
                    response
                )
                if match_reason:
                    reason = match_reason.group(1).strip()
                else:
                    parts = response.split("Final Answer:")
                    reason = parts[0].strip() if len(parts) > 1 else response.strip()

                if "misclass" in reason.lower() and classification == "TRUE_POSITIVE":
                    classification = "MISCLASSIFIED_ATTACK"

                if decision == "UNBLOCK":
                    self.dispatch(
                        "execute_unban",
                        alert.get("src_ip", "")
                    )

                history.append(
                    {
                        "role": "assistant",
                        "content": response
                    }
                )

                return {
                    "decision": decision,
                    "classification": classification,
                    "corrected_attack": corrected_attack,
                    "reason": reason,
                    "steps": step,
                    "history": history
                }

            msgs.append({"role": "assistant", "content": response})
            msgs.append({"role": "user", "content": "Observation: Please proceed by specifying Thought: and Action: tool_name(argument), or Final Answer: and Reason:."})

        msgs.append({"role": "user", "content": "Evidence gathering complete. Provide your Final Answer now (KEEP_BLOCK or UNBLOCK), Classification, Corrected_Attack, with Reason:."})
        response = self.query("", messages=msgs)

        match_ans = re.search(
            r"Final Answer:\s*[*_]*([A-Z_]+)",
            response
        )
        if match_ans:
            decision = match_ans.group(1).strip()

        classification = "TRUE_POSITIVE" if decision == "KEEP_BLOCK" else "FALSE_POSITIVE"
        match_class = re.search(
            r"Classification:\s*[*_]*([A-Z_]+)",
            response
        )
        if match_class:
            classification = match_class.group(1).strip()

        corrected_attack = "Benign" if decision == "UNBLOCK" else alert.get("reason", "SYN")
        match_attack = re.search(
            r"Corrected_Attack:\s*[*_]*([^\n*]+)",
            response
        )
        if match_attack:
            val = match_attack.group(1).strip().replace('*', '').strip()
            if val.upper() != "NONE":
                corrected_attack = val

        if decision == "UNBLOCK":
            corrected_attack = "Benign"
        else:
            corrected_attack = normalize_attack_label(
                corrected_attack,
                fallback=alert.get("reason", "SYN")
            )

        match_reason = re.search(
            r"Reason:\s*([\s\S]+?)(?=\n\s*(?:Final Answer|Classification|Corrected_Attack|Action|Thought)|$)",
            response
        )
        if match_reason:
            reason = match_reason.group(1).strip()
        else:
            parts = response.split("Final Answer:")
            reason = parts[0].strip() if len(parts) > 1 else response.strip()

        if "misclass" in reason.lower() and classification == "TRUE_POSITIVE":
            classification = "MISCLASSIFIED_ATTACK"

        if decision == "UNBLOCK":
            self.dispatch(
                "execute_unban",
                alert.get("src_ip", "")
            )

        history.append(
            {
                "role": "assistant",
                "content": response
            }
        )

        return {
            "decision": decision,
            "classification": classification,
            "corrected_attack": corrected_attack,
            "reason": reason,
            "steps": max_steps,
            "history": history
        }

    def explain(self, alert, packets=None):
        attack = alert.get("reason", "DDoS")
        desc = lookup_description(attack)
        prompt = build_explain_prompt(alert, description=desc, packets=packets)
        return self.query(prompt)

    def mitigate(self, alert, device="iptables", packets=None):
        attack = alert.get("reason", "DDoS")
        desc = lookup_description(attack)
        prompt = build_mitigation_prompt(alert, description=desc, device=device, packets=packets)
        return self.query(prompt)
