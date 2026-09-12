import os
import sys
import json
import subprocess

ENFORCER_REF = None

def set_enforcer(enforcer):
    global ENFORCER_REF
    ENFORCER_REF = enforcer

def execute_unban(src_ip):
    global ENFORCER_REF
    if ENFORCER_REF is not None:
        try:
            ENFORCER_REF.unban_ip(src_ip)
            return json.dumps({"status": "ok", "action": "unban", "src_ip": src_ip})
        except Exception as err:
            return json.dumps({"status": "error", "action": "unban", "message": str(err)})

    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"], capture_output=True, timeout=3)
        return json.dumps({"status": "ok", "action": "unban", "src_ip": src_ip, "mode": "fallback_iptables"})
    except Exception as err:
        return json.dumps({"status": "error", "message": str(err)})

def execute_extend(src_ip, ttl_seconds=3600):
    global ENFORCER_REF
    try:
        ttl = int(ttl_seconds)
    except Exception:
        ttl = 3600

    if ENFORCER_REF is not None:
        try:
            from prevent.enforcer import Signature
            sig = Signature(src_ip=src_ip, reason="LLM_EXTENDED_BAN")
            count, final_ttl = ENFORCER_REF.block_ip(sig)
            return json.dumps({"status": "ok", "action": "extend_ban", "src_ip": src_ip, "ttl_secs": final_ttl, "offense_count": count})
        except Exception as err:
            return json.dumps({"status": "error", "action": "extend_ban", "message": str(err)})

    return json.dumps({"status": "ok", "action": "extend_ban", "src_ip": src_ip, "ttl_secs": ttl})

def execute_command(cmd_str):
    allowed_prefixes = ("iptables", "tc", "ip", "ss", "nft", "conntrack")
    cmd_clean = str(cmd_str).strip()

    if not any(cmd_clean.startswith(prefix) for prefix in allowed_prefixes):
        return json.dumps({"status": "rejected", "message": "Command not in allowed network security tools list."})

    try:
        res = subprocess.run(cmd_clean, shell=True, capture_output=True, text=True, timeout=5)
        return json.dumps({
            "status": "ok",
            "exit_code": res.returncode,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip()
        })
    except Exception as err:
        return json.dumps({"status": "error", "message": str(err)})
