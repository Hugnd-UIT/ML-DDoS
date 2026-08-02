import os
import time
import threading
from collections import defaultdict

import requests


# Load Telegram configuration from environment variables
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
TG_MAX_RETRY = int(os.environ.get("TG_MAX_RETRY", "3"))
TG_TIMEOUT_S = int(os.environ.get("TG_TIMEOUT_S", "8"))

# Set maximum alerts allowed per minute
MAX_ALERTS_PER_MINUTE = 2

# Set Telegram API endpoint
TG_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"


# Store alert history for rate limiting
alert_history = defaultdict(list)

# Create a lock for thread-safe access
alert_lock = threading.Lock()


# Check whether an IP has exceeded the alert limit
def is_rate_limited(ip_str):
    # Get the current timestamp
    now = time.time()

    # Lock alert history during the check
    with alert_lock:
        # Get alert history for the current IP
        history = alert_history[ip_str]

        # Keep only alerts from the last 60 seconds
        history[:] = [
            timestamp
            for timestamp in history
            if now - timestamp < 60.0
        ]

        # Stop if the IP has reached the alert limit
        if len(history) >= MAX_ALERTS_PER_MINUTE:
            return True

        # Store the current alert timestamp
        history.append(now)

        return False


# Format an alert message when XDP blocks an IP
def format_block_message(sig):
    # Get the current UTC timestamp
    ts = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC",
        time.gmtime()
    )

    # Build the Telegram alert message
    return (
        f"<b>DDoS ATTACK ALERT</b>\n\n"
        f"Time: <code>{ts}</code>\n"
        f"Attacker IP: <code>{sig.src_ip}</code>\n"
        f"Signature: <code>{sig.signature_key}</code>\n\n"
        f"<b>Details:</b>\n"
        f"  Protocol: <code>{sig.protocol}</code>\n"
        f"  Port: <code>{sig.dst_port}</code>\n"
        f"  PPS: <code>{sig.pps:.0f}</code>\n"
        f"  Mean Length: <code>{sig.fwd_len_mean:.1f}</code>\n"
        f"  Reason: <code>{sig.reason}</code>\n\n"
        f"Action: <b>XDP DROP</b> | TTL: 300s"
    )


# Format a periodic attack summary message
def format_summary_message(
    total_blocked,
    top_ips,
    window_label="5 minutes"
):
    # Get the current UTC timestamp
    ts = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC",
        time.gmtime()
    )

    # Create the summary message
    lines = [
        f"<b>ATTACK SUMMARY - {window_label}</b>",
        f"Time: <code>{ts}</code>",
        f"Total Blocked IPs: <b>{total_blocked}</b>",
        "",
        "<b>Top Attacking IPs:</b>"
    ]

    # Add the top five attacking IPs
    for rank, (ip, count) in enumerate(
        top_ips[:5],
        1
    ):
        lines.append(
            f"  {rank}. <code>{ip}</code> - {count} times"
        )

    # Combine all message lines
    return "\n".join(lines)


# Send a message through the Telegram API
def send_telegram(text, parse_mode="HTML"):
    # Check whether Telegram credentials are configured
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print(
            "[-] TG_BOT_TOKEN or TG_CHAT_ID missing. Alert skipped."
        )
        return False

    # Build the Telegram API URL
    url = TG_API_BASE.format(
        token=TG_BOT_TOKEN
    )

    # Build the Telegram request payload
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": text,
        "parse_mode": parse_mode
    }

    # Try sending the message multiple times
    for attempt in range(
        1,
        TG_MAX_RETRY + 1
    ):
        try:
            # Send the Telegram request
            resp = requests.post(
                url,
                json=payload,
                timeout=TG_TIMEOUT_S
            )

            # Check whether the request was successful
            if resp.status_code == 200:
                print(
                    f"[+] Telegram alert sent - attempt {attempt}"
                )
                return True

            # Show the HTTP error status
            print(
                f"[-] Telegram HTTP {resp.status_code} "
                f"- attempt {attempt}"
            )

        except Exception as e:
            # Show the request error
            print(
                f"[-] Telegram error - attempt {attempt}: {e}"
            )

        # Wait before the next retry
        if attempt < TG_MAX_RETRY:
            time.sleep(
                2 ** attempt
            )

    return False


# Send an alert for a newly blocked IP
def send_block_alert(sig):
    # Check the alert rate limit
    if is_rate_limited(sig.src_ip):
        print(
            f"[!] Rate-limited Telegram alert for {sig.src_ip}"
        )
        return False

    # Format and send the block alert
    return send_telegram(
        format_block_message(sig)
    )


# Send a periodic attack summary
def send_digest_alert(
    total_blocked,
    top_ips,
    window_label="5 minutes"
):
    # Format and send the summary alert
    return send_telegram(
        format_summary_message(
            total_blocked,
            top_ips,
            window_label
        )
    )