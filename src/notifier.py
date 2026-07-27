import os
import time
import threading
from collections import defaultdict
import requests

# Cấu hình Telegram từ biến môi trường
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
TG_MAX_RETRY = int(os.environ.get("TG_MAX_RETRY", "3"))
TG_TIMEOUT_S = int(os.environ.get("TG_TIMEOUT_S", "8"))
MAX_ALERTS_PER_MINUTE = 2

TG_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"

# Lưu lịch sử cảnh báo để giới hạn tốc độ - rate limit
alert_history = defaultdict(list)
alert_lock = threading.Lock()

def is_rate_limited(ip_str):
    # Kiểm tra xem IP này có đang gửi quá nhiều cảnh báo không
    now = time.time()
    with alert_lock:
        history = alert_history[ip_str]
        # Giữ lại các cảnh báo trong vòng 60 giây qua
        history[:] = [t for t in history if now - t < 60.0]
        if len(history) >= MAX_ALERTS_PER_MINUTE:
            return True
        history.append(now)
        return False

def format_block_message(sig):
    # Định dạng tin nhắn cảnh báo khi XDP chặn IP
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return (
        f"<b>CANH BAO TAN CONG DDOS</b>\n\n"
        f"Thoi gian: <code>{ts}</code>\n"
        f"IP tan cong: <code>{sig.src_ip}</code>\n"
        f"Chu ky: <code>{sig.signature_key}</code>\n\n"
        f"<b>Chi tiet:</b>\n"
        f"  Protocol: <code>{sig.protocol}</code>\n"
        f"  Port: <code>{sig.dst_port}</code>\n"
        f"  PPS: <code>{sig.pps:.0f}</code>\n"
        f"  Len Mean: <code>{sig.fwd_len_mean:.1f}</code>\n"
        f"  Ly do: <code>{sig.reason}</code>\n\n"
        f"Hanh dong: <b>XDP DROP</b> | TTL: 300s"
    )

def format_summary_message(total_blocked, top_ips, window_label="5 phut"):
    # Định dạng tin nhắn báo cáo định kỳ
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    lines = [
        f"<b>TOM TAT TAN CONG - {window_label}</b>",
        f"Thoi diem: <code>{ts}</code>",
        f"Tong IP bi khoa: <b>{total_blocked}</b>",
        "",
        "<b>Top IP tan cong:</b>"
    ]
    for rank, (ip, cnt) in enumerate(top_ips[:5], 1):
        lines.append(f"  {rank}. <code>{ip}</code> - {cnt} lan")
    return "\n".join(lines)

def send_telegram(text, parse_mode="HTML"):
    # Hàm gửi tin nhắn qua Telegram API có thử lại khi lỗi
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[-] TG_BOT_TOKEN or TG_CHAT_ID missing. Alert skipped.")
        return False

    url = TG_API_BASE.format(token=TG_BOT_TOKEN)
    payload = {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": parse_mode}

    for attempt in range(1, TG_MAX_RETRY + 1):
        try:
            resp = requests.post(url, json=payload, timeout=TG_TIMEOUT_S)
            if resp.status_code == 200:
                print(f"[+] Telegram alert sent - attempt {attempt}")
                return True
            else:
                print(f"[-] Telegram HTTP {resp.status_code} - attempt {attempt}")
        except Exception as e:
            print(f"[-] Telegram error - attempt {attempt} : {e}")

        if attempt < TG_MAX_RETRY:
            time.sleep(2 ** attempt)

    return False

def send_block_alert(sig):
    # Gửi cảnh báo block một IP mới
    if is_rate_limited(sig.src_ip):
        print(f"[!] Rate-limited Telegram alert for {sig.src_ip}")
        return False
    return send_telegram(format_block_message(sig))

def send_digest_alert(total_blocked, top_ips, window_label="5 phut"):
    # Gửi bản tóm tắt định kỳ
    return send_telegram(format_summary_message(total_blocked, top_ips, window_label))
