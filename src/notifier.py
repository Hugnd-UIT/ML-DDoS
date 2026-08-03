"""
notifier.py — Telegram SOC Alert System

Kiến trúc thông báo theo Sự cố (Incident-based):
  - Gom nhóm theo Vector tấn công: (protocol, normalized_port, reason)
  - Dynamic Multi-Port Promotion: ≥ 4 cổng khác nhau → MULTI_PORT_FLOOD
  - Global Rate Limit: tối đa 5 tin cá nhân / phút trước khi vào Batch Mode
  - Digest Dispatcher: 1 daemon thread / incident → báo cáo tổng hợp mỗi 3 phút
  - KHÔNG bao giờ spam theo IP, KHÔNG phán bừa loại DDoS, chỉ nói dữ liệu thật
"""

import os
import time
import threading
from collections import defaultdict, Counter

import requests


# ── Cấu hình Telegram ─────────────────────────────────────────────────────────

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID   = os.environ.get("TG_CHAT_ID", "")
TG_MAX_RETRY = int(os.environ.get("TG_MAX_RETRY", "3"))
TG_TIMEOUT_S = int(os.environ.get("TG_TIMEOUT_S", "8"))

TG_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"


# ── Ngưỡng điều phối ──────────────────────────────────────────────────────────

# Số cảnh báo cá nhân tối đa mỗi phút (toàn cục, không tính theo IP)
GLOBAL_ALERT_LIMIT   = 5

# Số cổng khác nhau tối thiểu trong 1 incident để kích hoạt MULTI_PORT_FLOOD
MULTI_PORT_THRESHOLD = 4

# Chu kỳ gửi Digest Summary cho mỗi incident đang hoạt động (giây)
DIGEST_INTERVAL_S    = 180   # 3 phút

# Cổng dịch vụ quan trọng (ghi nhận tên thay vì số)
KNOWN_PORTS = {
    22:   "SSH",
    53:   "DNS",
    80:   "HTTP",
    443:  "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


# ── Trạng thái nội bộ (thread-safe) ──────────────────────────────────────────

_lock = threading.Lock()

# Bộ đếm global alerts trong 60s qua
_global_alert_timestamps: list = []

# Incidents đang theo dõi: key = (protocol, norm_port, reason)
# value = {
#   "first_seen": float,       # Unix timestamp lần đầu phát hiện
#   "block_count": int,        # Tổng IP bị ban từ incident này
#   "port_counter": Counter,   # Thống kê cổng thực tế bị nhắm vào
#   "reason_counter": Counter, # Phân bố RATE_LIMIT vs AI_INFERENCE
#   "top_ips": Counter,        # Thống kê IP nào bị ban nhiều nhất
#   "digest_thread": Thread | None,
# }
_incidents: dict = {}


# ── Gửi Telegram API ──────────────────────────────────────────────────────────

def send_telegram(text: str, parse_mode: str = "HTML") -> bool:
    """Gửi HTTP POST lên Telegram với retry exponential backoff."""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("[-] TG_BOT_TOKEN hoặc TG_CHAT_ID chưa được cấu hình. Bỏ qua alert.")
        return False

    url     = TG_API_BASE.format(token=TG_BOT_TOKEN)
    payload = {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": parse_mode}

    for attempt in range(1, TG_MAX_RETRY + 1):
        try:
            resp = requests.post(url, json=payload, timeout=TG_TIMEOUT_S)
            if resp.status_code == 200:
                print(f"[+] Telegram gửi thành công (lần {attempt})")
                return True
            print(f"[-] Telegram HTTP {resp.status_code} (lần {attempt})")
        except Exception as exc:
            print(f"[-] Telegram lỗi kết nối (lần {attempt}): {exc}")

        if attempt < TG_MAX_RETRY:
            time.sleep(2 ** attempt)

    return False


# ── Chuẩn hóa cổng (Port Normalization) ──────────────────────────────────────

def _port_label(port: int) -> str:
    """Chuyển số cổng thành nhãn đọc được."""
    if port in KNOWN_PORTS:
        return f"{KNOWN_PORTS[port]} ({port})"
    return str(port)


def _normalize_port_key(port: int, port_counter: "Counter") -> str:
    """
    Tính khóa cổng chuẩn hóa cho vector incident.
    - Nếu số cổng khác nhau trong incident < MULTI_PORT_THRESHOLD: dùng số cổng thật
    - Nếu >= MULTI_PORT_THRESHOLD: kích hoạt MULTI_PORT_FLOOD
    """
    if len(port_counter) >= MULTI_PORT_THRESHOLD:
        return "MULTI_PORT_FLOOD"
    return str(port)


# ── Global Rate Limiter ───────────────────────────────────────────────────────

def _is_global_limited() -> bool:
    """
    Kiểm tra hạn mức tổng toàn cục. Trả về True nếu đã vượt GLOBAL_ALERT_LIMIT
    trong vòng 60 giây qua → hệ thống chuyển sang Batch Mode cho incident đó.
    """
    now = time.time()
    with _lock:
        # Xóa timestamp cũ hơn 60s
        _global_alert_timestamps[:] = [t for t in _global_alert_timestamps if now - t < 60.0]
        if len(_global_alert_timestamps) >= GLOBAL_ALERT_LIMIT:
            return True
        _global_alert_timestamps.append(now)
        return False


# ── Định dạng tin nhắn ────────────────────────────────────────────────────────

def _fmt_incident_open(protocol: str, norm_port_key: str,
                        reason: str, pps: float, sig) -> str:
    """Tin nhắn khi phát hiện cuộc tấn công mới (1 lần / incident)."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    port_str = (
        "Nhiều cổng (Port Spraying)"
        if norm_port_key == "MULTI_PORT_FLOOD"
        else _port_label(int(norm_port_key))
    )

    return (
        f"🚨 <b>[SOC INCIDENT] Phát hiện luồng tấn công mới</b>\n\n"
        f"🕐 Thời điểm: <code>{ts}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 Giao thức L4: <code>{protocol}</code>\n"
        f"🎯 Cổng mục tiêu: <code>{port_str}</code>\n"
        f"📊 Tốc độ ghi nhận: <code>{pps:,.0f} PPS</code>\n"
        f"🔍 Tuyến phát hiện: <code>{reason}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ Hành động: XDP DROP đang kích hoạt tự động.\n"
        f"📈 Báo cáo tổng hợp sẽ được gửi mỗi 3 phút."
    )


def _fmt_incident_digest(protocol: str, norm_port_key: str,
                          incident: dict, window_s: float) -> str:
    """Tin nhắn báo cáo định kỳ (mỗi 3 phút / incident)."""
    ts       = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    win_min  = int(window_s // 60)
    win_sec  = int(window_s % 60)
    win_str  = f"{win_min}p{win_sec:02d}s" if win_min else f"{win_sec}s"

    port_str = (
        "Nhiều cổng (Port Spraying/MULTI_PORT_FLOOD)"
        if norm_port_key == "MULTI_PORT_FLOOD"
        else _port_label(int(norm_port_key))
    )

    # Phân bố nguồn phát hiện
    rc         = incident["reason_counter"]
    total_rc   = sum(rc.values()) or 1
    reason_str = "\n".join(
        f"    • <code>{r}</code>: {c} lượt ({c*100//total_rc}%)"
        for r, c in rc.most_common()
    )

    # Top 3 IP bị ban nhiều nhất trong incident
    top_ips = incident["top_ips"].most_common(3)
    top_str = "\n".join(
        f"    {i+1}. <code>{ip}</code> — {cnt} lần bị ban"
        for i, (ip, cnt) in enumerate(top_ips)
    ) or "    (chưa có dữ liệu)"

    # Nếu đang là Multi-Port, thống kê top cổng thật bị nhắm
    port_dist_str = ""
    if norm_port_key == "MULTI_PORT_FLOOD":
        top_ports = incident["port_counter"].most_common(5)
        port_dist_str = (
            "\n📋 <b>Phân bố cổng bị nhắm (Top 5):</b>\n"
            + "\n".join(
                f"    • Cổng <code>{_port_label(p)}</code>: {c} lượt"
                for p, c in top_ports
            )
        )

    return (
        f"📊 <b>[SOC DIGEST] Báo cáo luồng tấn công đang diễn ra</b>\n\n"
        f"🕐 Thời điểm: <code>{ts}</code>\n"
        f"⏱ Khung quan sát: <code>{win_str}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 Giao thức: <code>{protocol}</code>\n"
        f"🎯 Cổng mục tiêu: <code>{port_str}</code>\n"
        f"🔢 Tổng lượt IP bị khóa: <b>{incident['block_count']}</b>\n\n"
        f"🔍 <b>Tuyến phát hiện:</b>\n{reason_str}\n\n"
        f"🏆 <b>Top IP vi phạm nhiều nhất:</b>\n{top_str}"
        f"{port_dist_str}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ Hệ thống XDP/eBPF vẫn đang tự động bảo vệ.\n"
        f"🔎 Phân tích chuyên sâu (DDoS sub-type): xem SOC Dashboard."
    )


# ── Digest Dispatcher Daemon ──────────────────────────────────────────────────

def _digest_dispatcher(vector_key: tuple):
    """
    Luồng ngầm (daemon) chạy riêng cho mỗi incident.
    Cứ mỗi DIGEST_INTERVAL_S giây, gửi 1 tin báo cáo tổng hợp.
    Tự kết thúc khi không có thêm block mới trong 2 chu kỳ liên tiếp.
    """
    idle_cycles = 0
    last_count  = 0

    while True:
        time.sleep(DIGEST_INTERVAL_S)

        with _lock:
            incident = _incidents.get(vector_key)
            if incident is None:
                break

            current_count = incident["block_count"]
            window_s      = time.time() - incident["first_seen"]
            protocol, norm_port_key, reason = vector_key

        # Gửi digest nếu có block mới trong chu kỳ này
        if current_count > last_count:
            send_telegram(_fmt_incident_digest(
                protocol, norm_port_key, dict(incident), window_s
            ))
            idle_cycles = 0
        else:
            idle_cycles += 1

        last_count = current_count

        # Sau 2 chu kỳ không có block mới → incident kết thúc, dọn dẹp
        if idle_cycles >= 2:
            with _lock:
                _incidents.pop(vector_key, None)
            print(f"[~] Incident kết thúc: {vector_key}")
            break


# ── API công khai duy nhất ────────────────────────────────────────────────────

def send_block_alert(sig) -> bool:
    """
    Hàm duy nhất được gọi từ enforcer.block_signature().

    Logic phân loại:
    1. Chuẩn hóa vector incident: (protocol, port_key, reason)
    2. Nếu incident MỚI hoàn toàn → gửi tin cảnh báo ngay (nếu còn hạn mức toàn cục)
    3. Nếu incident ĐÃ TỒN TẠI → chỉ cộng dồn số liệu, để Digest Dispatcher xử lý
    4. Khi ≥4 cổng khác nhau → tự động promote sang MULTI_PORT_FLOOD
    """
    now = time.time()

    with _lock:
        # Xây dựng port_key sơ bộ dựa trên số cổng thật trước
        raw_port = int(sig.dst_port)

        # Tìm hoặc tạo incident tạm thời với cổng thật để đếm
        # Duyệt xem đã có incident nào cùng (protocol, reason) chưa,
        # đang ở dạng MULTI_PORT hoặc cùng cổng
        protocol = sig.protocol
        reason   = sig.reason
        matched_key = None

        for key, inc in _incidents.items():
            k_proto, k_port, k_reason = key
            if k_proto != protocol or k_reason != reason:
                continue
            # Trùng cổng thật
            if k_port == str(raw_port):
                matched_key = key
                break
            # Incident đã là MULTI_PORT_FLOOD — gom vào luôn
            if k_port == "MULTI_PORT_FLOOD":
                matched_key = key
                break
            # Cùng protocol+reason nhưng khác cổng → đây là cuộc rải cổng
            # → cập nhật port_counter của incident đó, rồi kiểm tra promote
            # (Tìm incident gần nhất cùng (proto, reason) nếu thời gian trong 60s)
            if now - inc["first_seen"] < 60.0:
                matched_key = key
                break

        if matched_key is not None:
            inc = _incidents[matched_key]
            inc["block_count"]    += 1
            inc["port_counter"][raw_port] += 1
            inc["reason_counter"][reason] += 1
            inc["top_ips"][sig.src_ip]    += 1

            # Kiểm tra promote sang MULTI_PORT_FLOOD
            k_proto, k_port, k_reason = matched_key
            if (k_port != "MULTI_PORT_FLOOD"
                    and len(inc["port_counter"]) >= MULTI_PORT_THRESHOLD):
                # Đổi key sang MULTI_PORT_FLOOD
                new_key = (k_proto, "MULTI_PORT_FLOOD", k_reason)
                _incidents[new_key] = _incidents.pop(matched_key)
                # Cập nhật tham chiếu digest thread nếu cần
                # (thread đang chạy sẽ dùng vector_key cũ, không sao —
                #  lần tiếp theo nó sẽ không tìm thấy key cũ và tự thoát)

            return False  # Đã gom vào incident, không gửi tin lẻ

        # ── Incident HOÀN TOÀN MỚI ──
        norm_key = str(raw_port)
        vector   = (protocol, norm_key, reason)

        _incidents[vector] = {
            "first_seen":    now,
            "block_count":   1,
            "port_counter":  Counter({raw_port: 1}),
            "reason_counter": Counter({reason: 1}),
            "top_ips":       Counter({sig.src_ip: 1}),
            "digest_thread": None,
        }
        incident = _incidents[vector]

    # Kiểm tra hạn mức tổng trước khi gửi tin mới
    if _is_global_limited():
        print(f"[!] Global rate limit đạt ngưỡng, bỏ qua tin mở incident {vector}")
        # Vẫn khởi động digest thread để báo cáo sau
    else:
        send_telegram(_fmt_incident_open(
            protocol, norm_key, reason, sig.pps, sig
        ))

    # Khởi động Digest Dispatcher daemon cho incident mới
    t = threading.Thread(
        target=_digest_dispatcher,
        args=(vector,),
        daemon=True,
        name=f"digest-{protocol}-{norm_key}-{reason}"
    )
    t.start()

    with _lock:
        if vector in _incidents:
            _incidents[vector]["digest_thread"] = t

    return True