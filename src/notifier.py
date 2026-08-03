"""
notifier.py — Telegram SOC Alert System (State Machine Architecture)

Kiến trúc tinh gọn theo State Machine toàn hệ thống:
  IDLE (Bình yên) 
    │ [Có block đầu tiên] → 🚨 Gửi 1 tin phát hiện duy nhất cho trạm SOC
    ▼
  UNDER_ATTACK (Đang xử lý tấn công) 
    │ [Mỗi 3 phút nếu có thêm lượt ban] → 📊 Gửi 1 bản tin Digest tổng hợp TOÀN BỘ luồng/cổng/lý do
    │ [Sau 3 chu kỳ liên tiếp không có lượt ban mới] → ✅ Gửi tin báo cáo "Lưu lượng đã bế mạc" & về IDLE

Ưu điểm kiên định theo tiêu chuẩn Bảo mật kẽ giáp:
  1. KHÔNG BAO GIỜ có hiện tượng spam bị chẻ vụn thành 4-5 tin/3 phút.
  2. Dù tấn công vào 1 cổng hay 65.535 cổng cùng lúc, mọi số liệu đều gom về 1 phễu trung tâm.
  3. Chỉ báo trung thực 100% hai lý do của cỗ máy: RATE_LIMIT (Volumetric) và AI_INFERENCE (Binary Model).
"""

import os
import time
import threading
from collections import Counter

import requests

# ── Cấu hình Telegram & Tự động nạp tệp mật ──────────────────────────────────

def _auto_load_dotenv():
    env_candidate_paths = [
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.getcwd(), ".env"),
        os.path.expanduser("~/.env"),
        os.path.expanduser("~/ML-DDoS/.env"),
        "/home/hoangminh13022006/ML-DDoS/.env",
        "/root/ML-DDoS/.env",
        "/root/.env",
    ]
    for filepath in env_candidate_paths:
        filepath = os.path.abspath(filepath)
        if os.path.exists(filepath):
            print(f"[+] Notifier: Tự động phát hiện và nạp cấu hình từ {filepath}")
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
                break
            except Exception as e:
                print(f"[-] Lỗi đọc file {filepath}: {e}")

_auto_load_dotenv()

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID   = os.environ.get("TG_CHAT_ID", "")
TG_MAX_RETRY = int(os.environ.get("TG_MAX_RETRY", "3"))
TG_TIMEOUT_S = int(os.environ.get("TG_TIMEOUT_S", "8"))

TG_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"

DIGEST_INTERVAL_S = 60  # Chu kỳ 1 phút / lần báo cáo toàn hệ thống

KNOWN_PORTS = {
    22:   "SSH (22)",
    53:   "DNS (53)",
    80:   "HTTP (80)",
    443:  "HTTPS (443)",
    3306: "MySQL (3306)",
    5432: "PostgreSQL (5432)",
    6379: "Redis (6379)",
    8080: "HTTP-Alt (8080)",
    8443: "HTTPS-Alt (8443)",
}

def _port_label(port: int) -> str:
    return KNOWN_PORTS.get(port, str(port))


# ── Bộ theo dõi tập trung toàn cơ sở (State Machine) ─────────────────────────

_lock = threading.Lock()
_state = "IDLE"  # "IDLE" hoặc "UNDER_ATTACK"

# Lưu trữ số liệu tích lũy của toàn trận chiến
_attack_start_time = 0.0
_total_blocks      = 0
_last_digest_count = 0
_idle_cycles       = 0

_proto_counter  = Counter()
_port_counter   = Counter()
_reason_counter = Counter()
_ip_counter     = Counter()
_dispatcher_thread = None


def send_telegram(text: str, parse_mode: str = "HTML") -> bool:
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


def _fmt_open_alert(sig) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    port_str = _port_label(int(sig.dst_port))
    return (
        f"🚨 <b>[SOC ALERT] Kích hoạt Trạng thái Chiến Đấu (UNDER_ATTACK)</b>\n\n"
        f"🕐 Thời điểm phát hiện: <code>{ts}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Tín hiệu khởi phát đầu tiên:\n"
        f"  • Nguồn bị chém: <code>{sig.src_ip}</code> ({sig.pps:,.0f} PPS)\n"
        f"  • Giao thức / Cổng: <code>{sig.protocol}</code> → <code>{port_str}</code>\n"
        f"  • Cơ chế cắn cờ: <code>{sig.reason}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ XDP eBPF đang cô lập chớp nhoáng tầng hạt nhân.\n"
        f"🔇 Hệ thống vào chế độ ngắt tiếng (Mute Mode) để chống bão Spam.\n"
        f"📈 Báo cáo thực tế chiến sự sẽ gửi trung bình mỗi 1 phút."
    )


def _fmt_digest(duration_s: float, total_b: int) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    mins = int(duration_s // 60)
    secs = int(duration_s % 60)
    dur_str = f"{mins}p{secs:02d}s" if mins > 0 else f"{secs}s"

    # Giao thức L4
    proto_total = sum(_proto_counter.values()) or 1
    proto_str = " | ".join(
        f"{p} ({c*100//proto_total}%)" for p, c in _proto_counter.most_common(2)
    )

    # Tuyến phát hiện
    reason_total = sum(_reason_counter.values()) or 1
    reason_str = "\n".join(
        f"    • <code>{r}</code>: {c} lượt ({c*100//reason_total}%)"
        for r, c in _reason_counter.most_common()
    )

    # Top cổng
    ports_str = ", ".join(
        _port_label(p) for p, _ in _port_counter.most_common(4)
    )
    if len(_port_counter) > 4:
        ports_str += f" (+{len(_port_counter)-4} cổng rải rác khác)"

    # Top IP
    ip_str = "\n".join(
        f"    {i+1}. <code>{ip}</code> — {cnt} lần chém"
        for i, (ip, cnt) in enumerate(_ip_counter.most_common(3))
    )

    return (
        f"📊 <b>[SOC DIGEST] Báo cáo Toàn cảnh Chiến sự (Mỗi 1 phút)</b>\n\n"
        f"🕐 Thời điểm: <code>{ts}</code>\n"
        f"⏱ Thời gian tác chiến liên tục: <code>{dur_str}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔢 Tổng lượt IP đã tước ban: <b>{total_b:,}</b> lượt\n"
        f"📡 Phân bố giao thức L4: <code>{proto_str}</code>\n"
        f"🎯 Các cổng nhắm mục tiêu: <code>{ports_str}</code>\n\n"
        f"🔍 <b>Cán cân cơ chế cản phá:</b>\n{reason_str}\n\n"
        f"🏆 <b>Top IP hung hăng nhất:</b>\n{ip_str}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ Hàng rào XDP eBPF giữ tải hệ thống ổn định tuyệt đối.\n"
        f"🔎 Phân tích chủng loại DDoS (Multi-class): xem tại SOC Dashboard."
    )


def _fmt_clear(duration_s: float, total_b: int) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    mins = int(duration_s // 60)
    secs = int(duration_s % 60)
    dur_str = f"{mins}p{secs:02d}s" if mins > 0 else f"{secs}s"
    return (
        f"✅ <b>[SOC CLEAR] Bão lưu lượng đã chấm dứt!</b>\n\n"
        f"🕐 Thời gian an bình trỗi lại: <code>{ts}</code>\n"
        f"⏱ Tổng thời gian kéo dài: <code>{dur_str}</code>\n"
        f"🔢 Tổng thành quả cô lập: <b>{total_b:,}</b> lượt block.\n\n"
        f"🛡️ Trạng thái hệ thống đã trở về <b>IDLE (Sẵn sàng)</b>. Chúc hai Quân sư vững tay tẩu mã!"
    )


def _global_dispatcher():
    global _state, _last_digest_count, _idle_cycles

    while True:
        time.sleep(DIGEST_INTERVAL_S)

        with _lock:
            if _state == "IDLE":
                break

            cur_blocks = _total_blocks
            duration_s = time.time() - _attack_start_time

            if cur_blocks > _last_digest_count:
                # Có chém thêm từ lúc trước → gửi báo cáo gộp toàn cơ sở
                send_telegram(_fmt_digest(duration_s, cur_blocks))
                _last_digest_count = cur_blocks
                _idle_cycles = 0
            else:
                _idle_cycles += 1
                # Nếu 2 chu kỳ liền không có thêm IP nào phạm lỗi → Hết bão
                if _idle_cycles >= 2:
                    send_telegram(_fmt_clear(duration_s, cur_blocks))
                    _state = "IDLE"
                    _reset_state_unlocked()
                    print("[~] Hệ thống kết thúc đợt chiến, trở về IDLE.")
                    break


def _reset_state_unlocked():
    global _attack_start_time, _total_blocks, _last_digest_count, _idle_cycles
    _attack_start_time = 0.0
    _total_blocks      = 0
    _last_digest_count = 0
    _idle_cycles       = 0
    _proto_counter.clear()
    _port_counter.clear()
    _reason_counter.clear()
    _ip_counter.clear()


def send_block_alert(sig) -> bool:
    """
    Hàm giao tiếp duy nhất nhận lệnh từ enforcer.
    Hoạt động thuần khiết trên cỗ máy trạng thái (State Machine): IDLE -> UNDER_ATTACK -> IDLE.
    """
    global _state, _attack_start_time, _total_blocks, _dispatcher_thread

    with _lock:
        now = time.time()

        # Cộng dồn số liệu vào bộ đếm chung
        _total_blocks += 1
        _proto_counter[sig.protocol]       += 1
        _port_counter[int(sig.dst_port)]   += 1
        _reason_counter[sig.reason]        += 1
        _ip_counter[sig.src_ip]            += 1

        if _state == "IDLE":
            _state = "UNDER_ATTACK"
            _attack_start_time = now
            _last_digest_count = _total_blocks
            _idle_cycles = 0

            # Khởi động luồng tổng giám định chiến sự toàn cơ sở
            _dispatcher_thread = threading.Thread(
                target=_global_dispatcher,
                daemon=True,
                name="global-soc-dispatcher"
            )
            _dispatcher_thread.start()

            # Gửi ĐÚNG 1 tin còi khai màn
            send_telegram(_fmt_open_alert(sig))
            return True

        # Nếu đang trong UNDER_ATTACK → Im lặng, để toàn bộ số liệu cho luồng Digest xử lý
        return False