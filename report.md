# Báo cáo rà soát & gia cố Gatekeeper IPS

Rà soát toàn bộ mã nguồn hệ thống phát hiện DDoS bằng Machine Learning + eBPF/XDP.
**32 lỗi đã sửa** qua ba vòng, trên 13 file. Mỗi mục gồm *hiện tượng* và *cách fix*.

Phần lớn không phải lỗi cú pháp — chúng là những chỗ hệ thống vẫn **chạy**, vẫn in
log đẹp, nhưng không còn bảo vệ được gì.

| | |
|---|---|
| Vòng 1 | 16/08/2026 — FIX-01 … FIX-22, rà soát mã nguồn |
| Vòng 2 | 05/09/2026 — FIX-23 … FIX-30, đọc lại (gồm 1 regression do vòng 1 gây ra) |
| Vòng 3 | 05/09/2026 — FIX-31, FIX-32, phát hiện khi **chạy thật trên VM1** |
| Kiểm chứng | 11 fix có test chạy thật, số liệu ghi kèm trong từng mục |
| Chưa test được | Phần eBPF (FIX-04, FIX-19, FIX-29) — BCC chỉ có trên Linux |

> **Hai lỗi nặng nhất chỉ lộ ra khi chạy thật, không phải khi đọc code:** FIX-31
> (chặn nhầm CDN hợp lệ vì ngưỡng sai) và FIX-32 (không nhận đúng loại tấn công vì
> lệch đơn vị đo feature). Cả hai đều "chạy bình thường" trên giấy.

---

## 1. LỆNH CẦN CHẠY

Đã kiểm tra thực trạng trên máy trước khi kết luận:

```
data/train_binary.csv       header KHỚP 18 feature
data/test_binary.csv        header KHỚP
data/train_multiclass.csv   header KHỚP
data/test_multiclass.csv    header KHỚP

binary.pkl          n_features_in_ = 18  KHỚP
binary_eval.pkl     n_features_in_ = 18  KHỚP
multiclass.pkl      n_features_in_ = 18  KHỚP
multiclass_eval.pkl n_features_in_ = 18  KHỚP
```

### KHÔNG cần chạy

- **`parser.py`** — dữ liệu đã đúng. Chỉ chạy lại nếu sửa `FEATURE_NAMES` trong `features.py`.
- **`trainer.py` (huấn luyện lại)** — model trên đĩa vẫn đúng. Thứ duy nhất lỗi thời là `threshold.json`.

Chạy `trainer.py --only binary` sẽ fit lại từ đầu trên 7 GB dữ liệu chỉ để sinh một
file JSON 500 byte, **và ghi đè `binary.pkl`** — làm số FPR/TPR đã đưa vào báo cáo
không còn mô tả đúng file đang nằm trên đĩa.

### CẦN chạy — một lệnh duy nhất

```bash
python src/recalibrate.py
```

Script mới (`src/recalibrate.py`) dùng lại đúng model hiện có:

1. Chấm `binary_eval.pkl` trên dữ liệu ngày 2 chưa từng thấy
2. Chọn ngưỡng đạt mục tiêu FPR → **ngưỡng và FPR/TPR đều là số đo thật**
3. Băm `binary_eval.pkl` ghi vào `threshold.json` (xem FIX-22)

Model được deploy là `binary_eval.pkl`, **không phải** `binary.pkl` — xem FIX-31.

Đọc dữ liệu theo chunk 1 triệu dòng nên không nổ RAM. Áp cùng cổng chất lượng như
trainer (FPR ≤ 2%, TPR ≥ 70%) và **từ chối ghi file** nếu model không đạt.
Thời gian: dưới một phút (chỉ đọc `test_binary.csv`).

### Sau đó — kiểm tra trên VM1

```bash
sudo -E python3 src/gatekeeper.py -i ens4
```

Phải thấy đủ các dòng sau lúc khởi động:

```
[+] IPv6 enforcement maps ready              ← FIX-04, xdp_filter.c mới đã attach
[+] XDP statistics counters ready            ← FIX-29
[+] Successfully loaded N/M rules            ← FIX-02, N phải BẰNG M
[+] Model integrity: sha256 khớp             ← FIX-22
    Path: .../models/binary_eval.pkl         ← FIX-31, KHÔNG phải binary.pkl
[+] Feature contract khớp: 18 feature        ← FIX-09
[+] Decision threshold: 0.9999               ← FIX-31
    FPR 0.0018% / TPR 76.4452%
```

**Không được** thấy dòng nào trong số này nữa sau khi chạy `recalibrate.py`:

```
[!] threshold.json chưa có binary_sha256; bỏ qua bước kiểm tra toàn vẹn
[!] threshold.json không xác nhận đã hiệu chỉnh trên chính model đang deploy
```

Chạy một lúc rồi `Ctrl+C`, chụp lại bảng `XDP DATA PLANE COUNTERS` — đó là số liệu
định lượng duy nhất chứng minh tầng kernel thật sự DROP gói, rất đáng đưa vào phần
đánh giá của báo cáo đồ án.

### Chỉ chạy lại full khi thật sự cần model mới

```bash
python src/parser.py     # chỉ khi đổi FEATURE_NAMES
python src/trainer.py    # ~30-60 phút, ghi đè cả 4 file .pkl
```

### Dọn kho git

```bash
git rm --cached models/scaler.pkl models/xgboost.pkl
git add src/features.py src/recalibrate.py models/threshold.json
```

`features.py` đang untracked dù **cả 4 module khác đều import từ nó** — clone mới sẽ
chết ngay ở dòng import.

---

## 2. BẢNG TRA NHANH

| # | Lỗi | Mức | File |
|---|---|---|---|
| 01 | Whitelist toàn bộ dải IP khách hàng GCP/Fastly | Nguy hiểm | enforcer.py |
| 02 | Map whitelist tràn 2 000 entry, lỗi bị nuốt | Nguy hiểm | xdp_filter.c |
| 03 | Flood giả mạo nguồn vượt cả hai tuyến phát hiện | Nguy hiểm | gatekeeper.py |
| 04 | IPv6 không được giám sát ở cả kernel lẫn user space | Nguy hiểm | xdp_filter.c |
| 05 | SOC Dashboard không có xác thực | Nguy hiểm | app.py |
| 06 | Memory Manager crash → ban vĩnh viễn | Vận hành | enforcer.py |
| 07 | Telegram giữ lock khi gọi mạng → IPS mù 30 giây | Vận hành | notifier.py |
| 08 | Bộ đếm vi phạm rò rỉ bộ nhớ vô hạn | Vận hành | enforcer.py |
| 09 | Model lệch feature → AI chết trong im lặng | Vận hành | gatekeeper.py |
| 10 | `threshold.json` bị `.gitignore` nuốt | Vận hành | .gitignore |
| 11 | Ngưỡng hiệu chỉnh trên model A, áp cho model B | Đúng đắn | trainer.py |
| 12 | Dashboard bịa loại tấn công cho dòng thiếu feature | Đúng đắn | app.py |
| 13 | Ô tìm kiếm nhận regex tuỳ ý → crash / ReDoS | Đúng đắn | app.py |
| 14 | Parser bỏ file CSV trong im lặng | Đúng đắn | parser.py |
| 15 | Dashboard quay vòng vô hạn khi chưa có dữ liệu | Đúng đắn | app.py |
| 16 | Upload GCS chạy đồng bộ trên đường bắt gói | Đúng đắn | gcs_utility.py |
| 17 | Tên file log trùng giây → ghi đè mất log | Nhỏ | gcs_utility.py |
| 18 | Quét whitelist tuyến tính trên đường nóng | Nhỏ | enforcer.py |
| 19 | Gói VLAN-tagged đi vòng qua blacklist | Nhỏ | xdp_filter.c |
| 20 | Container dashboard chạy bằng root | Nhỏ | Dockerfile |
| 21 | Notifier đọc `.env` ngoài phạm vi dự án | Nhỏ | notifier.py |
| 22 | Không có cách phát hiện model bị đánh tráo | Nhỏ | trainer.py |
| **23** | **REGRESSION: mọi lượt chặn IP ném `AttributeError`** | **Nguy hiểm** | gcs_utility.py |
| 24 | NFStream chết kéo sập luôn tầng chặn ở kernel | Vận hành | gatekeeper.py |
| 25 | Cơn bão gỡ ban giữ lock hàng giây | Vận hành | enforcer.py |
| 26 | Sổ ban là dict duy nhất còn không giới hạn | Vận hành | enforcer.py |
| 27 | Cảnh báo ngưỡng đặt ngược, im lặng đúng lúc cần kêu | Đúng đắn | gatekeeper.py |
| 28 | Whitelist Canonical dựa vào DNS | Đúng đắn | enforcer.py |
| 29 | Data plane hoàn toàn câm, không đếm được gói bị DROP | Đúng đắn | xdp_filter.c |
| 30 | Dashboard không đối chiếu feature model multiclass | Nhỏ | app.py |
| **31** | **Ngưỡng hiệu chỉnh trên dữ liệu model đã học → chặn nhầm CDN thật** | **Nguy hiểm** | trainer.py |
| **32** | **Lệch ngữ nghĩa feature → không nhận đúng loại tấn công** | **Nguy hiểm** | features.py |

---

## 3. LỖ HỔNG BẢO MẬT (01 – 05)

### FIX-01 — Whitelist toàn bộ dải IP khách hàng của GCP và Fastly
`src/enforcer.py · load_whitelist()`

**Hiện tượng.** Hệ thống tải `cloud.json`, `goog.json` và danh sách IP Fastly rồi nạp
thẳng vào whitelist. `cloud.json` là dải IP **khách hàng** của Google Cloud — hàng
triệu địa chỉ mà bất kỳ ai cũng thuê được với vài đô một tháng.

Trong `xdp_filter.c`, whitelist được tra **trước** blacklist. Nghĩa là attacker chỉ
cần dựng VM trên GCP hoặc đẩy traffic qua Fastly là được `XDP_PASS` vô điều kiện —
AI có phát hiện ra cũng không chặn nổi. Cửa hậu hoàn chỉnh, mở sẵn.

**Cách fix.**
- Bỏ hoàn toàn việc nạp hàng loạt khỏi luồng mặc định.
- Chỉ giữ đúng thứ mất đi thì mất quyền quản trị máy: IAP `35.235.240.0/20`,
  metadata `169.254.169.254/32`, health check `35.191.0.0/16` và `130.211.0.0/22`.
- Thêm `WHITELIST_CIDRS` để admin tự khai IP văn phòng / VPN.
- Bật lại được qua `WHITELIST_BULK_CLOUD=1` cho server nằm sau CDN, nhưng lúc đó
  code in cảnh báo rõ ràng.

### FIX-02 — Map whitelist tràn ở 2 000 entry, mọi lỗi nạp bị nuốt
`src/xdp_filter.c · src/enforcer.py`

**Hiện tượng.** `BPF_LPM_TRIE(whitelist_map, ..., 2000)` nhưng riêng GCP đã vượt con
số đó. Vòng nạp map lại bọc trong `except Exception: pass`, nên khi map đầy các entry
còn lại rơi vào hư không, không một dòng log nào.

Hệ quả nguy hiểm hơn cả việc thiếu entry: whitelist trong **kernel** và whitelist
trong **Python** không còn giống nhau. Hai tầng ra quyết định lệch nhau, và nội dung
nạp được phụ thuộc thứ tự tải — mỗi lần khởi động một kiểu.

**Cách fix.**
- Nâng lên 8 192 entry, thêm `whitelist6_map` 4 096 entry cho IPv6.
- Tách bạch CIDR sai cú pháp và CIDR không nạp được vào kernel, đếm riêng, in 10 mục đầu.
- Có entry bị từ chối → cảnh báo thẳng rằng whitelist hai tầng đang lệch nhau.
- Log đổi từ `"loaded N rules"` sang `"loaded N/M rules"`.

### FIX-03 — Flood phân tán / giả mạo nguồn vượt qua cả hai tuyến phát hiện
`src/gatekeeper.py · GlobalFloodDetector`

**Hiện tượng.** Tuyến AI chỉ vào cuộc khi flow có `bidirectional_packets >= 10`.
Tuyến rate limiter cộng dồn **theo từng src_ip riêng biệt**.

Một trận SYN flood rải 1–2 gói trên mỗi IP: flow quá nhỏ cho AI, không IP nào chạm
ngưỡng 200 SYN. Tổng lưu lượng vẫn thừa sức giết server nhưng hệ thống không thấy gì.
Đây chính là dạng DDoS phổ biến nhất ngoài thực tế.

**Cách fix.** Thêm `GlobalFloodDetector` — cửa sổ trượt cộng dồn trên **mọi** source,
theo dõi ba đại lượng: tổng SYN, tổng gói, và *số source khác nhau*. Đại lượng thứ ba
là chìa khoá: flood phân tán không có IP nào nổi bật, nhưng số lượng IP thì bùng nổ.

Khi vượt ngưỡng → **FLOOD MODE**:
- Ngưỡng per-IP hạ xuống `1/FLOOD_MODE_DIVISOR` (mặc định 1/10).
- Tuyến AI hạ yêu cầu từ 10 gói xuống 2 gói (mức tối thiểu `extract_features()` mô tả được).
- Cảnh báo Telegram riêng kèm số liệu cửa sổ.
- Thoát sau 15 giây yên ắng (có hysteresis, không dao động bật/tắt).

Code nói thẳng một sự thật quan trọng: nếu source bị giả mạo thì chặn theo src IP là
*vô nghĩa về bản chất*. Tuyến phòng thủ thật ở đó là `tcp_syncookies` + `rp_filter`
(đã bật trong `scripts/setup.sh`) và scrubbing upstream — không phải blacklist.

```
Kiểm chứng: 60 source × 1 gói SYN (không IP nào chạm ngưỡng 200)
  → flood phát hiện: True
  → lý do: distinct sources 60/5s > 50
  → sau 15s yên ắng: tự thoát FLOOD MODE ✓
```

### FIX-04 — IPv6 không được giám sát ở cả kernel lẫn user space
`src/xdp_filter.c · src/gatekeeper.py · src/enforcer.py`

**Hiện tượng.** Python `continue` ngay khi thấy `:` trong `src_ip`. XDP thì `XDP_PASS`
mọi ethertype không phải `ETH_P_IP`. Hai tầng cùng bỏ qua IPv6 → nếu VM có địa chỉ
IPv6 global thì đó là bypass 100%, attacker chỉ cần kết nối qua IPv6.

**Cách fix.**
- Thêm `blacklist6_map` (LRU hash, key 16 byte) và `whitelist6_map` (LPM trie), hàm `decide_v6()` tách riêng.
- `enforcer` tự chọn map theo họ địa chỉ qua `_blacklist_key()`; `CidrIndex` xử lý cả prefix v4 lẫn v6.
- `gatekeeper` bỏ dòng `continue`, `get_all_local_ips()` đọc cả `ip -6 addr`.
- Suy giảm an toàn: chạy với `xdp_filter.c` cũ vẫn được, IPv4-only, **nhưng in cảnh báo rõ ràng**.

### FIX-05 — SOC Dashboard công khai không có xác thực
`src/app.py · check_password()`

**Hiện tượng.** Streamlit chạy trần trên Cloud Run. Deploy với
`--allow-unauthenticated` thì bất kỳ ai có URL đều xem được toàn bộ IP đã bị chặn,
cổng bị nhắm, và cả vector đặc trưng 18 chiều của từng cuộc tấn công.

Với attacker đó không chỉ là rò rỉ thông tin — đó là **bảng phản hồi** cho biết chính
xác cái gì bị bắt và cái gì lọt lưới, tức là bản đồ để tinh chỉnh đợt tấn công sau.

**Cách fix.**
- Cổng mật khẩu qua `DASHBOARD_PASSWORD`, so sánh bằng `hmac.compare_digest`.
- **Mặc định từ chối**: không đặt mật khẩu thì hiện lỗi và `st.stop()`, không âm thầm mở toang.
- `DASHBOARD_ALLOW_ANONYMOUS=1` cho trường hợp đã có Cloud IAP phía trước, phải khai báo *rõ ràng*.
- Xác thực chạy trước khi render bất kỳ dữ liệu nào.

---

## 4. BUG LÀM HỎNG VẬN HÀNH (06 – 10)

### FIX-06 — Memory Manager crash mỗi vòng → IP bị ban vĩnh viễn
`src/enforcer.py · _memory_manager()`

**Hiện tượng.** Comment trong code ghi rõ chủ ý *"Find expired bans without holding
the lock"*. Nhưng `block_ip()` ghi vào `ban_registry` ở luồng bắt gói, còn
`_memory_manager` duyệt `.items()` của chính dict đó mà không giữ lock → Python ném
`RuntimeError: dictionary changed size during iteration`.

Exception bị nuốt, in một dòng, ngủ 5 giây rồi thử lại. Và vì lỗi chỉ xảy ra *khi
đang có block* — tức đúng lúc bị tấn công — vòng dọn dẹp gần như không bao giờ chạy
xong. Hệ quả: **IP không bao giờ được unban**, kể cả false positive. Exponential
backoff 5 phút / 1 giờ / 24 giờ trở thành vô hạn.

**Cách fix.** Chụp snapshot và dọn dẹp **bên trong** `self.lock`, dùng
`list(self.ban_registry.items())` để tách hẳn khỏi dict gốc. `unban_ip()` bỏ việc tự
lấy lock. Thêm `threading.Event` để dừng luồng sạch lúc shutdown.

```
Kiểm chứng — 5 000 vòng lặp với luồng ghi song song:
  RuntimeError · pattern CŨ  : 9
  RuntimeError · pattern MỚI : 0
```

> Xem thêm **FIX-25**: cách sửa này đúng nhưng lại tạo ra vấn đề mới về thời gian giữ lock.

### FIX-07 — Telegram giữ lock trong lúc gọi mạng → IPS mù tới 30 giây
`src/notifier.py · send_block_alert(), _global_dispatcher()`

**Hiện tượng.** `send_block_alert()` lấy `_lock` rồi gọi `send_telegram()` **bên
trong** lock. Hàm đó retry 3 lần, mỗi lần timeout 8 giây cộng backoff `2**n` — giữ
lock tới ~30 giây.

Mà `send_block_alert()` lại được `enforcer.block_ip()` gọi **đồng bộ ngay trong vòng
`for flow in streamer`**. Kết quả: Telegram chậm thì hệ thống ngừng xử lý gói suốt
nửa phút. Một IPS bị vô hiệu hoá bởi API của bên thứ ba.

**Cách fix.**
- Soạn nội dung *trong* lock, gửi *ngoài* lock — cho cả `send_block_alert()` lẫn `_global_dispatcher()`.
- Thêm `send_telegram_async()` đẩy hẳn việc gọi mạng sang luồng nền.
- **Phát hiện thêm:** `send_block_alert()` gán `_last_digest_count` và `_idle_cycles`
  mà *thiếu khai báo `global`* — Python tạo biến cục bộ, nên hai biến module-level
  không bao giờ được cập nhật. Máy trạng thái digest chạy sai từ đợt tấn công thứ hai
  trở đi. Đã bổ sung.

### FIX-08 — Bộ đếm vi phạm rò rỉ bộ nhớ vô hạn
`src/enforcer.py · offense_counts`

**Hiện tượng.** `offense_history` là `TTLCache` có `maxsize` và TTL 24 giờ — đúng.
Nhưng `_offense_counts` đi kèm lại là `dict` thường, không giới hạn, không hết hạn,
không bao giờ được dọn. Flood với source giả mạo tạo một entry cho mỗi IP mới → dict
phình cho tới khi **chính máy phòng thủ bị OOM**.

**Cách fix.** Đổi sang `TTLCache(maxsize=100_000, ttl=86400)`, khớp vòng đời của
`offense_history`. Khai báo tường minh trong `__init__` thay vì khởi tạo lười bằng
`getattr(self, "_offense_counts", {})`.

> Xem thêm **FIX-26**: `ban_registry` bị bỏ sót ở lần sửa này.

### FIX-09 — Model lệch feature làm AI chết trong im lặng
`src/gatekeeper.py · validate_model_contract()`

**Hiện tượng.** Nếu `binary.pkl` là bản cũ (19 feature) trong khi `features.py` đã rút
xuống 18, `predict_proba()` ném exception ở **mọi** flow. Handler per-flow bắt lấy,
in một dòng, chạy tiếp.

Hệ thống *trông như* vẫn chạy: banner đẹp, log chạy, XDP đã attach. Nhưng tuyến phát
hiện chính đã chết hoàn toàn, chỉ còn rate limiter — không ai nhận ra.

**Cách fix.**
- Đối chiếu `model.n_features_in_` với `N_FEATURES` lúc khởi động, lệch thì `sys.exit(1)`.
- Đối chiếu thêm `n_features` trong `threshold.json`.
- `trainer.py` ghi thêm `feature_names` đầy đủ để đối chiếu được cả tên.
- Sửa lỗi phụ ở handler: bản cũ in `flow.src_ip` bên trong `except`, nên nếu chính
  việc truy cập thuộc tính flow gây lỗi thì handler ném lần thứ hai. Nay bọc try riêng.

### FIX-10 — `threshold.json` bị `.gitignore` nuốt mất
`.gitignore`

**Hiện tượng.** Dòng `*.json` nuốt luôn `models/threshold.json` — file này chưa bao
giờ được commit. Trên bản clone mới, `load_threshold()` không tìm thấy và rơi về 0.5.
Theo chính số liệu trong file đó, FPR nhảy từ **0,0018% lên 0,966%** — gấp hơn **500
lần** số false positive. Deploy trên máy mới sẽ chặn nhầm hàng loạt người dùng hợp lệ
mà không ai hiểu tại sao trong khi "code y hệt nhau".

**Cách fix.** Thêm ngoại lệ `!models/threshold.json` kèm comment giải thích đây là
*artifact triển khai* chứ không phải file rác.

---

## 5. ĐÚNG ĐẮN & HIỆU NĂNG (11 – 16)

### FIX-11 — Ngưỡng hiệu chỉnh trên model đánh giá, đem áp cho model production
`src/trainer.py · transfer_threshold()`

> **Đây là điểm dễ bị hỏi nhất khi bảo vệ đồ án.**

**Hiện tượng.** Ngưỡng `0.9999` được chọn bằng cách quét trên `eval_model` (fit ngày
1, chấm ngày 2). Nhưng file được deploy là `binary.pkl` — một model **khác**, fit lại
trên toàn bộ dữ liệu, với calibration khác.

Một giá trị xác suất tuyệt đối không mang cùng ý nghĩa giữa hai model. Nên FPR/TPR
thực tế khi chạy production *không hề* là con số ghi trong `threshold.json`.

**Cách fix.** Giữ nguyên **phân vị** thay vì giữ nguyên **giá trị**. Nếu eval model
chặn 0,1% cao nhất trong nhóm benign, thì lấy ngưỡng của model production tại đúng
phân vị 99,9% trên phân phối điểm số benign của *chính nó*.

`threshold.json` tách bạch rõ hai nhóm số:
- `threshold` + `calibrated_on: "production_model"` → thứ gatekeeper dùng để chạy
- `measured_fpr` / `measured_tpr` + `metrics_source` → số liệu **trung thực** đo trên
  `binary_eval.pkl` với dữ liệu ngày 2 chưa từng thấy. **Chỉ nhóm này mới được đưa
  vào báo cáo đồ án.**

```
Kiểm chứng — mô phỏng hai model lệch calibration:
  Ngưỡng chọn trên eval model : 0.159298  (FPR 0.1000%)
  ÁP THẲNG sang production    : FPR thực tế = 12.5485%  ← lỗi cũ
  CHUYỂN THEO PHÂN VỊ         : FPR thực tế =  0.1000%  ← đã fix
```

Xác nhận trên model thật của dự án (lát cắt 300k dòng): ngưỡng eval `0.9999` chuyển
thành ngưỡng production `0.9849` — hai model **thật sự** lệch calibration.

### FIX-12 — Dashboard bịa loại tấn công cho dòng không có feature
`src/app.py · classify_attack_types() · src/gcs_utility.py`

**Hiện tượng.** Rate limiter có thể chặn một flow quá nhỏ để mô tả → `features = None`.
`csv.DictWriter` ghi ô rỗng, `read_csv` đọc ra `NaN`, `.fillna(0)` biến thành vector
toàn số 0. Model multiclass vẫn nhận và vẫn trả về một nhãn. Biểu đồ *"Attack Type
Distribution"* — nằm ngay giữa dashboard — hiển thị loại tấn công **hoàn toàn bịa ra**.

**Cách fix.**
- Thêm cột `has_features` vào CSV log.
- Chỉ chạy `predict()` trên dòng đủ điều kiện; còn lại giữ nguyên nhãn `reason`.
- Hiện chú thích cho người xem biết có bao nhiêu sự kiện giữ nhãn gốc và vì sao.
- Tương thích ngược với log cũ: rơi về `notna().all(axis=1)`.

```
Kiểm chứng — 4 dòng, 2 có feature và 2 không:
  CŨ  → ['Syn', 'Syn', 'Syn', 'Syn']
  MỚI → ['Syn', 'RATE_LIMIT (Volumetric)', 'Syn', 'RATE_LIMIT (Flood Mode)']
```

### FIX-13 — Ô tìm kiếm nhận biểu thức chính quy tuỳ ý
`src/app.py`

**Hiện tượng.** `str.contains(search_term)` mặc định coi chuỗi nhập vào là regex. Gõ
một dấu `(` là trang crash. Gõ `(a+)+$` là ReDoS — backtracking mũ treo nguyên
instance Cloud Run bằng đúng một ô input công khai.

**Cách fix.** Thêm `regex=False`. Người dùng tìm IP và tên giao thức, không ai cần
regex ở ô này.

```
Kiểm chứng:
  CŨ  → CRASH: ArrowInvalid: Invalid regular expression: missing )
  MỚI → không crash; tìm '10.0' vẫn khớp đúng IP
```

### FIX-14 — Parser bỏ nguyên file CSV trong im lặng
`src/parser.py · clean_data()`

**Hiện tượng.** `if missing_cols: continue` — không in một chữ nào. Một file CSV có
header khác đi (đổi tên cột, thừa dấu cách, bản CICFlowMeter khác) sẽ biến mất khỏi
dataset không dấu vết. Mô hình vẫn train xong, vẫn ra chỉ số đẹp — chỉ là trên nửa
dataset, và không ai biết là nửa nào.

**Cách fix.** In tên file bị bỏ kèm danh sách cột thiếu; in số dòng giữ lại của từng
file; in bảng tổng kết cuối mỗi thư mục. Thêm `.copy()` sau `isin(knowledge)` để loại
`SettingWithCopyWarning`.

### FIX-15 — Dashboard quay vòng vô hạn khi chưa có dữ liệu
`src/app.py`

**Hiện tượng.** Nhánh "chưa có log" gọi `st.rerun()` **không kèm `sleep`**. Mỗi vòng
là một lượt `list_blobs()` + download toàn bộ bucket, chạy nhanh hết mức CPU cho phép.
Trên Cloud Run đó vừa là instance thường trực 100% CPU vừa là hoá đơn GCS tăng không
giới hạn — và nó xảy ra đúng ở trạng thái *bình thường*, khi chưa chặn ai cả.

**Cách fix.** Gộp vào `schedule_refresh()` luôn có `sleep`. Chu kỳ lấy từ
`DASHBOARD_REFRESH_S` dùng chung cho cả nhãn checkbox và TTL của `st.cache_data`.
Giới hạn `DASHBOARD_MAX_LOG_FILES` (mặc định 50) chỉ đọc file mới nhất.

### FIX-16 — Upload GCS chạy đồng bộ ngay trên đường bắt gói
`src/gcs_utility.py`

**Hiện tượng.** `record_from_signature()` được `block_ip()` gọi đồng bộ trong vòng bắt
gói. Khi buffer đầy 100 000 dòng, nó gọi thẳng `flush_batch()` — serialize CSV và
upload lên GCS ngay tại đó. Cùng bản chất với FIX-07.

**Cách fix.**
- Đẩy flush khi đầy buffer sang luồng nền.
- `flush_loop` đổi `time.sleep` sang `Event.wait` để `stop()` đánh thức được ngay.
- Double-checked locking cho `get_collector()`: không có lock thì hai luồng gọi lần
  đầu cùng lúc sẽ tạo **hai** collector, log bị chia đôi ngẫu nhiên.
- Xoá `window_blocked` / `window_ips` — tính toán rồi reset mỗi lần flush nhưng không ai đọc.

> ⚠️ Chính bước xoá này gây ra **FIX-23**.

---

## 6. SỬA NHỎ & GIA CỐ (17 – 22)

### FIX-17 — Tên file log trùng giây làm mất trắng một lô log
`src/gcs_utility.py · flush_batch()`

**Hiện tượng.** Tên file chỉ có độ phân giải tới giây. Một lần flush theo chu kỳ trùng
giây với một lần flush do đầy buffer sẽ **ghi đè** lên nhau trên GCS. Không lỗi, không
cảnh báo — chỉ mất một lô log.

**Cách fix.** Thêm hậu tố ngẫu nhiên: `dirty_flows_<ts>_<uuid8>.csv`.

### FIX-18 — Quét whitelist tuyến tính ngay trên đường nóng
`src/enforcer.py · CidrIndex`

**Hiện tượng.** `any(addr in net for net in self.py_whitelist)` quét tuyến tính hơn
1 500 đối tượng `IPv4Network` cho *mỗi* flow bị nghi ngờ — đúng lúc đang bị tấn công
và cần CPU nhất.

**Cách fix.** `CidrIndex`: bảng băm theo độ dài prefix, tra từ prefix dài nhất xuống.
Tối đa 33 phép tra hash cho IPv4 và 129 cho IPv6, thực tế ít hơn nhiều. Đã kiểm chứng
khớp 10/10 trường hợp so với thư viện `ipaddress` chuẩn, gồm biên `/20`, host `/32`,
prefix IPv6 và chuỗi không hợp lệ.

### FIX-19 — Gói VLAN-tagged đi vòng qua toàn bộ blacklist
`src/xdp_filter.c`

**Hiện tượng.** Gói có tag 802.1Q mang `h_proto = ETH_P_8021Q` chứ không phải
`ETH_P_IP`, nên XDP trả `XDP_PASS` ngay mà không hề nhìn tới địa chỉ nguồn. Traffic có
tag bỏ qua sạch cả whitelist lẫn blacklist.

**Cách fix.** Bóc tối đa hai lớp VLAN tag (QinQ) bằng `#pragma unroll`, mỗi vòng tự
kiểm tra bounds để qua verifier. Tự khai báo `struct vlan_tag` thay vì phụ thuộc
`linux/if_vlan.h` — header đó không có mặt trên mọi bản linux-headers.

### FIX-20 — Container dashboard chạy bằng root
`Dockerfile`

**Hiện tượng.** Không có chỉ thị `USER`, nên Streamlit — tiến trình đối mặt Internet —
chạy dưới quyền root. `enableXsrfProtection` cũng không được đặt tường minh trong khi
`enableCORS` đã tắt.

**Cách fix.** Tạo user `socuser` (UID 10001), `chown` thư mục ứng dụng, chuyển `USER`
trước khi chạy. Bật `--server.enableXsrfProtection=true` tường minh.

### FIX-21 — Notifier đọc `.env` ngoài phạm vi dự án
`src/notifier.py · _auto_load_dotenv()`

**Hiện tượng.** Danh sách đường dẫn gồm `~/.env`, `/root/.env` và một đường dẫn
hardcode theo tên tài khoản của một máy cụ thể. Vừa không portable, vừa kéo biến môi
trường không liên quan của cả máy vào tiến trình IPS.

**Cách fix.** Thu hẹp còn ba nguồn: `GATEKEEPER_ENV_FILE` do người dùng chỉ định,
`.env` ở gốc dự án, `.env` ở thư mục làm việc hiện tại.

### FIX-22 — Không có cách nào phát hiện model bị đánh tráo
`src/trainer.py · src/gatekeeper.py`

**Hiện tượng.** `joblib.load()` thực chất là unpickle, tức là **thực thi mã tuỳ ý**
chứa trong file. Gatekeeper chạy dưới quyền root vì eBPF đòi hỏi thế. Một `binary.pkl`
bị đánh tráo sẽ chạy code của kẻ tấn công với quyền root, và không có gì để phát hiện.

**Cách fix.**
- `trainer.py` (và nay cả `recalibrate.py`) ghi `binary_sha256` vào `threshold.json`.
- `gatekeeper.py` đối chiếu hash **trước khi** gọi `joblib.load()` — kiểm tra sau khi
  đã unpickle thì đã muộn. Không khớp thì dừng hẳn.
- `GATEKEEPER_SKIP_INTEGRITY=1` cho trường hợp hợp lệ (vừa retrain trên máy khác).

Hash không ngăn được kẻ sửa được cả hai file. Nó biến một vụ đánh tráo âm thầm thành
một dòng cảnh báo nhìn thấy được — đó là toàn bộ mục tiêu.

---

## 7. VÒNG RÀ SOÁT THỨ HAI (23 – 30)

### FIX-23 — REGRESSION: mọi lượt chặn IP đều ném `AttributeError`
`src/gcs_utility.py · record_from_signature()`

**Hiện tượng.** FIX-16 xoá `window_blocked` và `window_ips` khỏi `__init__` vì không
ai đọc chúng — nhưng để sót đúng ba dòng vẫn *ghi* vào chúng. **Lỗi do chính vòng vá
trước gây ra.**

Hệ quả ẩn rất kỹ: `block_ip()` gọi hàm này bên trong `try/except`, nên mỗi lần chặn IP
chỉ in ra một dòng `[!] GCS logger error: ...` lẫn giữa hàng loạt dòng `[BLOCK]` trông
hoàn toàn bình thường. Việc chặn vẫn chạy, log vẫn lên GCS theo chu kỳ định kỳ —
nhưng **nhánh flush khi buffer đầy 100 000 dòng thì không bao giờ chạy tới**, vì
exception ném ra ngay trước nó.

**Cách fix.** Xoá nốt ba dòng còn sót.

Bài học: khi gỡ một thuộc tính, phải tìm hết *chỗ ghi* chứ không chỉ chỗ đọc — thuộc
tính chỉ-ghi-không-đọc vẫn làm chương trình chết như thường.

```
Kiểm chứng — gọi thẳng collector:
  TRƯỚC → AttributeError: 'DirtyFlowCollector' object has no attribute 'window_blocked'
  SAU   → OK, buffer=1
```

### FIX-24 — NFStream chết kéo sập luôn tầng chặn ở kernel
`src/gatekeeper.py · main()`

**Hiện tượng.** Vòng `for flow in streamer` nằm trần trong một `try` duy nhất, và khối
`finally` đi kèm gọi `enforcer.detach()`. Nghĩa là bất kỳ exception nào thoát ra từ
NFStream — libpcap mất interface, hết bộ nhớ, một gói dị dạng làm rơi luồng — đều dẫn
thẳng tới việc **gỡ chương trình XDP**.

Đây là điều tệ nhất có thể xảy ra vào đúng thời điểm tệ nhất. Một sự cố ở tầng *bắt
gói* (tầng chỉ để quan sát) lại tháo bỏ tầng *chặn* đang hoạt động: toàn bộ IP đang bị
ban lập tức đi qua được. Và những sự cố như vậy có xác suất cao nhất chính khi lưu
lượng đang cực lớn — tức là khi đang bị tấn công.

**Cách fix.**
- Tách vòng tiêu thụ flow thành `consume(streamer)`, bọc trong vòng supervisor tự dựng lại NFStream.
- `enforcer`, whitelist, model và sổ ban **giữ nguyên** qua mỗi lần khởi động lại —
  XDP không hề bị gỡ, IP đang bị ban vẫn bị chặn suốt thời gian đó.
- Backoff luỹ thừa 1s → 30s; chạy quá 60 giây thì reset về 1s vì đó là sự cố nhất thời.
- Mỗi lần khởi động lại in số IP còn trong sổ ban và bảng bộ đếm XDP.
- `detach()` chỉ chạy khi thoát thật sự (Ctrl+C).

### FIX-25 — Cơn bão gỡ ban giữ lock hàng giây
`src/enforcer.py · _memory_manager()`

**Hiện tượng.** Cải thiện trực tiếp cho **FIX-06**. Bản vá lần trước sửa đúng lỗi
`RuntimeError`, nhưng cách sửa lại tạo vấn đề mới: nó gọi `unban_ip()` cho từng IP
**ngay trong lock**, mỗi lượt kèm một syscall xoá eBPF map và một dòng `print`.

Vì gần như mọi lệnh ban đều dùng chung TTL 300 giây, cả một trận tấn công sẽ hết hạn
gần như *cùng một lúc*. Với 200 000 IP đó là 200 000 syscall nối tiếp nhau trong khi
vẫn giữ cái lock mà `block_ip()` ở luồng bắt gói đang chờ. IPS ngừng chặn suốt thời
gian đó — và chi phí này tăng **tuyến tính** theo quy mô trận tấn công.

**Cách fix.**
- Thêm min-heap `_ban_heap` theo mốc hết hạn. Vòng dọn dẹp chỉ chạm vào những IP *thật
  sự* đã hết hạn, thay vì quét lại toàn bộ sổ ban mỗi 5 giây.
- Chia ba bước: **chọn** danh sách trong lock → **xoá map** ngoài lock → **in một dòng
  tổng kết** thay vì một dòng mỗi IP.
- Trần `MAX_UNBAN_PER_CYCLE = 5 000` mỗi chu kỳ, nên thời gian giữ lock *có chặn trên*
  bất kể trận tấn công lớn cỡ nào.
- Bỏ qua entry cũ trong heap khi IP đã bị ban lại với hạn xa hơn — tránh gỡ nhầm một
  lệnh ban đang còn hiệu lực.

```
Kiểm chứng — thời gian giữ lock, chi phí syscall đo thật (2,99 µs/lần):

  N IP hết hạn      CŨ giữ lock    MỚI giữ lock
       50 000          171,8 ms         6,0 ms
      200 000          742,5 ms        10,9 ms
      500 000        1 716,0 ms         7,2 ms

  CŨ tăng tuyến tính · MỚI phẳng nhờ trần mỗi chu kỳ
```

### FIX-26 — Sổ ban là dict duy nhất còn lại không có giới hạn
`src/enforcer.py · ban_registry`

**Hiện tượng.** FIX-08 đã đổi `offense_counts` và `offense_history` sang `TTLCache` có
`maxsize`. Nhưng `ban_registry` bị bỏ sót — vẫn là `dict` thường, không giới hạn.

Đây đúng là kịch bản mà `GlobalFloodDetector` (FIX-03) sinh ra để bắt: flood với source
giả mạo. FLOOD MODE hạ ngưỡng per-IP xuống 1/10 nên tốc độ chặn tăng vọt lên hàng
nghìn IP mỗi giây, mỗi IP thêm một entry sống ít nhất 5 phút. Nói cách khác: **chính
cơ chế phòng thủ mới thêm vào lại là thứ làm đầy dict.**

**Cách fix.** Trần `MAX_TRACKED_BANS = 500 000`, bằng đúng `max_entries` của
`blacklist_map` trong `xdp_filter.c`. Giữ nhiều hơn là vô nghĩa vì LRU của kernel đã
đẩy entry cũ ra rồi. Chạm trần thì ép hết hạn IP có mốc gần nhất — cũng chính là IP mà
LRU của kernel sẽ loại trước.

### FIX-27 — Cảnh báo ngưỡng đặt ngược, im lặng đúng lúc cần kêu nhất
`src/gatekeeper.py · load_threshold()`

**Hiện tượng.** FIX-11 thêm cảnh báo cho trường hợp ngưỡng chưa hiệu chỉnh lại theo
model production. Nhưng điều kiện viết là `if meta.get("calibrated_on") == "eval_model"`
— chỉ kêu khi file *tự khai* mình có vấn đề.

Mà đúng file nguy hiểm nhất — `threshold.json` cũ, sinh ra *trước* khi FIX-11 tồn tại,
chứa ngưỡng `0.9999` lấy nguyên từ eval model — lại **không hề có trường đó**. Nên nó
chạy hoàn toàn im lặng. Đây chính là file đang nằm trên đĩa lúc này.

**Cách fix.**
- Đảo chiều: chỉ im lặng khi có *bằng chứng khẳng định* `calibrated_on == "production_model"`.
  Thiếu trường, sai giá trị, hay bất cứ gì khác đều cảnh báo.
- Đối chiếu thêm **tên và thứ tự** feature qua `feature_names`, không chỉ số lượng —
  hai bộ 18 feature khác thứ tự vẫn đếm ra 18 mà vector đưa vào model thì sai hoàn
  toàn. Lệch thì dừng hẳn.

```
Kiểm chứng — trên chính models/threshold.json đang có:
  calibrated_on = None
  Logic CŨ  có cảnh báo? False   ← im lặng
  Logic MỚI có cảnh báo? True    ← đã fix
```

### FIX-28 — Whitelist Canonical dựa vào câu trả lời DNS
`src/enforcer.py · _resolve_canonical_ips()`

**Hiện tượng.** FIX-01 giữ lại phần whitelist Canonical vì cho rằng cần cho
`apt update`. Đọc lại kỹ thì lập luận đó sai, và bản thân cơ chế cũng là phiên bản thu
nhỏ của chính lỗ hổng FIX-01:

- **Không cần thiết.** `apt` là kết nối do máy chủ *khởi tạo*, nên NFStream báo flow với
  `src_ip` là địa chỉ local và gatekeeper đã bỏ qua ở bước `local_ips`. Không có đường
  nào để Canonical bị đưa vào blacklist, nên whitelist nó không cứu được gì cả.
- **Nguy hiểm.** Whitelist theo DNS là whitelist theo thứ kẻ khác điều khiển được. Ai
  chi phối được câu trả lời DNS lúc IPS khởi động — resolver bị chiếm, cache poisoning,
  một máy cùng mạng — là tự đưa được IP của mình vào danh sách miễn nhiễm tuyệt đối.
  Thêm nữa `launchpad.net` và `canonical.com` nằm trên CDN dùng chung, nên một `/32` ở
  đó còn phục vụ cả những tên miền khác không liên quan.

**Cách fix.** Đưa ra sau cờ `WHITELIST_CANONICAL`, **mặc định tắt**, giống cách đã làm
với `WHITELIST_BULK_CLOUD`. Khi tắt, code in ra lý do đầy đủ để người vận hành hiểu vì
sao chứ không tưởng là thiếu sót.

### FIX-29 — Data plane hoàn toàn câm, không đếm được gói nào bị DROP
`src/xdp_filter.c · src/enforcer.py`

**Hiện tượng.** Chương trình XDP không có một bộ đếm nào. Mọi khẳng định về hiệu quả
chặn đều chỉ dựa vào log phía Python — tức là đếm số **quyết định** chặn, không phải
số **gói** bị chặn. Hai con số này khác nhau hàng nghìn lần, vì một lệnh ban duy nhất
chặn cả trận flood đi sau nó.

Với một đồ án thì đây là thiếu sót đáng kể: không có cách nào chứng minh nhánh VLAN
(FIX-19) và nhánh IPv6 (FIX-04) thật sự được đi qua, cũng không có con số nào cho phần
đánh giá hiệu năng của tầng kernel.

**Cách fix.**
- `BPF_PERCPU_ARRAY(stats_map, u64, 7)` với 7 ô: tổng gói, PASS do whitelist, DROP
  IPv4, DROP IPv6, gói có tag VLAN, gói IPv6, gói không phải IP.
- Dùng `PERCPU` chứ không phải biến chia sẻ: đây là đường nóng chạy ở tốc độ đường
  truyền, một cache line dùng chung giữa các lõi sẽ tự nó thành nút cổ chai.
- `enforcer.read_stats()` **cộng lại** giá trị của mọi CPU — lấy phần tử đầu tiên là số
  của đúng một lõi, tức là chia cho số lõi một cách âm thầm.
- `print_stats()` in bảng kèm tỉ lệ DROP, gọi ở mỗi lần supervisor khởi động lại và
  một lần cuối **trước** khi `detach()` — sau detach thì map biến mất cùng chương trình.

### FIX-30 — Dashboard không đối chiếu feature của model multiclass
`src/app.py · load_multiclass_model()`

**Hiện tượng.** FIX-09 thêm kiểm tra hợp đồng feature cho model nhị phân ở gatekeeper,
nhưng dashboard không có gì tương đương. Nếu `multiclass.pkl` cũ hơn `features.py`,
`model.predict()` ném lỗi ở mọi lần gọi và trang chỉ hiện một dòng warning nhỏ. Người
xem vẫn thấy một biểu đồ *"Attack Type Distribution"* trông bình thường — thực chất
đang vẽ bằng cột `reason`. Cùng bản chất "chết trong im lặng" với FIX-09.

**Cách fix.** Đối chiếu `n_features_in_` lúc nạp model. Lệch thì hiện `st.error` nói rõ
số feature của model, số feature hiện tại, và lệnh cần chạy; trả về `None` để dashboard
chuyển hẳn sang chế độ dùng nhãn `reason` một cách *tường minh*.

### Phụ — Tài liệu trong `notifier.py` ghi sai chu kỳ

**Hiện tượng.** Docstring đầu file mô tả máy trạng thái là *"mỗi 3 phút"* và *"sau 3
chu kỳ liên tiếp"*, trong khi code thực tế là `DIGEST_INTERVAL_S = 60` và
`_idle_cycles >= 2`. Nội dung tin Telegram gửi cho người vận hành cũng ghi cứng
*"mỗi 1 phút"*.

**Cách fix.** Đưa cả hai thành hằng số có tên (`DIGEST_INTERVAL_S`,
`IDLE_CYCLES_TO_CLEAR`, cấu hình được qua biến môi trường); docstring và tin nhắn đều
tham chiếu hằng số thay vì ghi cứng số.

Với một đồ án thì tài liệu sai còn khó chịu hơn không có tài liệu — người chấm sẽ tin
con số ghi trong docstring.

---

## 7b. FIX-31 — Ngưỡng hiệu chỉnh trên dữ liệu model đã học thuộc

`src/trainer.py · src/recalibrate.py · src/gatekeeper.py`

> Phát hiện khi chạy thử thật trên VM1. Đây là lỗi do **FIX-11 gây ra**.

**Hiện tượng.** Ngay lần chạy đầu trên VM, hệ thống chặn ba IP bằng tuyến AI với
`p = 0,9993 / 0,9968 / 0,9938`. Trong đó `151.101.128.223` thuộc dải
`151.101.0.0/16` của **Fastly CDN** — gần như chắc chắn là lưu lượng trả về từ
dịch vụ mà chính VM gọi ra (pip, apt, API). Chặn nó làm hỏng kết nối ra ngoài
của chính máy chủ.

Cả ba đều **dưới** ngưỡng cũ 0,9999 và **trên** ngưỡng mới 0,9649 — tức là chúng
bị chặn *chỉ vì* FIX-11 hạ ngưỡng.

**Nguyên nhân.** `transfer_threshold()` giữ nguyên *phân vị* của ngưỡng eval
trong phân phối điểm số benign của model production. Nhưng phân phối đó tính
trên chính dữ liệu mà model production **đã học thuộc**. Model chấm rất thấp cho
các dòng benign nó đã nhớ, nên phân vị cho ra ngưỡng thấp giả tạo.

Đo trực tiếp trên dữ liệu của dự án, dùng cùng một model (`binary_eval.pkl`) và
cùng một phân vị, chỉ khác dữ liệu là in-sample hay out-of-sample:

```
phân vị    ngưỡng IN-SAMPLE   ngưỡng ĐÚNG (out-of-sample)
0.999          0.906629              0.999389
0.9999         0.936523              0.999389
0.99998        0.958699              0.999611

Dùng ngưỡng in-sample 0.9587 (kỳ vọng FPR 0,002%)
→ FPR thực tế trên dữ liệu chưa thấy: 0,259%   — gấp 130 lần
```

Vấn đề gốc không nằm ở cách tính mà ở chính `binary.pkl`: nó fit trên **100%**
dữ liệu nên không còn dòng nào chưa thấy để hiệu chỉnh. **Không tồn tại** cách
hiệu chỉnh trung thực cho một model như vậy.

**Cách fix.** Deploy `binary_eval.pkl` — model fit ngày 1, đo ngày 2 chưa từng
thấy.

- `gatekeeper.py` nạp `binary_eval.pkl` thay vì `binary.pkl`.
- Gỡ hẳn `transfer_threshold()` khỏi `trainer.py`, thay bằng khối chú thích ghi
  lại số đo trên để không ai tái tạo lại lỗi này.
- `threshold.json` thêm trường `model_file`; gatekeeper `sys.exit(1)` nếu file
  đó không khớp model đang nạp — ngưỡng thuộc về model khác là dừng ngay.
- `binary.pkl` vẫn được train và lưu để tham khảo, nhưng không deploy.

**Lợi ích phụ cho đồ án:** model được deploy giờ **chính là** model đã đo. Không
còn hai bộ số "để chạy" và "để báo cáo" — chỉ còn một, và nó trung thực.

```
Sau khi sửa:
  Ngưỡng          : 0.9999
  FPR / TPR THẬT  : 0.0018% / 76.4452%   (đo trên ngày 2)
  Precision @ 0,1%: 97.73%

  193.47.62.69     p=0.9993  -> KHÔNG ban nữa
  2.57.121.112     p=0.9968  -> KHÔNG ban nữa
  151.101.128.223  p=0.9938  -> KHÔNG ban nữa
```

---

## 7c. FIX-32 — Không nhận đúng loại tấn công: lệch ngữ nghĩa feature

`src/features.py · extract_features()`

> Phát hiện khi test hping3 trên VM1: SYN flood chỉ ra nhãn chung
> `RATE_LIMIT (Volumetric)`, không bao giờ ra `Syn`.

**Hiện tượng.** Model multiclass biết 13 loại (`Syn`, `UDP`, `LDAP`, `MSSQL`,
`NTP`, `DNS`, `SSDP`, `NetBIOS`, `SNMP`, `TFTP`, `UDPLag`, `WebDDoS`, `BENIGN`)
và đạt **90,61%** trên dữ liệu CICDDoS2019 thật — **model không hỏng**. Nhưng
với vector do `extract_features()` sinh ra từ NFStream, nó đoán sai gần hết.

**Nguyên nhân — hai chỗ lệch ngữ nghĩa giữa CICFlowMeter và NFStream:**

| Cột | CICFlowMeter (dữ liệu train) | NFStream (code đang nạp) |
|---|---|---|
| `SYN/ACK Flag Count` | **cờ nhị phân 0/1** (max toàn tập = 1.00) | **số đếm gói**, có thể hàng nghìn |
| `Fwd/Bwd Packet Length` | độ dài **payload** | kích thước **cả khung** (+54B header) |

Hai cột này không phải chi tiết nhỏ. Đọc importance của chính `multiclass.pkl`:

```
32.47%  ACK Flag Count            <- feature QUAN TRỌNG NHẤT, đang nạp sai
14.61%  Fwd Packet Length Mean    <- lệch +54B
12.36%  Fwd Packet Length Min     <- lệch +54B
 9.79%  Bwd Packet Length Mean    <- lệch +54B
 ...
Tổng nhóm độ dài gói : 47.74%
Tổng nhóm thời gian  :  5.11%   <- nhóm NFStream không tái tạo được, nhưng vô hại
```

**80,2% sức mạnh quyết định của model đang được nạp giá trị sai.**

Bằng chứng rõ nhất cho chỗ độ dài gói: lớp `Syn` trong tập huấn luyện có
`Fwd Packet Length Mean` median = **0,00** — gói SYN không có payload. Nếu cột
đó đo cả khung thì giá trị phải là 54+, không đời nào bằng 0.

**Cách fix.**
- `SYN/ACK Flag Count` → cờ nhị phân: `1.0 if count > 0 else 0.0`.
- Trừ header khỏi mọi cột độ dài gói: 54 byte cho TCP (14 Eth + 20 IP + 20 TCP),
  42 byte cho UDP. Tổng byte trừ header của **từng gói**, không phải một lần.
- **Không** đụng `MIN_PACKETS_FOR_INFERENCE`: đã kiểm chứng trong 22 triệu dòng
  huấn luyện không có dòng nào ≤ 1 gói, nên ngưỡng 2 là đúng.
- **Không** bỏ nhóm feature thời gian: tuy NFStream chỉ có độ phân giải mili
  giây trong khi CICFlowMeter dùng micro giây, nhóm này chỉ chiếm 5,11%
  importance — không đáng để tái cấu trúc.

```
Kiểm chứng trên mẫu cân bằng theo lớp từ tập ngày 2:

  extract_features CŨ  (đang chạy trên VM) : 49.88%
  extract_features MỚI (đã sửa)            : 74.91%
  [trần] dữ liệu CICFlowMeter nguyên bản   : 74.91%   <- phục hồi HOÀN TOÀN

  Ví dụ lớp NetBIOS: nhận ra 49/800 dòng  ->  802/800 dòng
```

**Lưu ý còn lại.** Nếu tấn công dùng **một 5-tuple cố định** (`hping3 -s 5555 -k`),
NFStream gộp thành flow dài hàng giây trong khi CICFlowMeter tách thành micro-flow
2 gói — lúc đó `duration`/`rate` lệch 3 bậc và độ chính xác còn ~37,98%. Flood
thật ngoài đời dùng source port ngẫu nhiên nên tạo flow nhỏ, khớp với dữ liệu
huấn luyện. Đây là giới hạn cần nêu trong phần "hạn chế" của báo cáo, không phải
lỗi sửa được ở tầng code.

---

## 7d. FIX-33 — Ban nhầm lưu lượng tải về của chính máy chủ

**Hiện tượng.** Chạy `pip install -r requirements.txt` trên VM1 thì `151.101.0.223`
(Fastly CDN, chính là dải phục vụ `files.pythonhosted.org`) bị ban ngay lập tức:

```
timestamp                  src_ip           protocol  dst_port  pps      reason                     attack_type
2026-09-05 13:51:38+00:00  151.101.0.223    TCP       50350     1385.6   RATE_LIMIT (Volumetric)    BENIGN
```

Cột `attack_type` là **BENIGN** — model đã phán đúng. Rate limiter chặn đè lên.

**Nguyên nhân.** `1385,6 pps × WINDOW_SECONDS 5 = 6928 gói`, vượt `TOTAL_THRESHOLD
= 3000`. Rate limiter quyết định thuần theo khối lượng, không phân biệt được ai là
bên mở kết nối.

Chốt chặn duy nhất trước đó là `if flow.src_ip in local_ips: continue`, và nó
không bắt được ca này. Lý do: **NFStream gán hướng flow theo gói đầu tiên nó bắt
được**. Gatekeeper gắn vào interface giữa chừng, nên với một kết nối đi ra thì gói
đầu tiên nó thấy là gói máy chủ từ xa trả về — và máy chủ đó bị ghi nhận thành bên
khởi tạo. Hệ thống chưa hề có khái niệm "kết nối này do mình chủ động mở".

Đây **không phải ca lẻ**: mọi lượt tải nhanh hơn `3000 / 5 = 600` gói/giây từ một
host đều dính — `apt update`, `git clone`, `docker pull`, và cả lượt đọc GCS của
chính dashboard.

**Cách fix.** Dấu hiệu đáng tin là **cổng đích trên máy ta**, chứng cứ nằm ngay
trong log: `dst_port = 50350` là cổng ephemeral của VM1, không phải cổng dịch vụ.

Nguyên tắc: DDoS nhắm vào cổng dịch vụ (80, 443, 53...) vì mục tiêu là làm cạn
dịch vụ. Gói bắn vào cổng ephemeral ngẫu nhiên nơi không có gì lắng nghe chỉ khiến
kernel trả RST với chi phí không đáng kể.

```python
def is_reply_to_local_client(flow):
    if int(flow.protocol) not in (6, 17):
        return False

    dst_port = int(getattr(flow, "dst_port", 0))
    src_port = int(getattr(flow, "src_port", 0))

    if not (EPHEMERAL_PORT_MIN <= dst_port <= EPHEMERAL_PORT_MAX):
        return False

    return not (EPHEMERAL_PORT_MIN <= src_port <= EPHEMERAL_PORT_MAX)
```

Dải ephemeral đọc từ `/proc/sys/net/ipv4/ip_local_port_range` lúc khởi động, không
hard-code.

Điểm đặt trong vòng lặp là **sau `flood.observe()`**, có chủ đích: những gói này
vẫn phải cộng vào bộ đếm toàn cục, nếu không hệ thống sẽ mù trước tấn công vắt
kiệt băng thông nhắm vào cổng ephemeral. Chỉ miễn cho nó khỏi tuyến AI và rate
limiter per-IP — hai chỗ ra quyết định ban.

**Kiểm chứng.**

```
OK  pip/Fastly tra ve                  src=443    dst=50350  -> bo qua=True
OK  hping3 SYN vao web                 src=54321  dst=80     -> bo qua=False
OK  UDP flood vao DNS                  src=40000  dst=53     -> bo qua=False
OK  GCS doc log                        src=443    dst=44100  -> bo qua=True
OK  ICMP flood                         src=0      dst=0      -> bo qua=False
OK  Attack gia src 443 vao cong 80     src=443    dst=80     -> bo qua=False
```

Ca cuối quan trọng: attacker cố giả `src_port=443` để né vẫn bị bắt, vì cổng đích
80 không phải ephemeral. Muốn né thì phải bắn vào cổng ephemeral — nơi không có
dịch vụ nào để hạ.

Tắt bằng `TRUST_EPHEMERAL_REPLIES=0` nếu cần chứng minh hành vi cũ.

**Kèm theo.** `scripts/start.sh` vẫn kiểm tra `models/binary.pkl` tồn tại rồi mới
chạy, trong khi FIX-31 đã đổi model deploy sang `models/binary_eval.pkl` — chạy qua
script này sẽ tự abort. Đã sửa đường dẫn.

---

## 7e. FIX-34 & FIX-35 — Vẫn nhận sai loại: hai nguyên nhân độc lập

**Hiện tượng.** `hping3 -S -p 80 -i u1000` từ VM3 bị chặn đúng, nhưng dashboard gán
`attack_type = BENIGN`. Cùng một lệnh, lần trước ra `Syn`, lần sau ra `BENIGN`.

### Nguyên nhân 1 — `ACK Flag Count` không mang nghĩa như tên gọi

CICFlowMeter không điền hai cột cờ theo cờ TCP thật. Đo trên **dữ liệu gốc**:

```
file goc SYN-Flood.csv (capture cua chinh mot cuoc SYN flood):
    SYN Flag Count   mean = 0.0002     <- gan nhu luon 0
    ACK Flag Count   mean = 0.9996     <- gan nhu luon 1

tren ca 11 file goc:
    file             SYN mean  ACK mean  proto=6
    DNS.csv            0.0003    0.0040     1.4%
    LDAP.csv           0.0000    0.0001     0.1%
    MSSQL.csv          0.0000    0.0012     0.4%
    NTP.csv            0.0004    0.0295     8.8%
    NetBIOS.csv        0.0000    0.0014     0.4%
    SNMP.csv           0.0000    0.0001     0.0%
    SSDP.csv           0.0001    0.0008     0.2%
    SYN-Flood.csv      0.0001    0.9997   100.0%
    TFTP.csv           0.0002    0.9990    99.9%
    UDP-Flood.csv      0.0008    0.0050     1.0%
    UDP-Lag.csv        0.0001    0.5626    57.8%
```

`SYN Flag Count` ≈ 0 ở **mọi** lớp — cột chết, không mang một bit thông tin nào.
`ACK Flag Count` bám sát cột `Protocol == 6` — nó chỉ là **bản sao của Protocol**.

Parser không sai: nó chọn cột theo tên (`chunk[FEATURES]`), không theo vị trí, nên
không thể hoán vị. Dữ liệu gốc vốn như vậy.

FIX-32 tính `ack_count` theo nghĩa thật ("flow có gói ACK không"). SYN flood bắn
vào host không phản hồi thì không có gói ACK nào → `ack_count = 0`, trái ngược hẳn
dữ liệu huấn luyện. Đo trên 60.000 dòng thuộc lớp `Syn`:

```
nguyen ban tu dataset (SYN=0, ACK=1)     Syn=40.84%
nhu FIX-32 sinh ra    (SYN=1, ACK=0)     Syn= 5.81%  | BENIGN 84.3%
chi dao ACK -> 0                         Syn= 0.00%  | BENIGN 98.4%
chi dao SYN -> 1                         Syn=42.48%              <- cot chet
```

### Nguyên nhân 2 — dashboard dùng model không kiểm chứng được

Đây là **FIX-31 lặp lại nguyên vẹn cho tuyến multiclass**. `app.py` nạp
`multiclass.pkl`, model fit trên 100% dữ liệu.

```
                        Syn ngay 1        Syn ngay 2
multiclass.pkl            40.84%            99.97%    <- dashboard dang dung
multiclass_eval.pkl       99.72%            60.50%
```

`multiclass.pkl` sai **59,1% sang UDPLag** trên chính dữ liệu nó đã học thuộc.
Nguyên nhân: `cap_classes` lấy ngẫu nhiên 3 triệu dòng/lớp từ 5,94 triệu dòng `Syn`
gộp hai ngày, nên ~77% mẫu là ngày 2 và model bỏ rơi phân bố ngày 1.

`multiclass_eval.pkl` fit ngày 1 / chấm ngày 2 chưa từng thấy, nên có số đo trung
thực — trên mẫu 3,88 triệu dòng của tập kiểm tra:

| lớp | số dòng | recall | nhầm nhiều nhất sang |
|---|---:|---:|---|
| MSSQL | 1.117.218 | 93,86% | SNMP 2,1% |
| Syn | 911.924 | **88,17%** | BENIGN 6,8%, UDPLag 4,7% |
| UDP | 758.336 | 75,84% | SSDP 22,0% |
| NetBIOS | 704.611 | 99,72% | DNS 0,2% |
| LDAP | 374.456 | 80,06% | SNMP 15,9% |
| BENIGN | 11.400 | 96,49% | WebDDoS 2,4% |
| UDPLag | 332 | 59,04% | MSSQL 19,3% |

**Độ chính xác tổng: 88,73%.**

### Chứng minh cần cả hai fix

Dựng đúng vector NFStream sinh ra cho `hping3 -S -p 80 -i u1000`:

```
cach tinh 2 cot co                        multiclass.pkl    multiclass_eval.pkl
FIX-32 hien tai (SYN=1, ACK=0)              BENIGN (46%)           BENIGN (42%)
DE XUAT         (SYN=0, ACK=Protocol==6)    UDPLag (58%)              Syn (73%)
```

Sửa feature mà giữ `multiclass.pkl` → ra `UDPLag`. Đổi model mà không sửa feature →
vẫn `BENIGN`. Phải cả hai.

Cũng giải thích vì sao có lần ra `Syn`: lần đó lệnh có thêm `-d 120`, vector khác,
rơi đúng phía biên giới một cách may rủi.

### Cách fix

**FIX-34** — `features.py`, bám đúng ngữ nghĩa dataset thực sự ghi:

```python
syn_count = 0.0
ack_count = 1.0 if int(flow.protocol) == 6 else 0.0
```

**FIX-35** — `app.py` nạp `models/multiclass_eval.pkl` thay `models/multiclass.pkl`.

Không phải huấn luyện lại.

### Kiểm chứng

Cách gán mới có tái tạo đúng giá trị dataset không — đo trên 4,85 triệu dòng tập
kiểm tra:

```
ACK Flag Count == (Protocol==6) : 99.8402%
SYN Flag Count == 0             : 99.9944%
```

Khớp gần như tuyệt đối, nên con số 88,73% đo offline chuyển thẳng sang lúc chạy
thật — không còn khe hở train/serve ở hai cột này.

Chạy qua `extract_features()` thật sau khi sửa:

```
hping3 -S -p 80 (khung 54B, ko payload)  SYN=0 ACK=1  eval=Syn 64%
SYN flood 16 goi                         SYN=0 ACK=1  eval=Syn 75%
UDP flood cong 53 (doi chung)            SYN=0 ACK=0  eval=LDAP 62%
hping3 -S -p 80 -d 120                   SYN=0 ACK=1  eval=DNS 97%   <- xem duoi
```

**Hai giới hạn còn lại, cần nêu trong phần "hạn chế" của báo cáo.**

1. `-d 120` cho ra `DNS`. Lớp `Syn` trong dữ liệu huấn luyện có
   `Fwd Packet Length Mean` median = 0 — gói SYN không mang payload. Nhồi 120 byte
   payload vào gói SYN là hành vi không tồn tại trong dataset. Khi demo nên dùng
   `hping3 -S -p 80 -i u1000` không kèm `-d`.
2. UDP flood cổng 53 ra `LDAP` thay vì `UDP`. Các lớp `DNS`/`LDAP`/`SNMP`/`MSSQL`
   đều là tấn công phản xạ UDP với hồ sơ đặc trưng gần trùng nhau; trên 18 feature
   hiện có chúng không tách được. Thấy rõ trong bảng recall: `LDAP` nhầm sang
   `SNMP` 15,9%, `UDP` nhầm sang `SSDP` 22,0%.

**Hướng làm sạch triệt để (chưa làm).** Bỏ hẳn hai cột cờ khỏi `FEATURE_NAMES` — một
cột chết, một cột trùng `Protocol` — rồi chạy lại `parser.py` + `trainer.py`. Xoá
vĩnh viễn cái bẫy lệch ngữ nghĩa này, nhưng tốn vài giờ.

---

## 8. GHI CHÚ CHO BÁO CÁO ĐỒ ÁN

Sau FIX-31, **model được deploy chính là model đã đo** (`binary_eval.pkl`, fit ngày 1
/ chấm ngày 2). Nên chỉ còn **một** bộ số, dùng cho cả vận hành lẫn báo cáo:

| Chỉ số | Giá trị | Nguồn |
|---|---|---|
| Ngưỡng quyết định | **0.9999** | `threshold` |
| FPR trên benign | **0,0018%** | day-2 holdout |
| TPR trên attack | **76,45%** | day-2 holdout |
| Precision @ tỉ lệ tấn công 1% | 99,77% | suy ra từ FPR/TPR |
| Precision @ tỉ lệ tấn công 0,1% | 97,73% | suy ra từ FPR/TPR |

`binary.pkl` (fit trên 100% dữ liệu) **không** được deploy và **không** dùng để báo
cáo — nó đã nhìn thấy tập kiểm thử nên không đo được gì trung thực. Xem FIX-31.

Điểm đáng nói khi bảo vệ: đánh đổi có chủ ý ở ngưỡng 0,9999 là **bỏ ~20 điểm recall
để hạ FPR xuống 1/500**. Với một thiết bị chặn inline thì đây là lựa chọn đúng, vì
một false positive chặn nhầm người dùng thật, còn attack lọt qua vẫn còn tuyến rate
limiter và global flood detector đỡ. Chính lần chạy thử trên VM đã chứng minh điều
đó bằng thực nghiệm: ngưỡng thấp hơn (0,9649) lập tức chặn nhầm CDN thật.

---

## 9. BIẾN MÔI TRƯỜNG MỚI

Xem `.env.example` để biết đầy đủ. Các biến thêm trong hai vòng rà soát:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WHITELIST_CIDRS` | *(rỗng)* | Dải IP admin tự khai (văn phòng, VPN) |
| `WHITELIST_BULK_CLOUD` | `0` | Bật lại whitelist hàng loạt GCP/Fastly (FIX-01) |
| `WHITELIST_CANONICAL` | `0` | Bật lại whitelist Canonical bằng DNS (FIX-28) |
| `GLOBAL_SYN_THRESHOLD` | `2000` | Ngưỡng SYN toàn cục / 5s (FIX-03) |
| `GLOBAL_PACKET_THRESHOLD` | `20000` | Ngưỡng tổng gói toàn cục / 5s |
| `GLOBAL_SOURCE_THRESHOLD` | `500` | Ngưỡng số source khác nhau / 5s |
| `FLOOD_MODE_DIVISOR` | `10` | Hệ số hạ ngưỡng per-IP khi vào FLOOD MODE |
| `TRUST_EPHEMERAL_REPLIES` | `1` | Bỏ qua gói trả về cho kết nối máy tự mở (FIX-33) |
| `TG_DIGEST_INTERVAL_S` | `60` | Chu kỳ gửi digest Telegram |
| `TG_IDLE_CYCLES` | `2` | Số chu kỳ yên ắng trước khi báo hết bão |
| `GATEKEEPER_ENV_FILE` | *(rỗng)* | Đường dẫn `.env` chỉ định rõ (FIX-21) |
| `GATEKEEPER_SKIP_INTEGRITY` | `0` | Bỏ qua kiểm tra sha256 model (FIX-22) |
| `DASHBOARD_PASSWORD` | *(rỗng)* | Mật khẩu dashboard — **bắt buộc** (FIX-05) |
| `DASHBOARD_ALLOW_ANONYMOUS` | `0` | Cho phép không mật khẩu (chỉ khi có Cloud IAP) |
| `DASHBOARD_MAX_LOG_FILES` | `50` | Số file CSV đọc mỗi lần refresh (FIX-15) |
| `DASHBOARD_REFRESH_S` | `10` | Chu kỳ tự làm mới dashboard |
