# DDoS attack detection system using Machine Learning in Cloud Computing

## Monitoring mechanism

### Packet-based Analysis (DPI)

**Khái niệm:** Hệ thống chặn và đọc toàn bộ từng gói tin đi qua một điểm trong mạng — bao gồm cả phần **header** gồm địa chỉ IP, port, protocol và phần **payload** gồm nội dung thực sự bên trong. Kỹ thuật này gọi là **Deep Packet Inspection**.

**Cơ chế:** Luồng mạng được sao chép qua **cổng SPAN** trên switch hoặc một thiết bị tap vật lý. Công cụ như Wireshark hay TCPdump nhận bản sao này và lưu lại từng gói một dưới dạng file `.pcap`. Mỗi gói tin được phân tích riêng lẻ, hoàn toàn độc lập nhau.

```
[Network traffic]
      │
      │  SPAN port
      ▼
[Capture packet] → Header + Payload
      │
      ▼
    [DPI]
      │
      ▼
[Analysis engine]
      │
      ▼
[Alert / Report]
```

**Ưu điểm:**
 
- Thấy được toàn bộ nội dung hữu ích cho điều tra pháp y sau khi xảy ra sự cố
- Phát hiện được các mối đe dọa ẩn sâu trong payload mà phương pháp khác bỏ sót
- Không cần thiết bị hỗ trợ ở phía router/switch

**Nhược điểm:**
 
- Tốn tài nguyên cực kỳ lớn khi bị DDoS, mạng nhận hàng triệu gói/giây hệ thống không kịp xử lý
- Không scale được vì càng nhiều thiết bị mạng thì càng cần nhiều điểm capture riêng lẻ
- Tỷ lệ lưu trữ 1:1 mỗi byte trên mạng đều phải lưu lại

**Phân tích:**
 
Nội dung thực của từng gói tin, pattern trong payload, signature của malware cụ thể.

### Flow-based Analysis (NetFlow / IPFIX)

**Khái niệm:** Thay vì đọc từng gói tin, hệ thống nhóm các gói tin có chung 5 thuộc tính — gọi là **5-tuple** — thành một "flow", rồi chỉ xuất ra **metadata thống kê** của cả flow đó. Không có bất kỳ nội dung payload nào được lưu lại.
 
**5-tuple:**
 
| Thuộc tính |
|------------|
| Src IP     |
| Dst IP     | 
| Src Port   | 
| Dst Port   |
| Protocol   |

**Cơ chế:** Router và switch tự quan sát luồng traffic đi qua. Khi hai thiết bị liên lạc nhau, router gom tất cả gói tin thuộc cùng kết nối đó lại, tính toán các thống kê rồi xuất bản tin tóm tắt đến một **Flow Collector** qua các chuẩn NetFlow hoặc IPFIX. Công cụ như CICFlowMeter sau đó biến các bản tin này thành 80+ features dùng được cho ML.

```
[Network traffic]
      │
      │  Router / Switch
      ▼
[Group packets] → Src IP, Dst IP, Ports, Protocol
      │
      ▼
[Compute flow]
      │
      ▼
  [Export] → NetFlow / IPFIX
      │
      ▼
[Alert / Report]
```

**Ưu điểm:**
 
- Tỷ lệ nén ~500:1 so với packet capture băng thông export chỉ chiếm một phần nhỏ băng thông thực
- Tích hợp sẵn trên phần cứng: Cisco, Juniper, Palo Alto đều hỗ trợ NetFlow/IPFIX
- Một Flow Collector có thể nhận từ hàng trăm router/switch nhìn toàn bộ mạng từ một chỗ
- Không đọc payload nên không vi phạm quyền riêng tư, không vướng quy định pháp lý

**Nhược điểm:**
 
- Không thấy được nội dung payload các tấn công ẩn trong HTTP request body sẽ khó phát hiện hơn
- Phụ thuộc vào phần cứng phải hỗ trợ xuất flow thiết bị cũ hoặc consumer-grade thường không có
- Packet sampling trong sFlow có thể bỏ sót traffic nên kém chính xác hơn full flow export

**Phân tích:**
 
Hành vi thống kê của luồng mạng bao nhiêu gói, tốc độ, thời gian, cờ TCP, tỷ lệ gửi/nhận. Tín hiệu DDoS nằm hoàn toàn ở lớp này, không cần payload.

### Bảng so sánh

| Tiêu chí               | Packet-based          | Flow-based        |
|------------------------|-----------------------|-------------------|
| **Đơn vị**             | Từng gói tin riêng lẻ | Nhóm gói tin      |
| **Nội dung**           | Header + payload      | Metadata thống kê |
| **Tỷ lệ nén**          | ❌ 1:1               | ✅ ~500:1         |
| **Yêu cầu tài nguyên** | ❌ Rất cao           | ✅ Thấp           |
| **Khả năng scale**     | ❌ Kém               | ✅ Mạnh           |
| **Độ trễ**             | ⚠️ Realtime          | ✅ Near-realtime  |
| **Quyền riêng tư**     | ❌ Rủi ro cao        | ✅ An toàn        |