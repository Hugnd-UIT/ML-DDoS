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

## Features & Tool

**Source:** https://github.com/ahlashkari/CICFlowMeter

Để mô hình Học máy có thể phân tích được các tín hiệu điện tử thô trên đường truyền, toàn bộ lưu lượng mạng cần được chuyển đổi thành một cấu trúc dữ liệu dạng bảng. Bảng dưới đây trình bày Từ điển đặc trưng lưu lượng mạng được sử dụng làm đầu vào cho mô hình. Bộ đặc trưng này được ánh xạ trực tiếp từ tiêu chuẩn trích xuất của công cụ CICFlowMeter, mô tả một "Luồng mạng 5-Tuple". Các biến số này được chia làm hai cột cấu trúc: Feature và Description.

| **Feature**                | **Description**                                                      |
| -------------------------- | -------------------------------------------------------------------- |
| Flow duration              | Duration of the flow in microseconds                                 |
| Total Fwd Packet           | Total packets in the forward direction                               |
| Total Bwd Packets          | Total packets in the backward direction                              |
| Total Length of Fwd Packet | Total size of packets in the forward direction                       |
| Total Length of Bwd Packet | Total size of packets in the backward direction                      |
| Fwd Packet Length Min      | Minimum packet size in the forward direction                         |
| Fwd Packet Length Max      | Maximum packet size in the forward direction                         |
| Fwd Packet Length Mean     | Mean packet size in the forward direction                            |
| Fwd Packet Length Std      | Standard deviation of packet size in the forward direction           |
| Bwd Packet Length Min      | Minimum packet size in the backward direction                        |
| Bwd Packet Length Max      | Maximum packet size in the backward direction                        |
| Bwd Packet Length Mean     | Mean packet size in the backward direction                           |
| Bwd Packet Length Std      | Standard deviation of packet size in the backward direction          |
| Flow Bytes/s               | Number of flow bytes per second                                      |
| Flow Packets/s             | Number of flow packets per second                                    |
| Flow IAT Mean              | Mean inter-arrival time between packets in the flow                  |
| Flow IAT Std               | Standard deviation of inter-arrival time between packets in the flow |
| Flow IAT Max               | Maximum inter-arrival time between packets in the flow               |
| Flow IAT Min               | Minimum inter-arrival time between packets in the flow               |
| Fwd IAT Min                | Minimum inter-arrival time between forward packets                   |
| Fwd IAT Max                | Maximum inter-arrival time between forward packets                   |
| Fwd IAT Mean               | Mean inter-arrival time between forward packets                      |
| Fwd IAT Std                | Standard deviation of inter-arrival time between forward packets     |
| Fwd IAT Total              | Total inter-arrival time between forward packets                     |
| Bwd IAT Min                | Minimum inter-arrival time between backward packets                  |
| Bwd IAT Max                | Maximum inter-arrival time between backward packets                  |
| Bwd IAT Mean               | Mean inter-arrival time between backward packets                     |
| Bwd IAT Std                | Standard deviation of inter-arrival time between backward packets    |
| Bwd IAT Total              | Total inter-arrival time between backward packets                    |
| Fwd PSH Flags              | Number of PSH flags set in forward packets (0 for UDP)               |
| Bwd PSH Flags              | Number of PSH flags set in backward packets (0 for UDP)              |
| Fwd URG Flags              | Number of URG flags set in forward packets (0 for UDP)               |
| Bwd URG Flags              | Number of URG flags set in backward packets (0 for UDP)              |
| Fwd Header Length          | Total header bytes in the forward direction                          |
| Bwd Header Length          | Total header bytes in the backward direction                         |
| FWD Packets/s              | Number of forward packets per second                                 |
| Bwd Packets/s              | Number of backward packets per second                                |
| Packet Length Min          | Minimum packet length                                                |
| Packet Length Max          | Maximum packet length                                                |
| Packet Length Mean         | Mean packet length                                                   |
| Packet Length Std          | Standard deviation of packet length                                  |
| Packet Length Variance     | Variance of packet length                                            |
| FIN Flag Count             | Number of packets with FIN flag                                      |
| SYN Flag Count             | Number of packets with SYN flag                                      |
| RST Flag Count             | Number of packets with RST flag                                      |
| PSH Flag Count             | Number of packets with PSH flag                                      |
| ACK Flag Count             | Number of packets with ACK flag                                      |
| URG Flag Count             | Number of packets with URG flag                                      |
| CWR Flag Count             | Number of packets with CWR flag                                      |
| ECE Flag Count             | Number of packets with ECE flag                                      |
| Down/Up Ratio              | Download-to-upload ratio                                             |
| Average Packet Size        | Average packet size                                                  |
| Fwd Segment Size Avg       | Average segment size in the forward direction                        |
| Bwd Segment Size Avg       | Average segment size in the backward direction                       |
| Fwd Bytes/Bulk Avg         | Average bulk bytes in the forward direction                          |
| Fwd Packet/Bulk Avg        | Average bulk packets in the forward direction                        |
| Fwd Bulk Rate Avg          | Average bulk rate in the forward direction                           |
| Bwd Bytes/Bulk Avg         | Average bulk bytes in the backward direction                         |
| Bwd Packet/Bulk Avg        | Average bulk packets in the backward direction                       |
| Bwd Bulk Rate Avg          | Average bulk rate in the backward direction                          |
| Subflow Fwd Packets        | Average number of packets in a forward subflow                       |
| Subflow Fwd Bytes          | Average number of bytes in a forward subflow                         |
| Subflow Bwd Packets        | Average number of packets in a backward subflow                      |
| Subflow Bwd Bytes          | Average number of bytes in a backward subflow                        |
| Fwd Init Win Bytes         | Total bytes sent in the initial forward TCP window                   |
| Bwd Init Win Bytes         | Total bytes sent in the initial backward TCP window                  |
| Fwd Act Data Pkts          | Number of forward packets containing at least 1 byte of TCP payload  |
| Fwd Seg Size Min           | Minimum segment size in the forward direction                        |
| Active Min                 | Minimum active time before a flow becomes idle                       |
| Active Mean                | Mean active time before a flow becomes idle                          |
| Active Max                 | Maximum active time before a flow becomes idle                       |
| Active Std                 | Standard deviation of active time before a flow becomes idle         |
| Idle Min                   | Minimum idle time before a flow becomes active                       |
| Idle Mean                  | Mean idle time before a flow becomes active                          |
| Idle Max                   | Maximum idle time before a flow becomes active                       |
| Idle Std                   | Standard deviation of idle time before a flow becomes active         |