# DDoS attack detection system using Machine Learning in Cloud Computing

## Cơ sở lý thuyết

### 1. Biểu hiện vật lý và logic của hệ thống dưới tác động DDoS
Khi xảy ra DDoS Attack, server target sẽ bị giảm hiệu năng và điều này thông qua các biểu hiện sau:
* **Network Bandwidth Saturation:** Sự gia tăng đột biến malware traffic làm cạn kiệt dung lượng đường truyền vật lý, gây tắc nghẽn luồng dữ liệu tại các thiết bị Edge Routers.
* **Resource Exhaustion:** Hiệu suất sử dụng CPU và RAM của các thiết bị mạng (Router, Switch, Load Balancer) và Web Server đạt ngưỡng tối đa, dẫn đến tình trạng treo hệ thống.
* **State Table Exhaustion:** Điển hình trong các cuộc tấn công khai thác giao thức (TCP SYN Flood), số lượng lớn các half-open connections làm tràn state table của thiết bị, buộc hệ thống từ chối các yêu cầu kết nối hợp lệ mới.
* **QoS Degradation:** Đặc trưng bởi tỷ lệ packet loss gia tăng và latency tăng, gây gián đoạn hoàn toàn liên kết giữa client và server.

### 2. Hạn chế của Stateful Firewall
Việc áp dụng các bộ quy tắc tĩnh (ví dụ: Block IP) của tường lửa truyền thống sẽ kém hiệu quả trước các cuộc tấn công DDoS phân tán do các nguyên nhân sau:
* **Processing Overhead:** Stateful Firewall yêu cầu cấp phát tài nguyên hệ thống để duy trì và kiểm tra trạng thái của từng phiên kết nối. Dưới áp lực của hàng triệu yêu cầu/giây từ Botnet, tường lửa thường trở thành điểm nghẽn cổ chai và tê liệt trước khi các bộ quy tắc kịp phát huy tác dụng.
* **Bất cập trước IP Spoofing:** Trong các hình thức Reflection/Amplification DDoS, lưu lượng độc hại xuất phát từ các máy chủ dịch vụ hợp pháp (như DNS, NTP). Việc thiết lập quy tắc chặn tĩnh dựa trên IP nguồn sẽ dẫn đến tình trạng từ chối dịch vụ nhầm (False Positive) đối với các dịch vụ mạng thiết yếu.

### 3. Đánh giá tổng quan các bộ dữ liệu IDS/DDoS
Các bộ dữ liệu cổ điển như KDD99 hay NSL-KDD không còn phản ánh chính xác cấu trúc mạng và các kỹ thuật tấn công hiện đại (như Botnet IoT, tấn công mã hóa). Bộ dữ liệu CICIDS2017 mang tính bao quát đa dạng các rủi ro bảo mật (Web Attack, Brute Force), nhưng lại thiếu độ sâu chuyên biệt về dữ liệu để nhận diện các biến thể DDoS phức tạp.

### 4. Lý do chọn bộ dữ liệu CICDDoS2019
Nghiên cứu này lựa chọn bộ dữ liệu CICDDoS2019 làm tiêu chuẩn đánh giá dựa trên các ưu điểm vượt trội:
* **Tính chuyên sâu và cập nhật:** Tập dữ liệu tập trung hoàn toàn vào các kỹ thuật DDoS hiện đại, bao phủ các hình thức tấn công tầng ứng dụng (WebDDoS) và đa dạng các giao thức phản xạ (NTP, DNS, LDAP, SSDP, MSSQL, v.v.).
* **Thiết kế phương pháp luận kiểm thử chặt chẽ:** Tập dữ liệu được phân tách rõ ràng. Quá trình thu thập dữ liệu huấn luyện (Training day) bao gồm 12 loại hình tấn công DDoS. Ngược lại, tập kiểm thử (Testing day) được tinh giản còn 7 loại tấn công, đồng thời bổ sung một hình thức trinh sát mạng hoàn toàn mới (PortScan). Cấu trúc này mô phỏng môi trường Zero-day attack, cho phép đánh giá chính xác năng lực tổng quát hóa (generalization) của mô hình học máy khi đối mặt với các dạng lưu lượng bất thường chưa từng học qua.


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
| ------------------------| -----------------------| -------------------|
| **Đơn vị**             | Từng gói tin riêng lẻ | Nhóm gói tin      |
| **Nội dung**           | Header + payload      | Metadata thống kê |
| **Tỷ lệ nén**          | ❌ 1:1                 | ✅ ~500:1          |
| **Yêu cầu tài nguyên** | ❌ Rất cao             | ✅ Thấp            |
| **Khả năng scale**     | ❌ Kém                 | ✅ Mạnh            |
| **Độ trễ**             | ⚠️ Realtime            | ✅ Near-realtime   |
| **Quyền riêng tư**     | ❌ Rủi ro cao          | ✅ An toàn         |

### Methodology
Dữ liệu của CICDDoS2019 không được tạo ra từ mô phỏng lý thuyết mà được trích xuất từ một mạng lưới thử nghiệm (Testbed) thực tế:
* **Xây dựng hệ thống vật lý:** Mạng lưới victim được cấu trúc bao gồm các máy chủ Web Ubuntu, thiết bị tường lửa Fortinet và các máy trạm chạy hệ điều hành Windows. 
* **Benign Background Traffic:** Quá trình tạo lập traffic hợp lệ được thực hiện thông qua hệ thống B-Profile, giả lập hành vi tương tác tự nhiên của 25 người dùng qua các giao thức cơ bản (HTTP, HTTPS, FTP, SSH, Email), đảm bảo tính chân thực của đặc trưng mạng. 
* **Feature Extraction:** Toàn bộ lưu lượng mạng thô (dưới định dạng PCAP) được thu thập và phân tích thông qua bộ công cụ CICFlowMeter-V3. Đầu ra là các tập tin CSV chứa hơn 80 đặc trưng thống kê về luồng dữ liệu, tạo tiền đề vững chắc cho việc huấn luyện các thuật toán machine learning.

### Lý do chọn mô hình Tree-Based thay vì Deep Learning
Trong bài toán phát hiện và ngăn chặn tấn công DDoS, dữ liệu trích xuất từ Network Flow tồn tại dưới dạng bảng có cấu trúc (Tabular Data). Mô hình Tree-based mang lại hiệu quả so với Deep Learning nhờ các điểm:

* **1. Phù hợp với đặc điểm của dữ liệu dạng bảng (Tabular Data)**
Dữ liệu network flow là sự kết hợp của nhiều định dạng khác nhau: biến số lượng (độ dài gói tin, thời gian luồng) và biến phân loại (giao thức, cổng kết nối).

  * Mô hình Deep Learning: Bản chất CNN được thiết kế cho dữ liệu hình ảnh (không gian), còn RNN cho dữ liệu chuỗi thời gian (văn bản, âm thanh). Khi ép xử lý dữ liệu dạng bảng, mô hình cần rất nhiều tài nguyên toán học nhưng hiệu quả lại không cao.
  * Mô hình dạng Cây: Khớp hoàn toàn với dữ liệu dạng bảng. Nó xử lý trực tiếp được cả số và chữ, không bị ảnh hưởng bởi việc các cột dữ liệu lệch quy mô với nhau, giúp giữ nguyên giá trị nguyên bản của các đặc trưng mạng.

* **2. Quy luật phân tách dựa trên các ngưỡng logic**
Các dấu hiệu nhận biết cuộc tấn công DDoS thường tuân theo các quy luật logic dạng ngưỡng (If-Else). Ví dụ: Nếu số lượng gói tin trong 1 giây lớn hơn một ngưỡng X, đồng thời cờ SYN được bật, thì đó là tấn công.  

  * Mô hình dạng Cây hoạt động bằng cách liên tục chẻ nhánh dữ liệu dựa trên các câu lệnh điều kiện. Cách tiếp cận này trùng khớp với bản chất của các rule cấu hình an ninh mạng.  
  * Trong khi đó, Deep Learning cố gắng xấp xỉ quy luật này bằng các hàm số toán học phi tuyến phức tạp, vô tình làm phức tạp hóa một bài toán logic.

* **3. Tốc độ xử lý đáp ứng thời gian thực cho IPS**
Để xây dựng hệ thống ngăn chặn (IPS), mô hình bắt buộc phải đưa ra phán quyết trong vòng mili-giây trước khi web server bị nghẽn.

  * Mô hình dạng Cây sau khi train xong thực chất chỉ là một tập hợp các điều kiện If-Else chạy trực tiếp trên CPU. Phép toán này cực kỳ nhẹ và nhanh.  
  * Ngược lại, Deep Learning đòi hỏi hàng triệu phép tính nhân ma trận phức tạp. Nếu không có phần cứng chuyên dụng, nó sẽ gây ra độ trễ lớn, không khả thi cho một hệ thống IPS streaming thời gian thực.  

### So sánh các thuật toán ML
| **Tiêu chí**                         | **Decision Tree**                                                                      | **Random Forest**                                                                             | **XGBoost**                                                                                     | **Voting Classifier**                                                                          |
| --------------------------------------| ----------------------------------------------------------------------------------------| -----------------------------------------------------------------------------------------------| -------------------------------------------------------------------------------------------------| ------------------------------------------------------------------------------------------------|
| Cơ chế hoạt động                     | Sử dụng một cây logic duy nhất để phân loại dữ liệu từ trên xuống dưới.                | Gom kết quả của nhiều cây độc lập chạy song song, dùng số đông để ra quyết định.              | Xây các cây theo chuỗi tuần tự, cây sau tập trung sửa sai cho các cây phía trước.               | Kết hợp kết quả từ nhiều thuật toán khác nhau bằng cơ chế bỏ phiếu (cứng hoặc mềm).            |
| Khả năng chống học vẹt (Overfitting) | Kém nhất. Cây càng mọc sâu càng dễ bị bám sát vào dữ liệu nhiễu của tập train.         | Tốt. Nhờ cơ chế bốc thăm ngẫu nhiên dữ liệu cho từng cây, các lỗi sai lẻ tẻ sẽ bị triệt tiêu. | Rất tốt. Tích hợp sẵn các hàm phạt toán học để tự hãm độ phức tạp, không cho cây mọc thừa. chậm | Tối ưu. Điểm yếu của thuật toán này sẽ được bù đắp bằng điểm mạnh của thuật toán khác.         |
| Real-time Latency                    | Nhanh nhất. Chỉ tốn vài micro-giây vì cấu trúc lệnh rẽ nhánh siêu đơn giản.            | Trung bình. Tốc độ phụ thuộc vào tổng số lượng cây được cấu hình trong rừng.                  | Nhanh. Lõi thuật toán được tối ưu bằng C++ nên tốc độ tính toán ma trận rất cao.                | Chậm nhất. Hệ thống bắt buộc phải đợi tất cả các mô hình con chạy xong mới tổng hợp được điểm. |
| Ưu điểm cốt lõi                      | Mô hình rõ ràng, tốn ít tài nguyên phần cứng nhất.                                     | Độ ổn định cao, chạy mượt mà trên dữ liệu thực tế ngay cả khi không tinh chỉnh thông số. bình | Độ chính xác cao tối đa trên dữ liệu dạng bảng, xử lý thông minh các dòng bị thiếu số liệu.     | Khai thác được thế mạnh của cả 3 thuật toán đơn lẻ, cho ra kết quả toàn diện nhất.             |
| Hạn chế thực chiến                   | Mô hình có độ biến động cao, dễ đưa ra phán quyết sai nếu gặp dữ liệu mạng bị lag nhẹ. | Dung lượng lưu trữ file mô hình (.pkl) lớn, gây tốn tài nguyên bộ nhớ RAM khi vận hành.       | Đòi hỏi người làm hệ thống phải hiểu sâu để cấu hình tham số phức tạp.                          | Cồng kềnh, tốn tài nguyên hạ tầng Cloud do phải chạy đồng thời nhiều mô hình cùng lúc.         |

### Danh sách các kiểu DDoS sẽ áp dụng vào đồ án

```
                               ┌──────────────┐
                               │ DDoS Attacks │
                               └──────┬───────┘
                                      │
           ┌──────────────────────────┴──────────────────────────┐
           ▼                                                     ▼
┌────────────────────────────────────┐                ┌────────────────────────────────────┐
│         Reflection Attacks         │                │        Exploitation Attacks        │
└──────────────────┬─────────────────┘                └──────────────────┬─────────────────┘
                   │                                                     │
   ┌───────────────┼───────────────┐                     ┌───────────────┴───────────────┐
   ▼               ▼               ▼                     ▼                               ▼
┌───────────┐   ┌───────────┐   ┌───────────┐         ┌───────────┐                   ┌───────────┐
│ TCP Based │   │  TCP/UDP  │   │ UDP Based │         │ TCP Based │                   │ UDP Based │
└─────┬─────┘   └─────┬─────┘   └─────┬─────┘         └─────┬─────┘                   └─────┬─────┘
      │               │               │                     │                               │
      ├─► MSSQL       ├─► DNS         ├─► CharGen           └─► SYN Flood                   ├─► UDP Flood
      └─► SSDP        ├─► LDAP        ├─► NTP                                               └─► UDP-Lag
                      ├─► NETBIOS     └─► TFTP
                      ├─► SNMP
                      └─► PORTMAP
```

#### I. Reflection Attacks
Bản chất của nhóm tấn công này là spoofing địa chỉ IP của nạn nhân, sau đó gửi các truy vấn đến các máy chủ hợp lệ trên Internet. Các máy chủ này sẽ gửi gói dữ liệu phản hồi với dung lượng lớn hơn rất nhiều lần trực tiếp đến địa chỉ IP của nạn nhân, gây tắc nghẽn toàn bộ băng thông mạng.  
* **1. TCP-based attacks**
  * **MSSQL (Microsoft SQL Server Resolution Service):** Hình thức này khai thác dịch vụ phân giải của hệ quản trị cơ sở dữ liệu Microsoft SQL Server. Khi nhận được một gói tin truy vấn cấu hình (thường chỉ vài byte), máy chủ MSSQL sẽ phản hồi bằng một khối dữ liệu lớn chứa chi tiết về phiên bản và cấu trúc của cơ sở dữ liệu.  
  * **SSDP (Simple Service Discovery Protocol):** Giao thức này được sử dụng rộng rãi trong các thiết bị mạng gia đình và IoT (hỗ trợ UPnP) để tự động khám phá các dịch vụ trên mạng. Attacker kích hoạt lệnh tìm kiếm dịch vụ, khiến hàng loạt thiết bị đồng loạt dội ngược dữ liệu trạng thái mạng có kích thước lớn về victim.  
* **2. TCP/UDP-based attacks**
  * **DNS (Domain Name System)** Lợi dụng hệ thống phân giải tên miền. Bằng cách gửi một truy vấn đặc biệt (ví dụ: truy vấn ANY), kẻ tấn công buộc máy chủ DNS phải trả về toàn bộ các bản ghi liên quan đến một tên miền. Kích thước dữ liệu phản hồi có thể lớn gấp 50 đến 70 lần so với gói tin truy vấn ban đầu.  
  * **LDAP (Lightweight Directory Access Protocol):** Giao thức được sử dụng để duy trì và truy xuất thông tin danh bạ phân tán. Một truy vấn tìm kiếm nhỏ có thể kích hoạt máy chủ LDAP trả về toàn bộ danh sách người dùng hoặc cấu hình thư mục, tạo ra tỷ lệ khuếch đại lưu lượng cực kỳ cao.  
  * **NETBIOS (Network Basic Input/Output System):** Khai thác dịch vụ phân giải tên thiết bị trong các mạng cục bộ (LAN), đặc biệt trên hệ điều hành Windows. Máy chủ NetBIOS khi bị truy vấn sẽ gửi trả các bảng thông tin trạng thái mạng (NetBIOS name table) với dung lượng dư thừa.  
  * **SNMP (Simple Network Management Protocol):** Giao thức quản trị thiết bị mạng (Router, Switch). Bằng cách sử dụng lệnh GetBulk, kẻ tấn công yêu cầu thiết bị mạng cung cấp toàn bộ bảng thông tin thống kê định tuyến, dẫn đến việc thiết bị phản hồi bằng một luồng dữ liệu khổng lồ.  
  * **PORTMAP (RPCbind):** Dịch vụ ánh xạ cổng thường hoạt động trên các hệ thống Unix/Linux. Khi nhận được truy vấn, máy chủ Portmap sẽ xuất ra danh sách toàn bộ các dịch vụ RPC (Remote Procedure Call) đang chạy và các cổng tương ứng của chúng.  
* **3. UDP-based attacks**
  * **CharGen (Character Generator Protocol):** Một dịch vụ kiểm thử mạng nội bộ ra đời từ rất lâu. Dịch vụ này có đặc tính cốt lõi là liên tục sinh ra và gửi đi các chuỗi ký tự ngẫu nhiên ngay khi có bất kỳ kết nối nào được thiết lập.  
  * **NTP (Network Time Protocol):** Lợi dụng các máy chủ đồng bộ thời gian trên Internet. Kẻ tấn công gửi lệnh monlist (lệnh yêu cầu danh sách giám sát). Thay vì trả về thời gian, máy chủ NTP sẽ trả về danh sách 600 địa chỉ IP đã tương tác với nó gần đây nhất, tạo ra mức độ khuếch đại có thể lên tới 500 lần.  
  * **TFTP (Trivial File Transfer Protocol):** Giao thức truyền tải tập tin đơn giản không yêu cầu xác thực người dùng. Kẻ tấn công gửi một yêu cầu đọc tập tin (Read Request) với IP giả mạo. Máy chủ TFTP sẽ ngay lập tức tiến hành truyền các khối dữ liệu của tập tin đó đến địa chỉ của nạn nhân. 

#### II. Exploitation Attacks
Trái ngược với nhóm Phản xạ, nhóm Khai thác không cần đến máy chủ trung gian. Kẻ tấn công trực tiếp lợi dụng các lỗ hổng trong cơ chế hoạt động của giao thức mạng nhằm làm cạn kiệt tài nguyên xử lý (CPU, RAM, Bảng trạng thái) của hệ thống mục tiêu.  
* **1. TCP-based attacks**
  * **SYN Flood:** Đây là hình thức tấn công cạn kiệt tài nguyên kinh điển nhất, khai thác trực tiếp cơ chế bắt tay 3 bước (3-Way Handshake) của giao thức TCP. Kẻ tấn công gửi ồ ạt các gói tin yêu cầu kết nối (SYN), buộc máy chủ mục tiêu phải cấp phát bộ nhớ và trả lời bằng gói SYN-ACK. Tuy nhiên, kẻ tấn công không bao giờ gửi lại gói ACK cuối cùng. Hậu quả là máy chủ bị quá tải do phải duy trì một lượng khổng lồ các "kết nối bán mở" (half-open connections) trong bộ nhớ, dẫn đến việc không thể tiếp nhận thêm các yêu cầu hợp lệ từ người dùng thực.  
* **2. UDP-based attacks**
  * **UDP Flood:** Hình thức tấn công trực tiếp bằng cách làm tràn ngập một số lượng lớn các gói tin UDP ngẫu nhiên vào các cổng của máy chủ mục tiêu. Do đặc tính không yêu cầu thiết lập kết nối trước của UDP, máy chủ mục tiêu bắt buộc phải tiếp nhận gói tin, kiểm tra xem có ứng dụng nào đang lắng nghe tại cổng đó không, và sau đó tốn tài nguyên để tạo và gửi lại gói tin báo lỗi ICMP Destination Unreachable. Quá trình này làm vắt kiệt năng lực xử lý của hệ thống.  
  * **UDP-Lag:** Đây là một biến thể khai thác độ trễ của mạng. Thay vì gây tràn ngập băng thông, kẻ tấn công gửi các khối dữ liệu UDP với nhịp độ bất thường hoặc bị đứt đoạn. Mục tiêu là phá vỡ sự đồng bộ thời gian và làm gián đoạn liên kết giữa máy khách và máy chủ, đặc biệt gây ảnh hưởng nghiêm trọng đến các ứng dụng yêu cầu xử lý thời gian thực (như VoIP, các hệ thống trò chơi trực tuyến, hoặc thiết bị hội nghị trực tuyến).  

## Features & Tool

**Source:** https://github.com/ahlashkari/CICFlowMeter

Để mô hình Học máy có thể phân tích được các tín hiệu điện tử thô trên đường truyền, toàn bộ lưu lượng mạng cần được chuyển đổi thành một cấu trúc dữ liệu dạng bảng. Bảng dưới đây trình bày Từ điển đặc trưng lưu lượng mạng được sử dụng làm đầu vào cho mô hình. Bộ đặc trưng này được ánh xạ trực tiếp từ tiêu chuẩn trích xuất của công cụ CICFlowMeter, mô tả một "Luồng mạng 5-Tuple". Các biến số này được chia làm hai cột cấu trúc: Feature và Description.

**Danh sách các field giữ lại sau khi lọc**
Trong các file dữ liệu csv của CICDDoS2019 dữ liệu có 88 trường nhưng ở giai đoạn Preprocessing cần lược bỏ bớt để tránh trùng lặp dữ liệu, tốn tài nguyên và tránh để AI không bị “lười” dẫn đến phán đoán sai.

### Danh sách các trường đặc trưng sau khi lọc (Feature Selection)

Để tối ưu hóa tài nguyên tính toán, tăng tốc độ xử lý thời gian thực cho hệ thống IPS và tránh hiện tượng mô hình học vẹt (Overfitting), hệ thống tiến hành lọc bỏ các trường trùng lặp và giữ lại 20 trường đặc trưng cốt lõi thuộc 5 nhóm chức năng sau:

| Nhóm đặc trưng                                        | Feature (Tên trường)          | Ý nghĩa thực chiến & Cơ chế nhận diện                                                                                                                                                                                              |
| :------------------------------------------------------| :------------------------------| :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1. Cường độ & Lưu lượng (Volumetric)**              | `Flow Duration`               | Xác định tổng thời gian sống của luồng. Giúp bắt được các đòn tấn công "ngâm" kết nối lâu như Slowloris, hoặc hành vi xả đạn chớp nhoáng rồi tắt.                                                                                  |
|                                                       | `Flow Bytes/s`                | Đo lượng byte truyền đi trên giây. Bắt trực tiếp các hành vi nhồi nhét, vắt kiệt băng thông tầng mạng (UDP Flood, ICMP Flood).                                                                                                     |
|                                                       | `Flow Packets/s`              | Đo số lượng gói tin trên giây. Bắt hành vi chia nhỏ gói tin với mật độ cao nhằm đánh gục năng lực xử lý CPU của thiết bị định tuyến.                                                                                               |
|                                                       | `Total Fwd Packets`           | Tổng số lượng gói tin được truyền đi theo chiều thuận (Forward).                                                                                                                                                                   |
|                                                       | `Total Bwd Packets`           | Tổng số lượng gói tin phản hồi về theo chiều nghịch (Backward).                                                                                                                                                                    |
|                                                       | `Down/Up Ratio`               | Tỉ lệ gói dữ liệu tải xuống/tải lên. Dấu hiệu sống còn để vạch mặt các cuộc tấn công phản xạ khuếch đại (DNS/NTP Amplification) khi tỷ lệ gửi/nhận bị lệch vọt lên hàng chục lần (Gửi 1 nhận 50).                                  |
| **2. Kích thước tải trọng (Payload Size)**            | `Total Length of Fwd Packets` | Tổng dung lượng dữ liệu truyền đi theo chiều thuận. Giúp AI tính toán chính xác tải trọng thực tế mà hệ thống đang phải gồng gánh.                                                                                                 |
|                                                       | `Total Length of Bwd Packets` | Tổng dung lượng dữ liệu phản hồi về theo chiều nghịch.                                                                                                                                                                             |
|                                                       | `Fwd Packet Length Max`       | Kích thước gói tin lớn nhất theo chiều thuận. Bắt lỗi cấu hình cố định phi lý của Botnet rác (Nếu Max, Min, Mean bằng nhau, AI sẽ định danh ngay đây là tool xả rác tự động thay vì con người lướt web).                           |
|                                                       | `Fwd Packet Length Min`       | Kích thước gói tin nhỏ nhất theo chiều thuận.                                                                                                                                                                                      |
|                                                       | `Fwd Packet Length Mean`      | Kích thước gói tin trung bình theo chiều thuận.                                                                                                                                                                                    |
|                                                       | `Bwd Packet Length Mean`      | Kích thước gói tin trung bình trả về từ máy chủ. Giúp đối chiếu xem máy chủ có đang phải trả về các trang báo lỗi hệ thống (503 Service Unavailable) hàng loạt hay không.                                                          |
| **3. Nhịp điệu thời gian (Inter-Arrival Time - IAT)** | `Flow IAT Mean`               | Khoảng cách thời gian trung bình giữa các gói tin trong một luồng. Giúp phân biệt "người" và "máy" (Botnet thường xả đạn theo vòng lặp lệnh cố định nên khoảng cách cực kỳ đều đặn).                                               |
|                                                       | `Flow IAT Std`                | Độ lệch chuẩn của khoảng cách thời gian giữa các gói tin. Đối với mã độc tự động, độ lệch chuẩn này sẽ tiệm cận bằng 0; ngược lại người dùng thật sẽ bấm click ngẫu nhiên.                                                         |
|                                                       | `Fwd IAT Total`               | Tổng thời gian trễ của toàn bộ các gói tin gửi đi, dùng để củng cố độ chính xác cho việc phân tích nhịp điệu của luồng.                                                                                                            |
| **4. Giao thức & Vân tay cấu hình (Fingerprinting)**  | `Protocol`                    | Định danh giao thức mạng (TCP, UDP...). Cung cấp ngữ cảnh để AI áp dụng trọng số logic chính xác, vì hành vi của UDP hoàn toàn khác với TCP SYN Flood.                                                                             |
|                                                       | `SYN Flag Count`              | Số lượng gói tin được bật cờ thiết lập kết nối (SYN). Bộ đôi kết hợp cùng ACK Flag để tiêu diệt các cuộc tấn công cạn kiệt tài nguyên kết nối dạng TCP SYN Flood.                                                                  |
|                                                       | `ACK Flag Count`              | Số lượng gói tin được bật cờ xác nhận kết nối (ACK). Nếu lượng cờ SYN chiếm đa số tuyệt đối mà vắng bóng cờ ACK, hệ thống khẳng định là tấn công half-open.                                                                        |
|                                                       | `Init_Win_bytes_forward`      | Kích thước cửa sổ TCP ban đầu (TCP Window Size) theo chiều thuận. Đây là dấu vết "vân tay cấu hình" không thể chối cãi vì các công cụ tấn công lỏ thường không giả lập được thông số này giống hệ điều hành chuẩn (Windows/Linux). |
| **5. Nhãn hệ thống (Mandatory)**                      | `Label`                       | Cột nhãn mục tiêu (Benign hoặc tên cụ thể của loại hình DDoS). Trường bắt buộc phục vụ quá trình huấn luyện có giám sát (Supervised Learning) và được lược bỏ khi đưa mô hình ra môi trường thực tế.                               |

### Kiến trúc huấn luyện mô hình ML

```
                        ┌───────────────────────┐
                        │      Dữ liệu thô      │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │   Tiền xử lý dữ liệu  │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  Trích xuất đặc trưng │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │ Huấn luyện mô hình ML │
                        └───────────┬───────────┘
                                    │
             ┌──────────────────────┴──────────────────────┐
             │                                             │
          Luồng 1                                       Luồng 2
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│    Phân loại Nhị phân   │           │       Phân loại Đa      │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│    Chia tập dữ liệu     │           │    Chia tập dữ liệu     │
│    Train/Test 80/20     │           │    Train/Test 80/20     │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│ Huấn luyện 4 thuật toán │           │ Huấn luyện 4 thuật toán │
│ DT, RF, XGBoost, Voting │           │ DT, RF, XGBoost, Voting │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│   Chấm điểm Benchmark   │           │   Chấm điểm Benchmark   │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│      Xuất file .pkl     │           │      Xuất file .pkl     │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                             │
             ▼                                             ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│   Chặn DDoS Real-time   │           │   Phân tích DDoS lên    │
│                         │           │        Dashboard        │
└─────────────────────────┘           └─────────────────────────┘
```

* **Luồng 1: Inline Real-Time IPS**
  * **Mục tiêu:** Giải quyết bài toán phân loại nhị phân. Tại bước này, toàn bộ tập dữ liệu gốc CICDDoS2019 chứa các nhãn tấn công đa dạng (SYN, UDP, NetBIOS...) sẽ được ánh xạ và rút gọn về một trạng thái duy nhất là nhãn 1 (DDoS), trong khi các lưu lượng hợp lệ giữ nhãn 0 (Normal).  
  * **Tiến trình thực nghiệm:**
    * **Phân chia dữ liệu:** Tập dữ liệu nhị phân sạch được chia tách theo tỷ lệ 80% để huấn luyện (Train set) và 20% để kiểm thử độc lập (Test set).  
    * **Huấn luyện và Đánh giá:** Hệ thống tiến hành huấn luyện đồng thời 4 thuật toán cốt lõi bao gồm Decision Tree, Random Forest, XGBoost và Voting Classifier. Quá trình đánh giá Benchmark ở luồng này đặt ưu tiên hàng đầu vào chỉ số Inference Latency và F1-Score, nhằm tìm ra mô hình có khả năng đưa ra phán đoán nhanh nhất trong môi trường RAM thực tế.  
  * **Môi trường triển khai:** Mô hình tối ưu sau bước Benchmark được đóng gói thành tệp .pkl. Tệp này được triển khai trực tiếp tại card mạng của Máy ảo Gác cổng. Mô hình thực hiện quét dòng chảy dữ liệu liên tục từ công cụ trích xuất thời gian thực, nếu phát hiện dấu hiệu DDoS, hệ thống ngay lập tức thực thi lệnh tường lửa (iptables DROP) để chặn đứng tác nhân tấn công trong vòng mili-giây, bảo vệ tính toàn vẹn của Web Server phía trong.  
* **Luồng 2: Out-of-Band Analytics Dashboard**
  * **Mục tiêu:** Giải quyết bài toán phân loại đa lớp. Trái với Luồng 1, tập dữ liệu ở luồng này giữ nguyên cấu trúc của từng loại hình tấn công DDoS cụ thể (ví dụ: phân tách rõ ràng đâu là tấn công phản xạ tầng ứng dụng, đâu là tấn công tràn ngập tầng mạng) kết hợp cùng nhãn lưu lượng sạch (Normal).  
    * **Tiến trình thực nghiệm:**
      * **Phân chia dữ liệu:** Áp dụng đồng bộ tỷ lệ phân tách 80/20 trên cùng một cơ sở hạ tầng phân phối đặc trưng nhằm đảm bảo tính đối sánh khoa học giữa hai luồng.  
      * **Huấn luyện và Đánh giá (Benchmark):** Tiếp tục đưa 4 thuật toán (DT, RF, XGBoost, Voting Classifier) vào môi trường huấn luyện đa lớp. Tiêu chí chấm điểm Benchmark tại nhánh này ưu tiên tối đa cho Độ chính xác theo từng lớp (Class-specific Accuracy) và Ma trận nhầm lẫn (Confusion Matrix) nhằm đảm bảo hệ thống có thể bóc tách, gọi tên chính xác cơ chế tấn công của hacker mà không bị nhầm lẫn giữa các kỹ thuật DDoS có hành vi tương đồng.  
    * **Môi trường triển khai ứng dụng:** Mô hình đa lớp chiến thắng sau thực nghiệm được xuất thành tệp .pkl thứ hai. Về mặt kiến trúc, mô hình này không tham gia vào quá trình chặn dòng traffic trực tiếp (để tránh gây nghẽn mạch hệ thống). Thay vào đó, nó được triển khai ở chế độ bất đồng bộ (Out-of-band) tại tầng xử lý hậu phương hoặc Điện toán đám mây. Mô hình chỉ tiếp nhận các tệp nhật ký (Log) hoặc các dòng dữ liệu luồng độc hại đã bị Luồng 1 phát hiện, tiến hành định danh chính xác chủng loại tấn công, và đẩy số liệu trực quan lên giao diện Dashboard (Streamlit) phục vụ công tác thống kê và báo cáo an ninh mạng. 

### Sơ đồ kiến trúc triển khai hệ thống trên Cloud 

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           INTERNET                                           │
│                ┌──────────────┐                                             ┌───────────┐    │
│                │     User     │                                             │    SOC    │    │
│                └──────┬───────┘                                             └─────┬─────┘    │
└───────────────────────┼───────────────────────────────────────────────────────────┼──────────┘
                        │ Truy cập IP Public                                        │
────────────────────────┼───────────────────────────────────────────────────────────┼───────────
                        ▼                                                           │
┌──────────────────────────────────────────────────────────┐                        │
│                       MẠNG NỘI BỘ                        │                        │
│  ┌────────────────────────────────────────────────────┐  │                        │
│  │        VM3: Google Compute Engine Attacker         │  │                        │
│  └──────────────────────────┬─────────────────────────┘  │                        │
│                             │ DDoS qua IP Nội bộ         │                        │
│                             ▼                            │                        │
│               ┌───────────────────────────┐              │                        │
│               │    VM1: Google Compute    │◄. . . . . . .┼. . . . . . . . . . . . ┤
│               │    Engine IPS Gác Cổng    │   Nạp file   │                        ·
│               └──────┬─────────────┬──────┘  binary.pkl  │                        ·
│                      │             │                     │                        ·
│  HỢP LỆ:             │             │ DDoS: Chặn bằng     │                        ·
│  Forward qua LAN     │             │ iptables & Bắn Log  │                        ·
│                      ▼             ▼                     │                        ·
│  ┌──────────────────────┐    ┌───────────────────────────┼──────────────┐         ·
│  │ VM2: Google Compute  │    │       Ổ CỨNG ĐÁM MÂY      │              │         │ Xem biểu đồ
│  │  Engine Web Server   │    │ ┌──────────────────────┐  │              │         │
│  └──────────────────────┘    │ │ Google Cloud Storage │  │              │         │
└──────────────────────────────│ │  Kho lưu .pkl & Log  │  │              │         │
                               │ └──────────┬─────────┬─┘  │              │         │
                               └────────────┼─────────┼────┘              │         │
                                            │         │                   │         │
                                   Nạp file │         │ Truy xuất         │         │
                             multiclass.pkl │         │ Log độc hại       │         │
                                            ▼         ▼                   ▼         ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     GIAO DIỆN SERVERLESS                                     │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                             Google Cloud Run SOC Dashboard                             │  │
│  └────────────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Cấu trúc Repos

```
ML-DDoS/
├── .dockerignore                 # Ẩn file không cần build vào Docker
├── .gitignore                    
├── Dockerfile                    # Dockerfile cho SOC Dashboard (Cloud Run)
├── README.md                     
├── requirements.txt              # Danh sách thư viện
│
├── data/                         # Chứa dataset CICDDoS2019 lúc test local
│   └── .gitkeep
│
├── models/                       # Nơi chứa file model sau khi train hoặc pull từ GCS về
│   └── .gitkeep
│
├── scripts/                      # Các script tiện ích hỗ trợ
│   ├── setup.sh                  # Script cài ipset, iptables, python trên VM1
│   └── simulate_attack.sh        # Script chạy hping3 để test trên VM (Attacker)
│
└── src/                          # Code lõi của hệ thống
    ├── __init__.py             
    ├── config.py                 # Chứa API Key Telegram, GCS Bucket Name, Active Timeout
    │
    ├── # --- NHÓM MODULE AI & PROCESSING ---
    ├── parser.py                 # Tiền xử lý dữ liệu, chuẩn hóa Features
    ├── trainer.py                # Train mô hình Binary & Multiclass
    │
    ├── # --- NHÓM MODULE TUYẾN ĐẦU (CHẠY TRÊN VM1) ---
    ├── collector.py              # Lắng nghe card mạng bằng NFStream
    ├── enforcer.py               # Thực thi lệnh iptables / ipset DROP
    ├── notifier.py               # Gửi tin nhắn cảnh báo qua Telegram
    ├── gcs_utility.py            # Upload log bẩn lên Cloud Storage
    ├── gatekeeper.py             # File chạy chính cho VM1 (Nối collector + enforcer + notifier)
    │
    └── dashboard/                # Chứa code Web SOC Dashboard (Chạy trên Cloud Run)
        ├── app.py                # Web Server (Flask/FastAPI/Streamlit)
        ├── static/               # CSS, JS, Images cho Dashboard
        └── templates/            # HTML Templates
```

## Rủi ro và hạn chế

* **1. Hạn chế về Hiệu năng**
    * Rủi ro lọt gói tin ở chu kỳ đầu tiên: Thư viện NFStream vận hành dựa trên cơ chế gom gói tin thô thành Luồng với một khoảng thời gian trễ nhất định (Active Timeout mặc định = 1 giây). Do đó, trong giây đầu tiên khi cuộc tấn công bùng phát, toàn bộ bão gói tin vẫn được hệ điều hành chuyển tiếp trực tiếp sang Web Server (VM2) trước khi AI kịp đưa ra phán quyết và ra lệnh chặn.
    * SoftIRQ Bottleneck: Đối với các cuộc tấn công dạng Volumetric DDoS sử dụng gói tin kích thước nhỏ (như SYN/UDP Flood) với mật độ vượt ngưỡng 150.000 PPS, tài nguyên CPU của con VM1 sẽ bị vắt kiệt hoàn toàn cho tiến trình xử lý ngắt mạng (ksoftirqd). Điều này khiến tầng Ứng dụng bị bỏ đói tài nguyên, script Python chứa AI bị đóng băng và mất khả năng kích hoạt tường lửa.

* **2. Software Architectural Ceiling**
    * Điểm nghẽn xử lý đơn luồng của Python (GIL Constraint): Do ảnh hưởng của cơ chế GIL, AI chỉ có thể chạy trên một lõi CPU duy nhất tại một thời điểm. Khi đối đầu với Botnet phân tán quy mô lớn, số lượng luồng độc lập xuất hiện đồng thời nhiều, hàng đợi của Python sẽ bị tràn, triệt tiêu tính Real-time của hệ thống.
    * Chi phí tài nguyên (Syscall Overhead): Việc script Python sử dụng các phương thức CLI truyền thống (subprocess hoặc os.system) để đẩy IP DDoS vào ipset tạo ra xung đột tài nguyên rất lớn (Overhead do phải liên tục Fork/Exec tiến trình con). Tốc độ thực thi chặn bị giới hạn cơ học ở ngưỡng ~1.000 IP/giây, tạo khe hở thời gian cho traffic bẩn lọt lưới.
    * Firewall Set Overflow: Công cụ ipset của Linux khi khởi tạo mặc định chỉ cho phép chứa tối đa 65.536 phần tử (maxelem). Nếu đối đầu với các đợt tấn công Botnet toàn cầu có số lượng IP vượt quá con số này, hệ thống tường lửa tầng kernel sẽ báo lỗi tràn bộ nhớ và từ chối nhận thêm luật chặn mới.

* **3. Enterprise Production Risks**
    * Single Point of Failure - SPOF: Kiến trúc hiện tại đặt con VM1 làm gác cổng inline duy nhất. Nếu script Python bị sập do lỗi ngoại lệ chưa được bắt (Uncaught Exception) hoặc con VM1 gặp sự cố hạ tầng, toàn bộ luồng mạng của doanh nghiệp sẽ rơi vào trạng thái Fail-Closed hoặc Fail-Open.
    * State Isolation: Danh sách IP bị khóa bằng ipset chỉ tồn tại cục bộ trong bộ nhớ RAM của riêng con VM1. Kiến trúc này không có khả năng đồng bộ trạng thái nếu doanh nghiệp có nhu cầu mở rộng quy mô lên thành một cụm nhiều con IPS để chia tải.
    * Rủi ro leo thang đặc quyền: Để thực thi được lệnh ipset add tầng sâu, tiến trình Python bắt buộc phải được cấp đặc quyền Root. Do script Python liên tục bóc tách và phân tích các gói tin thô không đáng tin cậy từ Internet dội vào (NFStream parsing), nếu hacker khai thác được lỗi tràn bộ đềm trong các thư viện này, họ có Root access của toàn bộ con VM1.