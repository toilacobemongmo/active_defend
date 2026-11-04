#  Mini-SOC Active Defense & Deception Ecosystem

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20Compose-blue)](https://www.docker.com/)

Hệ thống **Trung tâm Điều hành An ninh Mạng thu nhỏ (Mini-SOC)** kết hợp **Bẫy mồi chủ động (Deception Technology / Honeynet)** và **Tự động hóa phản ứng sự cố an ninh (SOAR - Security Orchestration, Automation, and Response)**.

Dự án chuyển dịch mô hình an ninh mạng từ **Phòng thủ thụ động (Passive Defense)** sang **Phòng thủ chủ động (Active Defense)**: dẫn dụ kẻ tấn công vào bẫy, trinh sát ngược danh tính/hạ tầng của đối thủ và tự động hóa xử lý sự cố trong vài giây mà không cần sự can thiệp thủ công của con người.

---

##  Điểm nổi bật & Tính năng cốt lõi

1. **Honeypot SSH Tương tác cao (High-Interaction SSH Honeypot):**
   * Giả lập đầy đủ hệ thống tệp Linux (Virtual In-Memory VFS) chuẩn Debian/Ubuntu.
   * Ghi nhận toàn bộ keystroke, phiên gõ lệnh, payload tải về và hành vi dò quét.
2. **Khử ẩn danh kẻ tấn công (De-anonymization via Honeytokens):**
   * Cài cắm các "bánh mì vụn" (breadcrumbs) như `.aws/credentials`, `.bash_history`, file backup SQL giả lập có nhúng URL Webhook Canary.
   * Khi hacker exfiltrate dữ liệu và mở ra trên máy thật, hệ thống lật tẩy **Real IP**, **User-Agent** thật, bỏ qua hoàn toàn mạng ẩn danh Tor hoặc VPN/Proxy.
3. **Động cơ Tương quan Luật (MITRE ATT&CK Correlation Engine):**
   * Ánh xạ tự động hành vi tấn công theo ma trận MITRE ATT&CK (T1110 - Brute Force, T1078 - Valid Accounts, T1082 - Discovery, T1105 - Ingress Tool Transfer, T1552 - Honeytoken Access).
4. **Trinh sát ngược (Reverse Threat Intelligence):**
   * Tự động tra cứu OSINT danh tiếng IP đối thủ qua AbuseIPDB, Shodan và quét port nhanh an toàn.
   * Phân loại tự động: Tor Exit Node, Mass Scanner, Botnet hay Targeted APT.
5. **Tự động hóa Phản ứng Sự cố Đa tầng (Multi-tier SOAR Enforcer):**
   * **Adaptive Progressive Jail:** Phản ứng chặn lũy tiến thông minh theo chu kỳ vi phạm (Lần 1: 10 phút, Lần 2: 1 giờ, Lần 3: 24 giờ).
   * **TCP Tarpit Resource Exhaustion:** Làm chậm kết nối, giam lỏng tài nguyên quét của botnet.
   * **Cách ly mã độc:** Băm mã SHA256 và quét mã độc tự động qua VirusTotal API.
6. **Động cơ Chấm điểm Nguy cơ Động (Dynamic Threat Risk Scoring Engine):**
   * Chấm điểm rủi ro tích lũy (0 - 100) theo thời gian thực cho từng IP dựa trên trọng số hành vi (Brute Force, System Recon, Malware Staging, Honeytoken Breach).
   * Phân cấp phản ứng tương ứng: `PASSIVE_MONITOR` -> `ACTIVE_DECEPTION` -> `TARPIT_EXHAUSTION` -> `CONTAINMENT_BLOCK`.
7. **Pháp y Số & Xem lại Phiên Tấn công (Terminal Forensics & Session Replay):**
   * Ghi nhận từng phím bấm (keystrokes) và chuỗi lệnh của attacker khi đột nhập Honeypot shell.
   * Cung cấp giao diện trực quan trên Dashboard mô phỏng lại toàn bộ phiên gõ lệnh của hacker (chuẩn TTY/Asciinema).
8. **Chuẩn hóa Chia sẻ Tình báo Quốc tế (STIX 2.1 & Snort IDS Rules):**
   * Tự động xuất bản Indicator of Compromise (IoC) định dạng chuẩn OASIS STIX 2.1 (`data/stix_indicators.json`).
   * Tự động sinh tệp luật NIDS Snort / Suricata (`data/honeynet_snort_rules.rules`) sẵn sàng đẩy sang hệ thống SIEM/NIDS doanh nghiệp.
9. **Tương tác 2 chiều qua Telegram SOAR Bot & Web SOC Dashboard:**
   * Gửi cảnh báo tức thời theo thời gian thực.
   * Cho phép chuyên viên SOC duyệt hành động ngay trên điện thoại hoặc giám sát qua Web Dashboard Streamlit.

---

##  Kiến trúc Tổng thể Hệ thống

```
+-----------------------------------------------------------------------------------+
|                            KẺ TẤN CÔNG / BOTNET (INTERNET)                        |
+-----------------------------------------------------------------------------------+
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼ (Cổng 2222)                                         ▼ (Cổng 8080)
+──────────────────────────────+                         +──────────────────────────+
|      Live SSH Honeypot       |                         |  Canary Webhook Server   |
|   (Virtual VFS & Decoys)     |                         |  (De-anonymization Trap) |
+──────────────────────────────+                         +──────────────────────────+
             │                                                         │
             │ (Log sự kiện JSON)                                      │ (Real IP & Beacon)
             └──────────────────────────┬──────────────────────────────┘
                                        ▼
             +──────────────────────────────────────────────────────+
             |            Event Correlation Engine                  |
             |       (Quy tắc tương quan MITRE ATT&CK)              |
             +──────────────────────────────────────────────────────+
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
+────────────────────────+ +────────────────────────+ +────────────────────────+
|   Threat Intelligence  | |      SOAR Enforcer     | |   Telegram SOAR Bot    |
| (AbuseIPDB/Shodan/VT)  | |   (Firewall/Tarpit)    | | & Streamlit Dashboard  |
+────────────────────────+ +────────────────────────+ +────────────────────────+
```

---

##  Hướng dẫn Cài đặt & Chạy ứng dụng

### Yêu cầu hệ thống
* Python 3.10 trở lên.
* Hỗ trợ cả **Windows** (có sẵn Windows Firewall support) và **Linux** (`iptables` support).

### Cách 1: Chạy 1-Click Demo (Khuyên dùng cho thuyết trình)
* **Trên Windows:** Click đúp vào file [`run_demo.bat`](file:///C:/Users/ghaob/soc-honeynet-active-defense/run_demo.bat) hoặc chạy:
  ```powershell
  .\run_demo.bat
  ```
* **Trên Linux / macOS:**
  ```bash
  chmod +x run_demo.sh
  ./run_demo.sh
  ```

### Cách 2: Chạy thủ công từng thành phần
1. **Cài đặt thư viện:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Cấu hình biến môi trường (Tùy chọn):**
   ```bash
   cp .env.example .env
   # Điền TELEGRAM_BOT_TOKEN hoặc API Key nếu muốn nhận thông báo thật
   ```
3. **Khởi chạy Hệ sinh thái Mini-SOC:**
   ```bash
   python main.py
   ```
   *(Hệ thống sẽ lắng nghe SSH Honeypot tại port `2222` và Canary Webhook tại port `8080`)*

4. **Khởi chạy Web SOC Dashboard:**
   Mở terminal thứ hai và chạy:
   ```bash
   streamlit run scripts/dashboard.py
   ```
   Truy cập giao diện tại: `http://localhost:8501`

### Cách 3: Triển khai qua Docker Compose
```bash
docker compose up -d --build
```

---

##  Kịch bản Kiểm thử & Demo Thực tế

### 1. Kiểm thử kết nối SSH Honeypot
Mở một Terminal khác và thực hiện SSH vào máy bẫy:
```bash
ssh root@127.0.0.1 -p 2222
```
* **Thử Brute Force:** Gõ sai mật khẩu liên tục 5 lần -> SOAR Enforcer phát hiện và tự động chặn IP trên Firewall.
* **Thử Thâm nhập:** Nhập mật khẩu đúng `root123` -> Truy cập Shell Linux bẫy mồi.
* **Thử Bẫy Honeytoken:** Đọc file credential nhử:
  ```bash
  cat /root/.aws/credentials
  cat /root/.bash_history
  ```

### 2. Kiểm thử Khử ẩn danh (Canary Trap)
Giả lập tình huống hacker lấy được link bí mật và mở trên trình duyệt:
```bash
curl http://127.0.0.1:8080/canary/patch.sh
```
Hệ thống lập tức trích xuất Real IP và gửi thông báo khẩn cấp đến SOC.

### 3. Kiểm thử Tự động hóa Pipeline & Unit Test
Chạy bộ kiểm thử tự động với PyTest:
```bash
pytest tests/ -v
```

---

##  Ma trận So sánh Tính năng

| Tiêu chí | Mô hình Truyền thống (Passive) | Hệ sinh thái Mini-SOC Deception (Active) |
| :--- | :--- | :--- |
| **Thời gian phát hiện (MTTD)** | Vài giờ đến vài ngày sau xâm nhập | **Thời gian thực (< 1 giây)** |
| **Tỉ lệ Báo động giả (False Positive)**| Cao (nhiều cảnh báo rác từ log thường)| **Gần như bằng 0 (chỉ honeypot có traffic)**|
| **Ứng phó sự cố (MTTR)** | Thủ công (chờ analyst đọc log và block) | **Tự động chặn Firewall & Tarpit ngay tức thì**|
| **Đối phó mạng Tor/VPN** | Bị che giấu IP nguồn | **Lật tẩy Real IP bằng Honeytoken Webhook Beacon**|
| **Tình báo đối thủ (Threat Intel)**| Thu thập bị động sau cuộc tấn công | **Tự động trinh sát ngược (Reverse Recon) danh tính**|

---

##  Cấu trúc Thư mục Dự án

```
soc-honeynet-active-defense/
├── core/                         # Các module lõi
│   ├── mini_ssh_honeypot.py      # SSH Honeypot tương tác cao có VFS
│   ├── canary_server.py          # Webhook bẫy khử ẩn danh
│   ├── correlation_engine.py     # Động cơ tương quan sự kiện MITRE ATT&CK
│   ├── honeytoken_manager.py     # Quản lý tài liệu mồi nhử & beacon
│   ├── reverse_intel.py          # Trinh sát ngược OSINT (AbuseIPDB/Shodan)
│   ├── soar_enforcer.py          # Thực thi chặn firewall & Tarpit
│   ├── payload_analyzer.py       # Phân tích mã độc & tích hợp VirusTotal
│   ├── cowrie_listener.py        # Đọc & lắng nghe luồng log Cowrie
│   └── telegram_soar_bot.py      # Bot Telegram tương tác 2 chiều
├── config/
│   └── config.yaml               # File cấu hình hệ thống
├── scripts/
│   ├── dashboard.py              # Web SOC Dashboard (Streamlit)
│   ├── simulate_attack.py        # Bộ sinh traffic tấn công mô phỏng Red Team
│   └── test_pipeline.py          # Kiểm thử luồng xử lý log
├── tests/
│   └── test_soar_pipeline.py     # Bộ Unit Test tự động (PyTest)
├── reports/                      # Báo cáo đồ án & sơ đồ kiến trúc
├── Dockerfile                    # Containerization
├── docker-compose.yml            # Multi-service container orchestrator
├── requirements.txt              # Danh sách thư viện phụ thuộc
├── .env.example                  # Mẫu cấu hình bảo mật môi trường
├── run_demo.bat                  # Script khởi động nhanh trên Windows
├── run_demo.sh                   # Script khởi động nhanh trên Linux
└── main.py                       # Điểm vào chính của toàn bộ hệ thống
```

---

##  Bản quyền & Tác giả
Dự án được xây dựng phục vụ nghiên cứu và thực nghiệm An ninh mạng, Mô hình Deception Technology và Tự động hóa Phản ứng Sự cố (SOAR).
Mọi hành vi sử dụng trong môi trường thực tế cần tuân thủ các quy định bảo mật hiện hành.
