FROM python:3.11-slim

# Cài đặt công cụ mạng cơ bản cho SOAR & Honeypot
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cài đặt Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn
COPY . .

# Tạo thư mục dữ liệu và phân quyền
RUN mkdir -p data/downloads data/quarantine

# Expose port Honeypot SSH (2222), Canary Webhook (8080) và Streamlit Dashboard (8501)
EXPOSE 2222 8080 8501

# Chạy hệ thống Mini-SOC Orchestrator
CMD ["python", "main.py"]
