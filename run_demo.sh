#!/usr/bin/env bash
set -e

echo "=============================================================================="
echo "  MINI-SOC DECEPTION & SOAR ECOSYSTEM - AUTOMATED LIVE DEMO RUNNER"
echo "=============================================================================="

if [ ! -f ".env" ]; then
    echo "[*] Khoi tao file .env tu mau .env.example..."
    cp .env.example .env
fi

echo "[*] Kiem tra dependencies..."
python3 -c "import paramiko, yaml, requests" 2>/dev/null || {
    echo "[!] Cai dat dependencies tu requirements.txt..."
    pip install -r requirements.txt
}

echo ""
echo "=============================================================================="
echo "  BAT DAU DEMO HE THONG SOAR HONEYNET (SSH: 2222, WEBHOOK: 8080)"
echo "  Tu dong kich hoat 4 kich ban tan cong mo phong Red Team sau 2s."
echo "  Nhan Ctrl+C de dung."
echo "=============================================================================="
echo ""

python3 main.py --simulate
