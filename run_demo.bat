@echo off
chcp 65001 >nul
echo ==============================================================================
echo   MINI-SOC DECEPTION & SOAR ECOSYSTEM - AUTOMATED LIVE DEMO RUNNER
echo ==============================================================================
echo.

if not exist ".env" (
    echo [*] Khoi tao file .env tu mau .env.example...
    copy .env.example .env >nul
)

echo [*] Kiem tra moi truong va thu vien can thiet...
python -c "import paramiko, yaml, requests" 2>nul
if %errorlevel% neq 0 (
    echo [!] Phat hien thieu thu vien, dang tu dong cai dat...
    python -m pip install -r requirements.txt
)

echo.
echo ==============================================================================
echo   BAT DAU DEMO HE THONG SOAR HONEYNET (PORT SSH: 2222, WEBHOOK: 8080)
echo   Chuc nang tu dong mo phong 4 kich ban tan cong MITRE ATT&CK se kich hoat sau 2s.
echo   Nhan Ctrl+C de dung.
echo ==============================================================================
echo.

python main.py --simulate
