@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ==============================================================================
echo   MINI-SOC ACTIVE DEFENSE - LOCAL "VPS" RUNNER (Windows native)
echo ==============================================================================
echo  Chay truc tiep tren Windows de giu nguyen Source IP that cua attacker.
echo  Docker Desktop NAT se lam mat IP that -> chi dung Docker khi demo noi bo.
echo ==============================================================================
echo.

if not exist ".env" (
    echo [*] Tao file .env tu .env.example ...
    copy .env.example .env >nul
)

echo [*] Kiem tra thu vien Python ...
python -c "import paramiko, yaml, requests, dotenv" 2>nul
if %errorlevel% neq 0 (
    echo [!] Thieu thu vien, dang cai dat requirements ...
    python -m pip install -r requirements.txt
)

echo.
echo [*] Mo Windows Firewall cho port 2222 (Honeypot SSH) va 8080 (Canary) ...
netsh advfirewall firewall show rule name="SOC_Honeypot_2222" >nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="SOC_Honeypot_2222" dir=in action=allow protocol=TCP localport=2222 >nul
    echo     [+] Da them rule TCP 2222
)
netsh advfirewall firewall show rule name="SOC_Canary_8080" >nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="SOC_Canary_8080" dir=in action=allow protocol=TCP localport=8080 >nul
    echo     [+] Da them rule TCP 8080
)

echo.
echo ==============================================================================
echo   KHOI DONG HE THONG (SSH Honeypot: 2222 ^| Canary Webhook: 8080 ^| Collector: 9090)
echo   Dashboard: chay rieng bang lenh  ->  python -m streamlit run scripts/dashboard.py
echo ==============================================================================
echo.

python main.py %*
