#!/usr/bin/env bash
# ==============================================================================
# Trien khai SOC Honeynet Active Defense len Oracle Cloud Always Free
#   Image : Ubuntu 22.04 / 24.04 (Canonical)
#   Shape : VM.Standard.A1.Flex (ARM Ampere) - 4 OCPU / 24 GB
#
# Chay TREN VM, tai thu muc goc cua repo:
#   git clone <repo> && cd soc-honeynet-active-defense
#   sudo bash scripts/deploy_oci.sh
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

HONEYPOT_PORT=2222
CANARY_PORT=8080

log()  { printf '\n\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ !! ]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[LOI ]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Can quyen root. Chay lai: sudo bash scripts/deploy_oci.sh"

# ------------------------------------------------------------------------------
# 1. Mo port tren firewall cua OS
#    OCI: mo port o Security List la CHUA DU. Image Ubuntu cua Oracle co san
#    rules iptables chan het tru 22. Thieu buoc nay thi tu ngoai van timeout
#    trong khi `ss -lntp` van thay port dang listen.
# ------------------------------------------------------------------------------
log "Mo port $HONEYPOT_PORT va $CANARY_PORT tren firewall cua OS"

# Ubuntu/Debian: iptables (Image Ubuntu cua Oracle co san rules chan het tru 22)
# Oracle Linux 9: firewalld. Xu ly ca hai cho chac.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    for p in "$HONEYPOT_PORT" "$CANARY_PORT"; do
        firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null
        ok "firewalld: da mo port $p"
    done
    firewall-cmd --reload >/dev/null
    ok "firewalld: da reload"
else
    for p in "$HONEYPOT_PORT" "$CANARY_PORT"; do
        if iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null; then
            ok "Port $p da duoc mo truoc do"
        else
            iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
            ok "Da mo port $p"
        fi
    done

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 && ok "Da luu rules (netfilter-persistent)"
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ok "Da luu rules -> /etc/iptables/rules.v4"
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$HONEYPOT_PORT"/tcp >/dev/null
        ufw allow "$CANARY_PORT"/tcp >/dev/null
        ok "Da mo port tren ufw"
    fi
fi

# ------------------------------------------------------------------------------
# 2. Cai Docker Engine + compose plugin
# ------------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker + compose plugin da co san"
else
    log "Cai Docker Engine + compose plugin"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    ok "Cai Docker xong"
fi

# ------------------------------------------------------------------------------
# 3. Chuan bi .env
#    docker-compose.yml dung `env_file: .env` -> thieu file la compose loi ngay.
# ------------------------------------------------------------------------------
if [ ! -f .env ]; then
    cp .env.example .env
    warn "Chua co .env -> da tao tu .env.example"
    warn "Dien TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID roi chay lai script neu muon bot that."
fi

# ------------------------------------------------------------------------------
# 4. Build va khoi dong
# ------------------------------------------------------------------------------
log "Build image va khoi dong stack (lan dau tren ARM ~5-10 phut)"
docker compose up -d --build

# ------------------------------------------------------------------------------
# 5. Kiem tra
# ------------------------------------------------------------------------------
log "Cho honeypot listen tren port $HONEYPOT_PORT..."
LISTENING=0
for _ in $(seq 1 30); do
    if ss -lntp 2>/dev/null | grep -q ":${HONEYPOT_PORT}"; then
        LISTENING=1
        break
    fi
    sleep 2
done

if [ "$LISTENING" -eq 1 ]; then
    ok "Port dang listen"
else
    warn "Chua thay port listen. Xem log: docker compose logs -f soc-core"
fi

ss -lntp 2>/dev/null | grep -E ":${HONEYPOT_PORT}|:${CANARY_PORT}" || true

PUBLIC_IP="$(curl -fsS -m 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"

cat <<EOF

============================================================
 ENDPOINT CONG KHAI
   SSH honeypot : ssh -p ${HONEYPOT_PORT} root@${PUBLIC_IP}
   Canary       : http://${PUBLIC_IP}:${CANARY_PORT}/
   Dashboard    : ssh -L 8501:127.0.0.1:8501 root@${PUBLIC_IP}
                  roi mo http://127.0.0.1:8501

 LENH HUU ICH
   docker compose logs -f soc-core
   docker compose ps
   docker compose restart soc-core
============================================================
EOF
