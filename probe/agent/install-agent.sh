#!/usr/bin/env bash
# Instalador de la sonda xdp-probe en la Raspberry Pi / mini-PC (Debian/Ubuntu/RaspOS).
# Uso:
#   sudo ./install-agent.sh https://dns.xdp.es/probe  <TOKEN>  [id-sonda]
set -euo pipefail

URL="${1:?uso: install-agent.sh <URL /probe> <TOKEN> [id]}"
TOKEN="${2:?falta el TOKEN}"
ID="${3:-$(hostname)}"

command -v python3 >/dev/null || { echo "Instala python3 primero"; exit 1; }

install -d /opt/xdp-probe
install -m755 "$(dirname "$0")/xdp-probe.py" /opt/xdp-probe/xdp-probe.py

umask 077
cat > /etc/xdp-probe.env <<EOF
XDP_PROBE_URL=${URL%/}
XDP_PROBE_TOKEN=${TOKEN}
XDP_PROBE_ID=${ID}
EOF
chmod 600 /etc/xdp-probe.env

install -m644 "$(dirname "$0")/xdp-probe.service" /etc/systemd/system/xdp-probe.service
systemctl daemon-reload
systemctl enable --now xdp-probe.service

echo
echo "Sonda instalada. Estado:"
systemctl --no-pager --lines=5 status xdp-probe.service || true
echo
echo "Logs en vivo:  journalctl -u xdp-probe -f"
