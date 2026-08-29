#!/usr/bin/env bash
# Install evade-proxy, the blocked-IP sync, and the probe ingest server.
# Usage: sudo ./scripts/install.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${XDP_PREFIX:-/opt/xdp-dns-evadeproxy}"

command -v cargo >/dev/null || { echo "Install a stable Rust toolchain first (https://rustup.rs)."; exit 1; }
command -v python3 >/dev/null || { echo "Install python3 first."; exit 1; }
command -v curl >/dev/null || { echo "Install curl first."; exit 1; }
command -v dig >/dev/null || echo "Warning: dig not found; the probe server needs dnsutils/bind-utils."

echo "[1/5] Building evade-proxy (release)…"
(cd "$ROOT" && cargo build --release --locked)
install -m 0755 "$ROOT/target/release/evade-proxy" /usr/local/bin/evade-proxy

echo "[2/5] Installing sources to $PREFIX…"
mkdir -p "$PREFIX" /etc/unbound /var/lib/evade-proxy "$PREFIX/data"
tar -C "$ROOT" --exclude target --exclude .git -cf - . | tar -C "$PREFIX" -xf -

echo "[3/5] Environment file…"
if [[ ! -f /etc/evade-proxy.env ]]; then
    install -m 0600 "$ROOT/evade-proxy.env.example" /etc/evade-proxy.env
    echo "Wrote /etc/evade-proxy.env — set PROBE_TOKEN before starting the probe server."
else
    echo "/etc/evade-proxy.env already exists; leaving it."
fi

echo "[4/5] systemd units…"
install -m 0644 "$PREFIX/systemd/xdp-evade-proxy.service" /etc/systemd/system/xdp-evade-proxy.service
install -m 0644 "$PREFIX/systemd/update-blocked-ips.service" /etc/systemd/system/update-blocked-ips.service
install -m 0644 "$PREFIX/systemd/update-blocked-ips.timer" /etc/systemd/system/update-blocked-ips.timer
install -m 0644 "$PREFIX/systemd/xdp-probe-server.service" /etc/systemd/system/xdp-probe-server.service
systemctl daemon-reload

echo "[5/5] First blocklist + Cloudflare prefix sync…"
XDP_PREFIX="$PREFIX" "$PREFIX/scripts/update-cloudflare-prefixes.py" || true
XDP_PREFIX="$PREFIX" "$PREFIX/scripts/update-blocked-ips.sh" || true

systemctl enable --now update-blocked-ips.timer
systemctl enable --now xdp-evade-proxy.service

echo
echo "Installed."
echo "  evade-proxy:           systemctl status xdp-evade-proxy"
echo "  blocked-IP sync:       systemctl status update-blocked-ips.timer"
echo "  probe server:          edit /etc/evade-proxy.env then:"
echo "                         systemctl enable --now xdp-probe-server"
echo "  home agent:            see probe/README.md"
echo
echo "Do not run this together with a Python evade_proxy on the same ports."
