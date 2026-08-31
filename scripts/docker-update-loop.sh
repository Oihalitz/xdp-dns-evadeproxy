#!/usr/bin/env bash
# Docker-only entrypoint for the blocklist-updater service: replicates
# update-blocked-ips.timer (systemd, every 15s) without systemd.
set -euo pipefail

INTERVAL="${UPDATE_INTERVAL:-15}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/update-cloudflare-prefixes.py" || true

while true; do
    "$SCRIPT_DIR/update-blocked-ips.sh" || true
    sleep "$INTERVAL"
done
