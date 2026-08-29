#!/usr/bin/env bash
# Sync the public IPv4 blocklist and merge residential-probe detections.
#
# When an ISP cuts Cloudflare anycast IPs indiscriminately, this list plus the
# home probe feed evade-proxy so it can jump to a neighbour that still serves.
set -euo pipefail

PREFIX="${XDP_PREFIX:-/opt/xdp-dns-evadeproxy}"

URL="${BLOCKLIST_URL:-https://hayahora.futbol/estado/blocked-any.txt}"
TARGET_FILE="${EVADE_BLOCKED_IPV4_FILE:-/etc/unbound/blocked_ips.txt}"
BACKUP_FILE="${EVADE_BLOCKED_IPV4_BACKUP:-$PREFIX/data/blocked_ips.txt}"

SOURCE_IPV6="${EVADE_OONI_IPV6_FILE:-/etc/unbound/ooni_bloqueados_ipv6.txt}"
TARGET_IPV6="${EVADE_BLOCKED_IPV6_FILE:-/etc/unbound/blocked_ipv6.txt}"
BACKUP_IPV6="${EVADE_BLOCKED_IPV6_BACKUP:-$PREFIX/data/blocked_ipv6.txt}"

# IPs confirmed blocked by the residential probe (xdp-probe-server).
PROBE_V4="${PROBE_BLOCKED_V4:-/etc/unbound/probe_blocked_ips.txt}"
PROBE_V6="${PROBE_BLOCKED_V6:-/etc/unbound/probe_blocked_ipv6.txt}"

CF_V4_FILE="${EVADE_CF_IPV4_FILE:-/etc/unbound/cloudflare_prefixes_v4.txt}"
CF_UPDATE="${PREFIX}/scripts/update-cloudflare-prefixes.py"
POST_HOOK="${UPDATE_BLOCKED_POST_HOOK:-}"

TEMP_FILE=$(mktemp)
cleanup() { rm -f "$TEMP_FILE"; }
trap cleanup EXIT

# 0. Refresh Cloudflare AS13335 prefixes if missing or older than 24 hours.
if [[ ! -f "$CF_V4_FILE" ]] || [[ -n "$(find "$CF_V4_FILE" -mtime +1 -print 2>/dev/null)" ]]; then
    if [[ -x "$CF_UPDATE" ]] || [[ -f "$CF_UPDATE" ]]; then
        /usr/bin/python3 "$CF_UPDATE" >/dev/null 2>&1 || true
    fi
fi

# 1. Fetch public IPv4 anycast blocklist.
if curl -s -f -L --connect-timeout 10 --max-time 20 \
        -H "User-Agent: xdp-dns-evadeproxy/1.0" "$URL" -o "$TEMP_FILE"; then
    FILTERED_TEMP=$(mktemp)
    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$TEMP_FILE" \
        | sort -u > "$FILTERED_TEMP" || true

    if [[ -f "$PROBE_V4" ]]; then
        cat "$FILTERED_TEMP" "$PROBE_V4" \
            | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
            | sort -u > "${FILTERED_TEMP}.u" && mv "${FILTERED_TEMP}.u" "$FILTERED_TEMP"
    fi
    COUNT=$(wc -l < "$FILTERED_TEMP")

    mkdir -p "$(dirname "$TARGET_FILE")" "$(dirname "$BACKUP_FILE")"

    if [[ ! -f "$TARGET_FILE" ]] || ! cmp -s "$FILTERED_TEMP" "$TARGET_FILE"; then
        mv "$FILTERED_TEMP" "$TARGET_FILE"
        chmod 644 "$TARGET_FILE"
        cp "$TARGET_FILE" "$BACKUP_FILE"
        echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Blocked IPv4 updated: ${COUNT} active entries (evasion: $([[ $COUNT -gt 0 ]] && echo YES || echo NO))."
        logger -t update-blocked-ips "Blocked IPv4 updated: ${COUNT} active entries" || true
        # No cache flush: evade-proxy rewrites blocked IPs on every response,
        # including cached Unbound answers. Flushing only hurts hit-rate.
    else
        rm -f "$FILTERED_TEMP"
        echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] No changes in blocked IPv4 (${COUNT} entries active)."
    fi
else
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Error: failed to fetch $URL" >&2
fi

# 2. IPv6 blocklist = optional static list (e.g. OONI) ∪ residential probe.
if [[ -f "$SOURCE_IPV6" ]] || [[ -f "$PROBE_V6" ]]; then
    mkdir -p "$(dirname "$TARGET_IPV6")" "$(dirname "$BACKUP_IPV6")"
    V6_TMP=$(mktemp)
    { [[ -f "$SOURCE_IPV6" ]] && cat "$SOURCE_IPV6"; [[ -f "$PROBE_V6" ]] && cat "$PROBE_V6"; } 2>/dev/null \
        | grep -E ':' | sort -u > "$V6_TMP" || true
    if [[ ! -f "$TARGET_IPV6" ]] || ! cmp -s "$V6_TMP" "$TARGET_IPV6"; then
        cp "$V6_TMP" "$TARGET_IPV6"
        chmod 644 "$TARGET_IPV6"
        cp "$V6_TMP" "$BACKUP_IPV6"
        echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Blocked IPv6 updated: $(wc -l < "$V6_TMP") entries."
    fi
    rm -f "$V6_TMP"
fi

# 3. Optional post-hook (dashboard JSON, notify, …). Not required for evasion.
if [[ -n "$POST_HOOK" && -e "$POST_HOOK" ]]; then
    /usr/bin/python3 "$POST_HOOK" >/dev/null 2>&1 || true
fi
