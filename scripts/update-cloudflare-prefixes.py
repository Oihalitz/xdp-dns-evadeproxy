#!/usr/bin/env python3
"""Sync Cloudflare (AS13335) BGP prefixes from RIPE Stat + Cloudflare IP endpoints.

evade-proxy only rewrites A/AAAA (and HTTPS/SVCB hints) that land inside these
prefixes. Addresses outside Cloudflare are left untouched.
"""

import ipaddress
import json
import os
import sys
import urllib.request

PREFIX = os.environ.get("XDP_PREFIX", "/opt/xdp-dns-evadeproxy")
TARGET_V4 = os.environ.get("EVADE_CF_IPV4_FILE", "/etc/unbound/cloudflare_prefixes_v4.txt")
TARGET_V6 = os.environ.get("EVADE_CF_IPV6_FILE", "/etc/unbound/cloudflare_prefixes_v6.txt")
BACKUP_V4 = os.environ.get("EVADE_CF_IPV4_BACKUP", os.path.join(PREFIX, "data/cloudflare_prefixes_v4.txt"))
BACKUP_V6 = os.environ.get("EVADE_CF_IPV6_BACKUP", os.path.join(PREFIX, "data/cloudflare_prefixes_v6.txt"))

headers = {"User-Agent": "xdp-dns-evadeproxy/1.0"}
prefixes_v4 = set()
prefixes_v6 = set()

try:
    req = urllib.request.Request(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335",
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode())
        for item in data.get("data", {}).get("prefixes", []):
            pfx = item.get("prefix", "").strip()
            if pfx:
                try:
                    net = ipaddress.ip_network(pfx, strict=False)
                    (prefixes_v4 if net.version == 4 else prefixes_v6).add(str(net))
                except Exception:
                    pass
except Exception as e:
    print(f"Warning: RIPE Stat fetch error: {e}", file=sys.stderr)

for url, pset in (
    ("https://www.cloudflare.com/ips-v4", prefixes_v4),
    ("https://www.cloudflare.com/ips-v6", prefixes_v6),
):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            for line in resp.read().decode().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        pset.add(str(ipaddress.ip_network(line, strict=False)))
                    except Exception:
                        pass
    except Exception as e:
        print(f"Warning: Cloudflare endpoint {url} error: {e}", file=sys.stderr)

if not prefixes_v4:
    print("Error: no IPv4 prefixes fetched; keeping existing files.", file=sys.stderr)
    sys.exit(0)

v4_nets = sorted(ipaddress.collapse_addresses(ipaddress.ip_network(p) for p in prefixes_v4))
v6_nets = sorted(ipaddress.collapse_addresses(ipaddress.ip_network(p) for p in prefixes_v6))


def write_atomic(filepath, lines):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    temp = filepath + ".tmp"
    with open(temp, "w") as f:
        for line in lines:
            f.write(f"{line}\n")
    os.chmod(temp, 0o644)
    os.replace(temp, filepath)


write_atomic(TARGET_V4, v4_nets)
write_atomic(TARGET_V6, v6_nets)
write_atomic(BACKUP_V4, v4_nets)
write_atomic(BACKUP_V6, v6_nets)

print(
    f"Cloudflare AS13335 prefixes synced: {len(v4_nets)} IPv4 networks, {len(v6_nets)} IPv6 networks."
)
