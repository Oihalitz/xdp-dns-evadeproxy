#!/usr/bin/env python3
"""Sync Cloudflare address ranges.

Two lists are written:

- EVADE_CF_IPV4_FILE / EVADE_CF_IPV6_FILE: Cloudflare's official proxy ranges
  (www.cloudflare.com/ips-v4, ips-v6). evade-proxy only rewrites A/AAAA (and
  HTTPS/SVCB hints) inside these: any address there serves any proxied site,
  so jumping to a neighbour is safe.
- EVADE_CF_ASN_IPV4_FILE / EVADE_CF_ASN_IPV6_FILE: everything AS13335
  announces (RIPE Stat). It also holds 1.1.1.0/24 and customer BYOIP / Magic
  Transit prefixes, where a neighbouring address is a different service, so it
  is informational only (e.g. the /blocked dashboard).
"""

import ipaddress
import json
import os
import sys
import urllib.request

PREFIX = os.environ.get("XDP_PREFIX", "/opt/xdp-dns-evadeproxy")
OFFICIAL_V4 = os.environ.get("EVADE_CF_IPV4_FILE", "/etc/unbound/cloudflare_official_v4.txt")
OFFICIAL_V6 = os.environ.get("EVADE_CF_IPV6_FILE", "/etc/unbound/cloudflare_official_v6.txt")
ASN_V4 = os.environ.get("EVADE_CF_ASN_IPV4_FILE", "/etc/unbound/cloudflare_prefixes_v4.txt")
ASN_V6 = os.environ.get("EVADE_CF_ASN_IPV6_FILE", "/etc/unbound/cloudflare_prefixes_v6.txt")
BACKUP_DIR = os.path.join(PREFIX, "data")

headers = {"User-Agent": "xdp-dns-evadeproxy/1.0"}


def fetch(url, timeout):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def networks(texts):
    out = set()
    for text in texts:
        text = text.strip()
        if text and not text.startswith("#"):
            try:
                out.add(ipaddress.ip_network(text, strict=False))
            except ValueError:
                pass
    return out


def collapse(nets, version):
    return sorted(ipaddress.collapse_addresses(n for n in nets if n.version == version))


def write_atomic(filepath, nets):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    temp = filepath + ".tmp"
    with open(temp, "w") as f:
        for net in nets:
            f.write(f"{net}\n")
    os.chmod(temp, 0o644)
    os.replace(temp, filepath)


def publish(filepath, nets):
    write_atomic(filepath, nets)
    write_atomic(os.path.join(BACKUP_DIR, os.path.basename(filepath)), nets)


official = set()
for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
    try:
        official |= networks(fetch(url, 10).splitlines())
    except Exception as e:
        print(f"Warning: Cloudflare endpoint {url} error: {e}", file=sys.stderr)

asn = set(official)
try:
    data = json.loads(fetch(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335", 20))
    asn |= networks(item.get("prefix", "") for item in data.get("data", {}).get("prefixes", []))
except Exception as e:
    print(f"Warning: RIPE Stat fetch error: {e}", file=sys.stderr)

official_v4, official_v6 = collapse(official, 4), collapse(official, 6)
if official_v4 and official_v6:
    publish(OFFICIAL_V4, official_v4)
    publish(OFFICIAL_V6, official_v6)
else:
    print("Error: incomplete official Cloudflare ranges; keeping existing files.", file=sys.stderr)

asn_v4, asn_v6 = collapse(asn, 4), collapse(asn, 6)
if len(asn_v4) > len(official_v4):
    publish(ASN_V4, asn_v4)
    publish(ASN_V6, asn_v6)
else:
    print("Error: no AS13335 prefixes from RIPE; keeping existing files.", file=sys.stderr)

print(
    f"Cloudflare ranges synced: official {len(official_v4)} IPv4 / {len(official_v6)} IPv6, "
    f"AS13335 {len(asn_v4)} IPv4 / {len(asn_v6)} IPv6."
)
