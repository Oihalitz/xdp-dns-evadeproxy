#!/usr/bin/env python3
"""xdp-probe — sonda residencial para xdp.es (correr en casa, línea Movistar).

Bucle: pide objetivos al servidor -> sondea cada IP desde ESTA línea
(TCP:443 + TLS con SNI + HTTP HEAD) en IPv4 e IPv6 -> reporta qué sirve y qué no.
El servidor confirma el bloqueo por diferencial y actúa. La sonda no decide nada.

Config por variables de entorno (o /etc/xdp-probe.env):
  XDP_PROBE_URL    p.ej. https://dns.xdp.es/probe   (sin barra final)
  XDP_PROBE_TOKEN  token compartido (bearer)
  XDP_PROBE_ID     identificador libre de esta sonda (def: hostname)
  XDP_PROBE_INTERVAL  segundos entre rondas (def: el que diga el servidor, o 30)
Sin dependencias externas: solo la stdlib de Python 3."""

import json
import os
import socket
import ssl
import time
import urllib.request

URL = os.environ.get("XDP_PROBE_URL", "").rstrip("/")
TOKEN = os.environ.get("XDP_PROBE_TOKEN", "")
PROBE_ID = os.environ.get("XDP_PROBE_ID") or socket.gethostname()
FIXED_INTERVAL = os.environ.get("XDP_PROBE_INTERVAL")
TIMEOUT = 6.0


def probe_ip(ip, sni, family, timeout=TIMEOUT):
    """TCP:443 + TLS(SNI, cert validado) + HTTP HEAD. Devuelve (serving, rtt_ms)."""
    t0 = time.monotonic()
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    raw = None
    try:
        raw = socket.socket(af, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((ip, 443))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            s.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
                f"User-Agent: xdp-probe\r\nConnection: close\r\n\r\n".encode()
            )
            data = s.recv(64)
        return data.startswith(b"HTTP/"), round((time.monotonic() - t0) * 1000, 1)
    except Exception:
        try:
            if raw is not None:
                raw.close()
        except Exception:
            pass
        return False, None


def http_json(method, path, payload=None):
    req = urllib.request.Request(
        f"{URL}{path}", method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "xdp-probe-agent",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read() or b"{}")


def have_ipv6():
    """¿Tiene esta línea IPv6 global de salida? (Movistar sí, pero por si acaso)."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111", 53))
        s.close()
        return True
    except Exception:
        return False


def run_once():
    tg = http_json("GET", "/targets")
    targets = tg.get("targets", [])
    v6ok = have_ipv6()
    results = []
    skipped6 = 0
    for t in targets:
        fam = int(t.get("family", 4))
        if fam == 6 and not v6ok:
            skipped6 += 1
            continue
        sni = t.get("sni", t["domain"])
        for ip in t.get("candidates", []):
            serving, rtt = probe_ip(ip, sni, fam)
            results.append({
                "domain": t["domain"], "family": fam, "ip": ip,
                "serving": serving, "rtt_ms": rtt,
            })
    resp = http_json("POST", "/report", {"probe_id": PROBE_ID, "results": results})
    conf = resp.get("confirmed_blocked", [])
    reds = resp.get("active_redirects", {})
    extra = f", IPv6 omitido x{skipped6}" if skipped6 else ""
    print(f"[{time.strftime('%H:%M:%S')}] {len(results)} sondas{extra} | "
          f"bloqueos confirmados: {len(conf)} | redirects activos: {len(reds)}",
          flush=True)
    if conf:
        for c in conf:
            print(f"    BLOQUEADA {c['domain']} ({c['family']}) {c['ip']}", flush=True)
    return int(FIXED_INTERVAL) if FIXED_INTERVAL else int(tg.get("interval", 30))


def main():
    if not URL or not TOKEN:
        raise SystemExit("Faltan XDP_PROBE_URL y/o XDP_PROBE_TOKEN")
    print(f"[xdp-probe] id={PROBE_ID} servidor={URL}", flush=True)
    backoff = 5
    while True:
        try:
            interval = run_once()
            backoff = 5
        except Exception as exc:
            interval = backoff
            backoff = min(backoff * 2, 120)
            print(f"[xdp-probe] error: {exc} (reintento en {interval}s)", flush=True)
        time.sleep(max(5, interval))


if __name__ == "__main__":
    main()
