#!/usr/bin/env python3
"""xdp-probe-server — ingesta de sondeos residenciales para xdp.es.

Escucha en 127.0.0.1:8090 (Caddy lo expone en https://dns.xdp.es/probe/*).
La sonda de casa (Movistar) pide objetivos, sondea desde su línea y reporta.
El servidor confirma el bloqueo por DIFERENCIAL (¿sirve desde aquí pero no desde
casa?), aplica histéresis y alimenta la evasión:

  - cf-blocklist  (Cloudflare anycast): añade la IP a probe_blocked_ipv6/ips;
    update-blocked-ips.sh las une al blocklist y el evade-proxy salta al vecino.
  - verified-pool (GitHub/Fastly, no anycast): fija un redirect dominio=IP_sana
    (verificada sirviendo desde casa Y desde el servidor) en el evade-proxy.

Sin logs de navegación en disco. Estado de histéresis en memoria."""

import hmac
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = (
    os.environ.get("PROBE_BIND", "127.0.0.1"),
    int(os.environ.get("PROBE_PORT", "8090")),
)
_PREFIX = os.environ.get("XDP_PREFIX", "/opt/xdp-dns-evadeproxy")
CONFIG = os.environ.get("PROBE_DOMAINS", os.path.join(_PREFIX, "probe/domains.json"))
TOKEN = os.environ.get("PROBE_TOKEN", "")

# Resolver recursivo directo: IPs REALES, antes de la evasión.
RESOLVER_IP = os.environ.get("PROBE_RESOLVER_IP", "127.0.0.1")
RESOLVER_PORT = os.environ.get("PROBE_RESOLVER_PORT", "5336")

PROBE_BLOCKED_V6 = os.environ.get("PROBE_BLOCKED_V6", "/etc/unbound/probe_blocked_ipv6.txt")
PROBE_BLOCKED_V4 = os.environ.get("PROBE_BLOCKED_V4", "/etc/unbound/probe_blocked_ips.txt")
REDIRECTS = os.environ.get("EVADE_REDIRECTS_FILE", "/run/evade-proxy/redirects.txt")

CONFIRM = 3          # rondas consecutivas bloqueado para actuar
CLEAR = 2            # rondas consecutivas sirviendo para revertir
REDIRECT_TTL = 300   # vida del redirect (s); se refresca en cada reporte
RESOLVE_TTL = 30     # caché de resolución de objetivos (s)
CONTROL_TTL = 15     # caché del chequeo de control del servidor (s)
PROBE_TIMEOUT = 6.0

_lock = threading.Lock()
_cfg = {"mtime": 0, "domains": []}
_targets_cache = {"ts": 0, "data": None}
_control_cache = {}                 # (ip,sni,fam) -> (ts, serving)
# Histéresis por (domain, family, ip):
_state = {}                         # key -> {"blocked": int, "serving": int, "last": float}
_redirects = {}                     # domain -> {4: ip, 6: ip}
_blocked = {4: set(), 6: set()}     # IPs confirmadas bloqueadas (para los ficheros)
_probes = {}                        # probe_id -> {last, reports, last_results, last_confirmed}


# ----------------------------- utilidades ---------------------------------
def load_config():
    try:
        st = os.stat(CONFIG)
        if st.st_mtime != _cfg["mtime"]:
            with open(CONFIG) as fh:
                data = json.load(fh)
            _cfg["domains"] = [d for d in data.get("domains", []) if d.get("domain")]
            _cfg["mtime"] = st.st_mtime
    except Exception as exc:
        print(f"[probe-server] config error: {exc}", flush=True)
    return _cfg["domains"]


def resolve(domain, family):
    rrtype = "AAAA" if family == 6 else "A"
    try:
        out = subprocess.run(
            ["/usr/bin/dig", "+short", "+time=3", "+tries=1",
             f"@{RESOLVER_IP}", "-p", RESOLVER_PORT, domain, rrtype],
            capture_output=True, timeout=6, encoding="utf-8", errors="replace",
        ).stdout
    except Exception:
        return []
    ips = []
    for line in out.splitlines():
        line = line.strip()
        if family == 6 and ":" in line:
            ips.append(line)
        elif family == 4 and line and line[0].isdigit() and ":" not in line:
            ips.append(line)
    return ips


def probe_ip(ip, sni, family, timeout=PROBE_TIMEOUT):
    """TCP:443 + TLS(SNI, cert validado) + HTTP HEAD. Devuelve (serving, rtt_ms).

    Un edge vivo completa el TLS con cert válido y responde un estado HTTP.
    Una IP bloqueada (drop/RST) o muerta lanza excepción -> serving False.
    La validación de cert además descarta páginas-bloqueo inyectadas por TLS."""
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


def control_serving(ip, sni, family):
    """¿Sirve la IP desde el propio servidor? (con caché corta)."""
    key = (ip, sni, family)
    now = time.time()
    hit = _control_cache.get(key)
    if hit and now - hit[0] < CONTROL_TTL:
        return hit[1]
    ok, _ = probe_ip(ip, sni, family)
    _control_cache[key] = (now, ok)
    return ok


# ----------------------------- persistencia -------------------------------
def _atomic_write_lines(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, path)


def flush_blocked_files():
    for fam, path in ((6, PROBE_BLOCKED_V6), (4, PROBE_BLOCKED_V4)):
        want = sorted(_blocked[fam])
        try:
            cur = []
            if os.path.exists(path):
                with open(path) as fh:
                    cur = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            if cur != want:
                _atomic_write_lines(path, want)
                print(f"[probe-server] {path}: {len(want)} IP(s) bloqueadas", flush=True)
        except Exception as exc:
            print(f"[probe-server] no pude escribir {path}: {exc}", flush=True)


def flush_redirects():
    expiry = int(time.time()) + REDIRECT_TTL
    lines = ["# generado por xdp-probe-server; no editar a mano"]
    for domain, fams in sorted(_redirects.items()):
        for fam, ip in sorted(fams.items()):
            if ip:
                lines.append(f"{domain}={ip} {expiry}")
    try:
        os.makedirs(os.path.dirname(REDIRECTS), exist_ok=True)
        _atomic_write_lines(REDIRECTS, lines)
    except Exception as exc:
        print(f"[probe-server] no pude escribir {REDIRECTS}: {exc}", flush=True)


# ----------------------------- lógica de decisión -------------------------
def build_targets():
    now = time.time()
    if _targets_cache["data"] and now - _targets_cache["ts"] < RESOLVE_TTL:
        return _targets_cache["data"]
    out = []
    for d in load_config():
        for fam in d.get("families", [4]):
            cand = resolve(d["domain"], fam)
            # Semillas fijas (pool de failover para dominios con una sola IP en DNS).
            for ip in d.get("extra_candidates", []):
                if ((":" in ip) == (fam == 6)) and ip not in cand:
                    cand.append(ip)
            out.append({
                "domain": d["domain"], "sni": d.get("sni", d["domain"]),
                "family": fam, "strategy": d.get("strategy", "cf-blocklist"),
                "candidates": cand,
            })
    payload = {"targets": out, "interval": 30}
    _targets_cache.update(ts=now, data=payload)
    return payload


def strategy_of(domain, family):
    for d in load_config():
        if d["domain"] == domain and family in d.get("families", [4]):
            return d.get("strategy", "cf-blocklist"), d.get("sni", domain)
    return None, domain


def process_report(probe_id, results):
    """results: [{domain, family, ip, serving(bool), rtt_ms}]. Devuelve resumen."""
    now = time.time()
    if probe_id and probe_id not in _probes:
        print(f"[probe-server] sonda conectada: {probe_id}", flush=True)
    # Agrupa por dominio+familia para decidir a nivel de dominio.
    by_dom = {}
    confirmed = []
    with _lock:
        for r in results:
            domain, fam, ip = r.get("domain"), int(r.get("family", 4)), r.get("ip")
            if not domain or not ip:
                continue
            strat, sni = strategy_of(domain, fam)
            if strat is None:
                continue  # objetivo no reconocido: ignora (anti-inyección)
            serving_home = bool(r.get("serving"))
            # Diferencial: solo cuenta como bloqueo si el servidor SÍ sirve.
            ctrl = control_serving(ip, sni, fam)
            is_block = (not serving_home) and ctrl
            key = (domain, fam, ip)
            st = _state.setdefault(key, {"blocked": 0, "serving": 0, "last": now})
            st["last"] = now
            if is_block:
                st["blocked"] += 1
                st["serving"] = 0
            elif serving_home and ctrl:
                st["serving"] += 1
                st["blocked"] = 0
            else:
                # ni sirve en casa ni en el servidor -> caída, no bloqueo ISP
                st["blocked"] = 0
            bucket = by_dom.setdefault((domain, fam, strat, sni), {"blocked": [], "healthy": []})
            if st["blocked"] >= CONFIRM:
                bucket["blocked"].append(ip)
                confirmed.append({"domain": domain, "family": fam, "ip": ip})
            if serving_home and ctrl and st["serving"] >= CLEAR:
                bucket["healthy"].append((r.get("rtt_ms") or 9e9, ip))

        # Aplica acciones por dominio.
        for (domain, fam, strat, sni), b in by_dom.items():
            if strat == "cf-blocklist":
                for ip in b["blocked"]:
                    _blocked[fam].add(ip)
                # revierte los que vuelven a servir de forma estable
                for ip in list(_blocked[fam]):
                    st = _state.get((domain, fam, ip))
                    if st and st["serving"] >= CLEAR:
                        _blocked[fam].discard(ip)
            elif strat == "verified-pool":
                fams = _redirects.setdefault(domain, {})
                if b["blocked"] and b["healthy"]:
                    fams[fam] = sorted(b["healthy"])[0][1]  # IP sana de menor RTT
                elif not b["blocked"] and fam in fams:
                    # todo sano de nuevo: quita el pin
                    st_ok = all(
                        _state.get((domain, fam, ip), {}).get("serving", 0) >= CLEAR
                        for ip in [fams[fam]]
                    )
                    if st_ok:
                        fams.pop(fam, None)

        # purga estado viejo (>1h sin ver)
        for k in [k for k, v in _state.items() if now - v["last"] > 3600]:
            del _state[k]

        if probe_id:
            prev = _probes.get(probe_id, {}).get("reports", 0)
            _probes[probe_id] = {
                "last": now, "reports": prev + 1,
                "last_results": len(results), "last_confirmed": len(confirmed),
            }

        flush_blocked_files()
        flush_redirects()

    return {
        "received": len(results),
        "confirmed_blocked": confirmed,
        "active_redirects": {d: v for d, v in _redirects.items() if any(v.values())},
        "blocked_counts": {"v4": len(_blocked[4]), "v6": len(_blocked[6])},
    }


# ----------------------------- HTTP ---------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # zero-logs

    def _auth(self):
        if not TOKEN:
            return False
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return False
        return hmac.compare_digest(hdr[7:].strip(), TOKEN)

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if path.endswith("/health"):
            return self._send(200, {"ok": True})
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if path.endswith("/targets"):
            return self._send(200, build_targets())
        if path.endswith("/status"):
            now = time.time()
            with _lock:
                probes = {
                    pid: {**v, "seen_ago_s": round(now - v["last"], 1)}
                    for pid, v in _probes.items()
                }
                redirects = {d: v for d, v in _redirects.items() if any(v.values())}
                counts = {"v4": len(_blocked[4]), "v6": len(_blocked[6])}
            return self._send(200, {
                "probes": probes, "active_redirects": redirects,
                "blocked_counts": counts,
            })
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if not path.endswith("/report"):
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            results = body.get("results", [])
            probe_id = str(body.get("probe_id", "") or "")[:64]
            if not isinstance(results, list) or len(results) > 5000:
                raise ValueError("bad results")
        except Exception as exc:
            return self._send(400, {"error": f"bad request: {exc}"})
        self._send(200, process_report(probe_id, results))


def main():
    if not TOKEN:
        print("[probe-server] FALTA PROBE_TOKEN; abortando (fail-closed).", flush=True)
        raise SystemExit(1)
    load_config()
    srv = ThreadingHTTPServer(BIND, Handler)
    print(f"[probe-server] escuchando en {BIND[0]}:{BIND[1]}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
