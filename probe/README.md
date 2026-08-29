# Sonda residencial de bloqueos

Detecta desde una línea **residencial** qué IPs de CDN el operador está
cortando de forma indiscriminada y alimenta evade-proxy. Cubre lo que una
lista pública IPv4 no da: **IPv6** y **dominios concretos** (GitHub / Fastly /
Akamai) que no son Cloudflare anycast.

## Por qué una sonda en casa

Los bloqueos los aplica el ISP, no el destino. El servidor está en un
datacenter que no sufre esas órdenes, así que no "ve" el bloqueo. Una sonda en
tu línea es un punto de observación *dentro* de la red que bloquea. La
confirmación es **diferencial**: una IP se marca bloqueada solo si **sirve
desde el servidor pero no desde casa**, con histéresis (3 rondas) para evitar
falsos positivos.

## Arquitectura

```
  CASA (ISP residencial, IPv4+IPv6)          SERVIDOR
  xdp-probe.py (systemd)                     probe-server.py (127.0.0.1:8090)
    GET  /targets     ──────────────────▶    resuelve IPs reales (Unbound)
    sondea cada IP: TCP443+TLS(SNI)+HTTP      + extra_candidates (pool failover)
    POST /report      ──────────────────▶    diferencial + histéresis, y:
       (solo conexiones salientes)            · cf-blocklist → probe_blocked_*
                                              · verified-pool → redirects.txt
                                             TLS inverso (Caddy) + token bearer
```

- **cf-blocklist** (Cloudflare anycast): la IP bloqueada se añade a
  `probe_blocked_ipv6.txt` / `probe_blocked_ips.txt`. `update-blocked-ips.sh`
  las une a `blocked_ipv6.txt` / `blocked_ips.txt` y evade-proxy salta al
  vecino del prefijo (seguro en Cloudflare).
- **verified-pool** (CDN no anycast — GitHub, Fastly, Akamai): no se puede
  saltar a ciegas (una IP vecina puede estar muerta o servir otro sitio). Se
  fija un `redirect` a una IP del pool **verificada sirviendo** desde casa y
  desde el servidor (SNI + cert válido) en `/run/evade-proxy/redirects.txt`.
  Si ninguna candidata sirve, no se toca nada.

## `domains.json`

```json
{ "domain": "...", "sni": "...", "families": [4, 6],
  "strategy": "cf-blocklist" | "verified-pool",
  "extra_candidates": ["ip", ...] }
```

`extra_candidates` da un pool de failover a dominios con una sola IP en DNS.

## Servidor

```sh
# /etc/evade-proxy.env  (chmod 600)
PROBE_TOKEN=…
sudo systemctl enable --now xdp-probe-server
```

Por defecto escucha `127.0.0.1:8090`. Expón `/probe/*` con TLS. Token bearer
obligatorio (fail-closed). El servidor solo acepta IPs de dominios/familias
configurados; los destinos de redirect salen **siempre** de la resolución del
servidor, nunca de lo que diga la sonda.

```bash
systemctl status xdp-probe-server
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example/probe/targets
curl -s -H "Authorization: Bearer $TOKEN" https://dns.example/probe/status
```

## Instalar la sonda en casa

```bash
sudo ./install-agent.sh https://dns.example/probe <PROBE_TOKEN> mi-casa
```

Instala `/opt/xdp-probe/xdp-probe.py`, escribe `/etc/xdp-probe.env` (chmod 600)
y arranca `xdp-probe.service`. Requisitos: `python3` (stdlib) y salida a
Internet IPv4+IPv6. La sonda solo hace conexiones **salientes** (funciona
tras el NAT del router). Logs: `journalctl -u xdp-probe -f`.

## Parámetros (`probe-server.py`)

| Constante | Def | Qué es |
|---|---|---|
| `CONFIRM` | 3 | rondas bloqueado consecutivas para actuar |
| `CLEAR` | 2 | rondas sirviendo para revertir |
| `REDIRECT_TTL` | 300 | vida del redirect (s), refrescada en cada reporte |
| `interval` | 30 | segundos entre rondas de la sonda |

## Seguridad

- Token bearer obligatorio. Comparación en tiempo constante.
- Anti-inyección: objetivos no reconocidos se ignoran; los redirects nunca
  usan una IP inventada por la sonda.
- Diferencial + histéresis: una sola sonda con ruido no envenena producción.
- Sin logs de navegación en disco; estado de histéresis en memoria.
