<div align="center">

<a href="https://xdp.es">
  <img src="https://xdp.es/android-chrome-192x192.png" width="88" height="88" alt="xdp.es">
</a>

# evade-proxy

Cuando un operador bloquea IPs **de forma indiscriminada**, esto se lo salta.

Proxy DNS del resolver público **[xdp.es](https://xdp.es)**

[**Usar el DNS**](https://xdp.es)&ensp;·&ensp;[Estadísticas](https://xdp.es/stats)&ensp;·&ensp;[Cómo funciona](https://xdp.es/about)&ensp;·&ensp;[IPs bloqueadas](https://xdp.es/blocked)

Desarrollado por [Oihalitz](https://github.com/Oihalitz) con [mateodd1](https://github.com/mateodd1)

</div>

---

<div align="center">

<h3>Usar el DNS de xdp.es</h3>

<p>No hace falta clonar este repo. Guía y copiar-y-pegar en <a href="https://xdp.es">xdp.es</a>.</p>

<h4>Adblock</h4>
<p>publicidad y malware fuera · DNSSEC · zero-logs</p>
<table align="center">
  <tr><td align="right"><strong>Web</strong></td><td align="left"><a href="https://xdp.es">https://xdp.es</a></td></tr>
  <tr><td align="right"><strong>DNS</strong></td><td align="left"><code>85.208.114.51</code> &nbsp; <code>2a0e:97c0:c40::51</code></td></tr>
  <tr><td align="right"><strong>DoH</strong></td><td align="left"><code>https://dns.xdp.es/dns-query</code></td></tr>
  <tr><td align="right"><strong>DoT</strong></td><td align="left"><code>dns.xdp.es</code> · puerto <code>853</code></td></tr>
  <tr><td align="right"><strong>DoQ</strong></td><td align="left"><code>quic://dns.xdp.es:853</code></td></tr>
  <tr><td align="right"><strong>iOS / macOS</strong></td><td align="left"><a href="https://xdp.es/dns_xdp_es_doh.mobileconfig">perfil DoH</a> · <a href="https://xdp.es/dns_xdp_es_dot.mobileconfig">perfil DoT</a></td></tr>
</table>

<h4>Standard</h4>
<p>sin adblock · la misma evasión · DNSSEC · zero-logs</p>
<table align="center">
  <tr><td align="right"><strong>Web</strong></td><td align="left"><a href="https://xdp.es">https://xdp.es</a></td></tr>
  <tr><td align="right"><strong>DNS</strong></td><td align="left"><code>85.208.114.52</code> &nbsp; <code>2a0e:97c0:c40::52</code></td></tr>
  <tr><td align="right"><strong>DoH</strong></td><td align="left"><code>https://lite.xdp.es/dns-query</code></td></tr>
  <tr><td align="right"><strong>DoT</strong></td><td align="left"><code>lite.xdp.es</code> · puerto <code>853</code></td></tr>
  <tr><td align="right"><strong>DoQ</strong></td><td align="left"><code>quic://lite.xdp.es:853</code></td></tr>
  <tr><td align="right"><strong>iOS / macOS</strong></td><td align="left"><a href="https://xdp.es/lite_xdp_es_doh.mobileconfig">perfil DoH</a> · <a href="https://xdp.es/lite_xdp_es_dot.mobileconfig">perfil DoT</a></td></tr>
</table>

</div>

---

## Qué es esto

A veces un operador no bloquea un dominio: bloquea **la IP**. En Cloudflare anycast esa misma dirección la comparten cientos de sitios, así que el corte es indiscriminado — cae lo que tocaba y lo que no. evade-proxy detecta esas IPs y, en la respuesta DNS, las sustituye por otra del mismo prefijo que no está cortada.

Tres piezas:

| | |
|:---|:---|
| **evade-proxy** | Proxy DNS en Rust. Reescribe en el paquete las IPs anycast bloqueadas. |
| **Lista de IPs** | Cada pocos segundos actualiza qué direcciones están cortadas y se lo pasa al proxy. |
| **Sonda residencial** | Un equipo en casa confirma IPv6 y CDNs que no son anycast. El servidor en datacenter no ve el bloqueo; la línea del abonado sí. |

## Cómo se lo salta

```
cliente → Blocky / DoH / DoT → evade-proxy :5335 → Unbound :5336
                                   │
                                   ├─ blocked_ips.txt       ← lista pública + sonda IPv4
                                   ├─ blocked_ipv6.txt      ← sonda IPv6
                                   ├─ cloudflare_prefixes   ← AS13335
                                   └─ redirects.txt         ← sonda (GitHub / Fastly / Akamai)
```

1. Unbound responde con la IP real (DNSSEC).
2. Si un A, AAAA o hint HTTPS/SVCB está en la blocklist **y** en un prefijo Cloudflare, el proxy la cambia por un vecino del mismo prefijo que no esté listado, y pone TTL 0.
3. Fuera de Cloudflare no se toca nada. En CDNs no-anycast la sonda fija un `redirect` a una IP **verificada** desde casa y desde el servidor.

La reescritura es in-place: punteros de compresión, flags y orden de registros se conservan.

## Compilar

Rust estable (1.82+):

```sh
cargo test --locked
cargo build --release --locked
./target/release/evade-proxy --help
```

Modo prueba (convive con producción: `:15335` / `:15337`, métricas `:15339`):

```sh
./target/release/evade-proxy --test \
  --redirect example.com=203.0.113.7
```

`--redirect` solo se acepta con `--test`.

## Instalar el servidor

Debian/Ubuntu, como root, desde el clone:

```sh
sudo ./scripts/install.sh
```

Instala el binario en `/usr/local/bin/evade-proxy`, el árbol en `/opt/xdp-dns-evadeproxy`, escribe `/etc/evade-proxy.env` y arranca el proxy + el timer de la lista de IPs.

```sh
sudo editor /etc/evade-proxy.env    # PROBE_TOKEN=…
sudo systemctl enable --now xdp-probe-server
```

Exponer el ingest de la sonda con TLS (Caddy):

```
handle /probe/* {
    reverse_proxy 127.0.0.1:8090
}
```

No ejecutar a la vez que un `evade_proxy` en Python: mismos puertos.

## Docker

Alternativa a `install.sh` para quien prefiera contenedores. El stack de ejemplo
levanta evade-proxy, un `unbound` recursivo con validación DNSSEC (su upstream
en `127.0.0.1:5336`/`:5338`) y el bucle que sincroniza blocklist + prefijos
Cloudflare:

```sh
cp evade-proxy.env.example evade-proxy.env   # PROBE_TOKEN=… si usas la sonda
docker compose up -d --build
```

`unbound` y `blocklist-updater` se unen al *network namespace* de
`evade-proxy` (`network_mode: "service:evade-proxy"`) porque el proxy siempre
resuelve su upstream en `127.0.0.1` (ver tabla de puertos más abajo) — no hay
forma de apuntarlo a otro contenedor por nombre de servicio.

Para ponerlo delante de un servidor DNS que ya use `network_mode: host` en el
mismo host (p. ej. AdGuard Home), añade `network_mode: host` al servicio
`evade-proxy`, quita su bloque `ports:`, y apunta el DNS upstream de ese
servidor a `127.0.0.1:5335`.

## Lista de IPs bloqueadas

`scripts/update-blocked-ips.sh`, timer cada 15 s:

1. Descarga el listado público IPv4 (`BLOCKLIST_URL`)
2. Se queda solo con direcciones IPv4
3. Une las IPs que confirmó la sonda
4. Escribe `/etc/unbound/blocked_ips.txt` — evade-proxy lo recarga cada 5 s
5. Une IPv6 de la sonda en `/etc/unbound/blocked_ipv6.txt`
6. Actualiza prefijos Cloudflare AS13335 (una vez al día)

No hace falta vaciar la caché del resolver: el proxy reescribe a la salida, también las respuestas ya cacheadas.

## Sonda residencial

Cubre **IPv6** y CDNs no-anycast. Pide objetivos, sondea `TCP:443` + TLS(SNI) + HTTP HEAD y reporta. El servidor solo marca bloqueo si **sirve en el datacenter y no en casa**, con histéresis (3 rondas para añadir, 2 para quitar).

En `probe/domains.json`:

- `cf-blocklist` — Cloudflare. La IP entra en la blocklist; el proxy salta al vecino.
- `verified-pool` — GitHub / Fastly / Akamai. Se fija `dominio=IP_sana` en `redirects.txt`.

En casa (Raspberry Pi / mini-PC):

```sh
sudo ./probe/agent/install-agent.sh https://dns.xdp.es/probe <TOKEN> mi-casa
```

Solo conexiones salientes (funciona detrás del NAT). Detalle: [`probe/README.md`](probe/README.md).

## Puertos

| Escucha | Upstream | Uso |
|:---|:---|:---|
| `127.0.0.1:5335` UDP/TCP | `:5336` | camino principal |
| `127.0.0.1:5337` UDP/TCP | `:5338` | segundo camino (Lite) |
| `127.0.0.1:5339` HTTP | — | `/metrics` y stats JSON |
| `127.0.0.1:8090` HTTP | — | ingest de la sonda |

Variables: [`evade-proxy.env.example`](evade-proxy.env.example). Redirects temporales de producción (`/run/evade-proxy/redirects.txt`):

```
ejemplo.es=104.18.13.102 1787609000
```

## Layout

```
src/main.rs                              evade-proxy
scripts/update-blocked-ips.sh            lista de IPs + sonda
scripts/update-cloudflare-prefixes.py    AS13335
probe/probe-server.py                    ingest + diferencial
probe/domains.json                       objetivos
probe/agent/                             sonda de casa
systemd/                                 unidades
```

<div align="center">

[Oihalitz](https://github.com/Oihalitz) con [mateodd1](https://github.com/mateodd1) · [xdp.es](https://xdp.es) · MIT

</div>
