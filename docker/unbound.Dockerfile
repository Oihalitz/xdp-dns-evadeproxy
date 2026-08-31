# syntax=docker/dockerfile:1
# Minimal DNSSEC-validating recursive resolver, upstream of evade-proxy in
# the example Docker Compose stack. It must run in the same network
# namespace as the evade-proxy container (127.0.0.1:5336 / :5338).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        unbound dns-root-data \
    && rm -rf /var/lib/apt/lists/*

COPY docker/unbound.conf /etc/unbound/unbound.conf
# Seed the DNSSEC trust anchor from dns-root-data (RFC 5011 keeps it fresh
# afterwards). This mirrors /usr/libexec/unbound-helper root_trust_anchor_update,
# which Debian's unbound.service normally runs via systemd.
RUN mkdir -p /var/lib/unbound \
    && cp /usr/share/dns/root.key /var/lib/unbound/root.key \
    && chown -R unbound:unbound /var/lib/unbound

USER unbound

ENTRYPOINT ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
