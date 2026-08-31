# syntax=docker/dockerfile:1
FROM rust:1.98-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl python3 dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin evade

COPY --from=builder /build/target/release/evade-proxy /usr/local/bin/evade-proxy
COPY scripts /opt/xdp-dns-evadeproxy/scripts
COPY probe/domains.json /opt/xdp-dns-evadeproxy/probe/domains.json

RUN mkdir -p /etc/unbound /var/lib/evade-proxy /run/evade-proxy /opt/xdp-dns-evadeproxy/data \
    && chown -R evade:evade /etc/unbound /var/lib/evade-proxy /run/evade-proxy /opt/xdp-dns-evadeproxy/data

ENV XDP_PREFIX=/opt/xdp-dns-evadeproxy
EXPOSE 5335/udp 5335/tcp 5337/udp 5337/tcp 5339/tcp

USER evade
ENTRYPOINT ["/usr/local/bin/evade-proxy"]
