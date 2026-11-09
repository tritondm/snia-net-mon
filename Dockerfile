# Snia-Net-Mon – Container-Image mit Server (snia-net-mon) und Demo-Generator (flowgen).
#
#   docker build -t snia-net-mon .
#   docker compose up -d                      # siehe docker-compose.yml
#
# Daten liegen unter /data (Volume), die Konfiguration unter /etc/snia-net-mon/config.toml.

# --- 1. Frontend (Svelte + Vite)
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- 2. Backend (Rust)
FROM rust:1-bookworm AS backend
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin snia-net-mon --bin flowgen \
    && install -Dm755 target/release/snia-net-mon target/release/flowgen -t /out

# --- 3. Laufzeit
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin snia \
    && install -d -o snia -g snia /data
COPY --from=backend /out/snia-net-mon /out/flowgen /usr/local/bin/
COPY --from=frontend /src/frontend/dist /usr/share/snia-net-mon/frontend
COPY docker/config.toml /etc/snia-net-mon/config.toml

USER snia
WORKDIR /data
VOLUME /data
# 8080/tcp: Web-UI und API · 2055/udp: NetFlow v9 / IPFIX
EXPOSE 8080/tcp 2055/udp
ENTRYPOINT ["snia-net-mon"]
CMD ["/etc/snia-net-mon/config.toml"]
