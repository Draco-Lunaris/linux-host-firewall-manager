FROM ubuntu:24.04 AS rust-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    curl pkg-config libssl-dev libpq-dev build-essential \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY migrations/ migrations/
RUN cargo build --release && \
    strip target/release/fw-web && \
    strip target/release/fw-worker && \
    strip target/release/fw-agent && \
    strip target/release/migrate-secrets

# ─── Frontend builder ────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS frontend-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

WORKDIR /build/frontend
COPY frontend/ .
RUN npm ci && npm run build

# ─── Runtime ─────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    libssl3t64 libfontconfig1 openssl postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin \
    --home-dir /opt/firewall-manager firewall-manager

RUN mkdir -p /etc/firewall-manager/jwt /etc/firewall-manager/ca /etc/firewall-manager/keys \
    /var/log/firewall-manager /var/www/firewall-agent-repo /opt/firewall-manager \
    /usr/share/firewall-manager/frontend /usr/share/firewall-manager/migrations

COPY --from=rust-builder /build/target/release/fw-web /usr/local/bin/
COPY --from=rust-builder /build/target/release/fw-worker /usr/local/bin/
COPY --from=rust-builder /build/target/release/fw-agent /usr/local/bin/
COPY --from=rust-builder /build/target/release/migrate-secrets /usr/local/bin/
COPY --from=frontend-builder /build/frontend/dist/ /usr/share/firewall-manager/frontend/
COPY migrations/ /usr/share/firewall-manager/migrations/
COPY config/config.example.toml /etc/firewall-manager/config.example.toml

RUN chown -R firewall-manager:firewall-manager /etc/firewall-manager /var/log/firewall-manager /var/www/firewall-agent-repo /opt/firewall-manager

EXPOSE 443 80

USER firewall-manager
WORKDIR /opt/firewall-manager

ENTRYPOINT ["fw-web"]