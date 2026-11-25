# syntax=docker/dockerfile:1

FROM rust:1.93.1-bookworm AS builder
WORKDIR /app

ARG CARGO_BUILD_JOBS
ARG TARGETARCH

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=matrix-proxy-target-${TARGETARCH},target=/app/target \
    if [ -n "${CARGO_BUILD_JOBS}" ]; then \
      cargo build --release --locked --bin matrix-proxy -j "${CARGO_BUILD_JOBS}"; \
    else \
      cargo build --release --locked --bin matrix-proxy; \
    fi \
    && cp /app/target/release/matrix-proxy /tmp/matrix-proxy

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="matrix-proxy" \
      org.opencontainers.image.description="High-performance multi-tenant Rust reverse proxy for Matrix Client-Server and Matrix Auth (MAS/OIDC) with auto-discovery, HTTP/IP:port & Tailscale support, global HTTP/SOCKS5 outbound proxy, zero-downtime hot reload, and standard PROXY Protocol v1/v2" \
      org.opencontainers.image.version="1.4.3" \
      org.opencontainers.image.source="https://github.com/utoptop/matrix-proxy" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 matrixproxy \
    && useradd --uid 1000 --gid matrixproxy --no-create-home matrixproxy

WORKDIR /app
COPY --from=builder /tmp/matrix-proxy /usr/local/bin/matrix-proxy
COPY config.example.toml /app/config.example.toml

USER 1000:1000
EXPOSE 8080

ENV LISTEN_ADDR=0.0.0.0:8080 \
    RUST_LOG=matrix_proxy=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["matrix-proxy", "--health-check"]

ENTRYPOINT ["matrix-proxy"]
