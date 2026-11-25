# matrix-proxy

A high-performance, multi-tenant, single-domain reverse proxy for **Matrix Client-Server** and **Matrix Auth (MAS / OIDC)** written in Rust.

Designed for environments where direct connectivity to upstream Matrix homeservers or separate authentication servers is restricted: users simply enter **one proxy domain** (e.g. `https://proxy.example.com`) in any Matrix client (Element X, Element Web, Cinny, FluffyChat, etc.), and `matrix-proxy` handles automatic service discovery, OAuth 2.0 / OIDC login & token flows, long-polling `/sync`, Sliding Sync, LiveKit RTC JWT (`/ _rtc`), and streaming media transfers transparently.

## Key Features

1. **Multi-Upstream Deployments: Shared-Port Virtual Hosting & Dedicated Ports**
   - Define any number of upstream Matrix / Auth / RTC services via `[[proxies]]` blocks in `config.toml`, and freely mix both routing strategies in a single process:
     - **Shared-port domain routing**: Omit `listen` on multiple `[[proxies]]` blocks so your edge proxy (Nginx, HAProxy, Caddy, Envoy) forwards multiple domains to one port; `matrix-proxy` routes in $O(1)$ by `X-Forwarded-Host` / `Host` (exact match and `*.example.com` wildcards; unmatched hosts return `421 Misdirected Request`).
     - **Dedicated per-upstream ports**: Assign custom ports (e.g. `listen = "0.0.0.0:8081"`, `0.0.0.0:8082`) per `[[proxies]]` block so your edge proxy maps each domain to an isolated backend port.
   - Fully backward-compatible with single-upstream `[upstream]` config or zero-TOML environment variables.

2. **Single-Domain Auto-Discovery & Complete OAuth 2.0 / OIDC / MAS Rewriting**
   - Generates/merges `/.well-known/matrix/client` (follows up to 3 upstream 301/302 redirects during discovery, rewrites `m.homeserver.base_url`, `org.matrix.msc2965.authentication`, and `org.matrix.msc4143.rtc_foci`).
   - Proxies and rewrites `/_matrix/client/v1/auth_metadata`, `/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`, `/.well-known/openid-configuration`, and `/.well-known/oauth-authorization-server` (including RFC 8414 path insertion).
   - Supports **`root`** (default, preserves MAS frontend asset paths), **`prefix`** (`/_auth/*`), and **dual-domain** (`public_auth_url`) auth routing modes.
   - Rewrites `Location` redirects (including RFC 9207 `iss` callback parameters), strips upstream `Set-Cookie` `Domain`, rewrites `Content-Security-Policy`, `Origin`/`Referer` headers, and Auth HTML/JSON/JS/CSS bodies, with dynamic origin learning and `rewrite_origins`.

3. **Real Client IP Forwarding (Standard HTTP Headers + Vendor-Neutral PROXY Protocol v1/v2)**
   - **Anti-spoofing allowlist (`server.trusted_proxies`)**: Only trusts incoming forwarded headers and inbound PROXY Protocol frames when the physical TCP peer belongs to configured trusted CIDRs.
   - **Standard HTTP headers (`client_ip_mode = "replace" | "append" | "off"`)**: Injects clean `X-Forwarded-For`, `X-Real-IP`, and RFC 7239 `Forwarded` headers upstream.
   - **Standard PROXY Protocol v1 & v2 (`proxy_protocol = "off" | "v1" | "v2"`)**: Vendor-neutral inbound (`inbound_proxy_protocol`) and per-target outbound (`matrix_proxy_protocol`, `auth_proxy_protocol`, `rtc_proxy_protocol`) support compatible with **Nginx (`proxy_protocol`)**, **HAProxy (`accept-proxy`/`send-proxy-v2`)**, **Envoy**, **Traefik**, **Caddy**, and **AWS NLB**.
   - Maintains a bounded `(upstream, protocol, client_ip)`-isolated TLS 1.3 + HTTP/2 multiplexed connection pool (zero cross-client IP leakage) with **automatic single retry on stale idle connections** and WebSocket PROXY Protocol support.

4. **Zero-Downtime Hot Reload & Graceful Connection Draining**
   - **Three reload triggers**:
     1. Automatic file & TLS certificate watcher (`hot_reload = true`, default 2s polling with write debounce).
     2. Unix `SIGHUP` signal (`docker kill -s HUP matrix-proxy`).
     3. Trusted HTTP management endpoint (`POST /_proxy/reload`).
   - **Atomic swap with rollback protection**: Validates TOML syntax, TLS certificates, concurrent discovery warmup, and newly added listener sockets before touching live state; invalid reloads are rejected while keeping the previous active configuration serving traffic without dropping existing Keep-Alive / HTTP/2 connections.
   - **Graceful draining (`shutdown_grace_secs`)**: Sends HTTP/2 `GOAWAY` and drains in-flight requests cleanly on `SIGTERM` / `SIGINT`.

5. **Performance, Security & Observability**
   - Full-path `TCP_NODELAY`, `SO_KEEPALIVE`, `listen_backlog = 4096`, adaptive HTTP/2 flow control, globally cached `webpki` root cert store, singleflight discovery refresh coalescing, zero-buffer `/_matrix/*` streaming, optional outbound `http://` / `https://` / `socks5://` / `socks5h://` proxies, and optional native Rustls TLS.
   - Built-in Slowloris defense (`header_read_timeout_secs`), concurrency semaphore backpressure (`max_concurrent_requests`), optional per-IP token-bucket rate limiting (`rate_limit_rps`), RFC 9110 dynamic `Connection` hop-by-hop stripping, and trusted-only management endpoints (`/_proxy/info`, `/_proxy/metrics`, `POST /_proxy/reload`).

## Quick Start (Docker)

Prebuilt `linux/amd64` image: `utoptop/matrix-proxy:1.0`

### Option 1: Docker Compose + TOML Config (Recommended)

```bash
cp config.example.toml config.toml
# Edit config.toml with your proxy domains and upstream Matrix / Auth URLs
docker compose up -d
```

Mount the directory to `/app/conf:ro` (as in [compose.yaml](compose.yaml)) so `matrix-proxy` auto-loads `/app/conf/config.toml` and detects atomic editor/SFTP saves for automatic zero-downtime hot reload. See [config.example.toml](config.example.toml) for all options.

### Option 2: Environment Variables (Single Upstream)

See [.env.example](.env.example) for the complete list of supported variables:

```bash
docker run -d --name matrix-proxy \
  --restart unless-stopped \
  -p 127.0.0.1:8910:8080 \
  -e PUBLIC_URL="https://proxy.example.com" \
  -e MATRIX_UPSTREAM="https://matrix.example.org" \
  -e AUTH_UPSTREAM="https://auth.example.org" \
  utoptop/matrix-proxy:1.0
```

## Reverse Proxy Integration Examples

### Nginx (Shared Port, Multi-Domain)

```nginx
server {
    listen 443 ssl http2;
    server_name matrix1.example.com matrix2.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8910;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 600s;
    }
}
```

If your **upstream** Matrix reverse proxy is Nginx listening with `listen 8443 ssl proxy_protocol;`, set `matrix_proxy_protocol = "v2"` (or `"v1"`) in `config.toml` so Nginx receives the real client IP via `$proxy_protocol_addr`.

### HAProxy (Shared Port, Multi-Domain)

```haproxy
frontend ft_main_http
    http-request set-header X-Forwarded-For   %[src]
    http-request set-header X-Real-IP         %[src]
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]

    acl is_matrix_proxy hdr(host) -i matrix1.example.com matrix2.example.com
    use_backend bk_matrix_proxy if is_matrix_proxy

backend bk_matrix_proxy
    mode http
    http-reuse safe
    option http-keep-alive
    no option httpclose
    no option http-server-close
    no option http-buffer-request

    timeout connect 5s
    timeout queue 3s
    timeout server 60s
    timeout tunnel 1h

    acl is_ws hdr_beg(Upgrade) -i websocket
    http-request set-header Upgrade websocket if is_ws
    http-request set-header Connection upgrade if is_ws

    option httpchk GET /_proxy/health
    http-check expect status 200

    # Standard HTTP mode (recommended on localhost with `inbound_proxy_protocol = "off"`):
    server matrix_proxy 127.0.0.1:8910 check inter 10s rise 2 fall 3

    # Optional inbound PROXY Protocol v2 (`inbound_proxy_protocol = "v2"`):
    # server matrix_proxy 127.0.0.1:8910 send-proxy-v2 check check-send-proxy inter 10s rise 2 fall 3
```

## Management, Metrics & Hot Reload Endpoints

- `GET /_proxy/health` — Lightweight liveness probe (`200 OK` with active `generation`, never exposes upstream config).
- `GET /_proxy/info` — Active listeners, upstream summaries, and runtime stats (gated by `expose_info = "trusted"`; returns `403` publicly; proxy credentials are redacted).
- `GET /_proxy/metrics` — Prometheus exposition metrics (requests, active connections, upstream errors, PROXY Protocol retries, rate limits, reload counters; gated by `expose_info`).
- `POST /_proxy/reload` — Trigger an immediate zero-downtime config & TLS certificate reload (gated by `expose_info`; alternatively edit `config.toml` directly or send `SIGHUP`).

## Development & Testing

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Build and push linux/amd64 image via remote build node
./scripts/build-utop.sh
```

## License

[MIT](LICENSE)
