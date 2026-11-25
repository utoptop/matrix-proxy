# matrix-proxy

A high-performance, multi-tenant reverse proxy for **Matrix Client-Server** and **Matrix Auth (MAS / OIDC)** written in Rust.

Designed for environments where direct connectivity to upstream Matrix homeservers or separate authentication servers is restricted — whether deployed behind a public domain (`https://proxy.example.com`) or directly over a private overlay network such as **Tailscale / WireGuard (`http://<tailscale-ip>:<port>`) with zero domains or TLS certificates required**. Users simply enter one `matrix_proxy_public_url` in any Matrix client (Element X, Element Web, Cinny, FluffyChat, etc.), and `matrix-proxy` transparently handles service discovery, direct MatrixRTC (`mrtc` / LiveKit JWT) delegation, OAuth 2.0 / OIDC login & token flows, long-polling `/sync`, Sliding Sync, and streaming media transfers.

## Key Features

1. **Flexible Multi-Upstream Architecture: Shared Port, Dedicated Ports & Domainless `http://ip:port` (Tailscale / LAN)**
   - Define any number of upstream Matrix / Auth services via `[[proxies]]` blocks in `config.toml`, freely combining all modes in one process:
     - **Shared-port host routing**: Omit `listen` on multiple `[[proxies]]` blocks so Nginx / HAProxy / Caddy / Envoy forwards multiple hosts to one port; `matrix-proxy` automatically derives routing hosts from `matrix_proxy_public_url` (no redundant `domains` list needed; unmatched hosts return `421 Misdirected Request`).
     - **Domainless `http://ip:port` mode (Tailscale / WireGuard / LAN)**: Set `listen = "0.0.0.0:8081"` and `matrix_proxy_public_url = "http://100.64.0.10:8081"` to access upstream Matrix servers directly over your Tailscale IP with zero domain registration or TLS certificate management. On plain HTTP public URLs, `matrix-proxy` automatically strips `Secure` & HSTS, downgrades `SameSite=None` cookies to `SameSite=Lax`, and removes CSP `upgrade-insecure-requests` so web OIDC/MAS logins work seamlessly.
     - **Single-upstream zero-TOML mode**: Still fully supported via environment variables.

2. **Global HTTP / HTTPS / SOCKS5 Outbound Proxy & Bypass Rules**
   - Configure `[defaults].outbound_proxy` once (`http://`, `https://`, `socks5://`, or `socks5h://` with optional `user:pass@` authentication) to route **all** outbound upstream Matrix, Auth, Discovery, WebSocket, and PROXY Protocol connections through an outbound proxy when the proxy node itself has network restrictions (`socks5h://` resolves DNS remotely via the proxy).
   - Fine-grained exemptions via `[defaults].outbound_no_proxy` (hostnames, `.domain` suffixes, IPs, and IPv4/IPv6 CIDRs such as `100.64.0.0/10`) and per-profile overrides (`outbound_proxy = "direct"` to bypass the global proxy for local/LAN upstreams, or a different proxy URL per upstream).

3. **Single-Endpoint Auto-Discovery, Direct MatrixRTC (`mrtc`) Delegation & Complete OAuth 2.0 / OIDC / MAS Rewriting**
   - Synthesizes/merges `/.well-known/matrix/client` (follows up to 3 upstream 301/302 redirects during discovery, rewrites `m.homeserver.base_url` and `org.matrix.msc2965.authentication`, and delegates `org.matrix.msc4143.rtc_foci` directly to your reachable MatrixRTC / LiveKit JWT server via `matrix_rtc_url` / `matrix_rtc_urls`, or preserves upstream foci with `"upstream"`, avoiding ineffective HTTP proxying and private proxy URL leaks in federated rooms).
   - Proxies and rewrites `/_matrix/client/v1/auth_metadata`, `/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`, `/.well-known/openid-configuration`, and `/.well-known/oauth-authorization-server` (including RFC 8414 path insertion), with built-in self-loop protection if an upstream already advertises the proxy's own `matrix_proxy_public_url`.
   - Supports **`root`** (default, preserves MAS frontend asset paths), **`prefix`** (`/_auth/*`), and **dual-URL** (`matrix_proxy_public_auth_url`) auth routing modes, plus three **Auth proxy strategies (`auth_proxy_mode`)**:
     - **`full`** (default): Rewrites and proxies the complete Auth/MAS flow (including `issuer`, `authorization_endpoint`, `account_management_uri`, `org.matrix.matrix-authentication-service.graphql_endpoint`, and token endpoints) — best for self-hosted homeservers and password/local-OIDC servers.
     - **`token_only`** (recommended for third-party servers with multi-hop external IdPs such as Mozilla Accounts, Google, Apple, or Passkey/WebAuthn): Keeps `issuer` and interactive browser login URLs on the official Auth origin (avoiding `invalid_redirect_uri` and anti-phishing blocks during initial login), while rewriting background machine endpoints (`token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `jwks_uri`, `userinfo_endpoint`) and Matrix Client-Server API so silent token refresh, messaging, and media run 24/7 through `matrix-proxy`.
     - **`direct`**: Passes Auth/OIDC metadata through verbatim and proxies Matrix Client-Server API only.
   - Rewrites `Location` redirects (including RFC 9207 `iss` and `next`/`redirect_to` parameters), Matrix Client-Server `401`/`403` UIA OAuth approval URLs (MSC4312 `m.oauth.url`, `org.matrix.cross_signing_reset` `approval_url`, `consent_uri` so in-app cross-signing/account resets stay on the proxy domain), strips upstream `Set-Cookie` `Domain`, rewrites `Content-Security-Policy`, `Origin`/`Referer` headers, and Auth HTML/JSON/JS/CSS bodies (including HTML-entity `&#x2f;` and percent-encoded origins), with dynamic origin learning and `upstream_rewrite_origins`.

4. **Real Client IP Forwarding (Standard HTTP Headers + Vendor-Neutral PROXY Protocol v1/v2)**
   - **Anti-spoofing allowlist (`server.trusted_proxies`)**: Only trusts incoming forwarded headers and inbound PROXY Protocol frames when the physical TCP peer belongs to configured trusted CIDRs.
   - **Standard HTTP headers (`client_ip_mode = "replace" | "append" | "off"`)**: Injects clean `X-Forwarded-For`, `X-Real-IP`, and RFC 7239 `Forwarded` headers upstream.
   - **Standard PROXY Protocol v1 & v2 (`"off" | "v1" | "v2"`)**: Vendor-neutral inbound (`inbound_proxy_protocol`) and per-target outbound (`upstream_matrix_proxy_protocol`, `upstream_auth_proxy_protocol`) support compatible with **Nginx (`proxy_protocol`)**, **HAProxy (`accept-proxy`/`send-proxy-v2`)**, **Envoy**, **Traefik**, **Caddy**, and **AWS NLB**.
   - Maintains a bounded `(upstream, protocol, client_ip)`-isolated TLS 1.3 + HTTP/2 multiplexed connection pool (zero cross-client IP leakage) with **cold-dial singleflight coalescing**, **automatic single retry on stale idle connections**, high-BDP HTTP/2 flow-control windows (`1 MiB` stream / `4 MiB` connection), and WebSocket PROXY Protocol support.

5. **Zero-Downtime Hot Reload, Caching, Graceful Draining & Observability**
   - **Low-latency caching & Stale-While-Revalidate (SWR)**: Non-blocking SWR upstream discovery refresh and singleflight TTL caching for `auth_metadata` / OIDC discovery documents (with stale-on-error fallback and `Cache-Control`) keep hot-path latency sub-millisecond with zero per-request header cloning.
   - **Three reload triggers**: non-blocking metadata-first file & TLS cert watcher (`hot_reload = true`, default 2s polling with debounce), Unix `SIGHUP` (`docker kill -s HUP matrix-proxy`), and `POST /_proxy/reload`.
   - **Rollback-safe atomic swap**: Validates TOML, TLS certificates, discovery warmup, and new listener binds before touching live state.
   - **Graceful draining (`shutdown_grace_secs`)**, Slowloris defense (`header_read_timeout_secs`), concurrency semaphore (`max_concurrent_requests`), optional per-IP rate limiting (`rate_limit_rps`), and trusted-only `/_proxy/info` & Prometheus `/_proxy/metrics`.

## Quick Start (Docker — Multi-Arch `linux/amd64` + `linux/arm64`)

Prebuilt native multi-arch (`linux/amd64` + `linux/arm64`) images are published to both **Docker Hub** and **GitHub Container Registry (GHCR)**:
- Docker Hub: `utoptop/matrix-proxy:1.0` / `utoptop/matrix-proxy:latest`
- GitHub Container Registry: `ghcr.io/utoptop/matrix-proxy:latest` / `ghcr.io/utoptop/matrix-proxy:1.0`

### Option 1: Docker Compose + TOML Config (Recommended)

```bash
cp config.example.toml config.toml
# Edit config.toml with your matrix_proxy_public_url and upstream_matrix_* URLs
docker compose up -d
```

Mount the config directory to `/app/conf:ro` (as in [compose.yaml](compose.yaml)) so `matrix-proxy` auto-loads `/app/conf/config.toml` and detects atomic editor/SFTP saves for automatic zero-downtime hot reload. See [config.example.toml](config.example.toml) for all options.

### Option 2: Domainless Tailscale `http://ip:port` Quick Start (No Domain / No TLS Cert)

Run `matrix-proxy` on a server connected to your Tailscale tailnet (for example `100.64.0.10`), optionally routing outbound upstream traffic through a local SOCKS5/HTTP proxy:

```toml
[defaults]
outbound_proxy = "socks5h://127.0.0.1:1080"
outbound_no_proxy = ["127.0.0.1", "localhost", "100.64.0.0/10"]

[[proxies]]
name = "matrix-org-tailscale"
listen = "0.0.0.0:8081"
matrix_proxy_public_url = "http://100.64.0.10:8081"
upstream_matrix_server_url = "https://matrix-client.matrix.org"
upstream_matrix_auth_url = "https://account.matrix.org"
upstream_matrix_server_name = "matrix.org"
matrix_rtc_url = "https://mrtc.example.org"
```

Then enter `http://100.64.0.10:8081` directly as your homeserver URL in your Matrix client on any device in the same Tailscale network.

### Option 3: Environment Variables (Single Upstream)

See [.env.example](.env.example) for the complete list of supported variables:

```bash
docker run -d --name matrix-proxy \
  --restart unless-stopped \
  -p 127.0.0.1:8910:8080 \
  -e MATRIX_PROXY_PUBLIC_URL="https://proxy.example.com" \
  -e UPSTREAM_MATRIX_SERVER_URL="https://matrix.example.org" \
  -e UPSTREAM_MATRIX_AUTH_URL="https://auth.example.org" \
  -e OUTBOUND_PROXY="socks5h://127.0.0.1:1080" \
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

If your **upstream** Matrix reverse proxy is Nginx listening with `listen 8443 ssl proxy_protocol;`, set `upstream_matrix_proxy_protocol = "v2"` (or `"v1"`) in `config.toml` so Nginx receives the real client IP via `$proxy_protocol_addr`.

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

## Management, Metrics, Validation & Hot Reload

- `matrix-proxy --check-config --config /path/to/config.toml` — Offline config & TLS certificate validator (exits `0` with a listener/profile/outbound-proxy summary, or `1` on syntax/routing/TLS errors — ideal before deploying or reloading).
- `GET /_proxy/health` — Lightweight liveness probe (`200 OK` with active `generation`, never exposes upstream config).
- `GET /_proxy/info` — Active listeners, upstream summaries, and runtime stats (gated by `expose_info = "trusted"`; returns `403` publicly; proxy credentials are redacted).
- `GET /_proxy/metrics` — Prometheus exposition metrics (requests, active connections, upstream errors, PROXY Protocol retries, rate limits, reload counters; gated by `expose_info`).
- `POST /_proxy/reload` — Trigger an immediate zero-downtime config & TLS certificate reload (gated by `expose_info`; alternatively edit `config.toml` directly or send `SIGHUP`).

## Configuration Structure & Precedence

`config.toml` uses three clean layers where **per-node `[[proxies]]` settings always take precedence**:

1. **`[[proxies]]`** — Per-node settings (overrides anything in `[defaults]` or `[server]`: custom `listen`, `outbound_proxy` including `"direct"`, `outbound_no_proxy`, `tls_cert = "off"`, `upstream_matrix_proxy_protocol`, `auth_mode`, timeouts, etc.).
2. **`[defaults]`** — Unified global defaults inherited by all `[[proxies]]` blocks (every key uses the exact same name inside `[[proxies]]`).
3. **`[server]`** (with optional `[server.reload]` and `[server.tuning]`) — Shared listener, TLS, `trusted_proxies`, management ACL, hot reload, and connection tuning.

Legacy flat `[server].*` and `[upstream]`/`[routing]`/`[discovery]` sections remain 100% backward compatible. See [config.example.toml](config.example.toml) for a complete reference.

## Development & Multi-Arch Build

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Native multi-arch build & push (local ARM64 Mac + remote AMD64 utop -> unified manifest)
./scripts/build-multiarch.sh
```

## License

[MIT](LICENSE)
