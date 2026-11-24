# matrix-proxy

使用 Rust 构建的高性能、多租户单域名 Matrix 反向代理工具，用于解决部分国家/地区无法直接连接上游 Matrix Homeserver 与独立 Matrix Auth 服务（如 MAS / OIDC / Tuwunel OIDC）的问题。

用户只需在 Matrix 客户端（Element X、Element Web、Cinny、FluffyChat 等）中直接输入**一个代理域名**（例如 `https://proxy.example.com`），即可完成自动服务发现、OAuth 2.0 / OIDC 登录授权、令牌交换、长轮询 `/sync`、Sliding Sync 与大文件媒体传输。

## 核心特性

1. **多上游模块部署：同时支持「统一单端口按域名分流」与「每上游自定义独立端口」**
   - 在 `config.toml` 中通过多个 `[[proxies]]` 模块定义多组上游 Matrix / Auth / RTC 服务，并支持在**同一进程内混排**：
     - **模式 A（统一单端口 + 域名自动分流）**：多个 `[[proxies]]` 省略 `listen`（共享 `server.listen`），前置 HAProxy / Nginx 将多个代理域名统一转发至同一端口，`matrix-proxy` 按 `X-Forwarded-Host` / `Host`（支持精确域名与 `*.example.com` 通配符）做 $O(1)$ 自动路由；未知域名返回 `421 Misdirected Request`。
     - **模式 B（每上游自定义独立端口）**：在 `[[proxies]]` 中各自指定 `listen = "0.0.0.0:8081"`、`0.0.0.0:8082` 等，HAProxy 按不同域名分别转发到不同后端端口。
   - **向下兼容**：不定义 `[[proxies]]` 时完全兼容单上游 `[upstream]` 配置与纯环境变量部署；容器挂载 `/app/config.toml` 时自动检测加载。
2. **单域名自动发现与完整 OAuth 2.0 / OIDC / MAS 重写**
   - 自动生成/合并并重写 `/.well-known/matrix/client`（重写 `m.homeserver.base_url`、`org.matrix.msc2965.authentication` 与可选 `org.matrix.msc4143.rtc_foci`）。
   - 自动代理并重写 `/_matrix/client/v1/auth_metadata`、`/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`（v1 与 unstable 自动互为降级）、`/.well-known/openid-configuration` 与 `/.well-known/oauth-authorization-server`（含 RFC 8414 路径插入形式）。
   - 支持 **`root`**（默认，零前端资源路径破坏）、**`prefix`**（`/_auth/*`）与**双域名**（`public_auth_url`）三种路由模式。
   - 完整处理登录交互：`Location` 重定向与 RFC 9207 `iss` 回调参数重写、`Set-Cookie` 上游 `Domain` 剥离、`Content-Security-Policy` 重写、表单 CSRF `Origin`/`Referer` 重写、Auth 登录页 HTML/JSON 硬编码上游地址重写，以及 `rewrite_origins` 与实时 `auth_metadata` 源站自动学习。
3. **真实客户端 IP 透传（双机制 + 防伪造）**
   - **可信代理白名单防伪造（`server.trusted_proxies`）**：仅当物理连接对端 IP 属于白名单 CIDR（如本机回环、Docker 网桥、内网 HAProxy）时才采信 `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` / `Forwarded` / `X-Forwarded-Host`，彻底阻断公网直连伪造 IP 或 Host 注入。
   - **标准 HTTP 头透传（`client_ip_mode = "replace" | "append" | "off"`）**：向上游规范写入 `X-Forwarded-For`、`X-Real-IP` 与 RFC 7239 `Forwarded`。
   - **原生 HAProxy PROXY Protocol v2（`send_proxy_v2` / `matrix_send_proxy_v2` / `auth_send_proxy_v2`）**：支持直连开启 `accept-proxy` 的上游端口（如 `8443`），在 TLS 握手前写入标准二进制 PPv2 头，上游内核级原生获取真实客户端 IP；同时维护**按 `(upstream, client_ip)` 隔离的有界 TLS 1.3 + HTTP/2 多路复用连接池**（同 IP 复用零握手延迟、跨 IP 零串用泄露），亦支持入站 `accept_proxy_v2 = true` 与 WebSocket PPv2 透传。
4. **极致性能与安全加固**
   - 全链路 `TCP_NODELAY`、`SO_KEEPALIVE`、高监听队列 `listen_backlog = 4096`、`HTTP/2` 自适应窗口与保活、`Arc` 零拷贝发现缓存、`/_matrix/*` 全程零缓冲流式转发、可选出站 `http://` / `https://` / `socks5://` / `socks5h://` 代理与原生 Rustls TLS。
   - 内置慢速攻击防护（`header_read_timeout_secs`）、并发信号量背压（`max_concurrent_requests`）、可选按 IP 令牌桶限流（`rate_limit_rps` / `rate_limit_burst`）、RFC 9110 动态 `Connection` hop-by-hop 清洗，以及 `/_proxy/info` 访问隔离（`expose_info = "trusted"`，默认仅允许本机/可信内网访问）。

## 快速开始（Docker）

预构建 `linux/amd64` 镜像：`utoptop/matrix-proxy:1.0`

### 方式一：Docker Compose + 多上游配置文件（推荐）

```bash
cp config.example.toml config.toml
# 编辑 config.toml 填入你的代理域名与上游 Matrix / Auth 地址
docker compose up -d
```

容器会自动检测并加载 `/app/config.toml`，并通过内置 `matrix-proxy --health-check` 进行健康检查。完整参数注释见 [config.example.toml](config.example.toml)。

### 方式二：纯环境变量单上游快速启动

完整环境变量清单见 [.env.example](.env.example)：

```bash
docker run -d --name matrix-proxy \
  --restart unless-stopped \
  -p 127.0.0.1:8910:8080 \
  -e PUBLIC_URL="https://proxy.example.com" \
  -e MATRIX_UPSTREAM="https://matrix.example.org" \
  -e AUTH_UPSTREAM="https://auth.example.org" \
  utoptop/matrix-proxy:1.0
```

## 前置反向代理示例

### HAProxy：统一单端口多域名自动分流

```haproxy
frontend ft_main_http
    # 请在 frontend 注入真实客户端 IP 与原始 Host
    http-request set-header X-Forwarded-For   %[src]
    http-request set-header X-Real-IP         %[src]
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]

    acl is_matrix_proxy hdr(host) -i proxy1.example.com proxy2.example.com
    use_backend bk_matrix_proxy if is_matrix_proxy

backend bk_matrix_proxy
    mode http
    http-reuse safe
    option http-keep-alive
    no option httpclose
    no option http-server-close
    no option http-buffer-request

    timeout connect 5s
    timeout queue 5s
    timeout server 360s
    timeout tunnel 1h

    acl is_ws hdr_beg(Upgrade) -i websocket
    http-request set-header Upgrade websocket if is_ws
    http-request set-header Connection upgrade if is_ws

    option httpchk GET /_proxy/health
    http-check expect status 200

    # 标准 HTTP 模式（config.toml: accept_proxy_v2 = false）：
    server matrix_proxy 127.0.0.1:8910 check inter 10s rise 2 fall 3

    # 若需全链路 HAProxy PROXY Protocol v2（config.toml: accept_proxy_v2 = true），
    # 请改用以下 server 行（务必加 check-send-proxy，并保持 http-reuse safe）：
    # server matrix_proxy 127.0.0.1:8910 send-proxy-v2 check check-send-proxy inter 10s rise 2 fall 3
```

### HAProxy：每上游自定义独立端口

当 `config.toml` 中为不同 `[[proxies]]` 分别配置了 `listen = "0.0.0.0:8080"`、`0.0.0.0:8081` 并映射为宿主机 `8910`、`8911` 时，在 HAProxy 中将不同域名分别指向 `127.0.0.1:8910` 和 `127.0.0.1:8911` 即可。

### Nginx 示例

```nginx
server {
    listen 443 ssl http2;
    server_name proxy1.example.com proxy2.example.com;

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

## 运维探针

- `GET /_proxy/health`：轻量存活探针（任何域名/无 `Host` 均返回 `200 OK`，不暴露上游信息）
- `GET /_proxy/info`：运行状态与已加载上游摘要（默认 `expose_info = "trusted"`，仅本机/可信内网可访问，公网返回 `403`；代理凭证自动脱敏）

## 本地测试与构建

```bash
# 格式化、Lint 与全量单元/集成测试
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# 在远程 x86_64 节点构建并推送 linux/amd64 镜像
./scripts/build-utop.sh
```

## License

[MIT](LICENSE)
