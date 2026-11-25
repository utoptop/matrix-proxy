use crate::client_ip::{encode_proxy_protocol_local, encode_proxy_protocol_proxy};
use crate::config::{ProxyProtocol, ServerConfig, should_bypass_outbound_proxy};
use crate::metrics::ProxyMetrics;
use crate::ws::{
    build_client_tls_config, connect_via_proxy, fallback_dst_addr, trim_ipv6_brackets,
};
use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;
use tracing::debug;
use url::Url;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
pub type BoxedStream = Box<dyn AsyncReadWrite>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: String,
    host: String,
    port: u16,
    proto: ProxyProtocol,
    client_ip: Option<IpAddr>,
}

struct H2Entry {
    sender: hyper::client::conn::http2::SendRequest<Body>,
    last_used: Instant,
}

struct H1Entry {
    sender: hyper::client::conn::http1::SendRequest<Body>,
    last_used: Instant,
}

enum SelectedConn {
    H2(hyper::client::conn::http2::SendRequest<Body>),
    H1(hyper::client::conn::http1::SendRequest<Body>),
}

/// High-performance HTTP/2 + HTTP/1.1 upstream client supporting HAProxy PROXY Protocol v1/v2.
/// Connections are pooled per `(upstream_host_port, proto, real_client_ip)` with cold-dial
/// singleflight coalescing so:
/// - Concurrent cold requests from the SAME client IP share ONE TCP + PROXY + TLS 1.3 + H2 handshake.
/// - Requests from DIFFERENT client IPs NEVER share a PROXY Protocol TCP connection (zero IP leakage).
pub struct Ppv2Client {
    tls_config: Arc<rustls::ClientConfig>,
    outbound_proxy: Option<Url>,
    outbound_no_proxy: Vec<String>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    tcp_keepalive: Duration,
    tcp_nodelay: bool,
    max_entries: usize,
    h2_pool: Mutex<HashMap<PoolKey, H2Entry>>,
    h1_pool: Mutex<HashMap<PoolKey, Vec<H1Entry>>>,
    /// Per-key singleflight coalescing map preventing cold-start TLS/H2 handshake stampedes.
    in_flight: Arc<Mutex<HashMap<PoolKey, Arc<Notify>>>>,
    last_sweep: Mutex<Instant>,
    metrics: Option<Arc<ProxyMetrics>>,
}

struct InFlightGuard {
    map: Arc<Mutex<HashMap<PoolKey, Arc<Notify>>>>,
    key: PoolKey,
    notify: Arc<Notify>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map
            .get(&self.key)
            .is_some_and(|existing| Arc::ptr_eq(existing, &self.notify))
        {
            map.remove(&self.key);
        }
        self.notify.notify_waiters();
    }
}

impl Ppv2Client {
    pub fn new(
        server: &ServerConfig,
        outbound_proxy: Option<&str>,
        outbound_no_proxy: Vec<String>,
        connect_timeout_secs: u64,
        danger_accept_invalid_certs: bool,
        metrics: Option<Arc<ProxyMetrics>>,
    ) -> Result<Self> {
        let tls_config = build_client_tls_config(
            danger_accept_invalid_certs,
            &[b"h2".as_slice(), b"http/1.1".as_slice()],
        )?;
        let proxy_url = match outbound_proxy {
            Some(raw) => Some(Url::parse(raw).context("invalid outbound_proxy URL")?),
            None => None,
        };
        Ok(Self {
            tls_config,
            outbound_proxy: proxy_url,
            outbound_no_proxy,
            connect_timeout: Duration::from_secs(connect_timeout_secs.max(1)),
            idle_timeout: Duration::from_secs(server.pool_idle_timeout_secs.max(10)),
            tcp_keepalive: Duration::from_secs(server.tcp_keepalive_secs),
            tcp_nodelay: server.tcp_nodelay,
            max_entries: server.proxy_protocol_pool_max_entries.max(64),
            h2_pool: Mutex::new(HashMap::with_capacity(256)),
            h1_pool: Mutex::new(HashMap::with_capacity(64)),
            in_flight: Arc::new(Mutex::new(HashMap::with_capacity(64))),
            last_sweep: Mutex::new(Instant::now()),
            metrics,
        })
    }

    /// Sends a streaming HTTP request to `target_url` with a PROXY Protocol v1/v2 header for `client_addr`
    /// (`None` sends a LOCAL/UNKNOWN header for proxy-originated discovery probes).
    /// Automatically retries once on a fresh TCP+PROXY+TLS connection if a pooled idle connection
    /// became stale before request transmission (eliminates transient 502s after upstream keepalive close).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request(
        &self,
        method: Method,
        target_url: &Url,
        host_override: Option<&str>,
        headers: HeaderMap,
        body: Body,
        proto: ProxyProtocol,
        client_addr: Option<SocketAddr>,
    ) -> Result<Response<Incoming>> {
        let host = target_url
            .host_str()
            .ok_or_else(|| anyhow!("missing upstream host in {target_url}"))?
            .to_string();
        let port = target_url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("missing upstream port in {target_url}"))?;
        let use_tls = target_url.scheme().eq_ignore_ascii_case("https");

        let key = PoolKey {
            scheme: target_url.scheme().to_ascii_lowercase(),
            host: host.clone(),
            port,
            proto,
            client_ip: client_addr.map(|s| s.ip()),
        };

        let pq = path_and_query(target_url);
        let host_hdr = if let Some(ov) = host_override {
            ov.to_string()
        } else {
            match target_url.port() {
                Some(p) => format!("{host}:{p}"),
                None => host.clone(),
            }
        };

        let can_replay_body = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);

        // Try pooled connection first; if stale before transmission (or safe idempotent replay), reconnect once.
        let (conn, was_reused) = self
            .checkout_or_connect(&key, &host, port, use_tls, proto, client_addr)
            .await?;

        match conn {
            SelectedConn::H2(mut sender) => {
                if let Err(err) = sender.ready().await {
                    if was_reused {
                        self.evict_h2(&key);
                        self.record_retry();
                        debug!(host = %host, port, error = %err, "stale pooled PROXY Protocol H2 connection evicted before send; reconnecting");
                        let fresh = self
                            .connect_fresh(&key, &host, port, use_tls, proto, client_addr)
                            .await?;
                        let req = build_hyper_req(&method, &pq, &host_hdr, &headers, body)?;
                        return self.dispatch_on_conn(&key, fresh, req).await;
                    }
                    return Err(err).context("upstream H2 sender not ready");
                }

                let req = build_hyper_req(&method, &pq, &host_hdr, &headers, body)?;
                match sender.send_request(req).await {
                    Ok(resp) => Ok(resp),
                    Err(err) if was_reused && can_replay_body => {
                        self.evict_h2(&key);
                        self.record_retry();
                        debug!(host = %host, port, error = %err, "pooled PROXY Protocol H2 request failed on idempotent method; retrying once");
                        let fresh = self
                            .connect_fresh(&key, &host, port, use_tls, proto, client_addr)
                            .await?;
                        let retry_req =
                            build_hyper_req(&method, &pq, &host_hdr, &headers, Body::empty())?;
                        self.dispatch_on_conn(&key, fresh, retry_req).await
                    }
                    Err(err) => {
                        self.evict_h2(&key);
                        Err(err).context("upstream H2 request failed")
                    }
                }
            }
            SelectedConn::H1(mut sender) => {
                if let Err(err) = sender.ready().await {
                    if was_reused {
                        self.record_retry();
                        debug!(host = %host, port, error = %err, "stale pooled PROXY Protocol H1 connection evicted before send; reconnecting");
                        let fresh = self
                            .connect_fresh(&key, &host, port, use_tls, proto, client_addr)
                            .await?;
                        let req = build_hyper_req(&method, &pq, &host_hdr, &headers, body)?;
                        return self.dispatch_on_conn(&key, fresh, req).await;
                    }
                    return Err(err).context("upstream H1 sender not ready");
                }

                let req = build_hyper_req(&method, &pq, &host_hdr, &headers, body)?;
                match sender.send_request(req).await {
                    Ok(resp) => {
                        if !sender.is_closed() && sender.is_ready() {
                            self.return_h1(key, sender);
                        }
                        Ok(resp)
                    }
                    Err(err) if was_reused && can_replay_body => {
                        self.record_retry();
                        debug!(host = %host, port, error = %err, "pooled PROXY Protocol H1 request failed on idempotent method; retrying once");
                        let fresh = self
                            .connect_fresh(&key, &host, port, use_tls, proto, client_addr)
                            .await?;
                        let retry_req =
                            build_hyper_req(&method, &pq, &host_hdr, &headers, Body::empty())?;
                        self.dispatch_on_conn(&key, fresh, retry_req).await
                    }
                    Err(err) => Err(err).context("upstream H1 request failed"),
                }
            }
        }
    }

    async fn dispatch_on_conn(
        &self,
        key: &PoolKey,
        conn: SelectedConn,
        req: Request<Body>,
    ) -> Result<Response<Incoming>> {
        match conn {
            SelectedConn::H2(mut sender) => {
                sender
                    .ready()
                    .await
                    .context("fresh upstream H2 sender not ready")?;
                sender
                    .send_request(req)
                    .await
                    .context("fresh upstream H2 request failed")
            }
            SelectedConn::H1(mut sender) => {
                sender
                    .ready()
                    .await
                    .context("fresh upstream H1 sender not ready")?;
                let resp = sender
                    .send_request(req)
                    .await
                    .context("fresh upstream H1 request failed")?;
                if !sender.is_closed() && sender.is_ready() {
                    self.return_h1(key.clone(), sender);
                }
                Ok(resp)
            }
        }
    }

    fn evict_h2(&self, key: &PoolKey) {
        let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.remove(key);
    }

    fn record_retry(&self) {
        if let Some(m) = &self.metrics {
            m.proxy_protocol_retries_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Convenience helper for buffered discovery/metadata GET requests over PROXY Protocol (LOCAL/UNKNOWN).
    pub async fn get_bytes(
        &self,
        url: &Url,
        host_override: Option<&str>,
        headers: HeaderMap,
        timeout: Duration,
        proto: ProxyProtocol,
    ) -> Result<(StatusCode, Vec<u8>, Option<HeaderValue>)> {
        self.get_bytes_for_client(url, host_override, headers, timeout, proto, None)
            .await
    }

    /// Buffered GET over PROXY Protocol v1/v2, optionally carrying the real client address in the header.
    pub async fn get_bytes_for_client(
        &self,
        url: &Url,
        host_override: Option<&str>,
        mut headers: HeaderMap,
        timeout: Duration,
        proto: ProxyProtocol,
        client_addr: Option<SocketAddr>,
    ) -> Result<(StatusCode, Vec<u8>, Option<HeaderValue>)> {
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );

        let resp = tokio::time::timeout(
            timeout,
            self.send_request(
                Method::GET,
                url,
                host_override,
                headers,
                Body::empty(),
                proto,
                client_addr,
            ),
        )
        .await
        .with_context(|| format!("timed out fetching {url} over PROXY Protocol {proto}"))??;

        let status = resp.status();
        let content_type = resp.headers().get(http::header::CONTENT_TYPE).cloned();
        let content_encoding = resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let raw_bytes = tokio::time::timeout(timeout, resp.into_body().collect())
            .await
            .with_context(|| format!("timed out reading body from {url}"))??
            .to_bytes();

        let decoded = maybe_gunzip(&content_encoding, &raw_bytes)?;
        Ok((status, decoded, content_type))
    }

    fn try_checkout_pooled(&self, key: &PoolKey) -> Option<SelectedConn> {
        // 1. Fast path: reuse warm multiplexed H2 connection for this `(upstream, proto, client_ip)`.
        {
            let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = pool.get_mut(key) {
                if !entry.sender.is_closed() && entry.last_used.elapsed() < self.idle_timeout {
                    entry.last_used = Instant::now();
                    return Some(SelectedConn::H2(entry.sender.clone()));
                }
                pool.remove(key);
            }
        }

        // 2. Fast path: reuse idle H1 connection for this `(upstream, proto, client_ip)`.
        {
            let mut pool = self.h1_pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(vec) = pool.get_mut(key) {
                while let Some(entry) = vec.pop() {
                    if !entry.sender.is_closed() && entry.last_used.elapsed() < self.idle_timeout {
                        return Some(SelectedConn::H1(entry.sender));
                    }
                }
                if vec.is_empty() {
                    pool.remove(key);
                }
            }
        }

        None
    }

    async fn checkout_or_connect(
        &self,
        key: &PoolKey,
        host: &str,
        port: u16,
        use_tls: bool,
        proto: ProxyProtocol,
        client_addr: Option<SocketAddr>,
    ) -> Result<(SelectedConn, bool)> {
        if let Some(conn) = self.try_checkout_pooled(key) {
            return Ok((conn, true));
        }

        // Singleflight cold-dial coalescing: if another task is already dialing this exact PoolKey,
        // wait briefly for it to populate `h2_pool` instead of opening redundant TLS/H2 connections.
        let (waiter, leader_guard) = {
            let mut inflight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = inflight.get(key) {
                (Some(Arc::clone(existing)), None)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(key.clone(), Arc::clone(&notify));
                (
                    None,
                    Some(InFlightGuard {
                        map: Arc::clone(&self.in_flight),
                        key: key.clone(),
                        notify,
                    }),
                )
            }
        };

        if let Some(notify) = waiter {
            let _ = tokio::time::timeout(self.connect_timeout, notify.notified()).await;
            if let Some(conn) = self.try_checkout_pooled(key) {
                return Ok((conn, true));
            }
            let fresh = self
                .connect_fresh(key, host, port, use_tls, proto, client_addr)
                .await?;
            return Ok((fresh, false));
        }

        let _guard = leader_guard;
        if let Some(conn) = self.try_checkout_pooled(key) {
            return Ok((conn, true));
        }

        let fresh = self
            .connect_fresh(key, host, port, use_tls, proto, client_addr)
            .await?;
        Ok((fresh, false))
    }

    async fn connect_fresh(
        &self,
        key: &PoolKey,
        host: &str,
        port: u16,
        use_tls: bool,
        proto: ProxyProtocol,
        client_addr: Option<SocketAddr>,
    ) -> Result<SelectedConn> {
        // Cold path: open TCP -> send PROXY Protocol header -> TLS handshake (ALPN h2,http/1.1) -> HTTP handshake.
        let (stream, is_h2) = tokio::time::timeout(
            self.connect_timeout,
            self.connect_pp_stream(host, port, use_tls, proto, client_addr),
        )
        .await
        .with_context(|| format!("PROXY Protocol {proto} connect timeout to {host}:{port}"))??;

        let io = TokioIo::new(stream);

        if is_h2 {
            let mut h2_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
            h2_builder
                .timer(TokioTimer::new())
                .adaptive_window(true)
                .initial_stream_window_size(1024 * 1024)
                .initial_connection_window_size(4 * 1024 * 1024)
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_timeout(Duration::from_secs(20))
                .keep_alive_while_idle(true);

            let (sender, conn) = h2_builder
                .handshake(io)
                .await
                .with_context(|| format!("upstream H2 handshake failed for {host}:{port}"))?;

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    debug!(error = %err, "PROXY Protocol H2 upstream connection closed");
                }
            });

            self.store_h2(key.clone(), sender.clone());
            Ok(SelectedConn::H2(sender))
        } else {
            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .with_context(|| format!("upstream H1 handshake failed for {host}:{port}"))?;

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    debug!(error = %err, "PROXY Protocol H1 upstream connection closed");
                }
            });

            Ok(SelectedConn::H1(sender))
        }
    }

    async fn connect_pp_stream(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
        proto: ProxyProtocol,
        client_addr: Option<SocketAddr>,
    ) -> Result<(BoxedStream, bool)> {
        let clean_host = trim_ipv6_brackets(host);
        let (mut stream, peer_addr): (BoxedStream, Option<SocketAddr>) = if let Some(proxy_url) =
            &self.outbound_proxy
            && !should_bypass_outbound_proxy(host, &self.outbound_no_proxy)
        {
            let proxied = connect_via_proxy(
                proxy_url,
                host,
                port,
                &self.tls_config,
                self.tcp_nodelay,
                self.tcp_keepalive,
            )
            .await?;
            (proxied, None)
        } else {
            let tcp = TcpStream::connect((clean_host, port))
                .await
                .with_context(|| format!("TCP connect to {host}:{port} failed"))?;
            configure_tcp_socket(&tcp, self.tcp_nodelay, self.tcp_keepalive);
            let peer = tcp.peer_addr().ok();
            (Box::new(tcp), peer)
        };

        let pp_hdr = match client_addr {
            Some(src) => {
                let dst_addr =
                    peer_addr.unwrap_or_else(|| fallback_dst_addr(clean_host, port, src));
                encode_proxy_protocol_proxy(proto, src, dst_addr)
            }
            None => encode_proxy_protocol_local(proto),
        };
        if !pp_hdr.is_empty() {
            stream.write_all(&pp_hdr).await.with_context(|| {
                format!("failed to write PROXY Protocol {proto} header to upstream")
            })?;
        }

        if !use_tls {
            return Ok((stream, false));
        }

        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let sni = ServerName::try_from(clean_host.to_string())
            .map_err(|_| anyhow!("invalid TLS SNI host '{host}'"))?;
        let tls_stream = connector.connect(sni, stream).await.with_context(|| {
            format!("TLS handshake to {host}:{port} failed after PROXY Protocol {proto} header")
        })?;

        let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        Ok((Box::new(tls_stream), negotiated_h2))
    }

    fn maybe_sweep_stale_pools(&self, now: Instant) {
        let should_sweep = {
            let mut last = self.last_sweep.lock().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(*last) >= Duration::from_secs(60) {
                *last = now;
                true
            } else {
                false
            }
        };
        if !should_sweep {
            return;
        }
        {
            let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() > 32 {
                pool.retain(|_, v| {
                    !v.sender.is_closed() && now.duration_since(v.last_used) < self.idle_timeout
                });
            }
        }
        {
            let mut pool = self.h1_pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() > 32 {
                pool.retain(|_, vec| {
                    vec.retain(|e| {
                        !e.sender.is_closed() && now.duration_since(e.last_used) < self.idle_timeout
                    });
                    !vec.is_empty()
                });
            }
        }
    }

    fn store_h2(&self, key: PoolKey, sender: hyper::client::conn::http2::SendRequest<Body>) {
        let now = Instant::now();
        self.maybe_sweep_stale_pools(now);
        let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() >= self.max_entries {
            pool.retain(|_, v| {
                !v.sender.is_closed() && now.duration_since(v.last_used) < self.idle_timeout
            });
            if pool.len() >= self.max_entries {
                // Evict oldest entry to keep pool strictly bounded.
                if let Some(oldest_key) = pool
                    .iter()
                    .min_by_key(|(_, v)| v.last_used)
                    .map(|(k, _)| k.clone())
                {
                    pool.remove(&oldest_key);
                }
            }
        }
        pool.insert(
            key,
            H2Entry {
                sender,
                last_used: now,
            },
        );
    }

    fn return_h1(&self, key: PoolKey, sender: hyper::client::conn::http1::SendRequest<Body>) {
        let mut pool = self.h1_pool.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if pool.len() >= self.max_entries {
            pool.retain(|_, vec| {
                vec.retain(|e| {
                    !e.sender.is_closed() && now.duration_since(e.last_used) < self.idle_timeout
                });
                !vec.is_empty()
            });
            if pool.len() >= self.max_entries
                && let Some(oldest_key) = pool
                    .iter()
                    .filter_map(|(k, vec)| vec.iter().map(|e| e.last_used).min().map(|t| (k, t)))
                    .min_by_key(|(_, t)| *t)
                    .map(|(k, _)| k.clone())
            {
                pool.remove(&oldest_key);
            }
        }
        let entries = pool.entry(key).or_default();
        if entries.len() < 4 {
            entries.push(H1Entry {
                sender,
                last_used: now,
            });
        }
    }
}

fn build_hyper_req(
    method: &Method,
    pq: &str,
    host_hdr: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Request<Body>> {
    let mut req_builder = Request::builder()
        .method(method.clone())
        .uri(pq)
        .header(http::header::HOST, host_hdr);

    for (name, val) in headers {
        if name == http::header::HOST {
            continue;
        }
        req_builder = req_builder.header(name.clone(), val.clone());
    }

    req_builder
        .body(body)
        .context("failed to build upstream PPv2 request")
}

pub fn configure_tcp_socket(stream: &TcpStream, nodelay: bool, keepalive: Duration) {
    let _ = stream.set_nodelay(nodelay);
    if !keepalive.is_zero() {
        let ka = TcpKeepalive::new()
            .with_time(keepalive)
            .with_interval(Duration::from_secs(10));
        let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
    }
}

pub fn maybe_gunzip(content_encoding: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if content_encoding.contains("gzip") {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .context("failed to gunzip upstream response")?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}
