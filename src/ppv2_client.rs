use crate::client_ip::{encode_ppv2_local, encode_ppv2_proxy};
use crate::config::ServerConfig;
use crate::ws::{build_client_tls_config, connect_via_proxy};
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
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

/// High-performance HTTP/2 + HTTP/1.1 upstream client supporting HAProxy PROXY Protocol v2.
/// Connections are pooled per `(upstream_host_port, real_client_ip)` so:
/// - Requests from the SAME client IP multiplex over ONE warm TLS 1.3 + HTTP/2 connection (0ms handshake overhead).
/// - Requests from DIFFERENT client IPs NEVER share a PPv2 TCP connection (zero cross-client IP leakage).
pub struct Ppv2Client {
    tls_config: Arc<rustls::ClientConfig>,
    outbound_proxy: Option<Url>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    tcp_keepalive: Duration,
    tcp_nodelay: bool,
    max_entries: usize,
    h2_pool: Mutex<HashMap<PoolKey, H2Entry>>,
    h1_pool: Mutex<HashMap<PoolKey, Vec<H1Entry>>>,
}

impl Ppv2Client {
    pub fn new(
        server: &ServerConfig,
        outbound_proxy: Option<&str>,
        connect_timeout_secs: u64,
        danger_accept_invalid_certs: bool,
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
            connect_timeout: Duration::from_secs(connect_timeout_secs.max(1)),
            idle_timeout: Duration::from_secs(server.pool_idle_timeout_secs.max(10)),
            tcp_keepalive: Duration::from_secs(server.tcp_keepalive_secs),
            tcp_nodelay: server.tcp_nodelay,
            max_entries: server.ppv2_pool_max_entries.max(64),
            h2_pool: Mutex::new(HashMap::with_capacity(256)),
            h1_pool: Mutex::new(HashMap::with_capacity(64)),
        })
    }

    /// Sends a streaming HTTP request to `target_url` with a PROXY Protocol v2 header for `client_addr`
    /// (`None` sends a PPv2 `LOCAL` header for proxy-originated discovery probes).
    pub async fn send_request(
        &self,
        method: Method,
        target_url: &Url,
        host_override: Option<&str>,
        headers: HeaderMap,
        body: Body,
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
            client_ip: client_addr.map(|s| s.ip()),
        };

        let mut req_builder = Request::builder()
            .method(method)
            .uri(path_and_query(target_url));

        let host_hdr = if let Some(ov) = host_override {
            ov.to_string()
        } else {
            match target_url.port() {
                Some(p) => format!("{host}:{p}"),
                None => host.clone(),
            }
        };
        req_builder = req_builder.header(http::header::HOST, host_hdr);

        for (name, val) in &headers {
            if name == http::header::HOST {
                continue;
            }
            req_builder = req_builder.header(name.clone(), val.clone());
        }

        let req = req_builder
            .body(body)
            .context("failed to build upstream PPv2 request")?;

        let conn = self
            .checkout_or_connect(&key, &host, port, use_tls, client_addr)
            .await?;

        match conn {
            SelectedConn::H2(mut sender) => {
                sender
                    .ready()
                    .await
                    .context("upstream H2 sender not ready")?;
                let resp = sender
                    .send_request(req)
                    .await
                    .context("upstream H2 request failed")?;
                Ok(resp)
            }
            SelectedConn::H1(mut sender) => {
                sender
                    .ready()
                    .await
                    .context("upstream H1 sender not ready")?;
                let resp = sender
                    .send_request(req)
                    .await
                    .context("upstream H1 request failed")?;
                // Return reusable H1 sender once response headers arrive (hyper queues pipelining/keepalive safely).
                if !sender.is_closed() {
                    self.return_h1(key, sender);
                }
                Ok(resp)
            }
        }
    }

    /// Convenience helper for buffered discovery/metadata GET requests over PROXY Protocol v2 (LOCAL command).
    pub async fn get_bytes(
        &self,
        url: &Url,
        host_override: Option<&str>,
        headers: HeaderMap,
        timeout: Duration,
    ) -> Result<(StatusCode, Vec<u8>, Option<HeaderValue>)> {
        self.get_bytes_for_client(url, host_override, headers, timeout, None)
            .await
    }

    /// Buffered GET over PROXY Protocol v2, optionally carrying the real client address in the PPv2 header.
    pub async fn get_bytes_for_client(
        &self,
        url: &Url,
        host_override: Option<&str>,
        mut headers: HeaderMap,
        timeout: Duration,
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
                client_addr,
            ),
        )
        .await
        .with_context(|| format!("timed out fetching {url} over PPv2"))??;

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

    async fn checkout_or_connect(
        &self,
        key: &PoolKey,
        host: &str,
        port: u16,
        use_tls: bool,
        client_addr: Option<SocketAddr>,
    ) -> Result<SelectedConn> {
        // 1. Fast path: reuse warm multiplexed H2 connection for this `(upstream, client_ip)`.
        {
            let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = pool.get_mut(key) {
                if !entry.sender.is_closed() && entry.last_used.elapsed() < self.idle_timeout {
                    entry.last_used = Instant::now();
                    return Ok(SelectedConn::H2(entry.sender.clone()));
                }
                pool.remove(key);
            }
        }

        // 2. Fast path: reuse idle H1 connection for this `(upstream, client_ip)`.
        {
            let mut pool = self.h1_pool.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(vec) = pool.get_mut(key) {
                while let Some(entry) = vec.pop() {
                    if !entry.sender.is_closed() && entry.last_used.elapsed() < self.idle_timeout {
                        return Ok(SelectedConn::H1(entry.sender));
                    }
                }
                if vec.is_empty() {
                    pool.remove(key);
                }
            }
        }

        // 3. Cold path: open TCP -> send PPv2 header -> TLS handshake (ALPN h2,http/1.1) -> HTTP handshake.
        let (stream, is_h2) = tokio::time::timeout(
            self.connect_timeout,
            self.connect_ppv2_stream(host, port, use_tls, client_addr),
        )
        .await
        .with_context(|| format!("PPv2 connect timeout to {host}:{port}"))??;

        let io = TokioIo::new(stream);

        if is_h2 {
            let mut h2_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
            h2_builder
                .timer(TokioTimer::new())
                .adaptive_window(true)
                .keep_alive_interval(Duration::from_secs(30))
                .keep_alive_while_idle(true);

            let (sender, conn) = h2_builder
                .handshake(io)
                .await
                .with_context(|| format!("upstream H2 handshake failed for {host}:{port}"))?;

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    debug!(error = %err, "PPv2 H2 upstream connection closed");
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
                    debug!(error = %err, "PPv2 H1 upstream connection closed");
                }
            });

            Ok(SelectedConn::H1(sender))
        }
    }

    async fn connect_ppv2_stream(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
        client_addr: Option<SocketAddr>,
    ) -> Result<(BoxedStream, bool)> {
        let mut tcp = if let Some(proxy_url) = &self.outbound_proxy {
            connect_via_proxy(proxy_url, host, port).await?
        } else {
            TcpStream::connect((host, port))
                .await
                .with_context(|| format!("TCP connect to {host}:{port} failed"))?
        };

        configure_tcp_socket(&tcp, self.tcp_nodelay, self.tcp_keepalive);

        let dst_addr = tcp
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)));

        let ppv2_hdr = match client_addr {
            Some(src) => encode_ppv2_proxy(src, dst_addr),
            None => encode_ppv2_local(),
        };
        tcp.write_all(&ppv2_hdr)
            .await
            .context("failed to write PROXY Protocol v2 header to upstream")?;

        if !use_tls {
            return Ok((Box::new(tcp), false));
        }

        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let sni = ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS SNI host '{host}'"))?;
        let tls_stream = connector
            .connect(sni, tcp)
            .await
            .with_context(|| format!("TLS handshake to {host}:{port} failed after PPv2 header"))?;

        let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        Ok((Box::new(tls_stream), negotiated_h2))
    }

    fn store_h2(&self, key: PoolKey, sender: hyper::client::conn::http2::SendRequest<Body>) {
        let mut pool = self.h2_pool.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
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
