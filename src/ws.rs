use crate::client_ip::{ClientInfo, apply_upstream_client_ip_headers, encode_proxy_protocol_proxy};
use crate::config::{ProxyProfile, ProxyProtocol, ServerConfig, should_bypass_outbound_proxy};
use crate::ppv2_client::{BoxedStream, configure_tcp_socket};
use crate::rewrite::RewriteEngine;
use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use url::Url;

pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let has_conn_upgrade = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    has_upgrade && has_conn_upgrade
}

#[allow(clippy::too_many_arguments)]
pub async fn proxy_websocket(
    server_cfg: &ServerConfig,
    profile: &ProxyProfile,
    tls_config: &Arc<rustls::ClientConfig>,
    rewriter: &RewriteEngine<'_>,
    client: &ClientInfo,
    req: Request<Body>,
    target_url: Url,
    host_override: Option<&str>,
    outbound_proxy_protocol: ProxyProtocol,
    strip_auth_prefix: bool,
) -> Result<Response<Body>> {
    let host = target_url
        .host_str()
        .ok_or_else(|| anyhow!("missing upstream host for websocket"))?
        .to_string();
    let port = target_url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("missing upstream port for websocket"))?;
    let use_tls = target_url.scheme().eq_ignore_ascii_case("https");

    let stream = tokio::time::timeout(
        Duration::from_secs(profile.upstream.connect_timeout_secs.max(1)),
        connect_upstream_ws_stream(
            server_cfg,
            profile.upstream.outbound_proxy.as_deref(),
            &profile.upstream.outbound_no_proxy,
            tls_config,
            &host,
            port,
            use_tls,
            outbound_proxy_protocol,
            if outbound_proxy_protocol.is_enabled() {
                Some(client.client_socket_addr())
            } else {
                None
            },
        ),
    )
    .await
    .with_context(|| format!("websocket connect timeout to {host}:{port}"))??;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("upstream websocket HTTP/1.1 handshake failed")?;

    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            debug!(error = %err, "upstream websocket connection ended");
        }
    });

    let pq = match target_url.query() {
        Some(q) => format!("{}?{}", target_url.path(), q),
        None => target_url.path().to_string(),
    };

    let host_header = if let Some(ov) = host_override {
        ov.to_string()
    } else {
        match target_url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        }
    };

    let mut out_headers = HeaderMap::new();
    for (name, value) in req.headers() {
        if name == http::header::HOST
            || matches!(
                name.as_str(),
                "forwarded"
                    | "x-forwarded-for"
                    | "x-real-ip"
                    | "x-forwarded-host"
                    | "x-forwarded-proto"
                    | "x-forwarded-port"
            )
        {
            continue;
        }
        if (name == http::header::ORIGIN || name == http::header::REFERER)
            && let Ok(val_str) = value.to_str()
            && let Some(rewritten) =
                rewriter.rewrite_request_origin_header(val_str, &target_url, strip_auth_prefix)
            && let Ok(hv) = HeaderValue::from_str(&rewritten)
        {
            out_headers.append(name.clone(), hv);
            continue;
        }
        out_headers.append(name.clone(), value.clone());
    }

    apply_upstream_client_ip_headers(&mut out_headers, client, profile.upstream.client_ip_mode);

    let mut upstream_req = Request::builder()
        .method(req.method().clone())
        .uri(pq)
        .header(http::header::HOST, host_header);

    for (name, value) in &out_headers {
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    let upstream_req = upstream_req
        .body(Empty::<bytes::Bytes>::new())
        .context("failed to build upstream websocket request")?;

    let mut upstream_resp = sender
        .send_request(upstream_req)
        .await
        .context("failed to send upstream websocket upgrade request")?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    if status != StatusCode::SWITCHING_PROTOCOLS {
        let mut builder = Response::builder().status(status);
        for (name, val) in &resp_headers {
            if name != http::header::TRANSFER_ENCODING {
                builder = builder.header(name.clone(), val.clone());
            }
        }
        return builder
            .body(Body::empty())
            .context("failed to construct non-upgrade websocket response");
    }

    let client_upgrade = hyper::upgrade::on(req);
    let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);

    tokio::spawn(async move {
        let (client_res, upstream_res) = tokio::join!(client_upgrade, upstream_upgrade);
        match (client_res, upstream_res) {
            (Ok(client_upgraded), Ok(upstream_upgraded)) => {
                let mut client_io = TokioIo::new(client_upgraded);
                let mut upstream_io = TokioIo::new(upstream_upgraded);
                if let Err(err) =
                    tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await
                {
                    debug!(error = %err, "websocket tunnel closed");
                }
            }
            (Err(e), _) => warn!(error = %e, "client websocket upgrade failed"),
            (_, Err(e)) => warn!(error = %e, "upstream websocket upgrade failed"),
        }
    });

    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, val) in &resp_headers {
        if !is_dropped_upgrade_resp_header(name) {
            builder = builder.header(name.clone(), val.clone());
        }
    }
    builder
        .body(Body::empty())
        .context("failed to build 101 switching protocols response")
}

fn is_dropped_upgrade_resp_header(name: &HeaderName) -> bool {
    name == http::header::TRANSFER_ENCODING || name == http::header::CONTENT_LENGTH
}

#[allow(clippy::too_many_arguments)]
async fn connect_upstream_ws_stream(
    server_cfg: &ServerConfig,
    outbound_proxy: Option<&str>,
    outbound_no_proxy: &[String],
    tls_config: &Arc<rustls::ClientConfig>,
    target_host: &str,
    target_port: u16,
    use_tls: bool,
    proxy_protocol: ProxyProtocol,
    pp_client_addr: Option<SocketAddr>,
) -> Result<BoxedStream> {
    let keepalive = Duration::from_secs(server_cfg.tcp_keepalive_secs);
    let clean_target = trim_ipv6_brackets(target_host);

    let (mut stream, peer_addr): (BoxedStream, Option<SocketAddr>) = if let Some(proxy_raw) =
        outbound_proxy
        && !should_bypass_outbound_proxy(target_host, outbound_no_proxy)
    {
        let proxy_url = Url::parse(proxy_raw).context("invalid outbound_proxy URL")?;
        let proxied = connect_via_proxy(
            &proxy_url,
            target_host,
            target_port,
            tls_config,
            server_cfg.tcp_nodelay,
            keepalive,
        )
        .await?;
        (proxied, None)
    } else {
        let tcp = TcpStream::connect((clean_target, target_port))
            .await
            .with_context(|| format!("TCP connect to {target_host}:{target_port} failed"))?;
        configure_tcp_socket(&tcp, server_cfg.tcp_nodelay, keepalive);
        let peer = tcp.peer_addr().ok();
        (Box::new(tcp), peer)
    };

    if proxy_protocol.is_enabled()
        && let Some(src_addr) = pp_client_addr
    {
        let dst_addr =
            peer_addr.unwrap_or_else(|| fallback_dst_addr(clean_target, target_port, src_addr));
        let pp_hdr = encode_proxy_protocol_proxy(proxy_protocol, src_addr, dst_addr);
        stream.write_all(&pp_hdr).await.with_context(|| {
            format!("failed to write PROXY Protocol {proxy_protocol} header for websocket")
        })?;
    }

    if !use_tls {
        return Ok(stream);
    }

    let connector = TlsConnector::from(Arc::clone(tls_config));
    let server_name = ServerName::try_from(clean_target.to_string())
        .map_err(|_| anyhow!("invalid TLS SNI server name '{target_host}'"))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("TLS handshake to {target_host}:{target_port} failed"))?;
    Ok(Box::new(tls_stream))
}

pub fn fallback_dst_addr(host: &str, port: u16, src_hint: SocketAddr) -> SocketAddr {
    if let Ok(ip) = trim_ipv6_brackets(host).parse::<IpAddr>() {
        return SocketAddr::new(ip, port);
    }
    match src_hint {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

pub fn trim_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

pub async fn connect_via_proxy(
    proxy_url: &Url,
    target_host: &str,
    target_port: u16,
    tls_config: &Arc<rustls::ClientConfig>,
    tcp_nodelay: bool,
    tcp_keepalive: Duration,
) -> Result<BoxedStream> {
    let proxy_host_raw = proxy_url
        .host_str()
        .ok_or_else(|| anyhow!("outbound proxy missing host"))?;
    let proxy_host = trim_ipv6_brackets(proxy_host_raw);
    let proxy_port = proxy_url.port_or_known_default().unwrap_or(1080);

    let tcp = TcpStream::connect((proxy_host, proxy_port))
        .await
        .with_context(|| {
            format!("failed to connect to outbound proxy {proxy_host_raw}:{proxy_port}")
        })?;
    configure_tcp_socket(&tcp, tcp_nodelay, tcp_keepalive);

    let mut stream: BoxedStream = if proxy_url.scheme().eq_ignore_ascii_case("https") {
        let proxy_tls_cfg = cached_https_proxy_tls_config(tls_config);
        let connector = TlsConnector::from(proxy_tls_cfg);
        let sni = ServerName::try_from(proxy_host.to_string())
            .map_err(|_| anyhow!("invalid HTTPS proxy SNI host '{proxy_host_raw}'"))?;
        let tls = connector.connect(sni, tcp).await.with_context(|| {
            format!("TLS handshake to HTTPS proxy {proxy_host_raw}:{proxy_port} failed")
        })?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let decoded_user = percent_decode(proxy_url.username());
    let decoded_pass = proxy_url.password().map(percent_decode);
    let has_auth = !decoded_user.is_empty() || decoded_pass.is_some();

    match proxy_url.scheme() {
        "http" | "https" => {
            let connect_authority = if target_host.contains(':') && !target_host.starts_with('[') {
                format!("[{target_host}]:{target_port}")
            } else {
                format!("{target_host}:{target_port}")
            };
            let mut req =
                format!("CONNECT {connect_authority} HTTP/1.1\r\nHost: {connect_authority}\r\n");
            if has_auth {
                let creds = format!(
                    "{}:{}",
                    decoded_user,
                    decoded_pass.as_deref().unwrap_or_default()
                );
                let encoded = base64_encode(creds.as_bytes());
                req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
            }
            req.push_str("\r\n");
            stream.write_all(req.as_bytes()).await?;

            let mut buf = Vec::with_capacity(512);
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).await.is_err() || buf.len() > 8192 {
                    bail!("truncated HTTP CONNECT response from outbound proxy");
                }
                buf.push(byte[0]);
            }
            let header_str = String::from_utf8_lossy(&buf);
            let status_line = header_str.lines().next().unwrap_or_default();
            if status_line.split_whitespace().nth(1) != Some("200") {
                bail!("outbound HTTP proxy rejected CONNECT: {status_line}");
            }
            Ok(stream)
        }
        "socks5" | "socks5h" => {
            if has_auth {
                stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            } else {
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
            }
            let mut method_resp = [0u8; 2];
            stream.read_exact(&mut method_resp).await?;
            if method_resp[0] != 0x05 {
                bail!("invalid SOCKS5 greeting version");
            }
            if method_resp[1] == 0x02 {
                let user = decoded_user.as_bytes();
                let pass = decoded_pass.as_deref().unwrap_or_default().as_bytes();
                if user.len() > 255 || pass.len() > 255 {
                    bail!("SOCKS5 credentials exceed 255 bytes");
                }
                let mut auth_msg = Vec::with_capacity(3 + user.len() + pass.len());
                auth_msg.push(0x01);
                auth_msg.push(user.len() as u8);
                auth_msg.extend_from_slice(user);
                auth_msg.push(pass.len() as u8);
                auth_msg.extend_from_slice(pass);
                stream.write_all(&auth_msg).await?;
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    bail!("SOCKS5 username/password authentication rejected");
                }
            } else if method_resp[1] != 0x00 {
                bail!(
                    "SOCKS5 proxy selected unsupported auth method {}",
                    method_resp[1]
                );
            }

            let clean_host = trim_ipv6_brackets(target_host);
            let mut connect_req = Vec::with_capacity(32);
            connect_req.extend_from_slice(&[0x05, 0x01, 0x00]);
            if let Ok(ip) = clean_host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        connect_req.push(0x01);
                        connect_req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        connect_req.push(0x04);
                        connect_req.extend_from_slice(&v6.octets());
                    }
                }
            } else {
                let host_bytes = clean_host.as_bytes();
                if host_bytes.len() > 255 {
                    bail!("target host exceeds SOCKS5 domain limit");
                }
                connect_req.push(0x03);
                connect_req.push(host_bytes.len() as u8);
                connect_req.extend_from_slice(host_bytes);
            }
            connect_req.extend_from_slice(&target_port.to_be_bytes());
            stream.write_all(&connect_req).await?;

            let mut reply_hdr = [0u8; 4];
            stream.read_exact(&mut reply_hdr).await?;
            if reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00 {
                bail!("SOCKS5 connect failed with reply code {}", reply_hdr[1]);
            }
            match reply_hdr[3] {
                0x01 => {
                    let mut skip = [0u8; 6];
                    stream.read_exact(&mut skip).await?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    let mut skip = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut skip).await?;
                }
                0x04 => {
                    let mut skip = [0u8; 18];
                    stream.read_exact(&mut skip).await?;
                }
                atyp => bail!("unexpected SOCKS5 address type {atyp}"),
            }
            Ok(stream)
        }
        other => bail!("unsupported outbound proxy scheme '{other}'"),
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn cached_https_proxy_tls_config(
    fallback: &Arc<rustls::ClientConfig>,
) -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CFG.get_or_init(|| build_client_tls_config(false, &[b"http/1.1".as_slice()]).ok())
        .as_ref()
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::clone(fallback))
}

fn cached_webpki_root_store() -> Arc<rustls::RootCertStore> {
    static STORE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    Arc::clone(STORE.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(roots)
    }))
}

pub fn build_client_tls_config(
    danger_accept_invalid_certs: bool,
    alpn_protocols: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = if danger_accept_invalid_certs {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(cached_webpki_root_store())
            .with_no_client_auth()
    };

    if !alpn_protocols.is_empty() {
        cfg.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();
    }

    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
