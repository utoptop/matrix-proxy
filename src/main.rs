use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::ConnectInfo;
use clap::Parser;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use matrix_proxy::client_ip::{InboundPeer, encode_ppv2_local, read_ppv2_header};
use matrix_proxy::config::{Config, ListenerPlan, RuntimeConfig, canonical_ip, redact_proxy_url};
use matrix_proxy::ppv2_client::configure_tcp_socket;
use matrix_proxy::proxy::{ListenerState, build_listener_router};
use matrix_proxy::ws::build_client_tls_config;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower::ServiceExt;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "matrix-proxy",
    version,
    about = "High-performance multi-tenant Rust reverse proxy for Matrix Client-Server & Matrix Auth (MAS/OIDC)"
)]
struct Cli {
    /// Path to optional TOML configuration file (auto-detects /app/config.toml or ./config.toml if present)
    #[arg(short, long, env = "MATRIX_PROXY_CONFIG")]
    config: Option<PathBuf>,

    /// Perform an HTTP(S) health check against all locally configured proxy listeners and exit 0/1
    #[arg(long)]
    health_check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let resolved_config_path = resolve_config_path(cli.config);

    if cli.health_check {
        return run_health_check(resolved_config_path.as_deref()).await;
    }

    init_tracing();

    if let Some(path) = &resolved_config_path {
        info!(config_file = %path.display(), "loading configuration file");
    }

    let config = Config::load(resolved_config_path.as_deref())?;
    let runtime = Arc::new(config.into_runtime()?);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = runtime.listeners.len(),
        max_concurrent_requests = runtime.server.max_concurrent_requests,
        rate_limit_rps = runtime.server.rate_limit_rps,
        tcp_nodelay = runtime.server.tcp_nodelay,
        expose_info = ?runtime.server.expose_info,
        "starting matrix-proxy"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(runtime.listeners.len());

    for plan in runtime.listeners.clone() {
        let state = ListenerState::build(Arc::clone(&runtime), plan.clone())?;
        state.warm_up_discovery().await?;

        let tls_acceptor = if plan.tls_enabled() {
            let cert_path = plan.tls_cert_path.as_deref().unwrap();
            let key_path = plan.tls_key_path.as_deref().unwrap();
            Some(load_tls_acceptor(cert_path, key_path)?)
        } else {
            None
        };

        let listener = bind_high_perf_listener(plan.listen, runtime.server.listen_backlog)?;
        let app = build_listener_router(Arc::clone(&state));

        let profile_names: Vec<&str> = plan.profiles.iter().map(|p| p.name.as_str()).collect();
        info!(
            listen = %plan.listen,
            tls = tls_acceptor.is_some(),
            accept_proxy_v2 = plan.accept_proxy_v2,
            profiles = ?profile_names,
            outbound_proxies = ?plan
                .profiles
                .iter()
                .filter_map(|p| p.upstream.outbound_proxy.as_deref().map(redact_proxy_url))
                .collect::<Vec<_>>(),
            "listener ready"
        );

        let rx = shutdown_rx.clone();
        let runtime_ref = Arc::clone(&runtime);
        handles.push(tokio::spawn(async move {
            serve_listener(listener, plan, runtime_ref, tls_acceptor, app, rx).await
        }));
    }

    shutdown_signal().await;
    info!("shutdown signal received, stopping all listeners");
    let _ = shutdown_tx.send(true);

    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = %err, "listener exited with error"),
            Err(err) => error!(error = %err, "listener task join error"),
        }
    }

    info!("matrix-proxy shut down cleanly");
    Ok(())
}

fn bind_high_perf_listener(addr: SocketAddr, backlog: u32) -> Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .with_context(|| format!("failed to create socket for {addr}"))?;
    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR")?;
    socket
        .set_nonblocking(true)
        .context("failed to set O_NONBLOCK")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("failed to bind {addr}"))?;
    socket
        .listen(backlog.clamp(128, 65535) as i32)
        .with_context(|| format!("failed to listen on {addr}"))?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .with_context(|| format!("failed to register Tokio listener on {addr}"))
}

async fn serve_listener(
    listener: TcpListener,
    plan: ListenerPlan,
    runtime: Arc<RuntimeConfig>,
    tls_acceptor: Option<TlsAcceptor>,
    app: axum::Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let server_cfg = &runtime.server;
    let header_timeout = Duration::from_secs(server_cfg.header_read_timeout_secs.max(1));
    let keepalive = Duration::from_secs(server_cfg.tcp_keepalive_secs);
    let tcp_nodelay = server_cfg.tcp_nodelay;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut tcp_stream, physical_peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        error!(listen = %plan.listen, error = %err, "TCP accept error");
                        continue;
                    }
                };

                configure_tcp_socket(&tcp_stream, tcp_nodelay, keepalive);

                let tls_acceptor = tls_acceptor.clone();
                let app = app.clone();
                let runtime_ref = Arc::clone(&runtime);
                let listen_addr = plan.listen;
                let accept_ppv2 = plan.accept_proxy_v2;

                tokio::spawn(async move {
                    let ppv2_client = if accept_ppv2 {
                        // Anti-spoofing guard: only accept inbound PROXY Protocol v2 from trusted_proxies
                        // (analogous to HAProxy `fc_src` whitelist).
                        let physical_ip = canonical_ip(physical_peer.ip());
                        if !runtime_ref.is_trusted_proxy(physical_ip) {
                            warn!(
                                peer = %physical_peer,
                                listen = %listen_addr,
                                "rejected inbound PROXY Protocol v2 connection from untrusted peer"
                            );
                            return;
                        }
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            read_ppv2_header(&mut tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(real_src)) => real_src,
                            Ok(Err(err)) => {
                                debug!(peer = %physical_peer, error = %err, "rejected invalid inbound PROXY Protocol v2 header");
                                return;
                            }
                            Err(_) => {
                                debug!(peer = %physical_peer, "timed out reading inbound PROXY Protocol v2 header");
                                return;
                            }
                        }
                    } else {
                        None
                    };

                    let inbound = InboundPeer {
                        physical_peer,
                        ppv2_client,
                    };
                    let effective_peer = ppv2_client.unwrap_or(physical_peer);

                    let service = TowerToHyperService::new(tower::service_fn(
                        move |req: http::Request<Incoming>| {
                            let app = app.clone();
                            async move {
                                let mut req = req.map(Body::new);
                                req.extensions_mut().insert(inbound);
                                req.extensions_mut().insert(ConnectInfo(effective_peer));
                                app.oneshot(req).await
                            }
                        },
                    ));

                    let mut builder = AutoServerBuilder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(header_timeout);
                    builder
                        .http2()
                        .timer(TokioTimer::new())
                        .adaptive_window(true)
                        .keep_alive_interval(Duration::from_secs(30))
                        .keep_alive_timeout(Duration::from_secs(20));

                    if let Some(acceptor) = tls_acceptor {
                        let tls_stream = match tokio::time::timeout(
                            Duration::from_secs(10),
                            acceptor.accept(tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(err)) => {
                                debug!(peer = %effective_peer, error = %err, "TLS accept handshake failed");
                                return;
                            }
                            Err(_) => {
                                debug!(peer = %effective_peer, "TLS accept handshake timed out");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                            debug!(peer = %effective_peer, error = %err, "TLS connection closed");
                        }
                    } else {
                        let io = TokioIo::new(tcp_stream);
                        if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                            debug!(peer = %effective_peer, error = %err, "HTTP connection closed");
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("failed to open TLS certificate '{cert_path}'"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from '{cert_path}'"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in '{cert_path}'"));
    }

    let key_file = File::open(key_path)
        .with_context(|| format!("failed to open TLS private key '{key_path}'"))?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to parse PEM private key from '{key_path}'"))?
        .ok_or_else(|| anyhow!("no private key found in '{key_path}'"))?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to configure TLS ServerConfig")?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn resolve_config_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if explicit.is_some() {
        return explicit;
    }
    for candidate in ["/app/config.toml", "./config.toml"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthCheckTarget {
    connect_addr: SocketAddr,
    proxy_prefix: String,
    tls: bool,
    accept_proxy_v2: bool,
}

impl HealthCheckTarget {
    fn from_parts(
        listen: &str,
        proxy_prefix: &str,
        tls: bool,
        accept_proxy_v2: bool,
    ) -> Result<Self> {
        let addr: SocketAddr = listen
            .parse()
            .with_context(|| format!("invalid listen address '{listen}'"))?;
        let connect_ip = if addr.ip().is_unspecified() {
            if addr.is_ipv6() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
        } else {
            addr.ip()
        };
        Ok(Self {
            connect_addr: SocketAddr::new(connect_ip, addr.port()),
            proxy_prefix: proxy_prefix.trim_end_matches('/').to_string(),
            tls,
            accept_proxy_v2,
        })
    }

    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let host = match self.connect_addr.ip() {
            IpAddr::V6(v6) => format!("[{v6}]"),
            IpAddr::V4(v4) => v4.to_string(),
        };
        format!(
            "{scheme}://{host}:{}{}/health",
            self.connect_addr.port(),
            self.proxy_prefix
        )
    }
}

async fn run_health_check(config_path: Option<&Path>) -> Result<()> {
    let targets = collect_health_check_targets(config_path)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()?;

    for target in targets {
        if target.accept_proxy_v2 {
            probe_ppv2_health(&target).await?;
        } else {
            let url = target.url();
            let resp = client
                .get(&url)
                .send()
                .await
                .with_context(|| format!("health check request to {url} failed"))?;

            if !resp.status().is_success() {
                anyhow::bail!("health check {url} returned HTTP {}", resp.status());
            }
        }
    }

    Ok(())
}

async fn probe_ppv2_health(target: &HealthCheckTarget) -> Result<()> {
    let timeout = Duration::from_secs(4);
    let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(target.connect_addr))
        .await
        .with_context(|| {
            format!(
                "PPv2 health check connect timed out for {}",
                target.connect_addr
            )
        })?
        .with_context(|| {
            format!(
                "PPv2 health check connect failed for {}",
                target.connect_addr
            )
        })?;

    let ppv2_local = encode_ppv2_local();
    tokio::time::timeout(timeout, tcp.write_all(&ppv2_local))
        .await
        .context("PPv2 health check write header timed out")?
        .context("PPv2 health check write header failed")?;

    let req = format!(
        "GET {}/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        target.proxy_prefix
    );

    let mut resp_buf = [0u8; 512];
    let n = if target.tls {
        let tls_cfg = build_client_tls_config(true, &[b"http/1.1".as_slice()])?;
        let connector = TlsConnector::from(tls_cfg);
        let sni = ServerName::try_from("localhost".to_string())
            .map_err(|_| anyhow!("invalid health check SNI"))?;
        let mut tls = tokio::time::timeout(timeout, connector.connect(sni, tcp))
            .await
            .context("PPv2 TLS health check handshake timed out")?
            .context("PPv2 TLS health check handshake failed")?;
        tokio::time::timeout(timeout, tls.write_all(req.as_bytes()))
            .await
            .context("PPv2 TLS health check write timed out")?
            .context("PPv2 TLS health check write failed")?;
        tokio::time::timeout(timeout, tls.read(&mut resp_buf))
            .await
            .context("PPv2 TLS health check read timed out")?
            .context("PPv2 TLS health check read failed")?
    } else {
        tokio::time::timeout(timeout, tcp.write_all(req.as_bytes()))
            .await
            .context("PPv2 health check write timed out")?
            .context("PPv2 health check write failed")?;
        tokio::time::timeout(timeout, tcp.read(&mut resp_buf))
            .await
            .context("PPv2 health check read timed out")?
            .context("PPv2 health check read failed")?
    };

    let head = String::from_utf8_lossy(&resp_buf[..n]);
    let status_line = head.lines().next().unwrap_or_default().trim();
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        anyhow::bail!(
            "PPv2 health check to {} returned unexpected status: '{status_line}'",
            target.connect_addr
        );
    }

    Ok(())
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn collect_health_check_targets(config_path: Option<&Path>) -> Result<Vec<HealthCheckTarget>> {
    // Prefer full Config::load -> RuntimeConfig so ALL listeners (including accept_proxy_v2) are checked.
    if let Ok(cfg) = Config::load(config_path)
        && let Ok(runtime) = cfg.into_runtime()
    {
        let mut targets = Vec::with_capacity(runtime.listeners.len());
        for listener in &runtime.listeners {
            targets.push(HealthCheckTarget::from_parts(
                &listener.listen.to_string(),
                &listener.proxy_prefix,
                listener.tls_enabled(),
                listener.accept_proxy_v2,
            )?);
        }
        if !targets.is_empty() {
            return Ok(targets);
        }
    }

    // Fallback when invoked without upstream env vars (e.g. standalone health check).
    let file_cfg = config_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| toml::from_str::<Config>(&s).ok());
    let listen = non_empty_env("LISTEN_ADDR")
        .or_else(|| non_empty_env("MATRIX_PROXY_LISTEN"))
        .or_else(|| file_cfg.as_ref().map(|c| c.server.listen.clone()))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let proxy_prefix = non_empty_env("PROXY_PREFIX")
        .or_else(|| file_cfg.as_ref().map(|c| c.routing.proxy_prefix.clone()))
        .unwrap_or_else(|| "/_proxy".to_string());
    let tls = (non_empty_env("TLS_CERT_PATH").is_some() && non_empty_env("TLS_KEY_PATH").is_some())
        || file_cfg.as_ref().is_some_and(Config::tls_enabled);
    let accept_ppv2 = file_cfg
        .as_ref()
        .map(|c| c.server.accept_proxy_v2)
        .unwrap_or(false);

    Ok(vec![HealthCheckTarget::from_parts(
        &listen,
        &proxy_prefix,
        tls,
        accept_ppv2,
    )?])
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("matrix_proxy=info,tower_http=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tls_fields_in_toml_do_not_trigger_https_healthcheck() {
        let raw_cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"
            tls_cert_path = ""
            tls_key_path = ""
            "#,
        )
        .unwrap();
        assert!(!raw_cfg.tls_enabled());
        let target = HealthCheckTarget::from_parts(
            &raw_cfg.server.listen,
            &raw_cfg.routing.proxy_prefix,
            raw_cfg.tls_enabled(),
            raw_cfg.server.accept_proxy_v2,
        )
        .unwrap();
        assert_eq!(target.url(), "http://127.0.0.1:8080/_proxy/health");
        assert!(!target.accept_proxy_v2);
    }

    #[tokio::test]
    async fn ppv2_health_check_probes_accept_proxy_v2_listener() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "127.0.0.1:0"
            accept_proxy_v2 = true
            expose_info = "trusted"

            [[proxies]]
            name = "test"
            domains = ["proxy.example.com"]
            matrix_url = "https://matrix.example.org"
            "#,
        )
        .unwrap();
        let runtime = Arc::new(cfg.into_runtime().unwrap());
        let plan = runtime.listeners[0].clone();
        let state = ListenerState::build(Arc::clone(&runtime), plan.clone()).unwrap();
        let app = build_listener_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = watch::channel(false);
        let server_task = tokio::spawn(async move {
            let _ = serve_listener(listener, plan, runtime, None, app, rx).await;
        });

        let target =
            HealthCheckTarget::from_parts(&addr.to_string(), "/_proxy", false, true).unwrap();
        probe_ppv2_health(&target).await.unwrap();

        let _ = tx.send(true);
        let _ = server_task.await;
    }
}
