use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::ConnectInfo;
use clap::Parser;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use matrix_proxy::client_ip::read_ppv2_header;
use matrix_proxy::config::{Config, ListenerPlan, redact_proxy_url};
use matrix_proxy::ppv2_client::configure_tcp_socket;
use matrix_proxy::proxy::{ListenerState, build_listener_router};
use rustls::pki_types::PrivateKeyDer;
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info};
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
        let server_cfg = runtime.server.clone();
        handles.push(tokio::spawn(async move {
            serve_listener(listener, plan, server_cfg, tls_acceptor, app, rx).await
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
    server_cfg: matrix_proxy::config::ServerConfig,
    tls_acceptor: Option<TlsAcceptor>,
    app: axum::Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let header_timeout = Duration::from_secs(server_cfg.header_read_timeout_secs.max(1));
    let keepalive = Duration::from_secs(server_cfg.tcp_keepalive_secs);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut tcp_stream, mut peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        error!(listen = %plan.listen, error = %err, "TCP accept error");
                        continue;
                    }
                };

                configure_tcp_socket(&tcp_stream, server_cfg.tcp_nodelay, keepalive);

                let tls_acceptor = tls_acceptor.clone();
                let app = app.clone();
                let accept_ppv2 = plan.accept_proxy_v2;

                tokio::spawn(async move {
                    if accept_ppv2 {
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            read_ppv2_header(&mut tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(Some(real_src))) => peer = real_src,
                            Ok(Ok(None)) => {} // PPv2 LOCAL command
                            Ok(Err(err)) => {
                                debug!(peer = %peer, error = %err, "rejected invalid inbound PROXY Protocol v2 header");
                                return;
                            }
                            Err(_) => {
                                debug!(peer = %peer, "timed out reading inbound PROXY Protocol v2 header");
                                return;
                            }
                        }
                    }

                    let service = TowerToHyperService::new(tower::service_fn(
                        move |req: http::Request<Incoming>| {
                            let app = app.clone();
                            async move {
                                let mut req = req.map(Body::new);
                                req.extensions_mut().insert(ConnectInfo(peer));
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
                                debug!(peer = %peer, error = %err, "TLS accept handshake failed");
                                return;
                            }
                            Err(_) => {
                                debug!(peer = %peer, "TLS accept handshake timed out");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                            debug!(peer = %peer, error = %err, "TLS connection closed");
                        }
                    } else {
                        let io = TokioIo::new(tcp_stream);
                        if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                            debug!(peer = %peer, error = %err, "HTTP connection closed");
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

async fn run_health_check(config_path: Option<&Path>) -> Result<()> {
    let urls = collect_health_check_urls(config_path)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()?;

    for url in urls {
        let resp = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("health check request to {url} failed"))?;

        if !resp.status().is_success() {
            anyhow::bail!("health check {url} returned HTTP {}", resp.status());
        }
    }

    Ok(())
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn collect_health_check_urls(config_path: Option<&Path>) -> Result<Vec<String>> {
    // Prefer full Config::load -> RuntimeConfig so multi-port [[proxies]] listeners are ALL checked.
    if let Ok(cfg) = Config::load(config_path)
        && let Ok(runtime) = cfg.into_runtime()
    {
        let mut urls = Vec::new();
        for listener in &runtime.listeners {
            if listener.accept_proxy_v2 {
                // Skip raw HTTP probe against listeners requiring binary PPv2 on TCP accept.
                continue;
            }
            urls.push(build_health_check_url_from_parts(
                &listener.listen.to_string(),
                &listener.proxy_prefix,
                listener.tls_enabled(),
            )?);
        }
        if !urls.is_empty() {
            return Ok(urls);
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

    Ok(vec![build_health_check_url_from_parts(
        &listen,
        &proxy_prefix,
        tls,
    )?])
}

fn build_health_check_url_from_parts(
    listen: &str,
    proxy_prefix: &str,
    tls: bool,
) -> Result<String> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address '{listen}'"))?;
    let host = if addr.ip().is_unspecified() {
        if addr.is_ipv6() { "[::1]" } else { "127.0.0.1" }.to_string()
    } else if addr.is_ipv6() {
        format!("[{}]", addr.ip())
    } else {
        addr.ip().to_string()
    };

    let scheme = if tls { "https" } else { "http" };
    let clean_prefix = proxy_prefix.trim_end_matches('/');
    Ok(format!(
        "{scheme}://{host}:{}{clean_prefix}/health",
        addr.port()
    ))
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
        let url = build_health_check_url_from_parts(
            &raw_cfg.server.listen,
            &raw_cfg.routing.proxy_prefix,
            raw_cfg.tls_enabled(),
        )
        .unwrap();
        assert_eq!(url, "http://127.0.0.1:8080/_proxy/health");
    }
}
