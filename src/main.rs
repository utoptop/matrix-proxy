use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::ConnectInfo;
use clap::Parser;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use matrix_proxy::client_ip::{
    InboundPeer, encode_proxy_protocol_local, read_proxy_protocol_header,
};
use matrix_proxy::config::{
    Config, ListenerPlan, ProxyProtocol, RuntimeConfig, canonical_ip, redact_proxy_url,
};
use matrix_proxy::metrics::ProxyMetrics;
use matrix_proxy::ppv2_client::configure_tcp_socket;
use matrix_proxy::proxy::{
    ListenerState, LiveListener, ReloadFn, ReloadReport, build_live_listener_router,
};
use matrix_proxy::ws::build_client_tls_config;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{Mutex, Notify, watch};
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

    /// Perform an HTTP(S) or PPv2 health check against all locally configured proxy listeners and exit 0/1
    #[arg(long)]
    health_check: bool,
}

#[derive(Clone)]
struct AcceptConfig {
    runtime: Arc<RuntimeConfig>,
    tls_acceptor: Option<TlsAcceptor>,
    inbound_proxy_protocol: ProxyProtocol,
    header_timeout: Duration,
    keepalive: Duration,
    tcp_nodelay: bool,
}

impl AcceptConfig {
    fn from_plan(
        runtime: Arc<RuntimeConfig>,
        plan: &ListenerPlan,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        Self {
            header_timeout: Duration::from_secs(runtime.server.header_read_timeout_secs.max(1)),
            keepalive: Duration::from_secs(runtime.server.tcp_keepalive_secs),
            tcp_nodelay: runtime.server.tcp_nodelay,
            inbound_proxy_protocol: plan.inbound_proxy_protocol,
            tls_acceptor,
            runtime,
        }
    }
}

/// Tracks live client TCP connections so SIGTERM/SIGINT can drain in-flight HTTP/2 & WS requests cleanly.
#[derive(Default)]
struct ConnectionTracker {
    active: AtomicUsize,
    notify: Notify,
}

impl ConnectionTracker {
    fn track(self: &Arc<Self>) -> ConnGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        ConnGuard {
            tracker: Arc::clone(self),
        }
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    async fn wait_drained(&self, timeout: Duration) {
        if self.active_count() == 0 {
            return;
        }
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            let notified = self.notify.notified();
            if self.active_count() == 0 {
                return;
            }
            tokio::select! {
                _ = notified => {
                    if self.active_count() == 0 {
                        return;
                    }
                }
                _ = &mut deadline => {
                    warn!(remaining = self.active_count(), "shutdown grace period elapsed with active connections still open");
                    return;
                }
            }
        }
    }
}

struct ConnGuard {
    tracker: Arc<ConnectionTracker>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self.tracker.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.notify.notify_waiters();
        }
    }
}

struct ActiveListener {
    live: Arc<LiveListener>,
    accept_cfg: Arc<RwLock<AcceptConfig>>,
    stop_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<()>>,
}

/// Coordinates zero-downtime live hot reload of TOML config, multi-port listeners, and TLS certificates.
struct ReloadCoordinator {
    config_path: Option<PathBuf>,
    metrics: Arc<ProxyMetrics>,
    tracker: Arc<ConnectionTracker>,
    listeners: Mutex<HashMap<SocketAddr, ActiveListener>>,
    reload_lock: Mutex<()>,
    watched_tls: RwLock<Vec<PathBuf>>,
    grace_secs: RwLock<u64>,
}

impl ReloadCoordinator {
    fn new(config_path: Option<PathBuf>, metrics: Arc<ProxyMetrics>) -> Arc<Self> {
        Arc::new(Self {
            config_path,
            metrics,
            tracker: Arc::new(ConnectionTracker::default()),
            listeners: Mutex::new(HashMap::new()),
            reload_lock: Mutex::new(()),
            watched_tls: RwLock::new(Vec::new()),
            grace_secs: RwLock::new(15),
        })
    }

    fn make_reload_fn(self: &Arc<Self>) -> Option<ReloadFn> {
        self.config_path.as_ref()?;
        let weak = Arc::downgrade(self);
        Some(Arc::new(move || {
            let weak = weak.clone();
            Box::pin(async move {
                let Some(coord) = weak.upgrade() else {
                    return Err("proxy is shutting down".to_string());
                };
                coord.reload("http_api").await.map_err(|e| format!("{e:#}"))
            })
        }))
    }

    async fn start_initial(self: &Arc<Self>, runtime: Arc<RuntimeConfig>) -> Result<()> {
        *self.grace_secs.write().unwrap_or_else(|e| e.into_inner()) =
            runtime.server.shutdown_grace_secs;
        *self.watched_tls.write().unwrap_or_else(|e| e.into_inner()) = runtime.tls_watched_paths();

        let prepared = self.prepare_listeners(&runtime).await?;
        let reload_fn = self.make_reload_fn();

        let mut map = self.listeners.lock().await;
        for (plan, state, tls_acceptor) in prepared {
            let tcp = bind_high_perf_listener(plan.listen, runtime.server.listen_backlog)?;
            let active = self.spawn_active_listener(
                tcp,
                &runtime,
                plan,
                state,
                tls_acceptor,
                reload_fn.clone(),
            );
            map.insert(active.0, active.1);
        }

        Ok(())
    }

    /// Atomically reloads `config.toml` and TLS certificates without dropping active connections on unchanged ports.
    /// If parsing, validation, TLS loading, or binding a newly added port fails, the previous live config stays active.
    async fn reload(self: &Arc<Self>, reason: &str) -> Result<ReloadReport> {
        let _guard = self.reload_lock.lock().await;
        let Some(path) = &self.config_path else {
            anyhow::bail!("cannot hot-reload without a configuration file");
        };

        let result = self.reload_inner(path, reason).await;
        match result {
            Ok(report) => Ok(report),
            Err(err) => {
                self.metrics.record_reload_failure();
                error!(
                    reason,
                    config_file = %path.display(),
                    error = %format!("{err:#}"),
                    "hot reload failed; previous configuration remains active"
                );
                Err(err)
            }
        }
    }

    async fn reload_inner(self: &Arc<Self>, path: &Path, reason: &str) -> Result<ReloadReport> {
        let config = Config::load(Some(path))
            .with_context(|| format!("failed to load config '{}'", path.display()))?;
        let runtime = Arc::new(config.into_runtime()?);

        // Stage 1: Build ALL ListenerStates, validate ALL TLS certs, and warm up discovery BEFORE touching live state.
        let prepared = self.prepare_listeners(&runtime).await?;

        // Stage 2: Pre-bind any newly added listening ports BEFORE mutating existing listeners (rollback-safe!).
        let mut map = self.listeners.lock().await;
        let new_addrs: HashSet<SocketAddr> = prepared.iter().map(|(p, _, _)| p.listen).collect();

        let mut prebound_new: HashMap<SocketAddr, TcpListener> = HashMap::new();
        for (plan, _, _) in &prepared {
            if !map.contains_key(&plan.listen) {
                let tcp = bind_high_perf_listener(plan.listen, runtime.server.listen_backlog)
                    .with_context(|| {
                        format!("failed to bind newly added listener {}", plan.listen)
                    })?;
                prebound_new.insert(plan.listen, tcp);
            }
        }

        // Stage 3: Commit — swap existing listeners atomically, spawn new ones, stop removed ones.
        let reload_fn = self.make_reload_fn();
        let mut added_listeners = Vec::new();
        let mut all_listener_strs = Vec::with_capacity(prepared.len());
        let mut all_profiles = Vec::new();

        for (plan, state, tls_acceptor) in prepared {
            let listen_addr = plan.listen;
            all_listener_strs.push(listen_addr.to_string());
            for p in &plan.profiles {
                all_profiles.push(p.name.clone());
            }

            if let Some(existing) = map.get(&listen_addr) {
                existing.live.swap(state);
                let new_accept = AcceptConfig::from_plan(Arc::clone(&runtime), &plan, tls_acceptor);
                *existing
                    .accept_cfg
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = new_accept;
                info!(
                    listen = %listen_addr,
                    tls = plan.tls_enabled(),
                    inbound_proxy_protocol = %plan.inbound_proxy_protocol,
                    profiles = ?plan.profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
                    "listener hot-reloaded in place"
                );
            } else if let Some(tcp) = prebound_new.remove(&listen_addr) {
                let (addr, active) = self.spawn_active_listener(
                    tcp,
                    &runtime,
                    plan,
                    state,
                    tls_acceptor,
                    reload_fn.clone(),
                );
                map.insert(addr, active);
                added_listeners.push(addr.to_string());
            }
        }

        let removed_addrs: Vec<SocketAddr> = map
            .keys()
            .copied()
            .filter(|addr| !new_addrs.contains(addr))
            .collect();
        let mut removed_listeners = Vec::with_capacity(removed_addrs.len());
        for addr in removed_addrs {
            if let Some(old) = map.remove(&addr) {
                let _ = old.stop_tx.send(true);
                removed_listeners.push(addr.to_string());
                info!(listen = %addr, "removed listener signalled to stop and drain");
                tokio::spawn(async move {
                    let _ = old.join.await;
                });
            }
        }

        *self.grace_secs.write().unwrap_or_else(|e| e.into_inner()) =
            runtime.server.shutdown_grace_secs;
        *self.watched_tls.write().unwrap_or_else(|e| e.into_inner()) = runtime.tls_watched_paths();

        let generation = self.metrics.record_reload_success();
        info!(
            reason,
            generation,
            listeners = ?all_listener_strs,
            profiles = ?all_profiles,
            added = ?added_listeners,
            removed = ?removed_listeners,
            "hot reload applied successfully"
        );

        Ok(ReloadReport {
            generation,
            reason: reason.to_string(),
            listeners: all_listener_strs,
            profiles: all_profiles,
            added_listeners,
            removed_listeners,
        })
    }

    async fn prepare_listeners(
        &self,
        runtime: &Arc<RuntimeConfig>,
    ) -> Result<Vec<(ListenerPlan, Arc<ListenerState>, Option<TlsAcceptor>)>> {
        let mut prepared = Vec::with_capacity(runtime.listeners.len());
        for plan in &runtime.listeners {
            let state = ListenerState::build_with_metrics(
                Arc::clone(runtime),
                plan.clone(),
                Arc::clone(&self.metrics),
            )?;
            let tls_acceptor = if plan.tls_enabled() {
                let cert_path = plan.tls_cert_path.as_deref().unwrap();
                let key_path = plan.tls_key_path.as_deref().unwrap();
                Some(load_tls_acceptor(cert_path, key_path)?)
            } else {
                None
            };
            prepared.push((plan.clone(), state, tls_acceptor));
        }

        let warm_futs = prepared
            .iter()
            .map(|(_, state, _)| state.warm_up_discovery());
        for res in futures_util::future::join_all(warm_futs).await {
            res?;
        }

        Ok(prepared)
    }

    fn spawn_active_listener(
        &self,
        listener: TcpListener,
        runtime: &Arc<RuntimeConfig>,
        plan: ListenerPlan,
        state: Arc<ListenerState>,
        tls_acceptor: Option<TlsAcceptor>,
        reload_fn: Option<ReloadFn>,
    ) -> (SocketAddr, ActiveListener) {
        let listen_addr = plan.listen;
        let has_tls = tls_acceptor.is_some();
        let profile_names: Vec<&str> = plan.profiles.iter().map(|p| p.name.as_str()).collect();
        let outbound_proxies: Vec<String> = plan
            .profiles
            .iter()
            .filter_map(|p| p.upstream.outbound_proxy.as_deref().map(redact_proxy_url))
            .collect();

        info!(
            listen = %listen_addr,
            tls = has_tls,
            inbound_proxy_protocol = %plan.inbound_proxy_protocol,
            profiles = ?profile_names,
            outbound_proxies = ?outbound_proxies,
            "listener ready"
        );

        let live = LiveListener::new(state, Arc::clone(&self.metrics), reload_fn);
        let app = build_live_listener_router(Arc::clone(&live));
        let accept_cfg = Arc::new(RwLock::new(AcceptConfig::from_plan(
            Arc::clone(runtime),
            &plan,
            tls_acceptor,
        )));
        let (stop_tx, stop_rx) = watch::channel(false);
        let tracker = Arc::clone(&self.tracker);
        let accept_cfg_ref = Arc::clone(&accept_cfg);

        let join = tokio::spawn(async move {
            serve_listener(listen_addr, listener, accept_cfg_ref, app, tracker, stop_rx).await
        });

        (
            listen_addr,
            ActiveListener {
                live,
                accept_cfg,
                stop_tx,
                join,
            },
        )
    }

    fn watched_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(cfg) = &self.config_path {
            paths.push(cfg.clone());
        }
        let tls = self.watched_tls.read().unwrap_or_else(|e| e.into_inner());
        for p in tls.iter() {
            if !paths.contains(p) {
                paths.push(p.clone());
            }
        }
        paths
    }

    async fn shutdown_all(&self) {
        let grace = Duration::from_secs(
            (*self.grace_secs.read().unwrap_or_else(|e| e.into_inner())).max(1),
        );
        let drained: Vec<ActiveListener> = {
            let mut map = self.listeners.lock().await;
            map.drain().map(|(_, v)| v).collect()
        };

        for active in &drained {
            let _ = active.stop_tx.send(true);
        }
        for active in drained {
            match active.join.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(error = %err, "listener exited with error"),
                Err(err) => error!(error = %err, "listener task join error"),
            }
        }

        let active_conns = self.tracker.active_count();
        if active_conns > 0 {
            info!(
                active_connections = active_conns,
                grace_secs = grace.as_secs(),
                "draining active connections gracefully"
            );
            self.tracker.wait_drained(grace).await;
        }
    }
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
        global_outbound_proxy = ?runtime.server.outbound_proxy.as_deref().map(redact_proxy_url),
        max_concurrent_requests = runtime.server.max_concurrent_requests,
        rate_limit_rps = runtime.server.rate_limit_rps,
        tcp_nodelay = runtime.server.tcp_nodelay,
        expose_info = ?runtime.server.expose_info,
        hot_reload = runtime.server.hot_reload && resolved_config_path.is_some(),
        hot_reload_interval_secs = runtime.server.hot_reload_interval_secs,
        shutdown_grace_secs = runtime.server.shutdown_grace_secs,
        "starting matrix-proxy"
    );

    let metrics = Arc::new(ProxyMetrics::new());
    let coordinator = ReloadCoordinator::new(resolved_config_path.clone(), metrics);
    coordinator.start_initial(Arc::clone(&runtime)).await?;

    let (bg_stop_tx, bg_stop_rx) = watch::channel(false);

    // Trigger 1: Automatic config file & TLS cert content polling watcher (works in Docker bind mounts too).
    let watcher_handle = if runtime.server.hot_reload && resolved_config_path.is_some() {
        let coord = Arc::clone(&coordinator);
        let interval = Duration::from_secs(runtime.server.hot_reload_interval_secs.max(1));
        let rx = bg_stop_rx.clone();
        Some(tokio::spawn(async move {
            run_file_watcher(coord, interval, rx).await;
        }))
    } else {
        None
    };

    // Trigger 2: Unix SIGHUP instant hot reload (`kill -HUP` / `docker kill -s HUP matrix-proxy`).
    #[cfg(unix)]
    let sighup_handle = if resolved_config_path.is_some() {
        let coord = Arc::clone(&coordinator);
        let rx = bg_stop_rx.clone();
        Some(tokio::spawn(async move {
            run_sighup_reloader(coord, rx).await;
        }))
    } else {
        None
    };

    shutdown_signal().await;
    info!("shutdown signal received, stopping all listeners");
    let _ = bg_stop_tx.send(true);
    if let Some(h) = watcher_handle {
        let _ = h.await;
    }
    #[cfg(unix)]
    if let Some(h) = sighup_handle {
        let _ = h.await;
    }

    coordinator.shutdown_all().await;
    info!("matrix-proxy shut down cleanly");
    Ok(())
}

type FileSnapshot = Vec<(PathBuf, Option<Vec<u8>>)>;

fn snapshot_files(paths: &[PathBuf]) -> FileSnapshot {
    paths
        .iter()
        .map(|p| (p.clone(), std::fs::read(p).ok()))
        .collect()
}

async fn run_file_watcher(
    coordinator: Arc<ReloadCoordinator>,
    interval: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let mut last_snapshot = snapshot_files(&coordinator.watched_paths());
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume immediate first tick

    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let paths = coordinator.watched_paths();
                let current = snapshot_files(&paths);
                if current != last_snapshot {
                    // Brief debounce so editors/scripts finish writing the complete file before reload.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let settled = snapshot_files(&coordinator.watched_paths());
                    if settled != last_snapshot {
                        let config_present = settled
                            .first()
                            .and_then(|(_, bytes)| bytes.as_ref())
                            .is_some_and(|b| !b.is_empty());
                        if config_present {
                            info!("detected configuration or TLS certificate change; triggering hot reload");
                            let _ = coordinator.reload("file_change").await;
                        }
                        // Advance baseline using refreshed watch list so broken configs don't spam logs every tick.
                        last_snapshot = snapshot_files(&coordinator.watched_paths());
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
async fn run_sighup_reloader(coordinator: Arc<ReloadCoordinator>, mut stop: watch::Receiver<bool>) {
    let Ok(mut hup) = signal::unix::signal(signal::unix::SignalKind::hangup()) else {
        warn!("failed to install SIGHUP hot-reload handler");
        return;
    };
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            Some(()) = hup.recv() => {
                info!("SIGHUP received; triggering hot reload");
                let _ = coordinator.reload("sighup").await;
            }
        }
    }
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
    listen_addr: SocketAddr,
    listener: TcpListener,
    accept_cfg: Arc<RwLock<AcceptConfig>>,
    app: axum::Router,
    tracker: Arc<ConnectionTracker>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
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
                        error!(listen = %listen_addr, error = %err, "TCP accept error");
                        continue;
                    }
                };

                let cfg = accept_cfg.read().unwrap_or_else(|e| e.into_inner()).clone();
                configure_tcp_socket(&tcp_stream, cfg.tcp_nodelay, cfg.keepalive);

                let app = app.clone();
                let conn_guard = tracker.track();
                let mut conn_shutdown = shutdown.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let ppv2_client = if cfg.inbound_proxy_protocol.is_enabled() {
                        // Anti-spoofing guard: only accept inbound PROXY Protocol from trusted_proxies.
                        let physical_ip = canonical_ip(physical_peer.ip());
                        if !cfg.runtime.is_trusted_proxy(physical_ip) {
                            warn!(
                                peer = %physical_peer,
                                listen = %listen_addr,
                                proxy_protocol = %cfg.inbound_proxy_protocol,
                                "rejected inbound PROXY Protocol connection from untrusted peer"
                            );
                            return;
                        }
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            read_proxy_protocol_header(&mut tcp_stream, cfg.inbound_proxy_protocol),
                        )
                        .await
                        {
                            Ok(Ok(real_src)) => real_src,
                            Ok(Err(err)) => {
                                debug!(peer = %physical_peer, proxy_protocol = %cfg.inbound_proxy_protocol, error = %err, "rejected invalid inbound PROXY Protocol header");
                                return;
                            }
                            Err(_) => {
                                debug!(peer = %physical_peer, proxy_protocol = %cfg.inbound_proxy_protocol, "timed out reading inbound PROXY Protocol header");
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
                        .header_read_timeout(cfg.header_timeout);
                    builder
                        .http2()
                        .timer(TokioTimer::new())
                        .adaptive_window(true)
                        .keep_alive_interval(Duration::from_secs(30))
                        .keep_alive_timeout(Duration::from_secs(20));

                    if let Some(acceptor) = cfg.tls_acceptor {
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
                        let conn = builder.serve_connection_with_upgrades(io, service);
                        tokio::pin!(conn);
                        let res = tokio::select! {
                            r = &mut conn => r,
                            _ = conn_shutdown.changed() => {
                                conn.as_mut().graceful_shutdown();
                                conn.await
                            }
                        };
                        if let Err(err) = res {
                            debug!(peer = %effective_peer, error = %err, "TLS connection closed");
                        }
                    } else {
                        let io = TokioIo::new(tcp_stream);
                        let conn = builder.serve_connection_with_upgrades(io, service);
                        tokio::pin!(conn);
                        let res = tokio::select! {
                            r = &mut conn => r,
                            _ = conn_shutdown.changed() => {
                                conn.as_mut().graceful_shutdown();
                                conn.await
                            }
                        };
                        if let Err(err) = res {
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
    for candidate in ["/app/conf/config.toml", "/app/config.toml", "./config.toml"] {
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
    inbound_proxy_protocol: ProxyProtocol,
}

impl HealthCheckTarget {
    fn from_parts(
        listen: &str,
        proxy_prefix: &str,
        tls: bool,
        inbound_proxy_protocol: ProxyProtocol,
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
            inbound_proxy_protocol,
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
        if target.inbound_proxy_protocol.is_enabled() {
            probe_proxy_protocol_health(&target).await?;
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

async fn probe_proxy_protocol_health(target: &HealthCheckTarget) -> Result<()> {
    let timeout = Duration::from_secs(4);
    let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(target.connect_addr))
        .await
        .with_context(|| {
            format!(
                "PROXY Protocol health check connect timed out for {}",
                target.connect_addr
            )
        })?
        .with_context(|| {
            format!(
                "PROXY Protocol health check connect failed for {}",
                target.connect_addr
            )
        })?;

    let pp_local = encode_proxy_protocol_local(target.inbound_proxy_protocol);
    tokio::time::timeout(timeout, tcp.write_all(&pp_local))
        .await
        .context("PROXY Protocol health check write header timed out")?
        .context("PROXY Protocol health check write header failed")?;

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
            .context("PROXY Protocol TLS health check handshake timed out")?
            .context("PROXY Protocol TLS health check handshake failed")?;
        tokio::time::timeout(timeout, tls.write_all(req.as_bytes()))
            .await
            .context("PROXY Protocol TLS health check write timed out")?
            .context("PROXY Protocol TLS health check write failed")?;
        tokio::time::timeout(timeout, tls.read(&mut resp_buf))
            .await
            .context("PROXY Protocol TLS health check read timed out")?
            .context("PROXY Protocol TLS health check read failed")?
    } else {
        tokio::time::timeout(timeout, tcp.write_all(req.as_bytes()))
            .await
            .context("PROXY Protocol health check write timed out")?
            .context("PROXY Protocol health check write failed")?;
        tokio::time::timeout(timeout, tcp.read(&mut resp_buf))
            .await
            .context("PROXY Protocol health check read timed out")?
            .context("PROXY Protocol health check read failed")?
    };

    let head = String::from_utf8_lossy(&resp_buf[..n]);
    let status_line = head.lines().next().unwrap_or_default().trim();
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        anyhow::bail!(
            "PROXY Protocol {} health check to {} returned unexpected status: '{status_line}'",
            target.inbound_proxy_protocol,
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
    // Prefer full Config::load -> RuntimeConfig so ALL listeners (including inbound PROXY Protocol) are checked.
    if let Ok(cfg) = Config::load(config_path)
        && let Ok(runtime) = cfg.into_runtime()
    {
        let mut targets = Vec::with_capacity(runtime.listeners.len());
        for listener in &runtime.listeners {
            targets.push(HealthCheckTarget::from_parts(
                &listener.listen.to_string(),
                &listener.proxy_prefix,
                listener.tls_enabled(),
                listener.inbound_proxy_protocol,
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
    let inbound_pp = file_cfg
        .as_ref()
        .map(|c| c.server.effective_inbound_proxy_protocol())
        .unwrap_or(ProxyProtocol::Off);

    Ok(vec![HealthCheckTarget::from_parts(
        &listen,
        &proxy_prefix,
        tls,
        inbound_pp,
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
    use axum::routing::get;

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
            raw_cfg.server.effective_inbound_proxy_protocol(),
        )
        .unwrap();
        assert_eq!(target.url(), "http://127.0.0.1:8080/_proxy/health");
        assert_eq!(target.inbound_proxy_protocol, ProxyProtocol::Off);
    }

    #[tokio::test]
    async fn proxy_protocol_health_check_probes_v1_and_v2_listeners() {
        for (proto_str, proto) in [("v1", ProxyProtocol::V1), ("v2", ProxyProtocol::V2)] {
            let cfg = Config::from_toml_str(&format!(
                r#"
                [server]
                listen = "127.0.0.1:0"
                inbound_proxy_protocol = "{proto_str}"
                expose_info = "trusted"

                [[proxies]]
                name = "test"
                matrix_proxy_public_url = "https://proxy.example.com"
                upstream_matrix_server_url = "https://matrix.example.org"
                "#
            ))
            .unwrap();
            let runtime = Arc::new(cfg.into_runtime().unwrap());
            let plan = runtime.listeners[0].clone();
            let state = ListenerState::build(Arc::clone(&runtime), plan.clone()).unwrap();
            let live = LiveListener::static_only(state);
            let app = build_live_listener_router(live);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let accept_cfg = Arc::new(RwLock::new(AcceptConfig::from_plan(runtime, &plan, None)));
            let tracker = Arc::new(ConnectionTracker::default());
            let (tx, rx) = watch::channel(false);
            let server_task = tokio::spawn(async move {
                let _ = serve_listener(addr, listener, accept_cfg, app, tracker, rx).await;
            });

            let target =
                HealthCheckTarget::from_parts(&addr.to_string(), "/_proxy", false, proto).unwrap();
            probe_proxy_protocol_health(&target).await.unwrap();

            let _ = tx.send(true);
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn hot_reload_swaps_profiles_and_rejects_invalid_config_safely() {
        // Spin up two mock upstream Matrix servers A and B
        let app_a = axum::Router::new().route(
            "/_matrix/client/versions",
            get(|| async { r#"{"versions":["upstream-A"]}"# }),
        );
        let app_b = axum::Router::new().route(
            "/_matrix/client/versions",
            get(|| async { r#"{"versions":["upstream-B"]}"# }),
        );
        let l_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = l_a.local_addr().unwrap();
        let l_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = l_b.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l_a, app_a).await;
        });
        tokio::spawn(async move {
            let _ = axum::serve(l_b, app_b).await;
        });

        // Reserve a free port for the proxy listener
        let probe_sock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = probe_sock.local_addr().unwrap();
        drop(probe_sock);

        let tmp_path = std::env::temp_dir().join(format!(
            "matrix-proxy-hot-reload-test-{}.toml",
            std::process::id()
        ));
        let cfg_v1 = format!(
            r#"
            [server]
            listen = "{proxy_addr}"
            expose_info = "trusted"
            hot_reload = true

            [[proxies]]
            name = "site-a"
            strict_host_match = true
            matrix_proxy_public_url = "https://a.example.com"
            upstream_matrix_server_url = "http://{addr_a}"
            "#
        );
        std::fs::write(&tmp_path, cfg_v1).unwrap();

        let initial_runtime = Arc::new(
            Config::load(Some(&tmp_path))
                .unwrap()
                .into_runtime()
                .unwrap(),
        );
        let metrics = Arc::new(ProxyMetrics::new());
        let coord = ReloadCoordinator::new(Some(tmp_path.clone()), Arc::clone(&metrics));
        coord.start_initial(initial_runtime).await.unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        // 1. Before reload: a.example.com -> upstream-A, b.example.com -> 421
        let r1 = client
            .get(format!("http://{proxy_addr}/_matrix/client/versions"))
            .header("host", "a.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 200);
        assert!(r1.text().await.unwrap().contains("upstream-A"));

        let r_b_before = client
            .get(format!("http://{proxy_addr}/_matrix/client/versions"))
            .header("host", "b.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r_b_before.status(), 421);

        // 2. Write v2 adding b.example.com and trigger POST /_proxy/reload
        let cfg_v2 = format!(
            r#"
            [server]
            listen = "{proxy_addr}"
            expose_info = "trusted"
            hot_reload = true

            [[proxies]]
            name = "site-a"
            strict_host_match = true
            matrix_proxy_public_url = "https://a.example.com"
            upstream_matrix_server_url = "http://{addr_a}"

            [[proxies]]
            name = "site-b"
            matrix_proxy_public_url = "https://b.example.com"
            upstream_matrix_server_url = "http://{addr_b}"
            "#
        );
        std::fs::write(&tmp_path, cfg_v2).unwrap();

        let reload_resp = client
            .post(format!("http://{proxy_addr}/_proxy/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(reload_resp.status(), 200);
        assert_eq!(metrics.generation(), 2);

        // b.example.com now routes live to upstream-B without restarting the listener!
        let r_b_after = client
            .get(format!("http://{proxy_addr}/_matrix/client/versions"))
            .header("host", "b.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r_b_after.status(), 200);
        assert!(r_b_after.text().await.unwrap().contains("upstream-B"));

        // 3. Write invalid TOML and trigger POST /_proxy/reload -> must return 400 and KEEP v2 active!
        std::fs::write(&tmp_path, "this is = [broken toml").unwrap();
        let bad_reload = client
            .post(format!("http://{proxy_addr}/_proxy/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(bad_reload.status(), 400);
        assert_eq!(metrics.generation(), 2);

        // Existing v2 routing still works with zero outage!
        let r_b_still = client
            .get(format!("http://{proxy_addr}/_matrix/client/versions"))
            .header("host", "b.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(r_b_still.status(), 200);
        assert!(r_b_still.text().await.unwrap().contains("upstream-B"));

        // 4. Verify /_proxy/metrics returns Prometheus text for trusted peer and 403 for untrusted XFF
        let metrics_ok = client
            .get(format!("http://{proxy_addr}/_proxy/metrics"))
            .send()
            .await
            .unwrap();
        assert_eq!(metrics_ok.status(), 200);
        let metrics_txt = metrics_ok.text().await.unwrap();
        assert!(metrics_txt.contains("matrix_proxy_config_generation 2"));
        assert!(metrics_txt.contains("matrix_proxy_reloads_total 1"));
        assert!(metrics_txt.contains("matrix_proxy_reload_failures_total 1"));

        let metrics_denied = client
            .get(format!("http://{proxy_addr}/_proxy/metrics"))
            .header("x-forwarded-for", "203.0.113.99")
            .send()
            .await
            .unwrap();
        assert_eq!(metrics_denied.status(), 403);

        coord.shutdown_all().await;
        let _ = std::fs::remove_file(&tmp_path);
    }
}
