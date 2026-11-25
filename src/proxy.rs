use crate::client_ip::{ClientInfo, InboundPeer, IpRateLimiter, apply_upstream_client_ip_headers};
use crate::config::{
    AuthProxyMode, ExposeInfoMode, ListenerPlan, ProxyProfile, ProxyProtocol, RuntimeConfig,
    ServerConfig, normalized_base_url, redact_proxy_url, should_bypass_outbound_proxy,
};
use crate::discovery::{DiscoveryManager, ResolvedUpstreams};
use crate::metrics::ProxyMetrics;
use crate::ppv2_client::{Ppv2Client, maybe_gunzip};
use crate::rewrite::{PublicContext, RewriteEngine, build_upstream_target_url};
use crate::router::{RouteTarget, VhostRouter, classify_request, extract_request_host};
use crate::ws::{build_client_tls_config, is_websocket_upgrade, proxy_websocket};
use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, error, warn};
use url::Url;

/// Result summary returned after a successful live hot reload.
#[derive(Debug, Clone, Serialize)]
pub struct ReloadReport {
    pub generation: u64,
    pub reason: String,
    pub listeners: Vec<String>,
    pub profiles: Vec<String>,
    pub added_listeners: Vec<String>,
    pub removed_listeners: Vec<String>,
}

/// Callback invoked by `POST /_proxy/reload` to trigger an atomic live reload.
pub type ReloadFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = std::result::Result<ReloadReport, String>> + Send>>
        + Send
        + Sync,
>;

/// Hot-swappable handle shared across all connections on a listening socket.
/// Swapping `ListenerState` takes effect immediately for both new and existing keep-alive/H2 connections.
pub struct LiveListener {
    state: RwLock<Arc<ListenerState>>,
    pub metrics: Arc<ProxyMetrics>,
    reload_fn: Option<ReloadFn>,
}

impl LiveListener {
    pub fn new(
        initial: Arc<ListenerState>,
        metrics: Arc<ProxyMetrics>,
        reload_fn: Option<ReloadFn>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(initial),
            metrics,
            reload_fn,
        })
    }

    pub fn static_only(initial: Arc<ListenerState>) -> Arc<Self> {
        let metrics = Arc::clone(&initial.metrics);
        Self::new(initial, metrics, None)
    }

    /// Lock-free-for-readers atomic snapshot of the current listener state.
    pub fn current(&self) -> Arc<ListenerState> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&guard)
    }

    /// Atomically replaces the active listener state (zero downtime for in-flight requests).
    pub fn swap(&self, next: Arc<ListenerState>) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }
}

pub struct ProxyInstance {
    pub profile: Arc<ProxyProfile>,
    pub discovery: Arc<DiscoveryManager>,
    /// Streaming HTTP client (preserves upstream Content-Encoding byte-for-byte).
    pub stream_client: reqwest::Client,
    /// Rewriting HTTP client (auto-decompresses gzip/br/deflate for JSON/HTML rewriting).
    pub rewrite_client: reqwest::Client,
    /// Native Hyper + Rustls HTTP/2+HTTP/1.1 client with outbound PROXY Protocol v2.
    pub ppv2_client: Option<Arc<Ppv2Client>>,
    /// Cached Rustls ClientConfig for WebSocket tunnels (HTTP/1.1 ALPN).
    pub ws_tls_config: Arc<rustls::ClientConfig>,
}

impl ProxyInstance {
    pub fn build(
        server: &ServerConfig,
        profile: ProxyProfile,
        metrics: Option<Arc<ProxyMetrics>>,
    ) -> Result<Arc<Self>> {
        let profile = Arc::new(profile);
        let stream_client = build_http_client(server, &profile, false, false)?;
        let rewrite_client = build_http_client(server, &profile, true, false)?;
        let well_known_client = build_http_client(server, &profile, true, true)?;

        warn_if_pp_on_standard_https_port(&profile);

        let ppv2_client = if profile.uses_outbound_proxy_protocol() {
            Some(Arc::new(Ppv2Client::new(
                server,
                profile.upstream.outbound_proxy.as_deref(),
                profile.upstream.outbound_no_proxy.clone(),
                profile.upstream.connect_timeout_secs,
                profile.upstream.danger_accept_invalid_certs,
                metrics,
            )?))
        } else {
            None
        };

        let ws_tls_config = build_client_tls_config(
            profile.upstream.danger_accept_invalid_certs,
            &[b"http/1.1".as_slice()],
        )?;

        let discovery = Arc::new(DiscoveryManager::new(
            Arc::clone(&profile),
            rewrite_client.clone(),
            well_known_client,
            ppv2_client.clone(),
        ));

        Ok(Arc::new(Self {
            profile,
            discovery,
            stream_client,
            rewrite_client,
            ppv2_client,
            ws_tls_config,
        }))
    }
}

fn warn_if_pp_on_standard_https_port(profile: &ProxyProfile) {
    for (label, proto, raw_url) in [
        (
            "upstream_matrix_server_url",
            profile.matrix_proxy_protocol(),
            profile.upstream.upstream_matrix_server_url.as_deref(),
        ),
        (
            "upstream_matrix_auth_url",
            profile.auth_proxy_protocol(),
            profile.upstream.upstream_matrix_auth_url.as_deref(),
        ),
    ] {
        if proto.is_enabled()
            && let Some(raw) = raw_url
            && let Ok(u) = Url::parse(raw)
            && u.scheme().eq_ignore_ascii_case("https")
            && u.port().is_none()
        {
            warn!(
                profile = %profile.name,
                field = label,
                proxy_protocol = %proto,
                upstream = %raw,
                "outbound PROXY Protocol is enabled on default HTTPS port 443; ensure the upstream proxy (Nginx `proxy_protocol` / HAProxy `accept-proxy` / Envoy) explicitly expects PROXY Protocol on 443 (public third-party Matrix servers will reject it with TLS handshake errors)"
            );
        }
    }
}

pub struct ListenerState {
    pub runtime: Arc<RuntimeConfig>,
    pub plan: ListenerPlan,
    pub vhost: VhostRouter<ProxyInstance>,
    pub concurrency: Option<Arc<Semaphore>>,
    pub rate_limiter: Option<Arc<IpRateLimiter>>,
    pub listener_is_tls: bool,
    pub metrics: Arc<ProxyMetrics>,
    pub health_path: String,
    pub health_path_slash: String,
    pub info_path: String,
    pub info_path_slash: String,
    pub metrics_path: String,
    pub metrics_path_slash: String,
    pub reload_path: String,
    pub reload_path_slash: String,
}

impl ListenerState {
    pub fn build(runtime: Arc<RuntimeConfig>, plan: ListenerPlan) -> Result<Arc<Self>> {
        Self::build_with_metrics(runtime, plan, Arc::new(ProxyMetrics::new()))
    }

    pub fn build_with_metrics(
        runtime: Arc<RuntimeConfig>,
        plan: ListenerPlan,
        metrics: Arc<ProxyMetrics>,
    ) -> Result<Arc<Self>> {
        let mut entries = Vec::with_capacity(plan.profiles.len());
        for profile in &plan.profiles {
            let inst =
                ProxyInstance::build(&runtime.server, profile.clone(), Some(Arc::clone(&metrics)))?;
            entries.push((
                profile.route_hosts.clone(),
                profile.is_default,
                profile.strict_host_match,
                inst,
            ));
        }
        let vhost = VhostRouter::build(entries);
        let concurrency = if runtime.server.max_concurrent_requests > 0 {
            Some(Arc::new(Semaphore::new(
                runtime.server.max_concurrent_requests,
            )))
        } else {
            None
        };
        let rate_limiter = IpRateLimiter::new(
            runtime.server.rate_limit_rps,
            runtime.server.rate_limit_burst,
        )
        .map(Arc::new);
        let listener_is_tls = plan.tls_enabled();

        let prefix = plan.proxy_prefix.trim_end_matches('/');
        let health_path = format!("{prefix}/health");
        let health_path_slash = format!("{health_path}/");
        let info_path = format!("{prefix}/info");
        let info_path_slash = format!("{info_path}/");
        let metrics_path = format!("{prefix}/metrics");
        let metrics_path_slash = format!("{metrics_path}/");
        let reload_path = format!("{prefix}/reload");
        let reload_path_slash = format!("{reload_path}/");

        Ok(Arc::new(Self {
            runtime,
            plan,
            vhost,
            concurrency,
            rate_limiter,
            listener_is_tls,
            metrics,
            health_path,
            health_path_slash,
            info_path,
            info_path_slash,
            metrics_path,
            metrics_path_slash,
            reload_path,
            reload_path_slash,
        }))
    }

    /// Concurrently warms up discovery across all profiles on this listener (bounded per-profile timeout
    /// so one unreachable optional upstream never stalls startup or hot reload).
    pub async fn warm_up_discovery(&self) -> Result<()> {
        let futs = self.vhost.instances().iter().map(|inst| async move {
            let res =
                tokio::time::timeout(Duration::from_secs(10), inst.discovery.initial_resolve())
                    .await;
            match res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(err)) => {
                    if inst.profile.upstream.upstream_matrix_server_url.is_none() {
                        Err(err).with_context(|| {
                            format!(
                                "startup upstream auto-discovery failed for profile '{}'",
                                inst.profile.name
                            )
                        })
                    } else {
                        warn!(
                            profile = %inst.profile.name,
                            error = %err,
                            "initial upstream discovery probe had warnings; will retry lazily"
                        );
                        Ok(())
                    }
                }
                Err(_) => {
                    if inst.profile.upstream.upstream_matrix_server_url.is_none() {
                        anyhow::bail!(
                            "startup upstream auto-discovery timed out for profile '{}'",
                            inst.profile.name
                        );
                    }
                    warn!(
                        profile = %inst.profile.name,
                        "initial upstream discovery probe timed out; will retry lazily"
                    );
                    Ok(())
                }
            }
        });

        for result in futures_util::future::join_all(futs).await {
            result?;
        }
        Ok(())
    }
}

pub fn build_listener_router(state: Arc<ListenerState>) -> Router {
    build_live_listener_router(LiveListener::static_only(state))
}

pub fn build_live_listener_router(live: Arc<LiveListener>) -> Router {
    Router::new().fallback(any(handle_request)).with_state(live)
}

fn build_http_client(
    server: &ServerConfig,
    profile: &ProxyProfile,
    auto_decompress: bool,
    follow_redirects: bool,
) -> Result<reqwest::Client> {
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(3)
    } else {
        reqwest::redirect::Policy::none()
    };
    let mut builder = reqwest::Client::builder()
        .redirect(redirect_policy)
        .connect_timeout(Duration::from_secs(
            profile.upstream.connect_timeout_secs.max(1),
        ))
        .pool_max_idle_per_host(server.pool_max_idle_per_host.max(1))
        .pool_idle_timeout(Duration::from_secs(server.pool_idle_timeout_secs))
        .tcp_nodelay(server.tcp_nodelay)
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(1024 * 1024)
        .http2_initial_connection_window_size(4 * 1024 * 1024)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(20))
        .http2_keep_alive_while_idle(true);

    if server.tcp_keepalive_secs > 0 {
        builder = builder.tcp_keepalive(Duration::from_secs(server.tcp_keepalive_secs));
    }
    if profile.upstream.request_timeout_secs > 0 {
        builder = builder.timeout(Duration::from_secs(profile.upstream.request_timeout_secs));
    }
    if profile.upstream.danger_accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if !auto_decompress {
        builder = builder.no_gzip().no_brotli().no_deflate();
    }
    if let Some(proxy_url) = &profile.upstream.outbound_proxy {
        // Validate proxy URL eagerly and use a unified custom matcher so CIDR/IP/domain
        // `outbound_no_proxy` rules match 100% identically across HTTP, WebSocket, and PROXY Protocol.
        let parsed_proxy = Url::parse(proxy_url).with_context(|| {
            format!(
                "invalid outbound proxy '{}' in profile '{}'",
                redact_proxy_url(proxy_url),
                profile.name
            )
        })?;
        let no_proxy_rules = profile.upstream.outbound_no_proxy.clone();
        let proxy = reqwest::Proxy::custom(move |target_url| {
            if let Some(host) = target_url.host_str()
                && should_bypass_outbound_proxy(host, &no_proxy_rules)
            {
                return None;
            }
            Some(parsed_proxy.clone())
        });
        // Explicitly replace ambient env proxies with the configured proxy + no_proxy rules.
        builder = builder.no_proxy().proxy(proxy);
    } else if profile.upstream.outbound_proxy_direct {
        builder = builder.no_proxy();
    }

    builder
        .build()
        .context("failed to build reqwest HTTP client")
}

async fn handle_request(
    State(live): State<Arc<LiveListener>>,
    req: Request<Body>,
) -> Response<Body> {
    let state = live.current();
    let method = req.method().clone();

    // 1. Fast-path listener liveness probe (always 200 OK regardless of Host header or upstream state).
    {
        let path = req.uri().path();
        if path == state.health_path || path == state.health_path_slash {
            return json_response(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "service": "matrix-proxy",
                    "version": env!("CARGO_PKG_VERSION"),
                    "generation": live.metrics.generation(),
                    "listener": state.plan.listen.to_string(),
                    "profiles": state.vhost.instances().len(),
                }),
                false,
            );
        }
    }

    let _req_guard = live.metrics.track_request();

    // 2. Global/per-listener concurrency guard (backpressure against flood/OOM).
    let _permit = if let Some(sem) = &state.concurrency {
        match Arc::clone(sem).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                live.metrics
                    .concurrency_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                let mut resp = json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "M_LIMIT_EXCEEDED",
                    "Proxy concurrency limit reached",
                );
                resp.headers_mut()
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
                return resp;
            }
        }
    } else {
        None
    };

    // 3. Extract verified real client IP (anti-spoofing protected; borrows headers with zero clone).
    let inbound = req
        .extensions()
        .get::<InboundPeer>()
        .copied()
        .unwrap_or_else(|| {
            let peer_addr = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0)
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
            InboundPeer {
                physical_peer: peer_addr,
                ppv2_client: None,
            }
        });

    let client = ClientInfo::extract_with_ppv2(
        &state.runtime,
        inbound.physical_peer,
        inbound.ppv2_client,
        req.headers(),
        state.listener_is_tls,
    );

    // 4. Optional per-IP rate limiting.
    if let Some(limiter) = &state.rate_limiter
        && !limiter.allow(client.client_ip)
    {
        live.metrics
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
        let mut resp = json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            "Too many requests",
        );
        resp.headers_mut()
            .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let req_host = extract_request_host(&client, req.headers());

    // 5. Listener-level management endpoints (`/info`, `/metrics`, `POST /reload`) gated by `expose_info` ACL.
    if req.uri().path() == state.info_path || req.uri().path() == state.info_path_slash {
        if let Some(denied) = check_info_access(&state, &client) {
            return denied;
        }
        if let Some(inst) = state.vhost.resolve(req_host.as_deref())
            && let Ok(upstreams) = inst.discovery.get_upstreams().await
        {
            let public = PublicContext::from_request(&inst.profile, &client, req.headers());
            return handle_profile_info(&state, &live.metrics, &inst, &public, &upstreams, &client);
        }
        return handle_listener_summary_info(&state, &live.metrics, &client);
    }

    if req.uri().path() == state.metrics_path || req.uri().path() == state.metrics_path_slash {
        if let Some(denied) = check_info_access(&state, &client) {
            return denied;
        }
        let body = live
            .metrics
            .render_prometheus(state.runtime.listeners.len(), state.vhost.instances().len());
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )
            .header("x-content-type-options", "nosniff")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    if req.uri().path() == state.reload_path || req.uri().path() == state.reload_path_slash {
        if let Some(denied) = check_info_access(&state, &client) {
            return denied;
        }
        if method != Method::POST {
            let mut resp = json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "M_UNRECOGNIZED",
                "Use POST to trigger a hot reload",
            );
            resp.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST"));
            return resp;
        }
        let Some(reload_fn) = &live.reload_fn else {
            return json_error(
                StatusCode::NOT_IMPLEMENTED,
                "M_UNKNOWN",
                "Hot reload is unavailable without a configuration file",
            );
        };
        return match (reload_fn)().await {
            Ok(report) => json_response(
                StatusCode::OK,
                &json!({
                    "status": "reloaded",
                    "report": report,
                }),
                false,
            ),
            Err(err) => json_error(
                StatusCode::BAD_REQUEST,
                "M_UNKNOWN",
                &format!("Hot reload rejected (previous config kept active): {err}"),
            ),
        };
    }

    // 6. Resolve target upstream profile by Host (shared port) or dedicated port.
    let Some(inst) = state.vhost.resolve(req_host.as_deref()) else {
        warn!(
            listener = %state.plan.listen,
            host = ?req_host,
            client_ip = %client.client_ip,
            "unmatched Host header on multi-profile listener"
        );
        return json_error(
            StatusCode::MISDIRECTED_REQUEST,
            "M_NOT_FOUND",
            "No Matrix proxy profile matches the requested Host",
        );
    };

    let upstreams = match inst.discovery.get_upstreams().await {
        Ok(u) => u,
        Err(err) => {
            live.metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!(
                profile = %inst.profile.name,
                error = %format!("{err:#}"),
                "failed to resolve upstream Matrix/Auth endpoints"
            );
            return json_error(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "Failed to resolve upstream Matrix/Auth service",
            );
        }
    };

    let public = PublicContext::from_request(&inst.profile, &client, req.headers());
    let target = classify_request(
        &inst.profile,
        &public,
        &client,
        req.headers(),
        req.uri().path(),
        req.uri().query(),
    );

    debug!(
        profile = %inst.profile.name,
        client_ip = %client.client_ip,
        method = %method,
        path = %req.uri().path(),
        target = ?target,
        "routing request"
    );

    match target {
        RouteTarget::ProxyHealth => json_response(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "service": "matrix-proxy",
                "profile": inst.profile.name,
                "version": env!("CARGO_PKG_VERSION"),
            }),
            false,
        ),

        RouteTarget::ProxyInfo => {
            if let Some(denied) = check_info_access(&state, &client) {
                return denied;
            }
            handle_profile_info(&state, &live.metrics, &inst, &public, &upstreams, &client)
        }

        RouteTarget::WellKnownMatrixClient => {
            if method == Method::OPTIONS {
                return cors_preflight_response(req.headers(), false);
            }
            let rewriter = RewriteEngine::new(&inst.profile, &public, &upstreams);
            let doc = rewriter.build_well_known_client();
            let mut resp = json_response(StatusCode::OK, &doc, true);
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                cache_control_header(inst.discovery.cache_ttl().as_secs()),
            );
            resp
        }

        RouteTarget::AuthMetadata { requested_path } => {
            if method == Method::OPTIONS {
                return cors_preflight_response(req.headers(), false);
            }
            handle_auth_metadata(
                &inst,
                &public,
                &upstreams,
                &client,
                &requested_path,
                req.headers(),
            )
            .await
        }

        RouteTarget::OidcDiscovery { upstream_path } => {
            if method == Method::OPTIONS {
                return cors_preflight_response(req.headers(), false);
            }
            handle_oidc_discovery(
                &inst,
                &public,
                &upstreams,
                &client,
                &upstream_path,
                req.headers(),
            )
            .await
        }

        RouteTarget::Matrix {
            upstream_path_and_query,
        } => {
            if method == Method::OPTIONS {
                return cors_preflight_response(req.headers(), false);
            }
            let target_url =
                build_upstream_target_url(&upstreams.matrix_url, &upstream_path_and_query);
            return forward_request(
                &state,
                &inst,
                &public,
                &upstreams,
                &client,
                req,
                target_url,
                ForwardKind::Matrix,
                false,
            )
            .await;
        }

        RouteTarget::Auth {
            upstream_path_and_query,
            stripped_prefix,
        } => {
            if method == Method::OPTIONS {
                return cors_preflight_response(req.headers(), true);
            }
            let auth_base = upstreams.effective_auth_url();
            let target_url = build_upstream_target_url(auth_base, &upstream_path_and_query);
            forward_request(
                &state,
                &inst,
                &public,
                &upstreams,
                &client,
                req,
                target_url,
                ForwardKind::Auth,
                stripped_prefix,
            )
            .await
        }
    }
}

fn check_info_access(state: &ListenerState, client: &ClientInfo) -> Option<Response<Body>> {
    match state.runtime.server.expose_info {
        ExposeInfoMode::Always => None,
        ExposeInfoMode::Disabled => Some(json_error(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Proxy info endpoint disabled",
        )),
        ExposeInfoMode::Trusted => {
            if state.runtime.is_trusted_proxy(client.client_ip) {
                None
            } else {
                Some(json_error(
                    StatusCode::FORBIDDEN,
                    "M_FORBIDDEN",
                    "Proxy info endpoint is restricted to trusted networks",
                ))
            }
        }
    }
}

fn runtime_metrics_json(state: &ListenerState, metrics: &ProxyMetrics) -> Value {
    json!({
        "config_generation": metrics.generation(),
        "reloads_total": metrics.reloads_total.load(Ordering::Relaxed),
        "reload_failures_total": metrics.reload_failures_total.load(Ordering::Relaxed),
        "last_reload_epoch_secs": metrics.last_reload_epoch_secs.load(Ordering::Relaxed),
        "uptime_secs": metrics.uptime_secs(),
        "requests_total": metrics.requests_total.load(Ordering::Relaxed),
        "requests_active": metrics.requests_active.load(Ordering::Relaxed),
        "upstream_errors_total": metrics.upstream_errors_total.load(Ordering::Relaxed),
        "proxy_protocol_retries_total": metrics.proxy_protocol_retries_total.load(Ordering::Relaxed),
        "hot_reload_enabled": state.runtime.server.hot_reload,
    })
}

fn handle_listener_summary_info(
    state: &ListenerState,
    metrics: &ProxyMetrics,
    client: &ClientInfo,
) -> Response<Body> {
    let profiles: Vec<Value> = state
        .vhost
        .instances()
        .iter()
        .map(|inst| {
            json!({
                "name": inst.profile.name,
                "route_hosts": inst.profile.route_hosts,
                "default": inst.profile.is_default,
                "matrix_proxy_public_url": inst.profile.matrix_proxy_public_url.as_ref().map(normalized_base_url),
                "outbound_proxy": inst.profile.upstream.outbound_proxy.as_deref().map(redact_proxy_url),
                "auth_proxy_mode": inst.profile.discovery.auth_proxy_mode,
                "matrix_rtc": inst.profile.matrix_rtc.info_json(),
                "upstream_matrix_proxy_protocol": inst.profile.matrix_proxy_protocol(),
                "upstream_auth_proxy_protocol": inst.profile.auth_proxy_protocol(),
                "client_ip_mode": inst.profile.upstream.client_ip_mode,
            })
        })
        .collect();

    json_response(
        StatusCode::OK,
        &json!({
            "service": "matrix-proxy",
            "version": env!("CARGO_PKG_VERSION"),
            "listener": state.plan.listen.to_string(),
            "inbound_proxy_protocol": state.plan.inbound_proxy_protocol,
            "global_outbound_proxy": state.runtime.server.outbound_proxy.as_deref().map(redact_proxy_url),
            "shared_port": state.vhost.is_shared_port(),
            "seen_client_ip": client.client_ip.to_string(),
            "runtime": runtime_metrics_json(state, metrics),
            "profiles": profiles,
        }),
        false,
    )
}

fn handle_profile_info(
    state: &ListenerState,
    metrics: &ProxyMetrics,
    inst: &ProxyInstance,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    client: &ClientInfo,
) -> Response<Body> {
    let body = json!({
        "service": "matrix-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "profile": inst.profile.name,
        "route_hosts": inst.profile.route_hosts,
        "inbound_proxy_protocol": state.plan.inbound_proxy_protocol,
        "seen_client_ip": client.client_ip.to_string(),
        "runtime": runtime_metrics_json(state, metrics),
        "public": {
            "matrix_proxy_public_url": normalized_base_url(&public.matrix_base),
            "matrix_proxy_public_auth_url": normalized_base_url(&public.auth_base),
            "dual_domain": public.dual_domain,
            "auth_mode": inst.profile.routing.auth_mode,
            "auth_prefix": public.auth_prefix,
        },
        "upstream": {
            "upstream_matrix_server_url": normalized_base_url(&upstreams.matrix_url),
            "upstream_matrix_auth_url": normalized_base_url(upstreams.effective_auth_url()),
            "auth_is_separate": upstreams.auth_is_separate(),
            "outbound_proxy": inst.profile.upstream.outbound_proxy.as_deref().map(redact_proxy_url),
            "outbound_no_proxy": inst.profile.upstream.outbound_no_proxy,
            "client_ip_mode": inst.profile.upstream.client_ip_mode,
            "upstream_matrix_proxy_protocol": inst.profile.matrix_proxy_protocol(),
            "upstream_auth_proxy_protocol": inst.profile.auth_proxy_protocol(),
        },
        "discovery": {
            "auth_proxy_mode": inst.profile.discovery.auth_proxy_mode,
            "matrix_rtc": inst.profile.matrix_rtc.info_json(),
            "rewrite_issuer": inst.profile.discovery.rewrite_issuer,
            "rewrite_auth_body": inst.profile.discovery.rewrite_auth_body,
            "observed_auth_origins": upstreams.observed_auth_origins,
        }
    });
    json_response(StatusCode::OK, &body, false)
}

fn cache_control_header(ttl_secs: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("public, max-age={}", ttl_secs.max(1)))
        .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=60"))
}

fn build_rewritten_metadata_response(
    inst: &ProxyInstance,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    raw_doc: Value,
) -> Response<Body> {
    let rewriter = RewriteEngine::new(&inst.profile, public, upstreams);
    let rewritten = rewriter.rewrite_auth_metadata(raw_doc);
    let mut resp = json_response(StatusCode::OK, &rewritten, true);
    resp.headers_mut().insert(
        http::header::CACHE_CONTROL,
        cache_control_header(inst.discovery.cache_ttl().as_secs()),
    );
    resp
}

async fn handle_auth_metadata(
    inst: &ProxyInstance,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    client: &ClientInfo,
    requested_path: &str,
    req_headers: &HeaderMap,
) -> Response<Body> {
    let cache_key = format!("auth_meta:{requested_path}");
    let stale_fallback = match inst.discovery.cached_metadata(&cache_key) {
        Some((doc, true)) => {
            return build_rewritten_metadata_response(inst, public, upstreams, doc);
        }
        Some((doc, false)) => Some(doc),
        None => None,
    };

    // Singleflight: coalesce concurrent cache-miss metadata fetches into one upstream probe.
    let _refresh_guard = inst.discovery.metadata_refresh_lock().lock().await;
    if let Some((doc, true)) = inst.discovery.cached_metadata(&cache_key) {
        let fresh_upstreams = inst
            .discovery
            .get_upstreams()
            .await
            .unwrap_or_else(|_| Arc::new(upstreams.clone()));
        return build_rewritten_metadata_response(inst, public, &fresh_upstreams, doc);
    }

    let fallback_path = if requested_path == "/_matrix/client/v1/auth_metadata" {
        "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata"
    } else {
        "/_matrix/client/v1/auth_metadata"
    };

    let matrix_pp = inst.profile.matrix_proxy_protocol();
    let matrix_host_ov = inst.profile.upstream.upstream_matrix_host_header.as_deref();
    let auth_pp = inst.profile.auth_proxy_protocol();
    let auth_host_ov = inst.profile.upstream.upstream_auth_host_header.as_deref();

    let mut candidates: Vec<(Url, ProxyProtocol, Option<&str>)> = vec![
        (
            build_upstream_target_url(&upstreams.matrix_url, requested_path),
            matrix_pp,
            matrix_host_ov,
        ),
        (
            build_upstream_target_url(&upstreams.matrix_url, fallback_path),
            matrix_pp,
            matrix_host_ov,
        ),
    ];

    if upstreams.auth_is_separate() {
        let auth_base = upstreams.effective_auth_url();
        candidates.push((
            build_upstream_target_url(auth_base, requested_path),
            auth_pp,
            auth_host_ov,
        ));
        candidates.push((
            build_upstream_target_url(auth_base, "/.well-known/oauth-authorization-server"),
            auth_pp,
            auth_host_ov,
        ));
        candidates.push((
            build_upstream_target_url(auth_base, "/.well-known/openid-configuration"),
            auth_pp,
            auth_host_ov,
        ));
    }

    let mut last_non_200: Option<(StatusCode, Vec<u8>, Option<HeaderValue>)> = None;

    for (url, pp, host_ov) in candidates {
        match fetch_metadata_json(inst, client, &url, pp, host_ov, req_headers).await {
            Ok((status, body_bytes, content_type)) if status.is_success() => {
                match serde_json::from_slice::<Value>(&body_bytes) {
                    Ok(json_val) => {
                        inst.discovery.observe_auth_metadata(&json_val);
                        inst.discovery
                            .store_metadata(cache_key.clone(), json_val.clone());
                        let fresh_upstreams = inst
                            .discovery
                            .get_upstreams()
                            .await
                            .unwrap_or_else(|_| Arc::new(upstreams.clone()));
                        return build_rewritten_metadata_response(
                            inst,
                            public,
                            &fresh_upstreams,
                            json_val,
                        );
                    }
                    Err(err) => {
                        warn!(url = %url, error = %err, "auth_metadata returned invalid JSON");
                        last_non_200 = Some((status, body_bytes, content_type));
                    }
                }
            }
            Ok((status, body_bytes, content_type)) => {
                debug!(url = %url, status = %status, "auth_metadata candidate returned non-success");
                if last_non_200.is_none() {
                    last_non_200 = Some((status, body_bytes, content_type));
                }
            }
            Err(err) => {
                warn!(url = %url, error = %format!("{err:#}"), "auth_metadata upstream fetch error");
            }
        }
    }

    if let Some(stale) = stale_fallback {
        warn!(profile = %inst.profile.name, path = requested_path, "serving stale cached auth_metadata after upstream refresh failure");
        return build_rewritten_metadata_response(inst, public, upstreams, stale);
    }

    if let Some((status, body_bytes, content_type)) = last_non_200 {
        let mut builder = Response::builder().status(status);
        if let Some(ct) = content_type {
            builder = builder.header(http::header::CONTENT_TYPE, ct);
        }
        builder = add_matrix_cors_headers(builder);
        return builder.body(Body::from(body_bytes)).unwrap_or_else(|_| {
            json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
        });
    }

    json_error(
        StatusCode::BAD_GATEWAY,
        "M_UNKNOWN",
        "Upstream auth_metadata unreachable",
    )
}

async fn handle_oidc_discovery(
    inst: &ProxyInstance,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    client: &ClientInfo,
    upstream_path: &str,
    req_headers: &HeaderMap,
) -> Response<Body> {
    let cache_key = format!("oidc:{upstream_path}");
    let stale_fallback = match inst.discovery.cached_metadata(&cache_key) {
        Some((doc, true)) => {
            return build_rewritten_metadata_response(inst, public, upstreams, doc);
        }
        Some((doc, false)) => Some(doc),
        None => None,
    };

    let _refresh_guard = inst.discovery.metadata_refresh_lock().lock().await;
    if let Some((doc, true)) = inst.discovery.cached_metadata(&cache_key) {
        let fresh_upstreams = inst
            .discovery
            .get_upstreams()
            .await
            .unwrap_or_else(|_| Arc::new(upstreams.clone()));
        return build_rewritten_metadata_response(inst, public, &fresh_upstreams, doc);
    }

    let auth_base = upstreams.effective_auth_url();
    let target_url = build_upstream_target_url(auth_base, upstream_path);
    let auth_pp = inst.profile.auth_proxy_protocol();
    let host_ov = inst.profile.upstream.upstream_auth_host_header.as_deref();

    match fetch_metadata_json(inst, client, &target_url, auth_pp, host_ov, req_headers).await {
        Ok((status, body_bytes, content_type)) if status.is_success() => {
            match serde_json::from_slice::<Value>(&body_bytes) {
                Ok(json_val) => {
                    inst.discovery.observe_auth_metadata(&json_val);
                    inst.discovery.store_metadata(cache_key, json_val.clone());
                    let fresh_upstreams = inst
                        .discovery
                        .get_upstreams()
                        .await
                        .unwrap_or_else(|_| Arc::new(upstreams.clone()));
                    build_rewritten_metadata_response(inst, public, &fresh_upstreams, json_val)
                }
                Err(_) => {
                    let mut builder = Response::builder().status(status);
                    if let Some(ct) = content_type {
                        builder = builder.header(http::header::CONTENT_TYPE, ct);
                    }
                    builder = add_matrix_cors_headers(builder);
                    builder.body(Body::from(body_bytes)).unwrap_or_else(|_| {
                        json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
                    })
                }
            }
        }
        Ok((status, body_bytes, content_type)) => {
            if let Some(stale) = stale_fallback {
                warn!(profile = %inst.profile.name, path = upstream_path, status = %status, "serving stale cached OIDC discovery after upstream error");
                return build_rewritten_metadata_response(inst, public, upstreams, stale);
            }
            let mut builder = Response::builder().status(status);
            if let Some(ct) = content_type {
                builder = builder.header(http::header::CONTENT_TYPE, ct);
            }
            builder = add_matrix_cors_headers(builder);
            builder.body(Body::from(body_bytes)).unwrap_or_else(|_| {
                json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
            })
        }
        Err(err) => {
            warn!(url = %target_url, error = %format!("{err:#}"), "OIDC discovery upstream fetch failed");
            if let Some(stale) = stale_fallback {
                return build_rewritten_metadata_response(inst, public, upstreams, stale);
            }
            json_error(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "Upstream OIDC discovery unreachable",
            )
        }
    }
}

async fn fetch_metadata_json(
    inst: &ProxyInstance,
    client: &ClientInfo,
    url: &Url,
    proxy_protocol: ProxyProtocol,
    host_override: Option<&str>,
    incoming_headers: &HeaderMap,
) -> Result<(StatusCode, Vec<u8>, Option<HeaderValue>)> {
    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        http::header::ACCEPT,
        HeaderValue::from_static("application/json"),
    );
    if let Some(ua) = incoming_headers.get(http::header::USER_AGENT) {
        out_headers.insert(http::header::USER_AGENT, ua.clone());
    }
    apply_upstream_client_ip_headers(
        &mut out_headers,
        client,
        inst.profile.upstream.client_ip_mode,
    );

    if proxy_protocol.is_enabled()
        && let Some(ppv2) = &inst.ppv2_client
    {
        return ppv2
            .get_bytes_for_client(
                url,
                host_override,
                out_headers,
                Duration::from_secs(15),
                proxy_protocol,
                Some(client.client_socket_addr()),
            )
            .await;
    }

    let mut builder = inst
        .rewrite_client
        .get(url.clone())
        .timeout(Duration::from_secs(15))
        .header(reqwest::header::ACCEPT_ENCODING, "identity");

    for (name, val) in &out_headers {
        builder = builder.header(name, val);
    }
    if let Some(host_ov) = host_override {
        builder = builder.header(reqwest::header::HOST, host_ov);
    }

    let resp = builder.send().await?;
    let status = resp.status();
    let content_type = resp.headers().get(http::header::CONTENT_TYPE).cloned();
    let bytes = resp.bytes().await?.to_vec();
    Ok((status, bytes, content_type))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardKind {
    Matrix,
    Auth,
}

#[allow(clippy::too_many_arguments)]
async fn forward_request(
    state: &ListenerState,
    inst: &ProxyInstance,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    client: &ClientInfo,
    req: Request<Body>,
    target_url: Url,
    kind: ForwardKind,
    strip_auth_prefix: bool,
) -> Response<Body> {
    let server_cfg = &state.runtime.server;
    let rewriter = RewriteEngine::new(&inst.profile, public, upstreams);
    let (outbound_pp, host_override) = match kind {
        ForwardKind::Matrix => (
            inst.profile.matrix_proxy_protocol(),
            inst.profile.upstream.upstream_matrix_host_header.as_deref(),
        ),
        ForwardKind::Auth => (
            inst.profile.auth_proxy_protocol(),
            inst.profile.upstream.upstream_auth_host_header.as_deref(),
        ),
    };

    if is_websocket_upgrade(req.headers()) {
        return match proxy_websocket(
            server_cfg,
            &inst.profile,
            &inst.ws_tls_config,
            &rewriter,
            client,
            req,
            target_url,
            host_override,
            outbound_pp,
            strip_auth_prefix,
        )
        .await
        {
            Ok(resp) => resp,
            Err(err) => {
                state
                    .metrics
                    .upstream_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!(profile = %inst.profile.name, error = %format!("{err:#}"), "websocket proxy error");
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "M_UNKNOWN",
                    "WebSocket upstream connection failed",
                )
            }
        };
    }

    let (parts, body) = req.into_parts();
    let is_auth = kind == ForwardKind::Auth;
    let is_full_auth_mode = inst.profile.discovery.auth_proxy_mode == AuthProxyMode::Full;
    let should_maybe_rewrite_body =
        is_auth && inst.profile.discovery.rewrite_auth_body && is_full_auth_mode;
    let restrict_uia_encoding =
        kind == ForwardKind::Matrix && is_full_auth_mode && is_uia_matrix_path(target_url.path());

    // Collect dynamic hop-by-hop headers declared via RFC 9110 `Connection: ...`.
    let dynamic_req_hop = collect_connection_headers(&parts.headers);
    let mut out_headers = HeaderMap::new();

    for (name, value) in &parts.headers {
        if is_hop_by_hop_header(name)
            || dynamic_req_hop.contains(name.as_str())
            || name == http::header::HOST
            || is_upstream_stripped_forwarded_header(name)
        {
            continue;
        }
        if (should_maybe_rewrite_body || restrict_uia_encoding)
            && name == http::header::ACCEPT_ENCODING
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

    if should_maybe_rewrite_body {
        out_headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    } else if restrict_uia_encoding {
        // Ensure UIA `401`/`403` JSON responses (e.g. cross-signing reset `m.oauth.url`) arrive
        // in gzip or identity encoding so they can always be decoded and rewritten.
        out_headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, identity"),
        );
    }

    apply_upstream_client_ip_headers(
        &mut out_headers,
        client,
        inst.profile.upstream.client_ip_mode,
    );

    let has_body = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS)
        || parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| n > 0)
            .unwrap_or(false)
        || parts.headers.contains_key(http::header::TRANSFER_ENCODING);

    // Path A: Native Hyper HTTP/2+HTTP/1.1 with standard PROXY Protocol v1/v2 carrying real client IP!
    if outbound_pp.is_enabled()
        && let Some(ppv2) = &inst.ppv2_client
    {
        let req_body = if has_body { body } else { Body::empty() };
        let upstream_fut = ppv2.send_request(
            parts.method,
            &target_url,
            host_override,
            out_headers,
            req_body,
            outbound_pp,
            Some(client.client_socket_addr()),
        );
        let upstream_resp = if inst.profile.upstream.request_timeout_secs > 0 {
            match tokio::time::timeout(
                Duration::from_secs(inst.profile.upstream.request_timeout_secs),
                upstream_fut,
            )
            .await
            {
                Ok(res) => res,
                Err(_) => {
                    state
                        .metrics
                        .upstream_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(profile = %inst.profile.name, target_url = %target_url, "PPv2 upstream request timed out");
                    return json_error(
                        StatusCode::GATEWAY_TIMEOUT,
                        "M_UNKNOWN",
                        "Upstream server timed out",
                    );
                }
            }
        } else {
            upstream_fut.await
        };

        let upstream_resp = match upstream_resp {
            Ok(r) => r,
            Err(err) => {
                state
                    .metrics
                    .upstream_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!(profile = %inst.profile.name, target_url = %target_url, error = %format!("{err:#}"), "PPv2 upstream request failed");
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    "M_UNKNOWN",
                    "Failed to connect to upstream server",
                );
            }
        };

        return finish_hyper_response(
            server_cfg,
            &rewriter,
            public,
            &parts.headers,
            kind,
            should_maybe_rewrite_body,
            upstream_resp,
        )
        .await;
    }

    // Path B: Standard HTTP/HTTPS upstream via tuned Reqwest connection pool.
    let http_client = if should_maybe_rewrite_body {
        &inst.rewrite_client
    } else {
        &inst.stream_client
    };

    let mut upstream_req = http_client.request(parts.method, target_url.clone());
    if let Some(host_ov) = host_override {
        upstream_req = upstream_req.header(reqwest::header::HOST, host_ov);
    }
    for (name, value) in &out_headers {
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }
    if has_body {
        upstream_req = upstream_req.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(err) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            if err.is_timeout() {
                warn!(profile = %inst.profile.name, target_url = %target_url, error = %format!("{err:#}"), "upstream request timed out");
                return json_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "M_UNKNOWN",
                    "Upstream server timed out",
                );
            }
            warn!(profile = %inst.profile.name, target_url = %target_url, error = %format!("{err:#}"), "upstream request failed");
            return json_error(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "Failed to connect to upstream server",
            );
        }
    };

    finish_reqwest_response(
        server_cfg,
        &rewriter,
        public,
        &parts.headers,
        kind,
        should_maybe_rewrite_body,
        upstream_resp,
    )
    .await
}

const MAX_MATRIX_UIA_REWRITE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRewriteMode {
    None,
    AuthText,
    MatrixUiaJson,
}

fn is_uia_matrix_path(path: &str) -> bool {
    path.contains("/keys/device_signing/upload")
        || path.contains("/delete_devices")
        || path.contains("/devices/")
        || path.contains("/account/")
}

fn is_json_content_type(ct: &str) -> bool {
    ct.starts_with("application/json") || ct.starts_with("application/problem+json")
}

fn is_decodable_encoding(ce: &str) -> bool {
    ce.is_empty() || ce == "identity" || ce == "gzip" || ce == "x-gzip" || ce == "deflate"
}

fn apply_buffered_body_rewrite(
    mode: BodyRewriteMode,
    rewriter: &RewriteEngine<'_>,
    content_encoding: &str,
    bytes: Vec<u8>,
) -> Vec<u8> {
    let decoded = maybe_gunzip(content_encoding, &bytes).unwrap_or(bytes);
    match mode {
        BodyRewriteMode::None => decoded,
        BodyRewriteMode::AuthText => match String::from_utf8(decoded) {
            Ok(text) => rewriter.rewrite_auth_text_body(&text).into_bytes(),
            Err(err) => err.into_bytes(),
        },
        BodyRewriteMode::MatrixUiaJson => match serde_json::from_slice::<Value>(&decoded) {
            Ok(val) => {
                let (rewritten, changed) = rewriter.rewrite_matrix_uia_json(val);
                if changed {
                    serde_json::to_vec(&rewritten).unwrap_or(decoded)
                } else {
                    decoded
                }
            }
            Err(_) => decoded,
        },
    }
}

async fn finish_hyper_response(
    server_cfg: &ServerConfig,
    rewriter: &RewriteEngine<'_>,
    public: &PublicContext,
    req_headers: &HeaderMap,
    kind: ForwardKind,
    should_maybe_rewrite_body: bool,
    upstream_resp: Response<hyper::body::Incoming>,
) -> Response<Body> {
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    let (rewrite_mode, content_encoding, max_bytes) = check_body_rewrite(
        kind,
        status,
        &resp_headers,
        rewriter.profile.discovery.auth_proxy_mode,
        should_maybe_rewrite_body,
        server_cfg.max_rewrite_body_bytes,
    );
    let do_body_rewrite = rewrite_mode != BodyRewriteMode::None;

    let out_builder = build_rewritten_response_headers(
        status,
        &resp_headers,
        rewriter,
        public,
        req_headers,
        kind,
        do_body_rewrite,
    );

    if do_body_rewrite {
        match read_bounded_incoming(upstream_resp.into_body(), max_bytes).await {
            Ok(BoundedBody::Buffered(bytes)) => {
                let out =
                    apply_buffered_body_rewrite(rewrite_mode, rewriter, &content_encoding, bytes);
                out_builder.body(Body::from(out)).unwrap_or_else(|_| {
                    json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
                })
            }
            Ok(BoundedBody::Overflowed(body)) => out_builder.body(body).unwrap_or_else(|_| {
                json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
            }),
            Err(err) => {
                warn!(error = %err, "error reading PPv2 response body");
                json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "Upstream read error")
            }
        }
    } else {
        out_builder
            .body(Body::new(upstream_resp.into_body()))
            .unwrap_or_else(|_| json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error"))
    }
}

async fn finish_reqwest_response(
    server_cfg: &ServerConfig,
    rewriter: &RewriteEngine<'_>,
    public: &PublicContext,
    req_headers: &HeaderMap,
    kind: ForwardKind,
    should_maybe_rewrite_body: bool,
    upstream_resp: reqwest::Response,
) -> Response<Body> {
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    let (rewrite_mode, content_encoding, max_bytes) = check_body_rewrite(
        kind,
        status,
        &resp_headers,
        rewriter.profile.discovery.auth_proxy_mode,
        should_maybe_rewrite_body,
        server_cfg.max_rewrite_body_bytes,
    );
    let do_body_rewrite = rewrite_mode != BodyRewriteMode::None;

    let out_builder = build_rewritten_response_headers(
        status,
        &resp_headers,
        rewriter,
        public,
        req_headers,
        kind,
        do_body_rewrite,
    );

    if do_body_rewrite {
        match read_bounded_reqwest(upstream_resp, max_bytes).await {
            Ok(BoundedBody::Buffered(bytes)) => {
                // `rewrite_client` auto-decompresses Auth responses, while `stream_client` preserves
                // upstream Content-Encoding on Matrix UIA `401`/`403` responses (decoded here via `maybe_gunzip`).
                let effective_enc = if rewrite_mode == BodyRewriteMode::MatrixUiaJson {
                    content_encoding.as_str()
                } else {
                    ""
                };
                let out = apply_buffered_body_rewrite(rewrite_mode, rewriter, effective_enc, bytes);
                out_builder.body(Body::from(out)).unwrap_or_else(|_| {
                    json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
                })
            }
            Ok(BoundedBody::Overflowed(body)) => out_builder.body(body).unwrap_or_else(|_| {
                json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error")
            }),
            Err(err) => {
                warn!(error = %err, "error reading upstream response body");
                json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "Upstream read error")
            }
        }
    } else {
        let stream = upstream_resp.bytes_stream();
        out_builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| json_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", "response error"))
    }
}

fn check_body_rewrite(
    kind: ForwardKind,
    status: StatusCode,
    resp_headers: &HeaderMap,
    auth_proxy_mode: AuthProxyMode,
    should_maybe_rewrite_body: bool,
    max_auth_bytes: usize,
) -> (BodyRewriteMode, String, usize) {
    let content_type = resp_headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let content_encoding = resp_headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let content_len = resp_headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    if should_maybe_rewrite_body
        && is_rewritable_auth_content_type(&content_type)
        && content_len.map(|n| n <= max_auth_bytes).unwrap_or(true)
    {
        return (BodyRewriteMode::AuthText, content_encoding, max_auth_bytes);
    }

    if kind == ForwardKind::Matrix
        && auth_proxy_mode == AuthProxyMode::Full
        && matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        && is_json_content_type(&content_type)
        && is_decodable_encoding(&content_encoding)
        && content_len
            .map(|n| n <= MAX_MATRIX_UIA_REWRITE_BYTES)
            .unwrap_or(true)
    {
        return (
            BodyRewriteMode::MatrixUiaJson,
            content_encoding,
            MAX_MATRIX_UIA_REWRITE_BYTES,
        );
    }

    (BodyRewriteMode::None, content_encoding, 0)
}

fn build_rewritten_response_headers(
    status: StatusCode,
    resp_headers: &HeaderMap,
    rewriter: &RewriteEngine<'_>,
    public: &PublicContext,
    req_headers: &HeaderMap,
    kind: ForwardKind,
    do_body_rewrite: bool,
) -> axum::http::response::Builder {
    let is_auth = kind == ForwardKind::Auth;
    let dynamic_resp_hop = collect_connection_headers(resp_headers);
    let mut out_builder = Response::builder().status(status);
    let mut has_acao = false;

    for (name, value) in resp_headers {
        if is_hop_by_hop_header(name) || dynamic_resp_hop.contains(name.as_str()) {
            continue;
        }
        if !public.public_is_https()
            && name
                .as_str()
                .eq_ignore_ascii_case("strict-transport-security")
        {
            continue;
        }
        if do_body_rewrite
            && (name == http::header::CONTENT_LENGTH || name == http::header::CONTENT_ENCODING)
        {
            continue;
        }

        if name == http::header::LOCATION
            && let Ok(loc) = value.to_str()
        {
            let rewritten = rewriter.rewrite_location_header(loc, is_auth);
            if let Ok(hv) = HeaderValue::from_str(&rewritten) {
                out_builder = out_builder.header(name.clone(), hv);
                continue;
            }
        }

        if name == http::header::SET_COOKIE
            && let Ok(cookie) = value.to_str()
        {
            let rewritten = rewriter.rewrite_set_cookie(cookie, is_auth);
            if let Ok(hv) = HeaderValue::from_str(&rewritten) {
                out_builder = out_builder.header(name.clone(), hv);
                continue;
            }
        }

        if (name
            .as_str()
            .eq_ignore_ascii_case("content-security-policy")
            || name
                .as_str()
                .eq_ignore_ascii_case("content-security-policy-report-only"))
            && let Ok(csp) = value.to_str()
        {
            let rewritten = rewriter.rewrite_csp_header(csp);
            if let Ok(hv) = HeaderValue::from_str(&rewritten) {
                out_builder = out_builder.header(name.clone(), hv);
                continue;
            }
        }

        if name == http::header::ACCESS_CONTROL_ALLOW_ORIGIN {
            has_acao = true;
            if let Ok(acao) = value.to_str() {
                let rewritten = rewriter.rewrite_url_str(acao, is_auth);
                if let Ok(hv) = HeaderValue::from_str(&rewritten) {
                    out_builder = out_builder.header(name.clone(), hv);
                    continue;
                }
            }
        }

        out_builder = out_builder.header(name.clone(), value.clone());
    }

    if kind == ForwardKind::Matrix && !has_acao {
        out_builder = add_matrix_cors_headers(out_builder);
    } else if kind == ForwardKind::Auth
        && !has_acao
        && let Some(origin) = req_headers.get(http::header::ORIGIN)
        && let Ok(origin_str) = origin.to_str()
        && origin_str != public.auth_origin()
        && origin_str != public.matrix_origin()
    {
        out_builder = out_builder
            .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone())
            .header(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
            .header(http::header::VARY, "Origin");
    }

    out_builder
}

enum BoundedBody {
    Buffered(Vec<u8>),
    Overflowed(Body),
}

async fn read_bounded_reqwest(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<BoundedBody> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            let prefix = Bytes::from(buf);
            let rest = resp.bytes_stream();
            let combined = futures_util::stream::iter([Ok(prefix), Ok(chunk)]).chain(rest);
            return Ok(BoundedBody::Overflowed(Body::from_stream(combined)));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(BoundedBody::Buffered(buf))
}

async fn read_bounded_incoming(
    mut incoming: hyper::body::Incoming,
    max_bytes: usize,
) -> Result<BoundedBody> {
    let mut buf = Vec::new();
    while let Some(frame_res) = incoming.frame().await {
        let frame = frame_res.context("upstream body frame error")?;
        if let Ok(chunk) = frame.into_data() {
            if buf.len().saturating_add(chunk.len()) > max_bytes {
                let prefix = Bytes::from(buf);
                let rest = incoming.into_data_stream();
                let combined = futures_util::stream::iter([Ok(prefix), Ok(chunk)]).chain(rest);
                return Ok(BoundedBody::Overflowed(Body::from_stream(combined)));
            }
            buf.extend_from_slice(&chunk);
        }
    }
    Ok(BoundedBody::Buffered(buf))
}

fn collect_connection_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for val in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() && t != "keep-alive" && t != "close" {
                    out.insert(t);
                }
            }
        }
    }
    out
}

fn is_rewritable_auth_content_type(ct: &str) -> bool {
    ct.starts_with("text/html")
        || ct.starts_with("application/json")
        || ct.starts_with("application/problem+json")
        || ct.starts_with("text/javascript")
        || ct.starts_with("application/javascript")
        || ct.starts_with("text/css")
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_upstream_stripped_forwarded_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "forwarded"
            | "x-forwarded-for"
            | "x-real-ip"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
    )
}

fn add_matrix_cors_headers(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    builder
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        )
        .header(
            http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "X-Requested-With, Content-Type, Authorization, Date, Origin, Accept",
        )
}

fn cors_preflight_response(req_headers: &HeaderMap, allow_credentials: bool) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);

    if allow_credentials {
        if let Some(origin) = req_headers.get(http::header::ORIGIN) {
            builder = builder
                .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone())
                .header(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
                .header(http::header::VARY, "Origin");
        } else {
            builder = builder.header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }
    } else {
        builder = builder.header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    }

    let req_hdrs = req_headers
        .get(http::header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("X-Requested-With, Content-Type, Authorization, Date, Origin, Accept");

    builder
        .header(
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        )
        .header(http::header::ACCESS_CONTROL_ALLOW_HEADERS, req_hdrs)
        .header(http::header::ACCESS_CONTROL_MAX_AGE, "86400")
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn json_response(status: StatusCode, value: &Value, with_matrix_cors: bool) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut builder = Response::builder()
        .status(status)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header("x-content-type-options", "nosniff");
    if with_matrix_cors {
        builder = add_matrix_cors_headers(builder);
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn json_error(status: StatusCode, errcode: &str, message: &str) -> Response<Body> {
    json_response(
        status,
        &json!({
            "errcode": errcode,
            "error": message,
        }),
        true,
    )
}
