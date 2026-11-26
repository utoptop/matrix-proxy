use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use url::Url;

pub fn default_trusted_proxies() -> Vec<String> {
    vec![
        "127.0.0.1/32".to_string(),
        "::1/128".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "fc00::/7".to_string(),
        "fe80::/10".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthRouteMode {
    #[default]
    Root,
    Prefix,
}

/// Controls how OAuth 2.0 / OIDC / MAS endpoints are rewritten and proxied:
/// - `full` (default): proxy and rewrite ALL Auth endpoints, `issuer`, cookies, CSP, and bodies (best for self-hosted/direct MAS password logins).
/// - `token_only`: keep `issuer` and browser-interactive pages (`authorization_endpoint`, `account_management_uri`, `graphql_endpoint`, `.well-known` auth)
///   on the official upstream Auth server so multi-hop third-party IdPs (Mozilla Accounts, Google, Apple, Passkey) work with zero `redirect_uri`/anti-phishing
///   issues during initial login, while STILL proxying background machine-to-machine endpoints (`token_endpoint`, `revocation_endpoint`, `registration_endpoint`,
///   `jwks_uri`) for 24/7 uninterrupted token refresh via `matrix-proxy`.
/// - `direct`: proxy only Matrix Client-Server; return all Auth metadata and `.well-known` auth fields untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProxyMode {
    #[default]
    Full,
    #[serde(alias = "token-only", alias = "hybrid")]
    TokenOnly,
    #[serde(alias = "passthrough", alias = "off")]
    Direct,
}

/// Direct MatrixRTC (MSC4143 / LiveKit JWT `mrtc`) delegation policy for `/.well-known/matrix/client`.
/// MatrixRTC is delegated directly to reachable `lk-jwt-service` URLs rather than HTTP-proxied,
/// because WebRTC SFU WebSocket/UDP media cannot be proxied through an HTTP reverse proxy and
/// advertising a proxy path would leak into federated room `m.call.member` state events.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(untagged)]
pub enum MatrixRtcDelegation {
    /// Preserve the upstream homeserver's `.well-known/matrix/client` `org.matrix.msc4143.rtc_foci` verbatim.
    #[default]
    Upstream,
    /// Delegate directly to one or more MatrixRTC / LiveKit JWT service URLs.
    Delegate(Vec<String>),
    /// Omit `org.matrix.msc4143.rtc_foci` from `/.well-known/matrix/client`.
    Disabled,
}

impl MatrixRtcDelegation {
    pub fn summary(&self) -> String {
        match self {
            Self::Upstream => "upstream".to_string(),
            Self::Disabled => "off".to_string(),
            Self::Delegate(urls) => urls.join(","),
        }
    }

    pub fn info_json(&self) -> serde_json::Value {
        match self {
            Self::Upstream => serde_json::json!("upstream"),
            Self::Disabled => serde_json::json!("off"),
            Self::Delegate(urls) => serde_json::json!(urls),
        }
    }
}

impl AuthProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::TokenOnly => "token_only",
            Self::Direct => "direct",
        }
    }
}

impl std::fmt::Display for AuthProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientIpMode {
    /// Set authoritative `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` to the verified real client IP.
    #[default]
    Replace,
    /// Append the physical peer IP onto any trusted incoming `X-Forwarded-For` chain and set `X-Real-IP`.
    Append,
    /// Do not forward client IP headers upstream.
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposeInfoMode {
    /// Only allow direct loopback / trusted-proxy clients to read `/_proxy/info`.
    #[default]
    Trusted,
    /// Allow any client to read `/_proxy/info`.
    Always,
    /// Disable `/_proxy/info` (returns 404).
    Disabled,
}

/// Standard PROXY Protocol transport version (vendor-neutral framing supported by Nginx, HAProxy,
/// Envoy, Traefik, Caddy, AWS NLB, and other L4/L7 reverse proxies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    /// Disabled — standard TCP / HTTP(S) transport.
    #[default]
    #[serde(alias = "none", alias = "disabled", alias = "false")]
    Off,
    /// PROXY Protocol v1 (human-readable text header: `PROXY TCP4/TCP6 ...`).
    #[serde(alias = "1", alias = "ppv1")]
    V1,
    /// PROXY Protocol v2 (compact binary header — recommended when supported).
    #[serde(alias = "2", alias = "ppv2")]
    V2,
}

impl ProxyProtocol {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    /// Unified global defaults inherited by every `[[proxies]]` block (any field set inside a
    /// `[[proxies]]` block overrides `[defaults]`).
    pub defaults: ProxyDefaultsConfig,
    /// Legacy single-upstream / v1.0-v1.3 default sections (fully backward compatible).
    pub upstream: UpstreamConfig,
    pub routing: RoutingConfig,
    pub discovery: DiscoveryConfig,
    /// Multi-upstream proxy profiles: each block can share `[server].listen` or bind its own port.
    #[serde(alias = "profiles")]
    pub proxies: Vec<ProxyProfileInput>,
}

/// Optional `[server.reload]` sub-table for hot reload and graceful draining.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerReloadConfig {
    pub enabled: Option<bool>,
    pub interval_secs: Option<u64>,
    pub shutdown_grace_secs: Option<u64>,
}

/// Optional `[server.tuning]` sub-table for connection pooling, socket, and abuse protection knobs.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerTuningConfig {
    pub max_rewrite_body_bytes: Option<usize>,
    pub max_concurrent_requests: Option<usize>,
    pub rate_limit_rps: Option<u64>,
    pub rate_limit_burst: Option<u64>,
    pub header_read_timeout_secs: Option<u64>,
    pub pool_max_idle_per_host: Option<usize>,
    pub pool_idle_timeout_secs: Option<u64>,
    pub tcp_keepalive_secs: Option<u64>,
    pub tcp_nodelay: Option<bool>,
    #[serde(alias = "ppv2_pool_max_entries")]
    pub proxy_protocol_pool_max_entries: Option<usize>,
    pub listen_backlog: Option<u32>,
}

/// Optional `[server.media_cache]` sub-table for edge caching of immutable Matrix media & thumbnails.
/// Uses a strictly bounded L1 hot RAM LRU (avatars/thumbnails) backed by an optional L2 SSD/disk LRU.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaCacheConfig {
    /// Enable edge media caching (default: `false` so no cache RAM/disk is allocated unless opted in).
    pub enabled: bool,
    /// Optional persistent L2 disk cache directory (e.g. `"/app/cache/media"`). Omit or leave empty for RAM-only.
    pub dir: Option<String>,
    /// Maximum L1 hot RAM cache budget in MiB (default: `32`; `0` disables L1 RAM cache).
    pub ram_max_mb: u64,
    /// Maximum single item size in KiB eligible for L1 RAM cache (default: `256` — ideal for avatars & thumbnails).
    pub ram_max_item_kb: u64,
    /// Maximum L2 persistent disk cache budget in MiB (default: `1024`; requires `dir`).
    pub disk_max_mb: u64,
    /// Maximum single cached media object size in MiB (default: `16`; larger files stream straight through).
    pub max_item_mb: u64,
    /// TTL in seconds for verified Matrix Bearer tokens (stored as SHA-256 hashes only) used to authorize
    /// cached responses for Matrix v1.11+ authenticated media endpoints (default: `180`).
    pub auth_cache_ttl_secs: u64,
}

impl Default for MediaCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: None,
            ram_max_mb: 32,
            ram_max_item_kb: 256,
            disk_max_mb: 1024,
            max_item_mb: 16,
            auth_cache_ttl_secs: 180,
        }
    }
}

impl MediaCacheConfig {
    pub fn ram_max_bytes(&self) -> usize {
        usize::try_from(self.ram_max_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
    }

    pub fn ram_max_item_bytes(&self) -> usize {
        usize::try_from(self.ram_max_item_kb.saturating_mul(1024)).unwrap_or(usize::MAX)
    }

    pub fn disk_max_bytes(&self) -> u64 {
        self.disk_max_mb.saturating_mul(1024 * 1024)
    }

    pub fn max_item_bytes(&self) -> usize {
        usize::try_from(self.max_item_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
    }
}

/// Validated avatar thumbnail dimension preset (`"{width}x{height}:{crop|scale}"`, e.g. `"96x96:crop"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct AvatarThumbSpec {
    pub width: u32,
    pub height: u32,
    pub method: String,
}

impl AvatarThumbSpec {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let (dims, method_raw) = match trimmed.split_once(':') {
            Some((d, m)) => (d.trim(), m.trim()),
            None => (trimmed, "crop"),
        };
        let (w_str, h_str) = dims
            .split_once('x')
            .or_else(|| dims.split_once('X'))
            .ok_or_else(|| {
                anyhow!(
                    "invalid avatar thumbnail spec '{raw}': expected 'WxH:crop' or 'WxH:scale' (e.g. '96x96:crop')"
                )
            })?;
        let width: u32 = w_str
            .trim()
            .parse()
            .with_context(|| format!("invalid width in avatar thumbnail spec '{raw}'"))?;
        let height: u32 = h_str
            .trim()
            .parse()
            .with_context(|| format!("invalid height in avatar thumbnail spec '{raw}'"))?;
        if !(16..=1024).contains(&width) || !(16..=1024).contains(&height) {
            bail!("avatar thumbnail dimensions in '{raw}' must be between 16 and 1024");
        }
        let method = method_raw.to_ascii_lowercase();
        if method != "crop" && method != "scale" {
            bail!("invalid thumbnail method '{method_raw}' in '{raw}': expected 'crop' or 'scale'");
        }
        Ok(Self {
            width,
            height,
            method,
        })
    }

    pub fn label(&self) -> String {
        format!("{}x{}:{}", self.width, self.height, self.method)
    }
}

/// Resolved per-profile media caching & proactive background preloading settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaProfileConfig {
    /// Allow this profile to read/write the shared edge `[server.media_cache]` (default: `true`).
    pub cache_enabled: bool,
    /// Enable proactive background media preloading from `/sync`, Sliding Sync, `/messages`, `/state`, `/members`, and `/profile`.
    pub preload_enabled: bool,
    /// Maximum concurrent background preload fetches for this profile (1..=16, default: `4`).
    pub preload_concurrency: usize,
    /// Maximum single object size in MiB fetched by the background preloader (1..=64, default: `4`).
    pub preload_max_item_mb: u64,
    /// When a `/thumbnail/{server}/{id}` is requested, proactively warm `/download/{server}/{id}` in background.
    pub preload_on_thumbnail: bool,
    /// Configured avatar thumbnail dimensions to pre-warm for discovered avatars (also adapts to client-observed square avatar sizes).
    pub preload_avatar_sizes: Vec<AvatarThumbSpec>,
}

impl Default for MediaProfileConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            preload_enabled: false,
            preload_concurrency: 4,
            preload_max_item_mb: 4,
            preload_on_thumbnail: true,
            preload_avatar_sizes: vec![AvatarThumbSpec {
                width: 96,
                height: 96,
                method: "crop".to_string(),
            }],
        }
    }
}

impl MediaProfileConfig {
    pub fn preload_max_item_bytes(&self) -> usize {
        usize::try_from(self.preload_max_item_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
    }
}

/// Unified `[defaults]` section holding all global proxy-node defaults.
/// Every key here has the exact same name inside `[[proxies]]`; per-profile values always win.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyDefaultsConfig {
    /// Global outbound HTTP / HTTPS / SOCKS5 / SOCKS5h proxy (or `"direct"`).
    pub outbound_proxy: Option<String>,
    /// Global bypass list (hosts, `.suffix` domains, IPs, CIDRs such as `100.64.0.0/10`).
    pub outbound_no_proxy: Option<Vec<String>>,
    /// Standard HTTP forwarded IP header mode (`"replace"` | `"append"` | `"off"`).
    pub client_ip_mode: Option<ClientIpMode>,
    /// Default outbound PROXY Protocol (`"off"` | `"v1"` | `"v2"`).
    #[serde(alias = "proxy_protocol")]
    pub upstream_proxy_protocol: Option<ProxyProtocol>,
    #[serde(alias = "matrix_proxy_protocol")]
    pub upstream_matrix_proxy_protocol: Option<ProxyProtocol>,
    #[serde(alias = "auth_proxy_protocol")]
    pub upstream_auth_proxy_protocol: Option<ProxyProtocol>,
    #[serde(alias = "rewrite_origins")]
    pub upstream_rewrite_origins: Option<Vec<String>>,
    pub connect_timeout_secs: Option<u64>,
    pub request_timeout_secs: Option<u64>,
    pub danger_accept_invalid_certs: Option<bool>,

    pub auth_mode: Option<AuthRouteMode>,
    pub auth_prefix: Option<String>,
    pub proxy_prefix: Option<String>,
    pub matrix_extra_prefixes: Option<Vec<String>>,
    pub auth_matrix_prefixes: Option<Vec<String>>,

    pub auth_proxy_mode: Option<AuthProxyMode>,
    /// Delegated MatrixRTC (`mrtc` / LiveKit JWT) service URL written directly to `/.well-known/matrix/client`
    /// (`"https://..."` | `"upstream"` / `""` | `"off"`).
    #[serde(
        alias = "mrtc_url",
        alias = "rtc_foci_url",
        alias = "livekit_service_url",
        alias = "upstream_matrix_rtc_url",
        alias = "rtc_url"
    )]
    pub matrix_rtc_url: Option<String>,
    /// Optional list of delegated MatrixRTC (`mrtc` / LiveKit JWT) service URLs (takes precedence over `matrix_rtc_url`).
    #[serde(alias = "mrtc_urls", alias = "rtc_foci_urls")]
    pub matrix_rtc_urls: Option<Vec<String>>,
    pub rewrite_issuer: Option<bool>,
    pub force_msc2965_well_known: Option<bool>,
    pub rewrite_auth_body: Option<bool>,
    pub merge_upstream_well_known: Option<bool>,
    pub identity_server_url: Option<String>,
    pub cache_ttl_secs: Option<u64>,
    /// Allow profiles to use the shared `[server.media_cache]` (default: `true` when media cache is enabled).
    pub media_cache: Option<bool>,
    /// Enable proactive background preloading of avatars & unencrypted media discovered in `/sync` and room timelines.
    pub media_preload: Option<bool>,
    /// Maximum concurrent background preload fetches per profile (default: `4`).
    pub media_preload_concurrency: Option<usize>,
    /// Maximum object size in MiB fetched by the background preloader (default: `4`).
    pub media_preload_max_item_mb: Option<u64>,
    /// Proactively fetch `/download/{server}/{id}` in background when a `/thumbnail/{server}/{id}` is requested (default: `true`).
    pub media_preload_on_thumbnail: Option<bool>,
    /// Avatar thumbnail presets (`"WxH:crop"` / `"WxH:scale"`) to pre-warm for discovered avatars (default: `["96x96:crop"]`).
    pub media_preload_avatar_sizes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: String,
    /// External/Tailscale proxy address exposed to Matrix clients (e.g. `https://proxy.example.com` or `http://100.64.0.10:8080`).
    #[serde(alias = "public_url")]
    pub matrix_proxy_public_url: Option<String>,
    /// Optional separate external Auth/OIDC proxy address (dual-URL mode).
    #[serde(alias = "public_auth_url")]
    pub matrix_proxy_public_auth_url: Option<String>,
    #[serde(alias = "tls_cert")]
    pub tls_cert_path: Option<String>,
    #[serde(alias = "tls_key")]
    pub tls_key_path: Option<String>,
    /// Inbound PROXY Protocol framing on accepted TCP connections (`"off"` | `"v1"` | `"v2"`).
    pub inbound_proxy_protocol: ProxyProtocol,
    /// Deprecated v1.1 alias for `inbound_proxy_protocol = "v2"`.
    #[serde(skip_serializing)]
    pub accept_proxy_v2: Option<bool>,
    /// Legacy v1.3 location for global outbound proxy (prefer `[defaults].outbound_proxy`).
    pub outbound_proxy: Option<String>,
    /// Legacy v1.3 location for global no-proxy list (prefer `[defaults].outbound_no_proxy`).
    pub outbound_no_proxy: Vec<String>,
    pub trust_forwarded_headers: bool,
    pub trusted_proxies: Vec<String>,
    pub expose_info: ExposeInfoMode,
    /// Clean structured hot-reload & graceful drain settings (`[server.reload]`).
    pub reload: Option<ServerReloadConfig>,
    /// Clean structured performance & abuse protection settings (`[server.tuning]`).
    pub tuning: Option<ServerTuningConfig>,
    /// Optional edge media cache settings (`[server.media_cache]`).
    pub media_cache: MediaCacheConfig,
    pub max_rewrite_body_bytes: usize,
    pub max_concurrent_requests: usize,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u64,
    pub header_read_timeout_secs: u64,
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub tcp_keepalive_secs: u64,
    pub tcp_nodelay: bool,
    #[serde(alias = "ppv2_pool_max_entries")]
    pub proxy_protocol_pool_max_entries: usize,
    pub listen_backlog: u32,
    /// Enable automatic config file & TLS certificate hot reload (in addition to SIGHUP / POST /_proxy/reload).
    pub hot_reload: bool,
    /// File polling interval in seconds for automatic hot reload (minimum 1s; default 2s).
    pub hot_reload_interval_secs: u64,
    /// Maximum seconds to wait for in-flight HTTP/2 & WebSocket connections to drain on SIGTERM/SIGINT.
    pub shutdown_grace_secs: u64,
}

impl ServerConfig {
    pub fn effective_inbound_proxy_protocol(&self) -> ProxyProtocol {
        if self.inbound_proxy_protocol.is_enabled() {
            self.inbound_proxy_protocol
        } else if self.accept_proxy_v2 == Some(true) {
            ProxyProtocol::V2
        } else {
            ProxyProtocol::Off
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            matrix_proxy_public_url: None,
            matrix_proxy_public_auth_url: None,
            tls_cert_path: None,
            tls_key_path: None,
            inbound_proxy_protocol: ProxyProtocol::Off,
            accept_proxy_v2: None,
            outbound_proxy: None,
            outbound_no_proxy: Vec::new(),
            trust_forwarded_headers: true,
            trusted_proxies: default_trusted_proxies(),
            expose_info: ExposeInfoMode::Trusted,
            reload: None,
            tuning: None,
            media_cache: MediaCacheConfig::default(),
            max_rewrite_body_bytes: 4 * 1024 * 1024,
            max_concurrent_requests: 10_000,
            rate_limit_rps: 0,
            rate_limit_burst: 200,
            header_read_timeout_secs: 15,
            pool_max_idle_per_host: 128,
            pool_idle_timeout_secs: 90,
            tcp_keepalive_secs: 30,
            tcp_nodelay: true,
            proxy_protocol_pool_max_entries: 4096,
            listen_backlog: 4096,
            hot_reload: true,
            hot_reload_interval_secs: 2,
            shutdown_grace_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamConfig {
    #[serde(alias = "matrix_url")]
    pub upstream_matrix_server_url: Option<String>,
    #[serde(alias = "auth_url")]
    pub upstream_matrix_auth_url: Option<String>,
    #[serde(alias = "server_name")]
    pub upstream_matrix_server_name: Option<String>,
    /// Deprecated v1.0-v1.4 location; folded into `discovery.matrix_rtc_url` as direct MatrixRTC delegation.
    #[serde(
        alias = "rtc_url",
        alias = "matrix_rtc_url",
        alias = "mrtc_url",
        skip_serializing
    )]
    pub upstream_matrix_rtc_url: Option<String>,
    #[serde(alias = "matrix_host_header")]
    pub upstream_matrix_host_header: Option<String>,
    #[serde(alias = "auth_host_header")]
    pub upstream_auth_host_header: Option<String>,
    #[serde(alias = "rewrite_origins")]
    pub upstream_rewrite_origins: Vec<String>,
    pub outbound_proxy: Option<String>,
    pub outbound_no_proxy: Vec<String>,
    /// Internal marker set when `outbound_proxy` explicitly specifies `"direct"` / `"none"` / `"off"`.
    #[serde(skip)]
    pub outbound_proxy_direct: bool,
    pub client_ip_mode: ClientIpMode,
    /// Outbound PROXY Protocol default for this upstream (`"off"` | `"v1"` | `"v2"`).
    #[serde(alias = "proxy_protocol")]
    pub upstream_proxy_protocol: ProxyProtocol,
    /// Optional per-service outbound PROXY Protocol override for the Matrix homeserver.
    #[serde(alias = "matrix_proxy_protocol")]
    pub upstream_matrix_proxy_protocol: Option<ProxyProtocol>,
    /// Optional per-service outbound PROXY Protocol override for the Matrix auth server (MAS/OIDC).
    #[serde(alias = "auth_proxy_protocol")]
    pub upstream_auth_proxy_protocol: Option<ProxyProtocol>,
    /// Deprecated v1.1 aliases for `upstream_*_proxy_protocol = "v2"`.
    #[serde(skip_serializing)]
    pub send_proxy_v2: Option<bool>,
    #[serde(skip_serializing)]
    pub matrix_send_proxy_v2: Option<bool>,
    #[serde(skip_serializing)]
    pub auth_send_proxy_v2: Option<bool>,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub danger_accept_invalid_certs: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            upstream_matrix_server_url: None,
            upstream_matrix_auth_url: None,
            upstream_matrix_server_name: None,
            upstream_matrix_rtc_url: None,
            upstream_matrix_host_header: None,
            upstream_auth_host_header: None,
            upstream_rewrite_origins: Vec::new(),
            outbound_proxy: None,
            outbound_no_proxy: Vec::new(),
            outbound_proxy_direct: false,
            client_ip_mode: ClientIpMode::Replace,
            upstream_proxy_protocol: ProxyProtocol::Off,
            upstream_matrix_proxy_protocol: None,
            upstream_auth_proxy_protocol: None,
            send_proxy_v2: None,
            matrix_send_proxy_v2: None,
            auth_send_proxy_v2: None,
            connect_timeout_secs: 15,
            request_timeout_secs: 0,
            danger_accept_invalid_certs: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub auth_mode: AuthRouteMode,
    pub auth_prefix: String,
    pub proxy_prefix: String,
    pub matrix_extra_prefixes: Vec<String>,
    pub auth_matrix_prefixes: Vec<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            auth_mode: AuthRouteMode::Root,
            auth_prefix: "/_auth".to_string(),
            proxy_prefix: "/_proxy".to_string(),
            matrix_extra_prefixes: Vec::new(),
            auth_matrix_prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub auth_proxy_mode: AuthProxyMode,
    /// Delegated MatrixRTC (`mrtc` / LiveKit JWT) service URL advertised directly in `/.well-known/matrix/client`
    /// (`"https://..."` | `"upstream"` / `""` | `"off"`).
    #[serde(
        alias = "mrtc_url",
        alias = "rtc_foci_url",
        alias = "livekit_service_url"
    )]
    pub matrix_rtc_url: Option<String>,
    /// Optional list of delegated MatrixRTC (`mrtc` / LiveKit JWT) service URLs.
    #[serde(alias = "mrtc_urls", alias = "rtc_foci_urls")]
    pub matrix_rtc_urls: Vec<String>,
    pub rewrite_issuer: bool,
    pub force_msc2965_well_known: bool,
    pub rewrite_auth_body: bool,
    pub merge_upstream_well_known: bool,
    pub identity_server_url: Option<String>,
    pub cache_ttl_secs: u64,
    pub media_cache: bool,
    pub media_preload: bool,
    pub media_preload_concurrency: usize,
    pub media_preload_max_item_mb: u64,
    pub media_preload_on_thumbnail: bool,
    pub media_preload_avatar_sizes: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            auth_proxy_mode: AuthProxyMode::Full,
            matrix_rtc_url: None,
            matrix_rtc_urls: Vec::new(),
            rewrite_issuer: true,
            force_msc2965_well_known: false,
            rewrite_auth_body: true,
            merge_upstream_well_known: true,
            identity_server_url: None,
            cache_ttl_secs: 60,
            media_cache: true,
            media_preload: false,
            media_preload_concurrency: 4,
            media_preload_max_item_mb: 4,
            media_preload_on_thumbnail: true,
            media_preload_avatar_sizes: vec!["96x96:crop".to_string()],
        }
    }
}

/// One upstream Matrix service block in `[[proxies]]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyProfileInput {
    pub name: Option<String>,
    /// Optional dedicated listen address (e.g. `"0.0.0.0:8081"`). Omit to share `server.listen`.
    pub listen: Option<String>,
    /// If true on a shared listener, handles unmatched `Host` headers as fallback.
    pub default: bool,
    /// If true on a single-profile dedicated listener, rejects requests whose Host does not match `matrix_proxy_public_url`.
    pub strict_host_match: bool,

    /// Proxy entry URL exposed to Matrix clients (supports `https://domain` or `http://ip:port`, e.g. Tailscale IP).
    /// On a shared port, the host in this URL automatically drives virtual-host routing.
    #[serde(alias = "public_url")]
    pub matrix_proxy_public_url: Option<String>,
    /// Optional separate proxy URL for Auth/OIDC in dual-URL deployments.
    #[serde(alias = "public_auth_url")]
    pub matrix_proxy_public_auth_url: Option<String>,
    #[serde(alias = "tls_cert")]
    pub tls_cert_path: Option<String>,
    #[serde(alias = "tls_key")]
    pub tls_key_path: Option<String>,
    pub inbound_proxy_protocol: Option<ProxyProtocol>,
    #[serde(skip_serializing)]
    pub accept_proxy_v2: Option<bool>,

    #[serde(alias = "matrix_url")]
    pub upstream_matrix_server_url: Option<String>,
    #[serde(alias = "auth_url")]
    pub upstream_matrix_auth_url: Option<String>,
    #[serde(alias = "server_name")]
    pub upstream_matrix_server_name: Option<String>,
    #[serde(alias = "matrix_host_header")]
    pub upstream_matrix_host_header: Option<String>,
    #[serde(alias = "auth_host_header")]
    pub upstream_auth_host_header: Option<String>,
    #[serde(alias = "rewrite_origins")]
    pub upstream_rewrite_origins: Option<Vec<String>>,
    /// Optional per-profile outbound proxy override (`http://`, `https://`, `socks5://`, `socks5h://`, or `"direct"` to bypass global `[defaults].outbound_proxy`).
    pub outbound_proxy: Option<String>,
    /// Optional per-profile `outbound_no_proxy` override (inherits `[defaults].outbound_no_proxy` when omitted).
    pub outbound_no_proxy: Option<Vec<String>>,
    pub client_ip_mode: Option<ClientIpMode>,
    #[serde(alias = "proxy_protocol")]
    pub upstream_proxy_protocol: Option<ProxyProtocol>,
    #[serde(alias = "matrix_proxy_protocol")]
    pub upstream_matrix_proxy_protocol: Option<ProxyProtocol>,
    #[serde(alias = "auth_proxy_protocol")]
    pub upstream_auth_proxy_protocol: Option<ProxyProtocol>,
    #[serde(skip_serializing)]
    pub send_proxy_v2: Option<bool>,
    #[serde(skip_serializing)]
    pub matrix_send_proxy_v2: Option<bool>,
    #[serde(skip_serializing)]
    pub auth_send_proxy_v2: Option<bool>,
    pub connect_timeout_secs: Option<u64>,
    pub request_timeout_secs: Option<u64>,
    pub danger_accept_invalid_certs: Option<bool>,

    pub auth_mode: Option<AuthRouteMode>,
    pub auth_prefix: Option<String>,
    pub proxy_prefix: Option<String>,
    pub matrix_extra_prefixes: Option<Vec<String>>,
    pub auth_matrix_prefixes: Option<Vec<String>>,

    pub auth_proxy_mode: Option<AuthProxyMode>,
    /// Optional per-node MatrixRTC (`mrtc` / LiveKit JWT) delegation URL written directly into `/.well-known/matrix/client`
    /// (`"https://..."` | `"upstream"` / `""` | `"off"`). Overrides `[defaults].matrix_rtc_url`.
    #[serde(
        alias = "mrtc_url",
        alias = "rtc_foci_url",
        alias = "livekit_service_url",
        alias = "upstream_matrix_rtc_url",
        alias = "rtc_url"
    )]
    pub matrix_rtc_url: Option<String>,
    /// Optional per-node list of delegated MatrixRTC (`mrtc` / LiveKit JWT) URLs.
    #[serde(alias = "mrtc_urls", alias = "rtc_foci_urls")]
    pub matrix_rtc_urls: Option<Vec<String>>,
    pub rewrite_issuer: Option<bool>,
    pub force_msc2965_well_known: Option<bool>,
    pub rewrite_auth_body: Option<bool>,
    pub merge_upstream_well_known: Option<bool>,
    pub identity_server_url: Option<String>,
    pub cache_ttl_secs: Option<u64>,
    /// Allow profiles to use the shared `[server.media_cache]` (default: `true` when media cache is enabled).
    pub media_cache: Option<bool>,
    /// Enable proactive background preloading of avatars & unencrypted media discovered in `/sync` and room timelines.
    pub media_preload: Option<bool>,
    /// Maximum concurrent background preload fetches per profile (default: `4`).
    pub media_preload_concurrency: Option<usize>,
    /// Maximum object size in MiB fetched by the background preloader (default: `4`).
    pub media_preload_max_item_mb: Option<u64>,
    /// Proactively fetch `/download/{server}/{id}` in background when a `/thumbnail/{server}/{id}` is requested (default: `true`).
    pub media_preload_on_thumbnail: Option<bool>,
    /// Avatar thumbnail presets (`"WxH:crop"` / `"WxH:scale"`) to pre-warm for discovered avatars (default: `["96x96:crop"]`).
    pub media_preload_avatar_sizes: Option<Vec<String>>,
}

/// Normalized, validated, self-contained runtime configuration for a single upstream proxy profile.
#[derive(Debug, Clone)]
pub struct ProxyProfile {
    pub name: String,
    pub listen: SocketAddr,
    /// Routing hosts automatically derived from `matrix_proxy_public_url` and `matrix_proxy_public_auth_url`.
    pub route_hosts: Vec<String>,
    pub is_default: bool,
    pub strict_host_match: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub inbound_proxy_protocol: ProxyProtocol,

    pub matrix_proxy_public_url: Option<Url>,
    pub matrix_proxy_public_auth_url: Option<Url>,

    pub upstream: UpstreamConfig,
    pub routing: RoutingConfig,
    pub discovery: DiscoveryConfig,
    /// Resolved direct MatrixRTC delegation policy advertised in `/.well-known/matrix/client`.
    pub matrix_rtc: MatrixRtcDelegation,
    /// Resolved edge media caching & proactive preloading policy for this profile.
    pub media: MediaProfileConfig,
    pub parsed_rewrite_origins: Vec<String>,
}

impl ProxyProfile {
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && self
                .tls_key_path
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    pub fn matrix_proxy_protocol(&self) -> ProxyProtocol {
        self.upstream
            .upstream_matrix_proxy_protocol
            .unwrap_or(self.upstream.upstream_proxy_protocol)
    }

    pub fn auth_proxy_protocol(&self) -> ProxyProtocol {
        self.upstream
            .upstream_auth_proxy_protocol
            .unwrap_or(self.upstream.upstream_proxy_protocol)
    }

    pub fn uses_outbound_proxy_protocol(&self) -> bool {
        self.matrix_proxy_protocol().is_enabled() || self.auth_proxy_protocol().is_enabled()
    }
}

/// Profiles grouped onto one physical listening socket (`SocketAddr`).
#[derive(Debug, Clone)]
pub struct ListenerPlan {
    pub listen: SocketAddr,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub inbound_proxy_protocol: ProxyProtocol,
    pub proxy_prefix: String,
    pub profiles: Vec<ProxyProfile>,
}

impl ListenerPlan {
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && self
                .tls_key_path
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub server: ServerConfig,
    pub trusted_proxies: Vec<IpNet>,
    pub listeners: Vec<ListenerPlan>,
}

impl RuntimeConfig {
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let canonical = canonical_ip(ip);
        self.trusted_proxies
            .iter()
            .any(|net| net.contains(&canonical))
    }

    /// Collects all unique configured TLS certificate/key file paths so hot-reload watches cert renewals too.
    pub fn tls_watched_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for plan in &self.listeners {
            for p in [&plan.tls_cert_path, &plan.tls_key_path]
                .into_iter()
                .flatten()
            {
                let trimmed = p.trim();
                if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
                    out.push(PathBuf::from(trimmed));
                }
            }
        }
        out
    }
}

impl Config {
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut cfg = if let Some(path) = config_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read config file {}", path.display()))?;
            toml::from_str::<Config>(&content)
                .with_context(|| format!("failed to parse TOML config {}", path.display()))?
        } else {
            Config::default()
        };

        cfg.apply_structured_sections();
        cfg.apply_env_overrides()?;
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(content).context("failed to parse TOML config")?;
        cfg.apply_structured_sections();
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    /// Folds the clean v1.4 structured sections (`[server.reload]`, `[server.tuning]`, `[defaults]`)
    /// into normalized runtime fields while preserving 100% compatibility with legacy flat keys.
    fn apply_structured_sections(&mut self) {
        if let Some(reload) = self.server.reload.take() {
            if let Some(v) = reload.enabled {
                self.server.hot_reload = v;
            }
            if let Some(v) = reload.interval_secs {
                self.server.hot_reload_interval_secs = v;
            }
            if let Some(v) = reload.shutdown_grace_secs {
                self.server.shutdown_grace_secs = v;
            }
        }
        if let Some(tuning) = self.server.tuning.take() {
            if let Some(v) = tuning.max_rewrite_body_bytes {
                self.server.max_rewrite_body_bytes = v;
            }
            if let Some(v) = tuning.max_concurrent_requests {
                self.server.max_concurrent_requests = v;
            }
            if let Some(v) = tuning.rate_limit_rps {
                self.server.rate_limit_rps = v;
            }
            if let Some(v) = tuning.rate_limit_burst {
                self.server.rate_limit_burst = v;
            }
            if let Some(v) = tuning.header_read_timeout_secs {
                self.server.header_read_timeout_secs = v;
            }
            if let Some(v) = tuning.pool_max_idle_per_host {
                self.server.pool_max_idle_per_host = v;
            }
            if let Some(v) = tuning.pool_idle_timeout_secs {
                self.server.pool_idle_timeout_secs = v;
            }
            if let Some(v) = tuning.tcp_keepalive_secs {
                self.server.tcp_keepalive_secs = v;
            }
            if let Some(v) = tuning.tcp_nodelay {
                self.server.tcp_nodelay = v;
            }
            if let Some(v) = tuning.proxy_protocol_pool_max_entries {
                self.server.proxy_protocol_pool_max_entries = v;
            }
            if let Some(v) = tuning.listen_backlog {
                self.server.listen_backlog = v;
            }
        }

        // Fold `[defaults]` over legacy `[upstream]`/`[routing]`/`[discovery]`/`[server].outbound_*`
        // (while individual `[[proxies]]` blocks still always take highest precedence!).
        let d = std::mem::take(&mut self.defaults);
        if let Some(v) = d.outbound_proxy {
            self.server.outbound_proxy = Some(v);
            self.upstream.outbound_proxy = None;
        }
        if let Some(v) = d.outbound_no_proxy {
            self.server.outbound_no_proxy = v;
            self.upstream.outbound_no_proxy.clear();
        }
        if let Some(v) = d.client_ip_mode {
            self.upstream.client_ip_mode = v;
        }
        if let Some(v) = d.upstream_proxy_protocol {
            self.upstream.upstream_proxy_protocol = v;
        }
        if let Some(v) = d.upstream_matrix_proxy_protocol {
            self.upstream.upstream_matrix_proxy_protocol = Some(v);
        }
        if let Some(v) = d.upstream_auth_proxy_protocol {
            self.upstream.upstream_auth_proxy_protocol = Some(v);
        }
        if let Some(v) = d.upstream_rewrite_origins {
            self.upstream.upstream_rewrite_origins = v;
        }
        if let Some(v) = d.connect_timeout_secs {
            self.upstream.connect_timeout_secs = v;
        }
        if let Some(v) = d.request_timeout_secs {
            self.upstream.request_timeout_secs = v;
        }
        if let Some(v) = d.danger_accept_invalid_certs {
            self.upstream.danger_accept_invalid_certs = v;
        }
        if let Some(v) = d.auth_mode {
            self.routing.auth_mode = v;
        }
        if let Some(v) = d.auth_prefix {
            self.routing.auth_prefix = v;
        }
        if let Some(v) = d.proxy_prefix {
            self.routing.proxy_prefix = v;
        }
        if let Some(v) = d.matrix_extra_prefixes {
            self.routing.matrix_extra_prefixes = v;
        }
        if let Some(v) = d.auth_matrix_prefixes {
            self.routing.auth_matrix_prefixes = v;
        }
        if let Some(v) = d.auth_proxy_mode {
            self.discovery.auth_proxy_mode = v;
        }
        if let Some(v) = d.matrix_rtc_url {
            self.discovery.matrix_rtc_url = Some(v);
        }
        if let Some(v) = d.matrix_rtc_urls {
            self.discovery.matrix_rtc_urls = v;
        }
        if let Some(v) = d.rewrite_issuer {
            self.discovery.rewrite_issuer = v;
        }
        if let Some(v) = d.force_msc2965_well_known {
            self.discovery.force_msc2965_well_known = v;
        }
        if let Some(v) = d.rewrite_auth_body {
            self.discovery.rewrite_auth_body = v;
        }
        if let Some(v) = d.merge_upstream_well_known {
            self.discovery.merge_upstream_well_known = v;
        }
        if let Some(v) = d.identity_server_url {
            self.discovery.identity_server_url = Some(v);
        }
        if let Some(v) = d.cache_ttl_secs {
            self.discovery.cache_ttl_secs = v;
        }
        if let Some(v) = d.media_cache {
            self.discovery.media_cache = v;
        }
        if let Some(v) = d.media_preload {
            self.discovery.media_preload = v;
        }
        if let Some(v) = d.media_preload_concurrency {
            self.discovery.media_preload_concurrency = v;
        }
        if let Some(v) = d.media_preload_max_item_mb {
            self.discovery.media_preload_max_item_mb = v;
        }
        if let Some(v) = d.media_preload_on_thumbnail {
            self.discovery.media_preload_on_thumbnail = v;
        }
        if let Some(v) = d.media_preload_avatar_sizes {
            self.discovery.media_preload_avatar_sizes = v;
        }
    }

    pub fn into_runtime(mut self) -> Result<RuntimeConfig> {
        self.apply_structured_sections();
        self.normalize_and_validate()?;
        let trusted_proxies = parse_trusted_proxies(&self.server.trusted_proxies)?;
        let profiles = self.build_profiles()?;
        let listeners = group_into_listeners(profiles)?;
        Ok(RuntimeConfig {
            server: self.server,
            trusted_proxies,
            listeners,
        })
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Some(v) =
            env_non_empty("LISTEN_ADDR").or_else(|| env_non_empty("MATRIX_PROXY_LISTEN"))
        {
            self.server.listen = v;
        }
        if let Some(v) =
            env_non_empty("MATRIX_PROXY_PUBLIC_URL").or_else(|| env_non_empty("PUBLIC_URL"))
        {
            self.server.matrix_proxy_public_url = Some(v);
        }
        if let Some(v) = env_non_empty("MATRIX_PROXY_PUBLIC_AUTH_URL")
            .or_else(|| env_non_empty("PUBLIC_AUTH_URL"))
        {
            self.server.matrix_proxy_public_auth_url = Some(v);
        }
        if let Some(v) = env_non_empty("TLS_CERT_PATH") {
            self.server.tls_cert_path = Some(v);
        }
        if let Some(v) = env_non_empty("TLS_KEY_PATH") {
            self.server.tls_key_path = Some(v);
        }
        if let Some(v) = env_non_empty("INBOUND_PROXY_PROTOCOL") {
            self.server.inbound_proxy_protocol = parse_proxy_protocol(&v)?;
        } else if let Some(v) = env_bool("ACCEPT_PROXY_V2")? {
            self.server.inbound_proxy_protocol = if v {
                ProxyProtocol::V2
            } else {
                ProxyProtocol::Off
            };
        }
        if let Some(v) = env_non_empty("OUTBOUND_PROXY") {
            self.server.outbound_proxy = Some(v);
        }
        if let Some(v) = env_non_empty("OUTBOUND_NO_PROXY") {
            self.server.outbound_no_proxy = split_csv(&v);
        }
        if let Some(v) = env_bool("TRUST_FORWARDED_HEADERS")? {
            self.server.trust_forwarded_headers = v;
        }
        if let Some(v) = env_non_empty("TRUSTED_PROXIES") {
            self.server.trusted_proxies = split_csv(&v);
        }
        if let Some(v) = env_non_empty("EXPOSE_INFO") {
            self.server.expose_info = parse_expose_info(&v)?;
        }
        if let Some(v) = env_parse::<usize>("MAX_REWRITE_BODY_BYTES")? {
            self.server.max_rewrite_body_bytes = v;
        }
        if let Some(v) = env_parse::<usize>("MAX_CONCURRENT_REQUESTS")? {
            self.server.max_concurrent_requests = v;
        }
        if let Some(v) = env_parse::<u64>("RATE_LIMIT_RPS")? {
            self.server.rate_limit_rps = v;
        }
        if let Some(v) = env_parse::<u64>("RATE_LIMIT_BURST")? {
            self.server.rate_limit_burst = v;
        }
        if let Some(v) = env_parse::<u64>("HEADER_READ_TIMEOUT_SECS")? {
            self.server.header_read_timeout_secs = v;
        }
        if let Some(v) = env_parse::<usize>("POOL_MAX_IDLE_PER_HOST")? {
            self.server.pool_max_idle_per_host = v;
        }
        if let Some(v) = env_parse::<u64>("POOL_IDLE_TIMEOUT_SECS")? {
            self.server.pool_idle_timeout_secs = v;
        }
        if let Some(v) = env_parse::<u64>("TCP_KEEPALIVE_SECS")? {
            self.server.tcp_keepalive_secs = v;
        }
        if let Some(v) = env_bool("TCP_NODELAY")? {
            self.server.tcp_nodelay = v;
        }
        if let Some(v) =
            env_parse::<usize>("PROXY_PROTOCOL_POOL_MAX_ENTRIES")?
                .or(env_parse::<usize>("PPV2_POOL_MAX_ENTRIES")?)
        {
            self.server.proxy_protocol_pool_max_entries = v;
        }
        if let Some(v) = env_parse::<u32>("LISTEN_BACKLOG")? {
            self.server.listen_backlog = v;
        }
        if let Some(v) = env_bool("HOT_RELOAD")? {
            self.server.hot_reload = v;
        }
        if let Some(v) = env_parse::<u64>("HOT_RELOAD_INTERVAL_SECS")? {
            self.server.hot_reload_interval_secs = v;
        }
        if let Some(v) = env_parse::<u64>("SHUTDOWN_GRACE_SECS")? {
            self.server.shutdown_grace_secs = v;
        }
        if let Some(v) = env_bool("MEDIA_CACHE_ENABLED")? {
            self.server.media_cache.enabled = v;
        }
        if let Some(v) = env_non_empty("MEDIA_CACHE_DIR") {
            self.server.media_cache.dir = Some(v);
        }
        if let Some(v) = env_parse::<u64>("MEDIA_CACHE_RAM_MAX_MB")? {
            self.server.media_cache.ram_max_mb = v;
        }
        if let Some(v) = env_parse::<u64>("MEDIA_CACHE_RAM_MAX_ITEM_KB")? {
            self.server.media_cache.ram_max_item_kb = v;
        }
        if let Some(v) = env_parse::<u64>("MEDIA_CACHE_DISK_MAX_MB")? {
            self.server.media_cache.disk_max_mb = v;
        }
        if let Some(v) = env_parse::<u64>("MEDIA_CACHE_MAX_ITEM_MB")? {
            self.server.media_cache.max_item_mb = v;
        }
        if let Some(v) = env_parse::<u64>("MEDIA_CACHE_AUTH_TTL_SECS")? {
            self.server.media_cache.auth_cache_ttl_secs = v;
        }

        if let Some(v) =
            env_non_empty("UPSTREAM_MATRIX_SERVER_URL").or_else(|| env_non_empty("MATRIX_UPSTREAM"))
        {
            self.upstream.upstream_matrix_server_url = Some(v);
        }
        if let Some(v) =
            env_non_empty("UPSTREAM_MATRIX_AUTH_URL").or_else(|| env_non_empty("AUTH_UPSTREAM"))
        {
            self.upstream.upstream_matrix_auth_url = Some(v);
        }
        if let Some(v) = env_non_empty("UPSTREAM_MATRIX_SERVER_NAME")
            .or_else(|| env_non_empty("MATRIX_SERVER_NAME"))
        {
            self.upstream.upstream_matrix_server_name = Some(v);
        }
        if let Some(v) = env_non_empty("MATRIX_RTC_URL")
            .or_else(|| env_non_empty("MRTC_URL"))
            .or_else(|| env_non_empty("UPSTREAM_MATRIX_RTC_URL"))
            .or_else(|| env_non_empty("RTC_UPSTREAM"))
        {
            self.discovery.matrix_rtc_url = Some(v);
        }
        if let Some(v) = env_non_empty("MATRIX_RTC_URLS").or_else(|| env_non_empty("MRTC_URLS")) {
            self.discovery.matrix_rtc_urls = split_csv(&v);
        }
        if let Some(v) = env_non_empty("UPSTREAM_MATRIX_HOST_HEADER")
            .or_else(|| env_non_empty("MATRIX_HOST_HEADER"))
        {
            self.upstream.upstream_matrix_host_header = Some(v);
        }
        if let Some(v) =
            env_non_empty("UPSTREAM_AUTH_HOST_HEADER").or_else(|| env_non_empty("AUTH_HOST_HEADER"))
        {
            self.upstream.upstream_auth_host_header = Some(v);
        }
        if let Some(v) =
            env_non_empty("UPSTREAM_REWRITE_ORIGINS").or_else(|| env_non_empty("REWRITE_ORIGINS"))
        {
            self.upstream.upstream_rewrite_origins = split_csv(&v);
        }
        if let Some(v) = env_non_empty("UPSTREAM_PROXY") {
            self.upstream.outbound_proxy = Some(v);
        }
        if let Some(v) = env_non_empty("CLIENT_IP_MODE") {
            self.upstream.client_ip_mode = parse_client_ip_mode(&v)?;
        }
        if let Some(v) =
            env_non_empty("UPSTREAM_PROXY_PROTOCOL").or_else(|| env_non_empty("PROXY_PROTOCOL"))
        {
            self.upstream.upstream_proxy_protocol = parse_proxy_protocol(&v)?;
        } else if let Some(v) = env_bool("SEND_PROXY_V2")? {
            self.upstream.upstream_proxy_protocol = bool_to_ppv2(v);
        }
        if let Some(v) = env_non_empty("UPSTREAM_MATRIX_PROXY_PROTOCOL")
            .or_else(|| env_non_empty("MATRIX_PROXY_PROTOCOL"))
        {
            self.upstream.upstream_matrix_proxy_protocol = Some(parse_proxy_protocol(&v)?);
        } else if let Some(v) = env_bool("MATRIX_SEND_PROXY_V2")? {
            self.upstream.upstream_matrix_proxy_protocol = Some(bool_to_ppv2(v));
        }
        if let Some(v) = env_non_empty("UPSTREAM_AUTH_PROXY_PROTOCOL")
            .or_else(|| env_non_empty("AUTH_PROXY_PROTOCOL"))
        {
            self.upstream.upstream_auth_proxy_protocol = Some(parse_proxy_protocol(&v)?);
        } else if let Some(v) = env_bool("AUTH_SEND_PROXY_V2")? {
            self.upstream.upstream_auth_proxy_protocol = Some(bool_to_ppv2(v));
        }
        if let Some(v) = env_parse::<u64>("CONNECT_TIMEOUT_SECS")? {
            self.upstream.connect_timeout_secs = v;
        }
        if let Some(v) = env_parse::<u64>("REQUEST_TIMEOUT_SECS")? {
            self.upstream.request_timeout_secs = v;
        }
        if let Some(v) = env_bool("DANGER_ACCEPT_INVALID_CERTS")? {
            self.upstream.danger_accept_invalid_certs = v;
        }

        if let Some(v) = env_non_empty("AUTH_MODE") {
            self.routing.auth_mode = match v.to_ascii_lowercase().as_str() {
                "root" => AuthRouteMode::Root,
                "prefix" => AuthRouteMode::Prefix,
                other => bail!("invalid AUTH_MODE '{other}': expected 'root' or 'prefix'"),
            };
        }
        if let Some(v) = env_non_empty("AUTH_PREFIX") {
            self.routing.auth_prefix = v;
        }
        if let Some(v) = env_non_empty("PROXY_PREFIX") {
            self.routing.proxy_prefix = v;
        }
        if let Some(v) = env_non_empty("MATRIX_EXTRA_PREFIXES") {
            self.routing.matrix_extra_prefixes = split_csv(&v);
        }
        if let Some(v) = env_non_empty("AUTH_MATRIX_PREFIXES") {
            self.routing.auth_matrix_prefixes = split_csv(&v);
        }

        if let Some(v) = env_non_empty("AUTH_PROXY_MODE") {
            self.discovery.auth_proxy_mode = parse_auth_proxy_mode(&v)?;
        }
        if let Some(v) = env_bool("REWRITE_ISSUER")? {
            self.discovery.rewrite_issuer = v;
        }
        if let Some(v) = env_bool("FORCE_MSC2965_WELL_KNOWN")? {
            self.discovery.force_msc2965_well_known = v;
        }
        if let Some(v) = env_bool("REWRITE_AUTH_BODY")? {
            self.discovery.rewrite_auth_body = v;
        }
        if let Some(v) = env_bool("MERGE_UPSTREAM_WELL_KNOWN")? {
            self.discovery.merge_upstream_well_known = v;
        }
        if let Some(v) = env_non_empty("IDENTITY_SERVER_URL") {
            self.discovery.identity_server_url = Some(v);
        }
        if let Some(v) = env_parse::<u64>("DISCOVERY_CACHE_TTL_SECS")? {
            self.discovery.cache_ttl_secs = v;
        }
        if let Some(v) = env_bool("MEDIA_CACHE")? {
            self.discovery.media_cache = v;
        }
        if let Some(v) = env_bool("MEDIA_PRELOAD")? {
            self.discovery.media_preload = v;
        }
        if let Some(v) = env_parse::<usize>("MEDIA_PRELOAD_CONCURRENCY")? {
            self.discovery.media_preload_concurrency = v;
        }
        if let Some(v) = env_parse::<u64>("MEDIA_PRELOAD_MAX_ITEM_MB")? {
            self.discovery.media_preload_max_item_mb = v;
        }
        if let Some(v) = env_bool("MEDIA_PRELOAD_ON_THUMBNAIL")? {
            self.discovery.media_preload_on_thumbnail = v;
        }
        if let Some(v) = env_non_empty("MEDIA_PRELOAD_AVATAR_SIZES") {
            self.discovery.media_preload_avatar_sizes = split_csv(&v);
        }

        Ok(())
    }

    pub fn normalize_and_validate(&mut self) -> Result<()> {
        normalize_http_url_opt(&mut self.server.matrix_proxy_public_url);
        normalize_http_url_opt(&mut self.server.matrix_proxy_public_auth_url);
        normalize_opt_string(&mut self.server.tls_cert_path);
        normalize_opt_string(&mut self.server.tls_key_path);
        normalize_opt_string(&mut self.server.outbound_proxy);
        normalize_opt_string(&mut self.server.media_cache.dir);
        self.server.media_cache.max_item_mb = self.server.media_cache.max_item_mb.clamp(1, 256);
        self.server.media_cache.auth_cache_ttl_secs =
            self.server.media_cache.auth_cache_ttl_secs.clamp(5, 3600);
        self.server.outbound_no_proxy = normalize_no_proxy_list(&self.server.outbound_no_proxy);
        if let Some(proxy) = &self.server.outbound_proxy {
            validate_outbound_proxy_value("server.outbound_proxy", proxy)?;
        }

        normalize_http_url_opt(&mut self.upstream.upstream_matrix_server_url);
        normalize_http_url_opt(&mut self.upstream.upstream_matrix_auth_url);
        normalize_opt_string(&mut self.upstream.upstream_matrix_server_name);
        normalize_opt_string(&mut self.upstream.upstream_matrix_rtc_url);
        normalize_opt_string(&mut self.upstream.upstream_matrix_host_header);
        normalize_opt_string(&mut self.upstream.upstream_auth_host_header);
        normalize_opt_string(&mut self.upstream.outbound_proxy);
        self.upstream.outbound_no_proxy = normalize_no_proxy_list(&self.upstream.outbound_no_proxy);
        normalize_opt_string(&mut self.discovery.matrix_rtc_url);
        normalize_http_url_opt(&mut self.discovery.identity_server_url);

        if self.discovery.matrix_rtc_url.is_none()
            && self.discovery.matrix_rtc_urls.is_empty()
            && self.upstream.upstream_matrix_rtc_url.is_some()
        {
            self.discovery.matrix_rtc_url = self.upstream.upstream_matrix_rtc_url.clone();
        }

        if self.server.tls_cert_path.is_some() ^ self.server.tls_key_path.is_some() {
            bail!(
                "server.tls_cert_path and server.tls_key_path must either both be set or both be omitted"
            );
        }

        let _ = parse_trusted_proxies(&self.server.trusted_proxies)?;

        self.routing.auth_prefix =
            normalize_prefix("routing.auth_prefix", &self.routing.auth_prefix)?;
        self.routing.proxy_prefix =
            normalize_prefix("routing.proxy_prefix", &self.routing.proxy_prefix)?;

        self.routing.matrix_extra_prefixes = self
            .routing
            .matrix_extra_prefixes
            .iter()
            .filter_map(|p| clean_path_prefix(p))
            .collect();
        self.routing.auth_matrix_prefixes = self
            .routing
            .auth_matrix_prefixes
            .iter()
            .filter_map(|p| clean_path_prefix(p))
            .collect();

        // Validate either legacy single profile or multi-profile [[proxies]]
        let profiles = self.build_profiles()?;
        let _ = group_into_listeners(profiles)?;
        Ok(())
    }

    fn build_profiles(&self) -> Result<Vec<ProxyProfile>> {
        if self.proxies.is_empty() {
            let p = self.build_legacy_profile()?;
            return Ok(vec![p]);
        }

        let mut out = Vec::with_capacity(self.proxies.len());
        let mut seen_names = HashSet::new();

        for (idx, raw) in self.proxies.iter().enumerate() {
            let name = raw
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("proxy-{}", idx + 1));

            if !seen_names.insert(name.clone()) {
                bail!("duplicate proxy profile name '{name}' in [[proxies]]");
            }

            let listen_raw = raw
                .listen
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(self.server.listen.as_str());
            let listen: SocketAddr = listen_raw.parse().with_context(|| {
                format!("invalid listen address '{listen_raw}' in profile '{name}'")
            })?;

            // Per-profile TLS override: explicit `""` / `"off"` / `"none"` disables TLS even if `[server]` enables it.
            let tls_cert_path = resolve_optional_tls_path(
                raw.tls_cert_path.as_deref(),
                self.server.tls_cert_path.as_deref(),
            );
            let tls_key_path = resolve_optional_tls_path(
                raw.tls_key_path.as_deref(),
                self.server.tls_key_path.as_deref(),
            );
            if tls_cert_path.is_some() ^ tls_key_path.is_some() {
                bail!(
                    "profile '{name}': tls_cert_path and tls_key_path must both be set or both omitted/disabled"
                );
            }
            let inbound_proxy_protocol = raw
                .inbound_proxy_protocol
                .or_else(|| raw.accept_proxy_v2.map(bool_to_ppv2))
                .unwrap_or_else(|| self.server.effective_inbound_proxy_protocol());

            let mut public_url_str = raw.matrix_proxy_public_url.clone();
            normalize_http_url_opt(&mut public_url_str);
            let matrix_proxy_public_url = parse_http_url_opt(
                &format!("proxies[{name}].matrix_proxy_public_url"),
                &public_url_str,
            )?;

            let mut public_auth_url_str = raw.matrix_proxy_public_auth_url.clone();
            normalize_http_url_opt(&mut public_auth_url_str);
            let matrix_proxy_public_auth_url = parse_http_url_opt(
                &format!("proxies[{name}].matrix_proxy_public_auth_url"),
                &public_auth_url_str,
            )?;

            let default_outbound_pp = resolve_outbound_pp(
                raw.upstream_proxy_protocol,
                raw.send_proxy_v2,
                resolve_outbound_pp(
                    Some(self.upstream.upstream_proxy_protocol).filter(|p| p.is_enabled()),
                    self.upstream.send_proxy_v2,
                    ProxyProtocol::Off,
                ),
            );
            let upstream_matrix_proxy_protocol = raw
                .upstream_matrix_proxy_protocol
                .or_else(|| raw.matrix_send_proxy_v2.map(bool_to_ppv2))
                .or(self.upstream.upstream_matrix_proxy_protocol)
                .or_else(|| self.upstream.matrix_send_proxy_v2.map(bool_to_ppv2));
            let upstream_auth_proxy_protocol = raw
                .upstream_auth_proxy_protocol
                .or_else(|| raw.auth_send_proxy_v2.map(bool_to_ppv2))
                .or(self.upstream.upstream_auth_proxy_protocol)
                .or_else(|| self.upstream.auth_send_proxy_v2.map(bool_to_ppv2));

            let effective_outbound_proxy = opt_trim(raw.outbound_proxy.as_deref())
                .or_else(|| opt_trim(self.upstream.outbound_proxy.as_deref()))
                .or_else(|| opt_trim(self.server.outbound_proxy.as_deref()));
            let effective_outbound_no_proxy = if let Some(list) = &raw.outbound_no_proxy {
                normalize_no_proxy_list(list)
            } else if !self.upstream.outbound_no_proxy.is_empty() {
                normalize_no_proxy_list(&self.upstream.outbound_no_proxy)
            } else {
                normalize_no_proxy_list(&self.server.outbound_no_proxy)
            };

            let effective_rewrite_origins = raw
                .upstream_rewrite_origins
                .clone()
                .unwrap_or_else(|| self.upstream.upstream_rewrite_origins.clone());

            let mut upstream = UpstreamConfig {
                upstream_matrix_server_url: raw.upstream_matrix_server_url.clone(),
                upstream_matrix_auth_url: raw.upstream_matrix_auth_url.clone(),
                upstream_matrix_server_name: raw.upstream_matrix_server_name.clone(),
                upstream_matrix_rtc_url: None,
                upstream_matrix_host_header: raw.upstream_matrix_host_header.clone(),
                upstream_auth_host_header: raw.upstream_auth_host_header.clone(),
                upstream_rewrite_origins: effective_rewrite_origins,
                outbound_proxy: effective_outbound_proxy,
                outbound_no_proxy: effective_outbound_no_proxy,
                outbound_proxy_direct: false,
                client_ip_mode: raw.client_ip_mode.unwrap_or(self.upstream.client_ip_mode),
                upstream_proxy_protocol: default_outbound_pp,
                upstream_matrix_proxy_protocol,
                upstream_auth_proxy_protocol,
                send_proxy_v2: None,
                matrix_send_proxy_v2: None,
                auth_send_proxy_v2: None,
                connect_timeout_secs: raw
                    .connect_timeout_secs
                    .unwrap_or(self.upstream.connect_timeout_secs),
                request_timeout_secs: raw
                    .request_timeout_secs
                    .unwrap_or(self.upstream.request_timeout_secs),
                danger_accept_invalid_certs: raw
                    .danger_accept_invalid_certs
                    .unwrap_or(self.upstream.danger_accept_invalid_certs),
            };
            let parsed_rewrite_origins =
                validate_upstream(&format!("proxies[{name}]"), &mut upstream)?;

            let routing = RoutingConfig {
                auth_mode: raw.auth_mode.unwrap_or(self.routing.auth_mode),
                auth_prefix: normalize_prefix(
                    &format!("proxies[{name}].auth_prefix"),
                    raw.auth_prefix
                        .as_deref()
                        .unwrap_or(&self.routing.auth_prefix),
                )?,
                proxy_prefix: normalize_prefix(
                    &format!("proxies[{name}].proxy_prefix"),
                    raw.proxy_prefix
                        .as_deref()
                        .unwrap_or(&self.routing.proxy_prefix),
                )?,
                matrix_extra_prefixes: raw
                    .matrix_extra_prefixes
                    .as_ref()
                    .unwrap_or(&self.routing.matrix_extra_prefixes)
                    .iter()
                    .filter_map(|p| clean_path_prefix(p))
                    .collect(),
                auth_matrix_prefixes: raw
                    .auth_matrix_prefixes
                    .as_ref()
                    .unwrap_or(&self.routing.auth_matrix_prefixes)
                    .iter()
                    .filter_map(|p| clean_path_prefix(p))
                    .collect(),
            };

            let mut id_url = raw
                .identity_server_url
                .clone()
                .or_else(|| self.discovery.identity_server_url.clone());
            normalize_http_url_opt(&mut id_url);
            let _ = parse_http_url_opt(&format!("proxies[{name}].identity_server_url"), &id_url)?;

            let matrix_rtc = resolve_matrix_rtc_delegation(
                &format!("proxies[{name}]"),
                raw.matrix_rtc_url.as_deref(),
                raw.matrix_rtc_urls.as_deref(),
                self.discovery.matrix_rtc_url.as_deref(),
                &self.discovery.matrix_rtc_urls,
            )?;

            let discovery = DiscoveryConfig {
                auth_proxy_mode: raw
                    .auth_proxy_mode
                    .unwrap_or(self.discovery.auth_proxy_mode),
                matrix_rtc_url: raw
                    .matrix_rtc_url
                    .clone()
                    .or_else(|| self.discovery.matrix_rtc_url.clone()),
                matrix_rtc_urls: raw
                    .matrix_rtc_urls
                    .clone()
                    .unwrap_or_else(|| self.discovery.matrix_rtc_urls.clone()),
                rewrite_issuer: raw.rewrite_issuer.unwrap_or(self.discovery.rewrite_issuer),
                force_msc2965_well_known: raw
                    .force_msc2965_well_known
                    .unwrap_or(self.discovery.force_msc2965_well_known),
                rewrite_auth_body: raw
                    .rewrite_auth_body
                    .unwrap_or(self.discovery.rewrite_auth_body),
                merge_upstream_well_known: raw
                    .merge_upstream_well_known
                    .unwrap_or(self.discovery.merge_upstream_well_known),
                identity_server_url: id_url,
                cache_ttl_secs: raw.cache_ttl_secs.unwrap_or(self.discovery.cache_ttl_secs),
                media_cache: raw.media_cache.unwrap_or(self.discovery.media_cache),
                media_preload: raw.media_preload.unwrap_or(self.discovery.media_preload),
                media_preload_concurrency: raw
                    .media_preload_concurrency
                    .unwrap_or(self.discovery.media_preload_concurrency),
                media_preload_max_item_mb: raw
                    .media_preload_max_item_mb
                    .unwrap_or(self.discovery.media_preload_max_item_mb),
                media_preload_on_thumbnail: raw
                    .media_preload_on_thumbnail
                    .unwrap_or(self.discovery.media_preload_on_thumbnail),
                media_preload_avatar_sizes: raw
                    .media_preload_avatar_sizes
                    .clone()
                    .unwrap_or_else(|| self.discovery.media_preload_avatar_sizes.clone()),
            };

            let media = resolve_media_profile_config(&format!("proxies[{name}]"), &discovery)?;

            let route_hosts = collect_profile_route_hosts(
                matrix_proxy_public_url.as_ref(),
                matrix_proxy_public_auth_url.as_ref(),
            );

            out.push(ProxyProfile {
                name,
                listen,
                route_hosts,
                is_default: raw.default,
                strict_host_match: raw.strict_host_match,
                tls_cert_path,
                tls_key_path,
                inbound_proxy_protocol,
                matrix_proxy_public_url,
                matrix_proxy_public_auth_url,
                upstream,
                routing,
                discovery,
                matrix_rtc,
                media,
                parsed_rewrite_origins,
            });
        }

        Ok(out)
    }

    fn build_legacy_profile(&self) -> Result<ProxyProfile> {
        let listen: SocketAddr =
            self.server.listen.parse().with_context(|| {
                format!("invalid server.listen address '{}'", self.server.listen)
            })?;

        let matrix_proxy_public_url = parse_http_url_opt(
            "server.matrix_proxy_public_url",
            &self.server.matrix_proxy_public_url,
        )?;
        let matrix_proxy_public_auth_url = parse_http_url_opt(
            "server.matrix_proxy_public_auth_url",
            &self.server.matrix_proxy_public_auth_url,
        )?;

        let mut upstream = self.upstream.clone();
        if upstream.outbound_proxy.is_none() {
            upstream.outbound_proxy = self.server.outbound_proxy.clone();
        }
        if upstream.outbound_no_proxy.is_empty() {
            upstream.outbound_no_proxy = self.server.outbound_no_proxy.clone();
        }
        upstream.upstream_proxy_protocol = resolve_outbound_pp(
            Some(upstream.upstream_proxy_protocol).filter(|p| p.is_enabled()),
            upstream.send_proxy_v2,
            ProxyProtocol::Off,
        );
        upstream.upstream_matrix_proxy_protocol = upstream
            .upstream_matrix_proxy_protocol
            .or_else(|| upstream.matrix_send_proxy_v2.map(bool_to_ppv2));
        upstream.upstream_auth_proxy_protocol = upstream
            .upstream_auth_proxy_protocol
            .or_else(|| upstream.auth_send_proxy_v2.map(bool_to_ppv2));
        let parsed_rewrite_origins = validate_upstream("upstream", &mut upstream)?;
        let _ = parse_http_url_opt(
            "discovery.identity_server_url",
            &self.discovery.identity_server_url,
        )?;
        let matrix_rtc = resolve_matrix_rtc_delegation(
            "discovery",
            None,
            None,
            self.discovery
                .matrix_rtc_url
                .as_deref()
                .or(upstream.upstream_matrix_rtc_url.as_deref()),
            &self.discovery.matrix_rtc_urls,
        )?;

        let media = resolve_media_profile_config("discovery", &self.discovery)?;

        let route_hosts = collect_profile_route_hosts(
            matrix_proxy_public_url.as_ref(),
            matrix_proxy_public_auth_url.as_ref(),
        );

        Ok(ProxyProfile {
            name: "default".to_string(),
            listen,
            route_hosts,
            is_default: true,
            strict_host_match: false,
            tls_cert_path: self.server.tls_cert_path.clone(),
            tls_key_path: self.server.tls_key_path.clone(),
            inbound_proxy_protocol: self.server.effective_inbound_proxy_protocol(),
            matrix_proxy_public_url,
            matrix_proxy_public_auth_url,
            upstream,
            routing: self.routing.clone(),
            discovery: self.discovery.clone(),
            matrix_rtc,
            media,
            parsed_rewrite_origins,
        })
    }

    pub fn parsed_public_url(&self) -> Option<Url> {
        self.server
            .matrix_proxy_public_url
            .as_deref()
            .and_then(|s| Url::parse(s).ok())
    }

    pub fn parsed_public_auth_url(&self) -> Option<Url> {
        self.server
            .matrix_proxy_public_auth_url
            .as_deref()
            .and_then(|s| Url::parse(s).ok())
    }

    pub fn tls_enabled(&self) -> bool {
        self.server
            .tls_cert_path
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && self
                .server
                .tls_key_path
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }
}

fn group_into_listeners(profiles: Vec<ProxyProfile>) -> Result<Vec<ListenerPlan>> {
    let mut by_addr: BTreeMap<SocketAddr, Vec<ProxyProfile>> = BTreeMap::new();
    for p in profiles {
        by_addr.entry(p.listen).or_default().push(p);
    }

    let mut listeners = Vec::with_capacity(by_addr.len());
    for (listen, group) in by_addr {
        let first_tls_cert = group[0].tls_cert_path.clone();
        let first_tls_key = group[0].tls_key_path.clone();
        let first_inbound_pp = group[0].inbound_proxy_protocol;
        let first_proxy_prefix = group[0].routing.proxy_prefix.clone();

        let is_shared = group.len() > 1;
        let mut seen_hosts = HashSet::new();
        let mut default_count = 0usize;

        for p in &group {
            if p.tls_cert_path != first_tls_cert || p.tls_key_path != first_tls_key {
                bail!(
                    "listener {listen}: profiles sharing the same port must use identical TLS settings (conflict in '{}')",
                    p.name
                );
            }
            if p.inbound_proxy_protocol != first_inbound_pp {
                bail!(
                    "listener {listen}: profiles sharing the same port must use identical inbound_proxy_protocol setting (conflict in '{}')",
                    p.name
                );
            }
            if p.routing.proxy_prefix != first_proxy_prefix {
                bail!(
                    "listener {listen}: profiles sharing the same port must use identical proxy_prefix setting (conflict in '{}')",
                    p.name
                );
            }
            if p.is_default {
                default_count += 1;
            }
            if is_shared {
                if p.route_hosts.is_empty() && !p.is_default {
                    bail!(
                        "listener {listen}: profile '{}' shares a port with other profiles and must set `matrix_proxy_public_url` (or `default = true`)",
                        p.name
                    );
                }
                for h in &p.route_hosts {
                    if !seen_hosts.insert(h.clone()) {
                        bail!(
                            "listener {listen}: duplicate routing host '{h}' claimed by multiple profiles (use distinct `matrix_proxy_public_url` hosts or separate `listen` ports)"
                        );
                    }
                }
            }
        }

        if default_count > 1 {
            bail!("listener {listen}: at most one profile can set `default = true`");
        }

        listeners.push(ListenerPlan {
            listen,
            tls_cert_path: first_tls_cert,
            tls_key_path: first_tls_key,
            inbound_proxy_protocol: first_inbound_pp,
            proxy_prefix: first_proxy_prefix,
            profiles: group,
        });
    }

    Ok(listeners)
}

fn resolve_media_profile_config(
    prefix: &str,
    discovery: &DiscoveryConfig,
) -> Result<MediaProfileConfig> {
    let mut avatar_sizes = Vec::new();
    for raw in &discovery.media_preload_avatar_sizes {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let spec = AvatarThumbSpec::parse(trimmed)
            .with_context(|| format!("invalid {prefix}.media_preload_avatar_sizes entry"))?;
        if !avatar_sizes.contains(&spec) {
            avatar_sizes.push(spec);
        }
    }
    if avatar_sizes.is_empty() {
        avatar_sizes.push(AvatarThumbSpec {
            width: 96,
            height: 96,
            method: "crop".to_string(),
        });
    }
    Ok(MediaProfileConfig {
        cache_enabled: discovery.media_cache,
        preload_enabled: discovery.media_preload,
        preload_concurrency: discovery.media_preload_concurrency.clamp(1, 16),
        preload_max_item_mb: discovery.media_preload_max_item_mb.clamp(1, 64),
        preload_on_thumbnail: discovery.media_preload_on_thumbnail,
        preload_avatar_sizes: avatar_sizes,
    })
}

fn resolve_matrix_rtc_delegation(
    prefix: &str,
    profile_url: Option<&str>,
    profile_urls: Option<&[String]>,
    default_url: Option<&str>,
    default_urls: &[String],
) -> Result<MatrixRtcDelegation> {
    if let Some(list) = profile_urls {
        return parse_matrix_rtc_url_list(&format!("{prefix}.matrix_rtc_urls"), list);
    }
    if let Some(raw) = profile_url {
        return parse_matrix_rtc_single(&format!("{prefix}.matrix_rtc_url"), raw);
    }
    if !default_urls.is_empty() {
        return parse_matrix_rtc_url_list("defaults.matrix_rtc_urls", default_urls);
    }
    if let Some(raw) = default_url {
        return parse_matrix_rtc_single("defaults.matrix_rtc_url", raw);
    }
    Ok(MatrixRtcDelegation::Upstream)
}

fn parse_matrix_rtc_single(label: &str, raw: &str) -> Result<MatrixRtcDelegation> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("upstream") {
        return Ok(MatrixRtcDelegation::Upstream);
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "off" | "none" | "disabled"
    ) {
        return Ok(MatrixRtcDelegation::Disabled);
    }
    let items: Vec<String> = trimmed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    parse_matrix_rtc_url_list(label, &items)
}

fn parse_matrix_rtc_url_list(label: &str, items: &[String]) -> Result<MatrixRtcDelegation> {
    if items.is_empty() {
        return Ok(MatrixRtcDelegation::Upstream);
    }
    let mut out = Vec::with_capacity(items.len());
    for raw in items {
        let mut s = Some(raw.clone());
        normalize_http_url_opt(&mut s);
        if let Some(parsed) = parse_http_url_opt(label, &s)? {
            let norm = normalized_base_url(&parsed);
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
    if out.is_empty() {
        Ok(MatrixRtcDelegation::Upstream)
    } else {
        Ok(MatrixRtcDelegation::Delegate(out))
    }
}

fn validate_upstream(prefix: &str, upstream: &mut UpstreamConfig) -> Result<Vec<String>> {
    normalize_http_url_opt(&mut upstream.upstream_matrix_server_url);
    normalize_http_url_opt(&mut upstream.upstream_matrix_auth_url);
    normalize_opt_string(&mut upstream.upstream_matrix_server_name);
    normalize_opt_string(&mut upstream.upstream_matrix_host_header);
    normalize_opt_string(&mut upstream.upstream_auth_host_header);
    normalize_opt_string(&mut upstream.outbound_proxy);
    upstream.outbound_no_proxy = normalize_no_proxy_list(&upstream.outbound_no_proxy);

    if upstream.upstream_matrix_server_url.is_none()
        && upstream.upstream_matrix_server_name.is_none()
    {
        bail!(
            "{prefix}: configuration requires at least one of upstream_matrix_server_url (UPSTREAM_MATRIX_SERVER_URL) or upstream_matrix_server_name (UPSTREAM_MATRIX_SERVER_NAME)"
        );
    }

    let _ = parse_http_url_opt(
        &format!("{prefix}.upstream_matrix_server_url"),
        &upstream.upstream_matrix_server_url,
    )?;
    let _ = parse_http_url_opt(
        &format!("{prefix}.upstream_matrix_auth_url"),
        &upstream.upstream_matrix_auth_url,
    )?;

    if let Some(proxy) = upstream.outbound_proxy.clone() {
        validate_outbound_proxy_value(&format!("{prefix}.outbound_proxy"), &proxy)?;
        if is_direct_proxy_keyword(&proxy) {
            upstream.outbound_proxy = None;
            upstream.outbound_proxy_direct = true;
        }
    }

    let mut rewrite_origins = Vec::new();
    for raw in &upstream.upstream_rewrite_origins {
        let mut s = Some(raw.clone());
        normalize_http_url_opt(&mut s);
        if let Some(url) = parse_http_url_opt(&format!("{prefix}.upstream_rewrite_origins"), &s)? {
            let origin = origin_string(&url);
            if !rewrite_origins.contains(&origin) {
                rewrite_origins.push(origin);
            }
        }
    }

    Ok(rewrite_origins)
}

pub fn is_direct_proxy_keyword(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "direct" | "none" | "off"
    )
}

fn validate_outbound_proxy_value(label: &str, proxy: &str) -> Result<()> {
    if is_direct_proxy_keyword(proxy) {
        return Ok(());
    }
    let parsed = Url::parse(proxy).with_context(|| format!("invalid {label} URL: {proxy}"))?;
    match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        s => bail!(
            "unsupported {label} scheme '{s}': expected http, https, socks5, socks5h, or direct"
        ),
    }
    if parsed.host_str().is_none() {
        bail!("invalid {label}: missing proxy host in '{proxy}'");
    }
    Ok(())
}

fn normalize_no_proxy_list(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in raw {
        for part in entry.split(',') {
            let trimmed = part.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !out.contains(&trimmed) {
                out.push(trimmed);
            }
        }
    }
    out
}

/// Checks whether a target host should bypass `outbound_proxy` according to `outbound_no_proxy` rules
/// (supports `*`, exact hostnames, `.domain.suffix` / `domain.suffix`, IP literals, and IPv4/IPv6 CIDRs).
pub fn should_bypass_outbound_proxy(target_host: &str, no_proxy: &[String]) -> bool {
    if no_proxy.is_empty() {
        return false;
    }
    let clean_target = target_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if clean_target.is_empty() {
        return false;
    }
    let target_ip = clean_target.parse::<IpAddr>().ok().map(canonical_ip);

    for raw_rule in no_proxy {
        let rule = raw_rule.trim().to_ascii_lowercase();
        if rule.is_empty() {
            continue;
        }
        if rule == "*" {
            return true;
        }
        if let Ok(net) = rule.parse::<IpNet>() {
            if let Some(ip) = target_ip
                && net.contains(&ip)
            {
                return true;
            }
            continue;
        }
        let stripped_rule = rule.trim_start_matches('[').trim_end_matches(']');
        if let Ok(rule_ip) = stripped_rule.parse::<IpAddr>() {
            if target_ip == Some(canonical_ip(rule_ip)) {
                return true;
            }
            continue;
        }
        let host_part = strip_host_port(&rule);
        let suffix = host_part.trim_start_matches('.');
        if !suffix.is_empty()
            && (clean_target == suffix
                || (clean_target.len() > suffix.len()
                    && clean_target.ends_with(suffix)
                    && clean_target.as_bytes()[clean_target.len() - suffix.len() - 1] == b'.'))
        {
            return true;
        }
    }
    false
}

fn collect_profile_route_hosts(
    public_url: Option<&Url>,
    public_auth_url: Option<&Url>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for url_opt in [public_url, public_auth_url] {
        if let Some(u) = url_opt
            && let Some(host) = u.host_str()
        {
            let h = host.to_ascii_lowercase();
            if seen.insert(h.clone()) {
                out.push(h);
            }
        }
    }
    out
}

fn parse_trusted_proxies(raw_list: &[String]) -> Result<Vec<IpNet>> {
    let mut nets = Vec::with_capacity(raw_list.len());
    for raw in raw_list {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(net) = trimmed.parse::<IpNet>() {
            nets.push(net);
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            nets.push(IpNet::from(canonical_ip(ip)));
        } else {
            return Err(anyhow!(
                "invalid CIDR or IP in server.trusted_proxies: '{trimmed}'"
            ));
        }
    }
    Ok(nets)
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

fn bool_to_ppv2(enabled: bool) -> ProxyProtocol {
    if enabled {
        ProxyProtocol::V2
    } else {
        ProxyProtocol::Off
    }
}

fn resolve_outbound_pp(
    explicit: Option<ProxyProtocol>,
    legacy_v2: Option<bool>,
    fallback: ProxyProtocol,
) -> ProxyProtocol {
    explicit
        .or_else(|| legacy_v2.map(bool_to_ppv2))
        .unwrap_or(fallback)
}

fn parse_proxy_protocol(raw: &str) -> Result<ProxyProtocol> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "disabled" | "false" | "0" => Ok(ProxyProtocol::Off),
        "v1" | "1" | "ppv1" => Ok(ProxyProtocol::V1),
        "v2" | "2" | "ppv2" => Ok(ProxyProtocol::V2),
        other => bail!("invalid proxy_protocol '{other}': expected 'off', 'v1', or 'v2'"),
    }
}

fn parse_client_ip_mode(raw: &str) -> Result<ClientIpMode> {
    match raw.to_ascii_lowercase().as_str() {
        "replace" => Ok(ClientIpMode::Replace),
        "append" => Ok(ClientIpMode::Append),
        "off" | "none" | "disabled" => Ok(ClientIpMode::Off),
        other => bail!("invalid CLIENT_IP_MODE '{other}': expected replace, append, or off"),
    }
}

fn parse_expose_info(raw: &str) -> Result<ExposeInfoMode> {
    match raw.to_ascii_lowercase().as_str() {
        "trusted" | "trusted_only" => Ok(ExposeInfoMode::Trusted),
        "always" | "public" | "true" => Ok(ExposeInfoMode::Always),
        "disabled" | "off" | "false" => Ok(ExposeInfoMode::Disabled),
        other => bail!("invalid EXPOSE_INFO '{other}': expected trusted, always, or disabled"),
    }
}

fn parse_auth_proxy_mode(raw: &str) -> Result<AuthProxyMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "full" => Ok(AuthProxyMode::Full),
        "token_only" | "token-only" | "hybrid" => Ok(AuthProxyMode::TokenOnly),
        "direct" | "passthrough" | "off" => Ok(AuthProxyMode::Direct),
        other => bail!("invalid AUTH_PROXY_MODE '{other}': expected full, token_only, or direct"),
    }
}

fn opt_trim(opt: Option<&str>) -> Option<String> {
    opt.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn resolve_optional_tls_path(
    profile_val: Option<&str>,
    global_val: Option<&str>,
) -> Option<String> {
    match profile_val {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("off")
                || trimmed.eq_ignore_ascii_case("none")
            {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => opt_trim(global_val),
    }
}

fn normalize_opt_string(opt: &mut Option<String>) {
    if let Some(val) = opt {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            *opt = None;
        } else if trimmed.len() != val.len() {
            *val = trimmed.to_string();
        }
    }
}

fn normalize_http_url_opt(opt: &mut Option<String>) {
    normalize_opt_string(opt);
    if let Some(val) = opt
        && !val.contains("://")
    {
        *val = format!("https://{val}");
    }
}

fn parse_http_url_opt(name: &str, opt: &Option<String>) -> Result<Option<Url>> {
    let Some(raw) = opt else {
        return Ok(None);
    };
    let parsed = Url::parse(raw).with_context(|| format!("invalid {name} URL: {raw}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => bail!("invalid {name} scheme '{s}': expected http or https"),
    }
    if parsed.host_str().is_none() {
        bail!("invalid {name}: missing host in '{raw}'");
    }
    Ok(Some(parsed))
}

fn normalize_prefix(name: &str, raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        bail!("{name} cannot be empty or root '/'");
    }
    if trimmed.starts_with('/') {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("/{trimmed}"))
    }
}

fn clean_path_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('/') {
        Some(trimmed.to_string())
    } else {
        Some(format!("/{trimmed}"))
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    env::var(key).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() { None } else { Some(t) }
    })
}

fn env_bool(key: &str) -> Result<Option<bool>> {
    match env_non_empty(key) {
        None => Ok(None),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            _ => bail!("invalid boolean for {key}: '{v}'"),
        },
    }
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match env_non_empty(key) {
        None => Ok(None),
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("invalid value for {key} ('{v}'): {e}")),
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[..=end];
        }
        return host;
    }
    host.split(':').next().unwrap_or(host)
}

pub fn origin_string(url: &Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

pub fn normalized_base_url(url: &Url) -> String {
    let origin = origin_string(url);
    let path = url.path().trim_end_matches('/');
    if path.is_empty() {
        origin
    } else {
        format!("{origin}{path}")
    }
}

pub fn redact_proxy_url(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => "<invalid-url>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hostnames_default_to_https_and_ip_port_keeps_http() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            matrix_proxy_public_url = "proxy.example.com"

            [upstream]
            upstream_matrix_server_url = "matrix.example.org"
            upstream_matrix_auth_url = "https://auth.example.org"
            upstream_matrix_rtc_url = "rtc.example.org"
            "#,
        )
        .unwrap();

        assert_eq!(
            cfg.server.matrix_proxy_public_url.as_deref(),
            Some("https://proxy.example.com")
        );
        assert_eq!(
            cfg.upstream.upstream_matrix_server_url.as_deref(),
            Some("https://matrix.example.org")
        );
        assert_eq!(
            cfg.upstream.upstream_matrix_auth_url.as_deref(),
            Some("https://auth.example.org")
        );
        let rt = cfg.into_runtime().unwrap();
        assert_eq!(
            rt.listeners[0].profiles[0].matrix_rtc,
            MatrixRtcDelegation::Delegate(vec!["https://rtc.example.org".to_string()])
        );

        let ts_cfg = Config::from_toml_str(
            r#"
            [[proxies]]
            name = "tailscale"
            listen = "0.0.0.0:8081"
            matrix_proxy_public_url = "http://100.64.0.10:8081"
            upstream_matrix_server_url = "https://matrix-client.matrix.org"
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();
        assert_eq!(
            ts_cfg.listeners[0].profiles[0]
                .matrix_proxy_public_url
                .as_ref()
                .map(normalized_base_url)
                .as_deref(),
            Some("http://100.64.0.10:8081")
        );
        assert_eq!(
            ts_cfg.listeners[0].profiles[0].route_hosts,
            vec!["100.64.0.10"]
        );
    }

    #[test]
    fn invalid_scheme_still_rejected() {
        let err = Config::from_toml_str(
            r#"
            [upstream]
            upstream_matrix_server_url = "ftp://matrix.example.org"
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid upstream.upstream_matrix_server_url scheme")
        );
    }

    #[test]
    fn multi_proxy_supports_shared_port_custom_ports_and_global_outbound_proxy() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"
            outbound_proxy = "socks5h://127.0.0.1:1080"
            outbound_no_proxy = ["127.0.0.1", "100.64.0.0/10", ".internal"]

            [[proxies]]
            name = "site-a"
            matrix_proxy_public_url = "https://a.example.com"
            upstream_matrix_server_url = "https://hs-a.internal:8443"
            upstream_proxy_protocol = "v2"
            upstream_rewrite_origins = ["https://hs-public.example.org"]

            [[proxies]]
            name = "site-b-direct"
            matrix_proxy_public_url = "https://b.example.com"
            upstream_matrix_server_url = "https://hs-b.internal"
            upstream_matrix_auth_url = "https://auth-b.internal"
            upstream_matrix_proxy_protocol = "v1"
            upstream_auth_proxy_protocol = "off"
            outbound_proxy = "direct"

            [[proxies]]
            name = "site-c-tailscale"
            listen = "0.0.0.0:8081"
            matrix_proxy_public_url = "http://100.64.0.10:8081"
            upstream_matrix_server_url = "https://hs-c.example.org"
            outbound_proxy = "http://127.0.0.1:7890"
            "#,
        )
        .unwrap();

        let runtime = cfg.into_runtime().unwrap();
        assert_eq!(runtime.listeners.len(), 2);
        assert_eq!(runtime.listeners[0].listen.port(), 8080);
        assert_eq!(runtime.listeners[0].profiles.len(), 2);
        assert_eq!(
            runtime.listeners[0].profiles[0].route_hosts,
            vec!["a.example.com"]
        );
        // Inherits global [server].outbound_proxy & outbound_no_proxy
        assert_eq!(
            runtime.listeners[0].profiles[0]
                .upstream
                .outbound_proxy
                .as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );
        assert_eq!(
            runtime.listeners[0].profiles[0].upstream.outbound_no_proxy,
            vec!["127.0.0.1", "100.64.0.0/10", ".internal"]
        );
        assert!(
            !runtime.listeners[0].profiles[0]
                .upstream
                .outbound_proxy_direct
        );
        assert_eq!(
            runtime.listeners[0].profiles[0].matrix_proxy_protocol(),
            ProxyProtocol::V2
        );
        assert_eq!(
            runtime.listeners[0].profiles[0].parsed_rewrite_origins,
            vec!["https://hs-public.example.org"]
        );

        // Profile B explicitly overrides global outbound_proxy with "direct"
        assert_eq!(
            runtime.listeners[0].profiles[1].upstream.outbound_proxy,
            None
        );
        assert!(
            runtime.listeners[0].profiles[1]
                .upstream
                .outbound_proxy_direct
        );
        assert_eq!(
            runtime.listeners[0].profiles[1].matrix_proxy_protocol(),
            ProxyProtocol::V1
        );
        assert_eq!(
            runtime.listeners[0].profiles[1].auth_proxy_protocol(),
            ProxyProtocol::Off
        );

        // Dedicated Tailscale port with per-profile HTTP proxy override
        assert_eq!(runtime.listeners[1].listen.port(), 8081);
        assert_eq!(runtime.listeners[1].profiles.len(), 1);
        assert_eq!(runtime.listeners[1].profiles[0].name, "site-c-tailscale");
        assert_eq!(
            runtime.listeners[1].profiles[0]
                .upstream
                .outbound_proxy
                .as_deref(),
            Some("http://127.0.0.1:7890")
        );
    }

    #[test]
    fn no_proxy_matching_handles_domains_ips_and_cidrs() {
        let rules = normalize_no_proxy_list(&[
            "localhost, 127.0.0.1".to_string(),
            "100.64.0.0/10".to_string(),
            ".internal.example".to_string(),
            "direct.org".to_string(),
        ]);
        assert!(should_bypass_outbound_proxy("localhost", &rules));
        assert!(should_bypass_outbound_proxy("127.0.0.1", &rules));
        assert!(should_bypass_outbound_proxy("100.64.12.34", &rules));
        assert!(should_bypass_outbound_proxy("hs.internal.example", &rules));
        assert!(should_bypass_outbound_proxy("internal.example", &rules));
        assert!(should_bypass_outbound_proxy("direct.org", &rules));
        assert!(should_bypass_outbound_proxy("sub.direct.org", &rules));
        assert!(!should_bypass_outbound_proxy("notdirect.org", &rules));
        assert!(!should_bypass_outbound_proxy("matrix.org", &rules));
    }

    #[test]
    fn legacy_field_names_and_ppv2_booleans_remain_backward_compatible() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"
            accept_proxy_v2 = true
            ppv2_pool_max_entries = 2048

            [[proxies]]
            name = "legacy"
            public_url = "https://legacy.example.com"
            matrix_url = "https://hs.example.org:8443"
            auth_url = "https://auth.example.org:8443"
            rtc_url = "https://rtc.example.org"
            server_name = "example.org"
            matrix_send_proxy_v2 = true
            auth_send_proxy_v2 = false
            "#,
        )
        .unwrap();
        let runtime = cfg.into_runtime().unwrap();
        assert_eq!(runtime.server.proxy_protocol_pool_max_entries, 2048);
        assert_eq!(
            runtime.listeners[0].inbound_proxy_protocol,
            ProxyProtocol::V2
        );
        let p = &runtime.listeners[0].profiles[0];
        assert_eq!(p.route_hosts, vec!["legacy.example.com"]);
        assert_eq!(
            p.upstream.upstream_matrix_server_url.as_deref(),
            Some("https://hs.example.org:8443")
        );
        assert_eq!(
            p.upstream.upstream_matrix_auth_url.as_deref(),
            Some("https://auth.example.org:8443")
        );
        assert_eq!(
            p.matrix_rtc,
            MatrixRtcDelegation::Delegate(vec!["https://rtc.example.org".to_string()])
        );
        assert_eq!(
            p.upstream.upstream_matrix_server_name.as_deref(),
            Some("example.org")
        );
        assert_eq!(p.matrix_proxy_protocol(), ProxyProtocol::V2);
        assert_eq!(p.auth_proxy_protocol(), ProxyProtocol::Off);
    }

    #[test]
    fn duplicate_routing_host_on_shared_port_is_rejected() {
        let err = Config::from_toml_str(
            r#"
            [[proxies]]
            name = "p1"
            matrix_proxy_public_url = "https://dup.example.com"
            upstream_matrix_server_url = "https://hs1.example.com"

            [[proxies]]
            name = "p2"
            matrix_proxy_public_url = "https://dup.example.com"
            upstream_matrix_server_url = "https://hs2.example.com"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate routing host"));
    }

    #[test]
    fn profile_fields_always_override_global_defaults() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"
            tls_cert_path = "/etc/certs/global.pem"
            tls_key_path = "/etc/certs/global.key"
            outbound_proxy = "http://127.0.0.1:7890"
            outbound_no_proxy = ["127.0.0.1", "10.0.0.0/8"]

            [upstream]
            client_ip_mode = "append"
            connect_timeout_secs = 20
            request_timeout_secs = 120
            upstream_rewrite_origins = ["https://global-origin.example.org"]

            [routing]
            auth_mode = "prefix"
            auth_prefix = "/_auth"

            [discovery]
            cache_ttl_secs = 120

            [[proxies]]
            name = "inherits-all"
            matrix_proxy_public_url = "https://inherit.example.com"
            upstream_matrix_server_url = "https://hs1.example.org"

            [[proxies]]
            name = "overrides-all"
            listen = "0.0.0.0:8081"
            tls_cert_path = "off"
            tls_key_path = "off"
            matrix_proxy_public_url = "http://100.64.0.10:8081"
            upstream_matrix_server_url = "https://hs2.example.org"
            outbound_proxy = "socks5h://user:pass@127.0.0.1:1080"
            outbound_no_proxy = ["100.64.0.0/10"]
            upstream_rewrite_origins = ["https://profile-only.example.org"]
            client_ip_mode = "replace"
            connect_timeout_secs = 5
            request_timeout_secs = 0
            auth_mode = "root"
            cache_ttl_secs = 30
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();

        assert_eq!(cfg.listeners.len(), 2);
        let l0 = &cfg.listeners[0];
        let p0 = &l0.profiles[0];
        assert_eq!(l0.listen.port(), 8080);
        assert!(l0.tls_enabled());
        assert_eq!(
            p0.upstream.outbound_proxy.as_deref(),
            Some("http://127.0.0.1:7890")
        );
        assert_eq!(
            p0.upstream.outbound_no_proxy,
            vec!["127.0.0.1", "10.0.0.0/8"]
        );
        assert_eq!(
            p0.parsed_rewrite_origins,
            vec!["https://global-origin.example.org"]
        );
        assert_eq!(p0.upstream.client_ip_mode, ClientIpMode::Append);
        assert_eq!(p0.upstream.connect_timeout_secs, 20);
        assert_eq!(p0.upstream.request_timeout_secs, 120);
        assert_eq!(p0.routing.auth_mode, AuthRouteMode::Prefix);
        assert_eq!(p0.discovery.cache_ttl_secs, 120);

        let l1 = &cfg.listeners[1];
        let p1 = &l1.profiles[0];
        assert_eq!(l1.listen.port(), 8081);
        assert!(!l1.tls_enabled());
        assert_eq!(
            p1.upstream.outbound_proxy.as_deref(),
            Some("socks5h://user:pass@127.0.0.1:1080")
        );
        assert_eq!(p1.upstream.outbound_no_proxy, vec!["100.64.0.0/10"]);
        assert_eq!(
            p1.parsed_rewrite_origins,
            vec!["https://profile-only.example.org"]
        );
        assert_eq!(p1.upstream.client_ip_mode, ClientIpMode::Replace);
        assert_eq!(p1.upstream.connect_timeout_secs, 5);
        assert_eq!(p1.upstream.request_timeout_secs, 0);
        assert_eq!(p1.routing.auth_mode, AuthRouteMode::Root);
        assert_eq!(p1.discovery.cache_ttl_secs, 30);
    }

    #[test]
    fn shared_port_conflicting_proxy_prefix_is_rejected() {
        let err = Config::from_toml_str(
            r#"
            [[proxies]]
            name = "p1"
            matrix_proxy_public_url = "https://a.example.com"
            upstream_matrix_server_url = "https://hs1.example.com"
            proxy_prefix = "/_proxy"

            [[proxies]]
            name = "p2"
            matrix_proxy_public_url = "https://b.example.com"
            upstream_matrix_server_url = "https://hs2.example.com"
            proxy_prefix = "/_admin"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("identical proxy_prefix"));
    }

    #[test]
    fn structured_v14_sections_and_defaults_precedence() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"
            tls_cert = "/certs/global.pem"
            tls_key = "/certs/global.key"
            inbound_proxy_protocol = "off"

            [server.reload]
            enabled = true
            interval_secs = 5
            shutdown_grace_secs = 30

            [server.tuning]
            max_concurrent_requests = 5000
            rate_limit_rps = 50
            proxy_protocol_pool_max_entries = 2048

            [defaults]
            outbound_proxy = "socks5h://127.0.0.1:1080"
            outbound_no_proxy = ["localhost", "100.64.0.0/10"]
            client_ip_mode = "replace"
            upstream_proxy_protocol = "off"
            auth_mode = "root"
            connect_timeout_secs = 12
            cache_ttl_secs = 90

            [[proxies]]
            name = "inherits-defaults"
            matrix_proxy_public_url = "https://one.example.com"
            upstream_matrix_server_url = "https://hs1.example.org"

            [[proxies]]
            name = "overrides-defaults"
            listen = "0.0.0.0:8081"
            tls_cert = "off"
            tls_key = "off"
            matrix_proxy_public_url = "http://100.64.0.10:8081"
            upstream_matrix_server_url = "https://hs2.example.org"
            outbound_proxy = "direct"
            outbound_no_proxy = []
            auth_mode = "prefix"
            connect_timeout_secs = 5
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();

        assert!(cfg.server.hot_reload);
        assert_eq!(cfg.server.hot_reload_interval_secs, 5);
        assert_eq!(cfg.server.shutdown_grace_secs, 30);
        assert_eq!(cfg.server.max_concurrent_requests, 5000);
        assert_eq!(cfg.server.rate_limit_rps, 50);
        assert_eq!(cfg.server.proxy_protocol_pool_max_entries, 2048);

        assert_eq!(cfg.listeners.len(), 2);
        let p0 = &cfg.listeners[0].profiles[0];
        assert!(cfg.listeners[0].tls_enabled());
        assert_eq!(
            p0.upstream.outbound_proxy.as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );
        assert_eq!(
            p0.upstream.outbound_no_proxy,
            vec!["localhost", "100.64.0.0/10"]
        );
        assert_eq!(p0.upstream.connect_timeout_secs, 12);
        assert_eq!(p0.discovery.cache_ttl_secs, 90);

        let p1 = &cfg.listeners[1].profiles[0];
        assert!(!cfg.listeners[1].tls_enabled());
        assert_eq!(p1.upstream.outbound_proxy, None);
        assert!(p1.upstream.outbound_proxy_direct);
        assert!(p1.upstream.outbound_no_proxy.is_empty());
        assert_eq!(p1.routing.auth_mode, AuthRouteMode::Prefix);
        assert_eq!(p1.upstream.connect_timeout_secs, 5);
    }

    #[test]
    fn bundled_config_example_toml_is_valid() {
        let example = include_str!("../config.example.toml");
        let runtime = Config::from_toml_str(example)
            .expect("config.example.toml must parse cleanly")
            .into_runtime()
            .expect("config.example.toml must build valid RuntimeConfig");
        assert_eq!(runtime.listeners.len(), 1);
        assert_eq!(runtime.listeners[0].profiles.len(), 2);
        assert_eq!(
            runtime.listeners[0].profiles[0].matrix_proxy_protocol(),
            ProxyProtocol::Off
        );
        assert_eq!(
            runtime.listeners[0].profiles[1].matrix_proxy_protocol(),
            ProxyProtocol::V2
        );
    }

    #[test]
    fn auth_proxy_mode_inherits_defaults_and_overrides_per_profile() {
        let cfg = Config::from_toml_str(
            r#"
            [defaults]
            auth_proxy_mode = "token_only"

            [[proxies]]
            name = "inherits-token-only"
            matrix_proxy_public_url = "https://a.example.com"
            upstream_matrix_server_url = "https://hs-a.example.org"

            [[proxies]]
            name = "overrides-full"
            matrix_proxy_public_url = "https://b.example.com"
            upstream_matrix_server_url = "https://hs-b.example.org"
            auth_proxy_mode = "full"

            [[proxies]]
            name = "overrides-direct"
            matrix_proxy_public_url = "https://c.example.com"
            upstream_matrix_server_url = "https://hs-c.example.org"
            auth_proxy_mode = "direct"

            [[proxies]]
            name = "alias-hybrid"
            matrix_proxy_public_url = "https://d.example.com"
            upstream_matrix_server_url = "https://hs-d.example.org"
            auth_proxy_mode = "hybrid"
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();

        let profiles = &cfg.listeners[0].profiles;
        assert_eq!(
            profiles[0].discovery.auth_proxy_mode,
            AuthProxyMode::TokenOnly
        );
        assert_eq!(profiles[1].discovery.auth_proxy_mode, AuthProxyMode::Full);
        assert_eq!(profiles[2].discovery.auth_proxy_mode, AuthProxyMode::Direct);
        assert_eq!(
            profiles[3].discovery.auth_proxy_mode,
            AuthProxyMode::TokenOnly
        );
    }
}
