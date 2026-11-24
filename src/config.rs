use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    /// Legacy single-upstream sections (fully backward compatible when `[[proxies]]` is empty).
    pub upstream: UpstreamConfig,
    pub routing: RoutingConfig,
    pub discovery: DiscoveryConfig,
    /// Multi-upstream proxy profiles: each block can bind its own port OR share `server.listen` by domain.
    #[serde(alias = "profiles")]
    pub proxies: Vec<ProxyProfileInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: String,
    pub public_url: Option<String>,
    pub public_auth_url: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub accept_proxy_v2: bool,
    pub trust_forwarded_headers: bool,
    pub trusted_proxies: Vec<String>,
    pub expose_info: ExposeInfoMode,
    pub max_rewrite_body_bytes: usize,
    pub max_concurrent_requests: usize,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u64,
    pub header_read_timeout_secs: u64,
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub tcp_keepalive_secs: u64,
    pub tcp_nodelay: bool,
    pub ppv2_pool_max_entries: usize,
    pub listen_backlog: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            public_url: None,
            public_auth_url: None,
            tls_cert_path: None,
            tls_key_path: None,
            accept_proxy_v2: false,
            trust_forwarded_headers: true,
            trusted_proxies: default_trusted_proxies(),
            expose_info: ExposeInfoMode::Trusted,
            max_rewrite_body_bytes: 4 * 1024 * 1024,
            max_concurrent_requests: 10_000,
            rate_limit_rps: 0,
            rate_limit_burst: 200,
            header_read_timeout_secs: 15,
            pool_max_idle_per_host: 128,
            pool_idle_timeout_secs: 90,
            tcp_keepalive_secs: 30,
            tcp_nodelay: true,
            ppv2_pool_max_entries: 4096,
            listen_backlog: 4096,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub matrix_url: Option<String>,
    pub auth_url: Option<String>,
    pub server_name: Option<String>,
    pub rtc_url: Option<String>,
    pub matrix_host_header: Option<String>,
    pub auth_host_header: Option<String>,
    pub rtc_host_header: Option<String>,
    pub rewrite_origins: Vec<String>,
    pub outbound_proxy: Option<String>,
    pub client_ip_mode: ClientIpMode,
    pub send_proxy_v2: bool,
    pub matrix_send_proxy_v2: Option<bool>,
    pub auth_send_proxy_v2: Option<bool>,
    pub rtc_send_proxy_v2: Option<bool>,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub danger_accept_invalid_certs: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            matrix_url: None,
            auth_url: None,
            server_name: None,
            rtc_url: None,
            matrix_host_header: None,
            auth_host_header: None,
            rtc_host_header: None,
            rewrite_origins: Vec::new(),
            outbound_proxy: None,
            client_ip_mode: ClientIpMode::Replace,
            send_proxy_v2: false,
            matrix_send_proxy_v2: None,
            auth_send_proxy_v2: None,
            rtc_send_proxy_v2: None,
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
    pub rtc_prefix: String,
    pub proxy_prefix: String,
    pub matrix_extra_prefixes: Vec<String>,
    pub auth_matrix_prefixes: Vec<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            auth_mode: AuthRouteMode::Root,
            auth_prefix: "/_auth".to_string(),
            rtc_prefix: "/_rtc".to_string(),
            proxy_prefix: "/_proxy".to_string(),
            matrix_extra_prefixes: Vec::new(),
            auth_matrix_prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub rewrite_issuer: bool,
    pub force_msc2965_well_known: bool,
    pub rewrite_auth_body: bool,
    pub merge_upstream_well_known: bool,
    pub identity_server_url: Option<String>,
    pub cache_ttl_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            rewrite_issuer: true,
            force_msc2965_well_known: false,
            rewrite_auth_body: true,
            merge_upstream_well_known: true,
            identity_server_url: None,
            cache_ttl_secs: 60,
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
    /// Domains routed to this profile when sharing a port (auto-inferred from `public_url` & `public_auth_url` if empty).
    pub domains: Vec<String>,
    /// If true on a shared listener, handles unmatched `Host` headers as fallback.
    pub default: bool,
    /// If true on a single-profile dedicated listener, rejects requests whose Host does not match `domains`.
    pub strict_host_match: bool,

    pub public_url: Option<String>,
    pub public_auth_url: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub accept_proxy_v2: Option<bool>,

    pub matrix_url: Option<String>,
    pub auth_url: Option<String>,
    pub server_name: Option<String>,
    pub rtc_url: Option<String>,
    pub matrix_host_header: Option<String>,
    pub auth_host_header: Option<String>,
    pub rtc_host_header: Option<String>,
    pub rewrite_origins: Vec<String>,
    pub outbound_proxy: Option<String>,
    pub client_ip_mode: Option<ClientIpMode>,
    pub send_proxy_v2: Option<bool>,
    pub matrix_send_proxy_v2: Option<bool>,
    pub auth_send_proxy_v2: Option<bool>,
    pub rtc_send_proxy_v2: Option<bool>,
    pub connect_timeout_secs: Option<u64>,
    pub request_timeout_secs: Option<u64>,
    pub danger_accept_invalid_certs: Option<bool>,

    pub auth_mode: Option<AuthRouteMode>,
    pub auth_prefix: Option<String>,
    pub rtc_prefix: Option<String>,
    pub proxy_prefix: Option<String>,
    pub matrix_extra_prefixes: Option<Vec<String>>,
    pub auth_matrix_prefixes: Option<Vec<String>>,

    pub rewrite_issuer: Option<bool>,
    pub force_msc2965_well_known: Option<bool>,
    pub rewrite_auth_body: Option<bool>,
    pub merge_upstream_well_known: Option<bool>,
    pub identity_server_url: Option<String>,
    pub cache_ttl_secs: Option<u64>,
}

/// Normalized, validated, self-contained runtime configuration for a single upstream proxy profile.
#[derive(Debug, Clone)]
pub struct ProxyProfile {
    pub name: String,
    pub listen: SocketAddr,
    pub domains: Vec<String>,
    pub is_default: bool,
    pub strict_host_match: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub accept_proxy_v2: bool,

    pub public_url: Option<Url>,
    pub public_auth_url: Option<Url>,

    pub upstream: UpstreamConfig,
    pub routing: RoutingConfig,
    pub discovery: DiscoveryConfig,
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

    pub fn matrix_uses_ppv2(&self) -> bool {
        self.upstream
            .matrix_send_proxy_v2
            .unwrap_or(self.upstream.send_proxy_v2)
    }

    pub fn auth_uses_ppv2(&self) -> bool {
        self.upstream
            .auth_send_proxy_v2
            .unwrap_or(self.upstream.send_proxy_v2)
    }

    pub fn rtc_uses_ppv2(&self) -> bool {
        self.upstream
            .rtc_send_proxy_v2
            .unwrap_or(self.upstream.send_proxy_v2)
    }
}

/// Profiles grouped onto one physical listening socket (`SocketAddr`).
#[derive(Debug, Clone)]
pub struct ListenerPlan {
    pub listen: SocketAddr,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub accept_proxy_v2: bool,
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

        cfg.apply_env_overrides()?;
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(content).context("failed to parse TOML config")?;
        cfg.normalize_and_validate()?;
        Ok(cfg)
    }

    pub fn into_runtime(mut self) -> Result<RuntimeConfig> {
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
        if let Some(v) = env_non_empty("PUBLIC_URL") {
            self.server.public_url = Some(v);
        }
        if let Some(v) = env_non_empty("PUBLIC_AUTH_URL") {
            self.server.public_auth_url = Some(v);
        }
        if let Some(v) = env_non_empty("TLS_CERT_PATH") {
            self.server.tls_cert_path = Some(v);
        }
        if let Some(v) = env_non_empty("TLS_KEY_PATH") {
            self.server.tls_key_path = Some(v);
        }
        if let Some(v) = env_bool("ACCEPT_PROXY_V2")? {
            self.server.accept_proxy_v2 = v;
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
        if let Some(v) = env_parse::<usize>("PPV2_POOL_MAX_ENTRIES")? {
            self.server.ppv2_pool_max_entries = v;
        }

        if let Some(v) = env_non_empty("MATRIX_UPSTREAM") {
            self.upstream.matrix_url = Some(v);
        }
        if let Some(v) = env_non_empty("AUTH_UPSTREAM") {
            self.upstream.auth_url = Some(v);
        }
        if let Some(v) = env_non_empty("MATRIX_SERVER_NAME") {
            self.upstream.server_name = Some(v);
        }
        if let Some(v) = env_non_empty("RTC_UPSTREAM") {
            self.upstream.rtc_url = Some(v);
        }
        if let Some(v) = env_non_empty("MATRIX_HOST_HEADER") {
            self.upstream.matrix_host_header = Some(v);
        }
        if let Some(v) = env_non_empty("AUTH_HOST_HEADER") {
            self.upstream.auth_host_header = Some(v);
        }
        if let Some(v) = env_non_empty("RTC_HOST_HEADER") {
            self.upstream.rtc_host_header = Some(v);
        }
        if let Some(v) = env_non_empty("REWRITE_ORIGINS") {
            self.upstream.rewrite_origins = split_csv(&v);
        }
        if let Some(v) = env_non_empty("UPSTREAM_PROXY") {
            self.upstream.outbound_proxy = Some(v);
        }
        if let Some(v) = env_non_empty("CLIENT_IP_MODE") {
            self.upstream.client_ip_mode = parse_client_ip_mode(&v)?;
        }
        if let Some(v) = env_bool("SEND_PROXY_V2")? {
            self.upstream.send_proxy_v2 = v;
        }
        if let Some(v) = env_bool("MATRIX_SEND_PROXY_V2")? {
            self.upstream.matrix_send_proxy_v2 = Some(v);
        }
        if let Some(v) = env_bool("AUTH_SEND_PROXY_V2")? {
            self.upstream.auth_send_proxy_v2 = Some(v);
        }
        if let Some(v) = env_bool("RTC_SEND_PROXY_V2")? {
            self.upstream.rtc_send_proxy_v2 = Some(v);
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
        if let Some(v) = env_non_empty("RTC_PREFIX") {
            self.routing.rtc_prefix = v;
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

        Ok(())
    }

    pub fn normalize_and_validate(&mut self) -> Result<()> {
        normalize_http_url_opt(&mut self.server.public_url);
        normalize_http_url_opt(&mut self.server.public_auth_url);
        normalize_opt_string(&mut self.server.tls_cert_path);
        normalize_opt_string(&mut self.server.tls_key_path);
        normalize_http_url_opt(&mut self.upstream.matrix_url);
        normalize_http_url_opt(&mut self.upstream.auth_url);
        normalize_opt_string(&mut self.upstream.server_name);
        normalize_http_url_opt(&mut self.upstream.rtc_url);
        normalize_opt_string(&mut self.upstream.matrix_host_header);
        normalize_opt_string(&mut self.upstream.auth_host_header);
        normalize_opt_string(&mut self.upstream.rtc_host_header);
        normalize_opt_string(&mut self.upstream.outbound_proxy);
        normalize_http_url_opt(&mut self.discovery.identity_server_url);

        if self.server.tls_cert_path.is_some() ^ self.server.tls_key_path.is_some() {
            bail!(
                "server.tls_cert_path and server.tls_key_path must either both be set or both be omitted"
            );
        }

        let _ = parse_trusted_proxies(&self.server.trusted_proxies)?;

        self.routing.auth_prefix =
            normalize_prefix("routing.auth_prefix", &self.routing.auth_prefix)?;
        self.routing.rtc_prefix = normalize_prefix("routing.rtc_prefix", &self.routing.rtc_prefix)?;
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

            let tls_cert_path = opt_trim(raw.tls_cert_path.as_deref())
                .or_else(|| opt_trim(self.server.tls_cert_path.as_deref()));
            let tls_key_path = opt_trim(raw.tls_key_path.as_deref())
                .or_else(|| opt_trim(self.server.tls_key_path.as_deref()));
            if tls_cert_path.is_some() ^ tls_key_path.is_some() {
                bail!(
                    "profile '{name}': tls_cert_path and tls_key_path must both be set or both omitted"
                );
            }
            let accept_proxy_v2 = raw.accept_proxy_v2.unwrap_or(self.server.accept_proxy_v2);

            let mut public_url_str = raw.public_url.clone();
            normalize_http_url_opt(&mut public_url_str);
            let public_url =
                parse_http_url_opt(&format!("proxies[{name}].public_url"), &public_url_str)?;

            let mut public_auth_url_str = raw.public_auth_url.clone();
            normalize_http_url_opt(&mut public_auth_url_str);
            let public_auth_url = parse_http_url_opt(
                &format!("proxies[{name}].public_auth_url"),
                &public_auth_url_str,
            )?;

            let mut upstream = UpstreamConfig {
                matrix_url: raw.matrix_url.clone(),
                auth_url: raw.auth_url.clone(),
                server_name: raw.server_name.clone(),
                rtc_url: raw.rtc_url.clone(),
                matrix_host_header: raw.matrix_host_header.clone(),
                auth_host_header: raw.auth_host_header.clone(),
                rtc_host_header: raw.rtc_host_header.clone(),
                rewrite_origins: raw.rewrite_origins.clone(),
                outbound_proxy: raw
                    .outbound_proxy
                    .clone()
                    .or_else(|| self.upstream.outbound_proxy.clone()),
                client_ip_mode: raw.client_ip_mode.unwrap_or(self.upstream.client_ip_mode),
                send_proxy_v2: raw.send_proxy_v2.unwrap_or(self.upstream.send_proxy_v2),
                matrix_send_proxy_v2: raw
                    .matrix_send_proxy_v2
                    .or(self.upstream.matrix_send_proxy_v2),
                auth_send_proxy_v2: raw.auth_send_proxy_v2.or(self.upstream.auth_send_proxy_v2),
                rtc_send_proxy_v2: raw.rtc_send_proxy_v2.or(self.upstream.rtc_send_proxy_v2),
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
                rtc_prefix: normalize_prefix(
                    &format!("proxies[{name}].rtc_prefix"),
                    raw.rtc_prefix
                        .as_deref()
                        .unwrap_or(&self.routing.rtc_prefix),
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

            let discovery = DiscoveryConfig {
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
            };

            let domains = collect_profile_domains(
                &raw.domains,
                public_url.as_ref(),
                public_auth_url.as_ref(),
            );

            out.push(ProxyProfile {
                name,
                listen,
                domains,
                is_default: raw.default,
                strict_host_match: raw.strict_host_match,
                tls_cert_path,
                tls_key_path,
                accept_proxy_v2,
                public_url,
                public_auth_url,
                upstream,
                routing,
                discovery,
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

        let public_url = parse_http_url_opt("server.public_url", &self.server.public_url)?;
        let public_auth_url =
            parse_http_url_opt("server.public_auth_url", &self.server.public_auth_url)?;

        let mut upstream = self.upstream.clone();
        let parsed_rewrite_origins = validate_upstream("upstream", &mut upstream)?;
        let _ = parse_http_url_opt(
            "discovery.identity_server_url",
            &self.discovery.identity_server_url,
        )?;

        let domains = collect_profile_domains(&[], public_url.as_ref(), public_auth_url.as_ref());

        Ok(ProxyProfile {
            name: "default".to_string(),
            listen,
            domains,
            is_default: true,
            strict_host_match: false,
            tls_cert_path: self.server.tls_cert_path.clone(),
            tls_key_path: self.server.tls_key_path.clone(),
            accept_proxy_v2: self.server.accept_proxy_v2,
            public_url,
            public_auth_url,
            upstream,
            routing: self.routing.clone(),
            discovery: self.discovery.clone(),
            parsed_rewrite_origins,
        })
    }

    pub fn parsed_public_url(&self) -> Option<Url> {
        self.server
            .public_url
            .as_deref()
            .and_then(|s| Url::parse(s).ok())
    }

    pub fn parsed_public_auth_url(&self) -> Option<Url> {
        self.server
            .public_auth_url
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
        let first_ppv2 = group[0].accept_proxy_v2;
        let first_proxy_prefix = group[0].routing.proxy_prefix.clone();

        let is_shared = group.len() > 1;
        let mut seen_domains = HashSet::new();
        let mut default_count = 0usize;

        for p in &group {
            if p.tls_cert_path != first_tls_cert || p.tls_key_path != first_tls_key {
                bail!(
                    "listener {listen}: profiles sharing the same port must use identical TLS settings (conflict in '{}')",
                    p.name
                );
            }
            if p.accept_proxy_v2 != first_ppv2 {
                bail!(
                    "listener {listen}: profiles sharing the same port must use identical accept_proxy_v2 setting (conflict in '{}')",
                    p.name
                );
            }
            if p.is_default {
                default_count += 1;
            }
            if is_shared {
                if p.domains.is_empty() && !p.is_default {
                    bail!(
                        "listener {listen}: profile '{}' shares a port with other profiles and must set `domains` or `public_url` (or `default = true`)",
                        p.name
                    );
                }
                for d in &p.domains {
                    if !seen_domains.insert(d.clone()) {
                        bail!(
                            "listener {listen}: duplicate domain '{d}' claimed by multiple profiles"
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
            accept_proxy_v2: first_ppv2,
            proxy_prefix: first_proxy_prefix,
            profiles: group,
        });
    }

    Ok(listeners)
}

fn validate_upstream(prefix: &str, upstream: &mut UpstreamConfig) -> Result<Vec<String>> {
    normalize_http_url_opt(&mut upstream.matrix_url);
    normalize_http_url_opt(&mut upstream.auth_url);
    normalize_opt_string(&mut upstream.server_name);
    normalize_http_url_opt(&mut upstream.rtc_url);
    normalize_opt_string(&mut upstream.matrix_host_header);
    normalize_opt_string(&mut upstream.auth_host_header);
    normalize_opt_string(&mut upstream.rtc_host_header);
    normalize_opt_string(&mut upstream.outbound_proxy);

    if upstream.matrix_url.is_none() && upstream.server_name.is_none() {
        bail!(
            "{prefix}: configuration requires at least one of matrix_url (MATRIX_UPSTREAM) or server_name (MATRIX_SERVER_NAME)"
        );
    }

    let _ = parse_http_url_opt(&format!("{prefix}.matrix_url"), &upstream.matrix_url)?;
    let _ = parse_http_url_opt(&format!("{prefix}.auth_url"), &upstream.auth_url)?;
    let _ = parse_http_url_opt(&format!("{prefix}.rtc_url"), &upstream.rtc_url)?;

    if let Some(proxy) = &upstream.outbound_proxy {
        let parsed = Url::parse(proxy)
            .with_context(|| format!("invalid {prefix}.outbound_proxy URL: {proxy}"))?;
        match parsed.scheme() {
            "http" | "https" | "socks5" | "socks5h" => {}
            s => bail!(
                "unsupported {prefix}.outbound_proxy scheme '{s}': expected http, https, socks5, or socks5h"
            ),
        }
    }

    let mut rewrite_origins = Vec::new();
    for raw in &upstream.rewrite_origins {
        let mut s = Some(raw.clone());
        normalize_http_url_opt(&mut s);
        if let Some(url) = parse_http_url_opt(&format!("{prefix}.rewrite_origins"), &s)? {
            let origin = origin_string(&url);
            if !rewrite_origins.contains(&origin) {
                rewrite_origins.push(origin);
            }
        }
    }

    Ok(rewrite_origins)
}

fn collect_profile_domains(
    explicit: &[String],
    public_url: Option<&Url>,
    public_auth_url: Option<&Url>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for raw in explicit {
        let cleaned = normalize_domain_entry(raw);
        if !cleaned.is_empty() && seen.insert(cleaned.clone()) {
            out.push(cleaned);
        }
    }
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

fn normalize_domain_entry(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains("://")
        && let Ok(u) = Url::parse(trimmed)
        && let Some(h) = u.host_str()
    {
        return h.to_ascii_lowercase();
    }
    strip_host_port(trimmed).to_ascii_lowercase()
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

fn opt_trim(opt: Option<&str>) -> Option<String> {
    opt.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
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
    fn bare_hostnames_default_to_https() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            public_url = "proxy.example.com"

            [upstream]
            matrix_url = "matrix.example.org"
            auth_url = "https://auth.example.org"
            rtc_url = "rtc.example.org"
            "#,
        )
        .unwrap();

        assert_eq!(
            cfg.server.public_url.as_deref(),
            Some("https://proxy.example.com")
        );
        assert_eq!(
            cfg.upstream.matrix_url.as_deref(),
            Some("https://matrix.example.org")
        );
        assert_eq!(
            cfg.upstream.auth_url.as_deref(),
            Some("https://auth.example.org")
        );
        assert_eq!(
            cfg.upstream.rtc_url.as_deref(),
            Some("https://rtc.example.org")
        );
    }

    #[test]
    fn invalid_scheme_still_rejected() {
        let err = Config::from_toml_str(
            r#"
            [upstream]
            matrix_url = "ftp://matrix.example.org"
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid upstream.matrix_url scheme")
        );
    }

    #[test]
    fn multi_proxy_supports_shared_port_and_custom_ports_simultaneously() {
        let cfg = Config::from_toml_str(
            r#"
            [server]
            listen = "0.0.0.0:8080"

            [[proxies]]
            name = "site-a"
            public_url = "https://a.example.com"
            matrix_url = "https://hs-a.internal:8443"
            send_proxy_v2 = true
            rewrite_origins = ["https://hs-public.example.org"]

            [[proxies]]
            name = "site-b"
            domains = ["b.example.com", "*.b.example.com"]
            public_url = "https://b.example.com"
            matrix_url = "https://hs-b.internal"
            auth_url = "https://auth-b.internal"

            [[proxies]]
            name = "site-c-dedicated"
            listen = "0.0.0.0:8081"
            public_url = "https://c.example.com"
            matrix_url = "https://hs-c.internal"
            "#,
        )
        .unwrap();

        let runtime = cfg.into_runtime().unwrap();
        assert_eq!(runtime.listeners.len(), 2);
        assert_eq!(runtime.listeners[0].listen.port(), 8080);
        assert_eq!(runtime.listeners[0].profiles.len(), 2);
        assert_eq!(
            runtime.listeners[0].profiles[0].domains,
            vec!["a.example.com"]
        );
        assert!(runtime.listeners[0].profiles[0].matrix_uses_ppv2());
        assert_eq!(
            runtime.listeners[0].profiles[0].parsed_rewrite_origins,
            vec!["https://hs-public.example.org"]
        );

        assert_eq!(runtime.listeners[1].listen.port(), 8081);
        assert_eq!(runtime.listeners[1].profiles.len(), 1);
        assert_eq!(runtime.listeners[1].profiles[0].name, "site-c-dedicated");
    }

    #[test]
    fn duplicate_domain_on_shared_port_is_rejected() {
        let err = Config::from_toml_str(
            r#"
            [[proxies]]
            name = "p1"
            public_url = "https://dup.example.com"
            matrix_url = "https://hs1.example.com"

            [[proxies]]
            name = "p2"
            public_url = "https://dup.example.com"
            matrix_url = "https://hs2.example.com"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate domain"));
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
    }
}
