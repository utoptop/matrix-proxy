use crate::config::{ProxyProfile, origin_string};
use crate::ppv2_client::Ppv2Client;
use anyhow::{Context, Result, anyhow};
use http::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct ResolvedUpstreams {
    pub matrix_url: Url,
    pub auth_url: Option<Url>,
    pub rtc_url: Option<Url>,
    pub upstream_well_known: Option<Value>,
    pub discovered_issuer: Option<String>,
    /// Extra auth origins observed dynamically from `auth_metadata` (crucial when `auth_url`
    /// connects via an internal/PPv2 address like `matrix.example.org:8443` while `auth_metadata`
    /// advertises a public origin like `https://auth.example.org`).
    pub observed_auth_origins: Vec<String>,
    /// Precomputed normalized origin strings (avoids repeated `Url` formatting on hot paths).
    pub matrix_origin: String,
    pub auth_origin: String,
    pub rtc_origin: Option<String>,
    pub wk_hs_origin: Option<String>,
}

impl ResolvedUpstreams {
    pub fn new(
        matrix_url: Url,
        auth_url: Option<Url>,
        rtc_url: Option<Url>,
        upstream_well_known: Option<Value>,
        discovered_issuer: Option<String>,
        observed_auth_origins: Vec<String>,
    ) -> Self {
        let matrix_origin = origin_string(&matrix_url);
        let auth_origin = auth_url
            .as_ref()
            .map(origin_string)
            .unwrap_or_else(|| matrix_origin.clone());
        let rtc_origin = rtc_url.as_ref().map(origin_string);
        let wk_hs_origin = upstream_well_known
            .as_ref()
            .and_then(|wk| wk.pointer("/m.homeserver/base_url"))
            .and_then(Value::as_str)
            .and_then(|s| Url::parse(s).ok())
            .map(|u| origin_string(&u));

        Self {
            matrix_url,
            auth_url,
            rtc_url,
            upstream_well_known,
            discovered_issuer,
            observed_auth_origins,
            matrix_origin,
            auth_origin,
            rtc_origin,
            wk_hs_origin,
        }
    }

    pub fn effective_auth_url(&self) -> &Url {
        self.auth_url.as_ref().unwrap_or(&self.matrix_url)
    }

    pub fn auth_is_separate(&self) -> bool {
        self.auth_url.is_some() && self.auth_origin != self.matrix_origin
    }
}

#[derive(Debug, Default)]
struct DiscoveryCache {
    resolved: Option<Arc<ResolvedUpstreams>>,
    dynamic_auth_url: Option<Url>,
    dynamic_issuer: Option<String>,
    observed_auth_origins: Vec<String>,
    last_refresh: Option<Instant>,
}

pub struct DiscoveryManager {
    profile: Arc<ProxyProfile>,
    /// Non-redirecting client for auth_metadata probes.
    client: reqwest::Client,
    /// Redirect-following client (max 3 hops) specifically for `server_name/.well-known/matrix/client`
    /// (e.g. `mozilla.org/.well-known/matrix/client` -> 301 -> `www.mozilla.org/.well-known/matrix/client`).
    well_known_client: reqwest::Client,
    ppv2_client: Option<Arc<Ppv2Client>>,
    cache: RwLock<DiscoveryCache>,
    /// Singleflight mutex preventing concurrent TTL-expiry discovery stampedes.
    refresh_lock: Mutex<()>,
}

impl DiscoveryManager {
    pub fn new(
        profile: Arc<ProxyProfile>,
        client: reqwest::Client,
        well_known_client: reqwest::Client,
        ppv2_client: Option<Arc<Ppv2Client>>,
    ) -> Self {
        Self {
            profile,
            client,
            well_known_client,
            ppv2_client,
            cache: RwLock::new(DiscoveryCache::default()),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn initial_resolve(&self) -> Result<Arc<ResolvedUpstreams>> {
        let resolved = self.refresh_internal(true).await?;
        info!(
            profile = %self.profile.name,
            matrix_upstream = %resolved.matrix_url,
            auth_upstream = %resolved.effective_auth_url(),
            auth_separate = resolved.auth_is_separate(),
            rtc_upstream = ?resolved.rtc_url.as_ref().map(|u| u.as_str()),
            matrix_ppv2 = self.profile.matrix_uses_ppv2(),
            auth_ppv2 = self.profile.auth_uses_ppv2(),
            "upstream discovery initialized"
        );
        Ok(resolved)
    }

    /// Hot-path O(1) `Arc` clone when cache is fresh; singleflight-coalesced when TTL expires.
    pub async fn get_upstreams(&self) -> Result<Arc<ResolvedUpstreams>> {
        let ttl = Duration::from_secs(self.profile.discovery.cache_ttl_secs.max(1));
        {
            let guard = self.cache.read().await;
            if let (Some(resolved), Some(last)) = (&guard.resolved, guard.last_refresh)
                && last.elapsed() < ttl
            {
                return Ok(Arc::clone(resolved));
            }
        }

        // Singleflight: only one concurrent caller refreshes after TTL expiry; others reuse its result.
        let _refresh_guard = self.refresh_lock.lock().await;
        {
            let guard = self.cache.read().await;
            if let (Some(resolved), Some(last)) = (&guard.resolved, guard.last_refresh)
                && last.elapsed() < ttl
            {
                return Ok(Arc::clone(resolved));
            }
        }

        match self.refresh_internal(false).await {
            Ok(fresh) => Ok(fresh),
            Err(err) => {
                let guard = self.cache.read().await;
                if let Some(stale) = &guard.resolved {
                    warn!(
                        profile = %self.profile.name,
                        error = %err,
                        "upstream discovery refresh failed, using cached state"
                    );
                    Ok(Arc::clone(stale))
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Dynamically learns an upstream Auth server URL, issuer, and extra rewrite origins from live `auth_metadata`.
    pub async fn observe_auth_metadata(&self, metadata: &Value) {
        let mut learned_url: Option<Url> = None;
        let mut learned_issuer: Option<String> = None;
        let mut observed_origins: Vec<String> = Vec::new();

        if let Some(issuer) = metadata.get("issuer").and_then(Value::as_str) {
            learned_issuer = Some(issuer.to_string());
            if let Ok(u) = Url::parse(issuer)
                && matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some()
            {
                let orig = origin_string(&u);
                if !observed_origins.contains(&orig) {
                    observed_origins.push(orig);
                }
                learned_url = Some(origin_only_url(&u));
            }
        }

        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "revocation_endpoint",
            "account_management_uri",
        ] {
            if let Some(raw) = metadata.get(key).and_then(Value::as_str)
                && let Ok(u) = Url::parse(raw)
                && matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some()
            {
                let orig = origin_string(&u);
                if !observed_origins.contains(&orig) {
                    observed_origins.push(orig);
                }
                if learned_url.is_none() {
                    learned_url = Some(origin_only_url(&u));
                }
            }
        }

        if learned_url.is_none() && learned_issuer.is_none() && observed_origins.is_empty() {
            return;
        }

        let mut guard = self.cache.write().await;
        let mut snapshot_changed = false;

        for orig in observed_origins {
            if !guard.observed_auth_origins.contains(&orig) {
                guard.observed_auth_origins.push(orig);
                snapshot_changed = true;
            }
        }

        if let Some(issuer) = learned_issuer
            && guard.dynamic_issuer.as_deref() != Some(issuer.as_str())
        {
            guard.dynamic_issuer = Some(issuer);
            snapshot_changed = true;
        }

        if self.profile.upstream.auth_url.is_none()
            && let Some(url) = learned_url
        {
            let changed = guard
                .dynamic_auth_url
                .as_ref()
                .map(|prev| origin_string(prev) != origin_string(&url))
                .unwrap_or(true);
            if changed {
                info!(
                    profile = %self.profile.name,
                    discovered_auth_upstream = %url,
                    "learned auth upstream from live auth_metadata"
                );
                guard.dynamic_auth_url = Some(url);
                snapshot_changed = true;
            }
        }

        if snapshot_changed && let Some(prev) = &guard.resolved {
            let new_auth_url =
                if self.profile.upstream.auth_url.is_none() && guard.dynamic_auth_url.is_some() {
                    guard.dynamic_auth_url.clone()
                } else {
                    prev.auth_url.clone()
                };
            let new_issuer = guard
                .dynamic_issuer
                .clone()
                .or_else(|| prev.discovered_issuer.clone());
            let updated = ResolvedUpstreams::new(
                prev.matrix_url.clone(),
                new_auth_url,
                prev.rtc_url.clone(),
                prev.upstream_well_known.clone(),
                new_issuer,
                guard.observed_auth_origins.clone(),
            );
            guard.resolved = Some(Arc::new(updated));
        }
    }

    async fn refresh_internal(&self, is_startup: bool) -> Result<Arc<ResolvedUpstreams>> {
        let mut upstream_well_known: Option<Value> = None;

        // 1. Try server_name well-known if configured (follows up to 3 HTTP/HTTPS redirects,
        //    e.g. `mozilla.org/.well-known/matrix/client` -> `www.mozilla.org/.well-known/matrix/client`).
        if let Some(server_name) = &self.profile.upstream.server_name {
            let wk_url = build_server_name_well_known_url(server_name)?;
            match self.fetch_json(&wk_url, false, None, true).await {
                Ok(json) => {
                    debug!(profile = %self.profile.name, url = %wk_url, "fetched server_name .well-known/matrix/client");
                    upstream_well_known = Some(json);
                }
                Err(err) => {
                    if self.profile.upstream.matrix_url.is_none() {
                        return Err(err).with_context(|| {
                            format!(
                                "failed to discover matrix_url from server_name '{server_name}' ({wk_url})"
                            )
                        });
                    }
                    debug!(profile = %self.profile.name, url = %wk_url, error = %err, "optional server_name .well-known probe failed");
                }
            }
        }

        // 2. Resolve matrix_url
        let matrix_url = if let Some(explicit) = &self.profile.upstream.matrix_url {
            Url::parse(explicit).context("invalid upstream.matrix_url")?
        } else if let Some(wk) = &upstream_well_known {
            let discovered = wk
                .pointer("/m.homeserver/base_url")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!("upstream /.well-known/matrix/client missing m.homeserver.base_url")
                })?;
            Url::parse(discovered).with_context(|| {
                format!("invalid discovered m.homeserver.base_url '{discovered}'")
            })?
        } else {
            return Err(anyhow!(
                "unable to resolve upstream matrix_url: neither matrix_url nor valid server_name well-known available"
            ));
        };

        let use_matrix_ppv2 = self.profile.matrix_uses_ppv2();
        let matrix_host_ov = self.profile.upstream.matrix_host_header.as_deref();

        // 3. Fallback well-known fetch from matrix_url if needed.
        if upstream_well_known.is_none()
            && self.profile.discovery.merge_upstream_well_known
            && let Ok(wk_url) = matrix_url.join("/.well-known/matrix/client")
        {
            match self
                .fetch_json(&wk_url, use_matrix_ppv2, matrix_host_ov, true)
                .await
            {
                Ok(json) => {
                    debug!(profile = %self.profile.name, url = %wk_url, "fetched matrix_url .well-known/matrix/client");
                    upstream_well_known = Some(json);
                }
                Err(err) => {
                    debug!(profile = %self.profile.name, url = %wk_url, error = %err, "matrix_url .well-known/matrix/client not available");
                }
            }
        }

        // 4. Resolve auth_url & observed origins.
        let mut discovered_issuer = upstream_well_known
            .as_ref()
            .and_then(|wk| wk.pointer("/org.matrix.msc2965.authentication/issuer"))
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let (prev_dyn_auth, prev_dyn_issuer, mut observed_origins) = {
            let guard = self.cache.read().await;
            (
                guard.dynamic_auth_url.clone(),
                guard.dynamic_issuer.clone(),
                guard.observed_auth_origins.clone(),
            )
        };
        if discovered_issuer.is_none() {
            discovered_issuer = prev_dyn_issuer;
        }

        let explicit_auth_url = match &self.profile.upstream.auth_url {
            Some(raw) => Some(Url::parse(raw).context("invalid upstream.auth_url")?),
            None => None,
        };

        let mut auth_url = explicit_auth_url.clone().or(prev_dyn_auth);

        if auth_url.is_none()
            && let Some(issuer) = &discovered_issuer
            && let Ok(u) = Url::parse(issuer)
            && matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
        {
            auth_url = Some(origin_only_url(&u));
        }

        // Probe upstream auth_metadata on startup or when auth_url / issuer still unknown.
        if (auth_url.is_none() || discovered_issuer.is_none() || observed_origins.is_empty())
            && (is_startup || self.profile.upstream.auth_url.is_none())
            && let Some(meta) = self
                .probe_auth_metadata(&matrix_url, use_matrix_ppv2, matrix_host_ov)
                .await
        {
            if let Some(issuer) = meta.get("issuer").and_then(Value::as_str) {
                discovered_issuer = Some(issuer.to_string());
                if let Ok(u) = Url::parse(issuer)
                    && matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some()
                {
                    let orig = origin_string(&u);
                    if !observed_origins.contains(&orig) {
                        observed_origins.push(orig);
                    }
                }
            }
            for key in [
                "authorization_endpoint",
                "token_endpoint",
                "registration_endpoint",
                "issuer",
            ] {
                if let Some(raw) = meta.get(key).and_then(Value::as_str)
                    && let Ok(u) = Url::parse(raw)
                    && matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some()
                {
                    let orig = origin_string(&u);
                    if !observed_origins.contains(&orig) {
                        observed_origins.push(orig);
                    }
                    if auth_url.is_none() {
                        auth_url = Some(origin_only_url(&u));
                    }
                }
            }
        }

        let rtc_url = match &self.profile.upstream.rtc_url {
            Some(raw) => Some(Url::parse(raw).context("invalid upstream.rtc_url")?),
            None => None,
        };

        let resolved = Arc::new(ResolvedUpstreams::new(
            matrix_url,
            auth_url,
            rtc_url,
            upstream_well_known,
            discovered_issuer,
            observed_origins.clone(),
        ));

        let mut guard = self.cache.write().await;
        guard.resolved = Some(Arc::clone(&resolved));
        guard.last_refresh = Some(Instant::now());
        guard.observed_auth_origins = observed_origins;
        if explicit_auth_url.is_none() && resolved.auth_url.is_some() {
            guard.dynamic_auth_url = resolved.auth_url.clone();
        }
        if resolved.discovered_issuer.is_some() {
            guard.dynamic_issuer = resolved.discovered_issuer.clone();
        }

        Ok(resolved)
    }

    async fn probe_auth_metadata(
        &self,
        matrix_url: &Url,
        use_ppv2: bool,
        host_override: Option<&str>,
    ) -> Option<Value> {
        for path in [
            "/_matrix/client/v1/auth_metadata",
            "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
        ] {
            if let Ok(url) = matrix_url.join(path) {
                match self.fetch_json(&url, use_ppv2, host_override, false).await {
                    Ok(json) => {
                        debug!(profile = %self.profile.name, url = %url, "discovered upstream auth_metadata");
                        return Some(json);
                    }
                    Err(err) => {
                        debug!(profile = %self.profile.name, url = %url, error = %err, "auth_metadata probe did not succeed");
                    }
                }
            }
        }
        None
    }

    async fn fetch_json(
        &self,
        url: &Url,
        use_ppv2: bool,
        host_override: Option<&str>,
        follow_redirects: bool,
    ) -> Result<Value> {
        if use_ppv2 && let Some(ppv2) = &self.ppv2_client {
            let mut hdrs = HeaderMap::new();
            hdrs.insert(
                http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            );
            let (status, bytes, _) = ppv2
                .get_bytes(url, host_override, hdrs, Duration::from_secs(10))
                .await?;
            if !status.is_success() {
                anyhow::bail!("GET {url} (PPv2) returned HTTP {status}");
            }
            return serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid JSON from {url}"));
        }

        let http_client = if follow_redirects {
            &self.well_known_client
        } else {
            &self.client
        };

        let mut req = http_client
            .get(url.clone())
            .timeout(Duration::from_secs(10))
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(host_ov) = host_override {
            req = req.header(reqwest::header::HOST, host_ov);
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;

        if !resp.status().is_success() {
            anyhow::bail!("GET {url} returned HTTP {}", resp.status());
        }

        resp.json::<Value>()
            .await
            .with_context(|| format!("invalid JSON from {url}"))
    }
}

fn build_server_name_well_known_url(server_name: &str) -> Result<Url> {
    let trimmed = server_name.trim().trim_end_matches('/');
    let raw = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        format!("{trimmed}/.well-known/matrix/client")
    } else {
        format!("https://{trimmed}/.well-known/matrix/client")
    };
    Url::parse(&raw).with_context(|| format!("invalid server_name '{server_name}'"))
}

pub fn origin_only_url(url: &Url) -> Url {
    Url::parse(&origin_string(url)).unwrap_or_else(|_| url.clone())
}
