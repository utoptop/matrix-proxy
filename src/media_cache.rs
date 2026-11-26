use crate::client_ip::{ClientInfo, apply_upstream_client_ip_headers};
use crate::config::{AvatarThumbSpec, MediaCacheConfig, ProxyProfile};
use crate::metrics::ProxyMetrics;
use crate::ppv2_client::Ppv2Client;
use crate::rewrite::build_upstream_target_url;
use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use bytes::{Bytes, BytesMut};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures_util::{Stream, StreamExt};
use http_body_util::BodyExt;
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{Notify, Semaphore, mpsc};
use tracing::{debug, info, warn};
use url::Url;

const DISK_CACHE_MAGIC: &[u8; 8] = b"MPMC01\0\0";
const MAX_VERIFIED_TOKENS: usize = 4096;
const MAX_OBSERVED_AVATAR_SIZES: usize = 2;
const MAX_EFFECTIVE_AVATAR_SIZES: usize = 4;
const MAX_DECOMPRESSED_SCAN_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PRELOAD_SCAN_RAW_BYTES: usize = 2 * 1024 * 1024;
const PRELOAD_QUEUE_CAPACITY: usize = 128;
const PRELOAD_RECENT_TTL: Duration = Duration::from_secs(600);
const PRELOAD_RECENT_MAX_ENTRIES: usize = 4096;
const MAX_HINTS_PER_PAYLOAD: usize = 48;
const DISK_STREAM_CHUNK_BYTES: usize = 64 * 1024;
pub const IMMUTABLE_MEDIA_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaEndpointFamily {
    /// Matrix v1.11+ authenticated media (`/_matrix/client/v1/media/...`).
    ClientV1,
    /// Matrix MSC3916 unstable authenticated media (`/_matrix/client/unstable/org.matrix.msc3916/media/...`).
    Msc3916,
    /// Legacy media v3 (`/_matrix/media/v3/...`).
    MediaV3,
    /// Legacy media r0 (`/_matrix/media/r0/...`).
    MediaR0,
}

impl MediaEndpointFamily {
    pub fn requires_auth(self) -> bool {
        matches!(self, Self::ClientV1 | Self::Msc3916)
    }

    pub fn base_prefix(self) -> &'static str {
        match self {
            Self::ClientV1 => "/_matrix/client/v1/media",
            Self::Msc3916 => "/_matrix/client/unstable/org.matrix.msc3916/media",
            Self::MediaV3 => "/_matrix/media/v3",
            Self::MediaR0 => "/_matrix/media/r0",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRouteInfo {
    pub family: MediaEndpointFamily,
    pub is_thumbnail: bool,
    pub server_name: String,
    pub media_id: String,
    pub file_name: Option<String>,
    pub thumbnail_spec: Option<AvatarThumbSpec>,
    pub canonical_query: String,
}

impl MediaRouteInfo {
    pub fn requires_auth(&self) -> bool {
        self.family.requires_auth()
    }

    pub fn cache_key(&self, profile_name: &str, upstream_origin: &str) -> String {
        if self.is_thumbnail {
            compute_cache_key_raw(
                profile_name,
                upstream_origin,
                "tn",
                &self.server_name,
                &self.media_id,
                &self.canonical_query,
            )
        } else {
            compute_cache_key_raw(
                profile_name,
                upstream_origin,
                "dl",
                &self.server_name,
                &self.media_id,
                self.file_name.as_deref().unwrap_or(""),
            )
        }
    }

    /// Returns the full-download upstream path matching this thumbnail's endpoint family.
    pub fn full_download_upstream_path(&self) -> String {
        format!(
            "{}/download/{}/{}",
            self.family.base_prefix(),
            self.server_name,
            self.media_id
        )
    }
}

pub fn cache_key_for_download(
    profile_name: &str,
    upstream_origin: &str,
    server_name: &str,
    media_id: &str,
) -> String {
    compute_cache_key_raw(
        profile_name,
        upstream_origin,
        "dl",
        server_name,
        media_id,
        "",
    )
}

pub fn cache_key_for_thumbnail(
    profile_name: &str,
    upstream_origin: &str,
    server_name: &str,
    media_id: &str,
    spec: &AvatarThumbSpec,
) -> String {
    let query = format!(
        "height={}&method={}&width={}",
        spec.height, spec.method, spec.width
    );
    compute_cache_key_raw(
        profile_name,
        upstream_origin,
        "tn",
        server_name,
        media_id,
        &query,
    )
}

fn compute_cache_key_raw(
    profile_name: &str,
    upstream_origin: &str,
    kind: &str,
    server_name: &str,
    media_id: &str,
    extra: &str,
) -> String {
    let raw =
        format!("{profile_name}\0{upstream_origin}\0{kind}\0{server_name}\0{media_id}\0{extra}");
    sha256_hex(raw.as_bytes())
}

/// Parses Matrix Client-Server media download/thumbnail GET/HEAD routes into a canonical descriptor.
pub fn parse_matrix_media_route(method: &Method, url: &Url) -> Option<MediaRouteInfo> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return None;
    }
    let path = url.path();
    let (family, rest) = if let Some(r) = path.strip_prefix("/_matrix/client/v1/media/") {
        (MediaEndpointFamily::ClientV1, r)
    } else if let Some(r) = path.strip_prefix("/_matrix/client/unstable/org.matrix.msc3916/media/")
    {
        (MediaEndpointFamily::Msc3916, r)
    } else if let Some(r) = path.strip_prefix("/_matrix/media/v3/") {
        (MediaEndpointFamily::MediaV3, r)
    } else if let Some(r) = path.strip_prefix("/_matrix/media/r0/") {
        (MediaEndpointFamily::MediaR0, r)
    } else {
        return None;
    };

    let (is_thumbnail, tail) = if let Some(t) = rest.strip_prefix("download/") {
        (false, t)
    } else if let Some(t) = rest.strip_prefix("thumbnail/") {
        (true, t)
    } else {
        return None;
    };

    let segments: Vec<&str> = tail.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 || segments.len() > 3 {
        return None;
    }
    if is_thumbnail && segments.len() != 2 {
        return None;
    }

    let server_name = segments[0];
    let media_id = segments[1];
    if !is_safe_mxc_segment(server_name) || !is_safe_mxc_segment(media_id) {
        return None;
    }
    let file_name = if segments.len() == 3 {
        let name = segments[2];
        if name.contains("..") || name.contains('\0') {
            return None;
        }
        Some(name.to_string())
    } else {
        None
    };

    let (canonical_query, thumbnail_spec) = if is_thumbnail {
        canonicalize_thumbnail_query(url.query())
    } else {
        (String::new(), None)
    };

    Some(MediaRouteInfo {
        family,
        is_thumbnail,
        server_name: server_name.to_string(),
        media_id: media_id.to_string(),
        file_name,
        thumbnail_spec,
        canonical_query,
    })
}

fn canonicalize_thumbnail_query(query: Option<&str>) -> (String, Option<AvatarThumbSpec>) {
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    if let Some(q) = query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            let key = k.to_ascii_lowercase();
            match key.as_str() {
                "width" | "height" => {
                    let val = v.trim().to_ascii_lowercase();
                    if !val.is_empty() {
                        params.insert(key, val);
                    }
                }
                // Per Matrix spec (MSC2705 / v1.11+), omitting `animated` defaults to `false`;
                // normalize `animated=false` / `0` away so preloaded thumbnails match real clients
                // (e.g. Element X / matrix-rust-sdk sending `?method=scale&width=192&height=192&animated=false`).
                "animated" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "true" || val == "1" {
                        params.insert(key, "true".to_string());
                    }
                }
                "allow_redirect" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "true" || val == "1" {
                        params.insert(key, "true".to_string());
                    }
                }
                "method" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "crop" || val == "scale" {
                        params.insert(key, val);
                    }
                }
                // Strip transport-only parameters (`allow_remote`, `timeout_ms`) so identical
                // thumbnails requested with different client timeout settings share 1 cache entry.
                _ => {}
            }
        }
    }

    let spec = params
        .get("width")
        .and_then(|w| w.parse::<u32>().ok())
        .zip(params.get("height").and_then(|h| h.parse::<u32>().ok()))
        .and_then(|(w, h)| {
            if (16..=1024).contains(&w) && (16..=1024).contains(&h) {
                let method = params
                    .get("method")
                    .cloned()
                    .unwrap_or_else(|| "scale".to_string());
                Some(AvatarThumbSpec {
                    width: w,
                    height: h,
                    method,
                })
            } else {
                None
            }
        });

    let canonical = params
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    (canonical, spec)
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let val = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let trimmed = val.trim();
    if trimmed.len() <= 7 {
        return None;
    }
    let (scheme, rest) = trimmed.split_at(7);
    if !scheme.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() { None } else { Some(token) }
}

pub fn is_safe_mxc_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.contains("..")
        && !s.bytes().any(|b| {
            b <= 0x20 || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@' | b'"' | b'\'' | 0x7f)
        })
}

pub fn is_preload_scan_path(method: &Method, path: &str) -> bool {
    if *method == Method::GET {
        return path == "/_matrix/client/v3/sync"
            || path == "/_matrix/client/r0/sync"
            || ((path.starts_with("/_matrix/client/v3/rooms/")
                || path.starts_with("/_matrix/client/r0/rooms/"))
                && (path.ends_with("/messages")
                    || path.ends_with("/state")
                    || path.ends_with("/members")
                    || path.ends_with("/joined_members")))
            || path.starts_with("/_matrix/client/v3/profile/")
            || path.starts_with("/_matrix/client/r0/profile/");
    }
    if *method == Method::POST {
        return path == "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"
            || path == "/_matrix/client/unstable/org.matrix.msc4186/sync"
            || path == "/_matrix/client/unstable/org.matrix.msc3575/sync"
            || path == "/_matrix/client/v4/sync";
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMediaMeta {
    pub content_type: String,
    pub content_disposition: Option<String>,
    pub etag: String,
    pub requires_auth: bool,
    pub body_len: u64,
    pub stored_epoch_secs: u64,
}

#[derive(Debug, Clone)]
pub enum CacheHit {
    Ram {
        meta: CachedMediaMeta,
        data: Bytes,
    },
    Disk {
        meta: CachedMediaMeta,
        path: PathBuf,
        data_offset: u64,
    },
}

impl CacheHit {
    pub fn meta(&self) -> &CachedMediaMeta {
        match self {
            Self::Ram { meta, .. } | Self::Disk { meta, .. } => meta,
        }
    }

    pub fn is_ram(&self) -> bool {
        matches!(self, Self::Ram { .. })
    }
}

struct L1Entry {
    meta: CachedMediaMeta,
    data: Bytes,
    last_seq: u64,
}

#[derive(Default)]
struct L1State {
    entries: HashMap<String, L1Entry>,
    total_bytes: usize,
    seq: u64,
}

struct L2Entry {
    meta: CachedMediaMeta,
    path: PathBuf,
    file_bytes: u64,
    data_offset: u64,
    last_seq: u64,
}

#[derive(Default)]
struct L2State {
    entries: HashMap<String, L2Entry>,
    total_bytes: u64,
    seq: u64,
}

pub enum InFlightOutcome {
    Leader(InFlightGuard),
    Waiter(Arc<Notify>),
}

pub struct InFlightGuard {
    cache: Arc<MediaCache>,
    key: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let notify = {
            let mut map = self
                .cache
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.remove(&self.key)
        };
        if let Some(n) = notify {
            n.notify_waiters();
        }
    }
}

/// Auth-safe two-tier immutable Matrix media cache:
/// - L1 hot RAM LRU (avatars/thumbnails `<= ram_max_item_kb`, strictly capped at `ram_max_mb`)
/// - L2 optional persistent SSD/disk LRU (single atomic file per object, strictly capped at `disk_max_mb`)
/// - Singleflight miss coalescing + verified Bearer token SHA-256 cache + adaptive avatar size tracking.
pub struct MediaCache {
    config: MediaCacheConfig,
    metrics: Arc<ProxyMetrics>,
    ram_max_bytes: usize,
    ram_max_item_bytes: usize,
    disk_max_bytes: u64,
    max_item_bytes: usize,
    auth_ttl: Duration,
    l1: Mutex<L1State>,
    disk_dir: Option<PathBuf>,
    l2: Mutex<L2State>,
    verified_tokens: Mutex<HashMap<[u8; 32], Instant>>,
    observed_avatar_sizes: Mutex<HashMap<String, VecDeque<AvatarThumbSpec>>>,
    in_flight: Mutex<HashMap<String, Arc<Notify>>>,
    tmp_seq: AtomicU64,
}

impl MediaCache {
    pub fn new(config: MediaCacheConfig, metrics: Arc<ProxyMetrics>) -> Arc<Self> {
        let ram_max_bytes = config.ram_max_bytes();
        let ram_max_item_bytes = config.ram_max_item_bytes();
        let disk_max_bytes = config.disk_max_bytes();
        let max_item_bytes = config.max_item_bytes();
        let auth_ttl = Duration::from_secs(config.auth_cache_ttl_secs.clamp(5, 3600));

        let (disk_dir, initial_l2) = if disk_max_bytes > 0
            && let Some(raw_dir) = config
                .dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            match init_disk_cache_dir(Path::new(raw_dir), disk_max_bytes) {
                Ok((dir, state)) => {
                    info!(
                        dir = %dir.display(),
                        existing_entries = state.entries.len(),
                        existing_bytes = state.total_bytes,
                        disk_max_mb = config.disk_max_mb,
                        ram_max_mb = config.ram_max_mb,
                        "media edge cache initialized (L1 RAM + L2 disk)"
                    );
                    (Some(dir), state)
                }
                Err(err) => {
                    warn!(
                        dir = raw_dir,
                        error = %format!("{err:#}"),
                        "media edge cache disk directory unavailable; falling back to L1 RAM cache only"
                    );
                    (None, L2State::default())
                }
            }
        } else {
            info!(
                ram_max_mb = config.ram_max_mb,
                ram_max_item_kb = config.ram_max_item_kb,
                "media edge cache initialized (L1 RAM only)"
            );
            (None, L2State::default())
        };

        metrics.media_cache_ram_bytes.store(0, Ordering::Relaxed);
        metrics
            .media_cache_disk_bytes
            .store(initial_l2.total_bytes, Ordering::Relaxed);

        Arc::new(Self {
            config,
            metrics,
            ram_max_bytes,
            ram_max_item_bytes,
            disk_max_bytes,
            max_item_bytes,
            auth_ttl,
            l1: Mutex::new(L1State::default()),
            disk_dir,
            l2: Mutex::new(initial_l2),
            verified_tokens: Mutex::new(HashMap::new()),
            observed_avatar_sizes: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            tmp_seq: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> &MediaCacheConfig {
        &self.config
    }

    pub fn max_item_bytes(&self) -> usize {
        self.max_item_bytes
    }

    pub fn disk_enabled(&self) -> bool {
        self.disk_dir.is_some()
    }

    pub fn record_verified_token(&self, profile: &str, token: &str) {
        let hash = token_hash(profile, token);
        let now = Instant::now();
        let mut map = self
            .verified_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_VERIFIED_TOKENS && !map.contains_key(&hash) {
            let ttl = self.auth_ttl;
            map.retain(|_, ts| now.duration_since(*ts) < ttl);
            if map.len() >= MAX_VERIFIED_TOKENS {
                // Evict oldest quarter to stay strictly bounded.
                let mut by_age: Vec<([u8; 32], Instant)> =
                    map.iter().map(|(k, v)| (*k, *v)).collect();
                by_age.sort_by_key(|(_, ts)| *ts);
                for (k, _) in by_age.into_iter().take(MAX_VERIFIED_TOKENS / 4) {
                    map.remove(&k);
                }
            }
        }
        map.insert(hash, now);
    }

    pub fn revoke_token(&self, profile: &str, token: &str) {
        let hash = token_hash(profile, token);
        let mut map = self
            .verified_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&hash);
    }

    pub fn is_token_verified(&self, profile: &str, token: &str) -> bool {
        let hash = token_hash(profile, token);
        let now = Instant::now();
        let mut map = self
            .verified_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match map.get(&hash).copied() {
            Some(ts) if now.duration_since(ts) < self.auth_ttl => true,
            Some(_) => {
                map.remove(&hash);
                false
            }
            None => false,
        }
    }

    /// Adaptively remembers the most recent square avatar thumbnail sizes actually requested by
    /// clients on this profile so the preloader warms the exact DPR/dimensions clients ask for.
    pub fn observe_avatar_thumb_size(&self, profile: &str, spec: &AvatarThumbSpec) {
        if spec.width != spec.height || !(24..=256).contains(&spec.width) {
            return;
        }
        let mut map = self
            .observed_avatar_sizes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let queue = map.entry(profile.to_string()).or_default();
        if let Some(pos) = queue.iter().position(|existing| existing == spec) {
            queue.remove(pos);
        }
        queue.push_front(spec.clone());
        while queue.len() > MAX_OBSERVED_AVATAR_SIZES {
            queue.pop_back();
        }
    }

    pub fn effective_avatar_sizes(
        &self,
        profile: &str,
        configured: &[AvatarThumbSpec],
    ) -> Vec<AvatarThumbSpec> {
        let mut out = Vec::with_capacity(MAX_EFFECTIVE_AVATAR_SIZES);
        {
            let map = self
                .observed_avatar_sizes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(observed) = map.get(profile) {
                for spec in observed {
                    if out.len() >= MAX_EFFECTIVE_AVATAR_SIZES {
                        break;
                    }
                    if !out.contains(spec) {
                        out.push(spec.clone());
                    }
                }
            }
        }
        for spec in configured {
            if out.len() >= MAX_EFFECTIVE_AVATAR_SIZES {
                break;
            }
            if !out.contains(spec) {
                out.push(spec.clone());
            }
        }
        out
    }

    pub fn contains_key(&self, key: &str) -> bool {
        {
            let l1 = self.l1.lock().unwrap_or_else(|e| e.into_inner());
            if l1.entries.contains_key(key) {
                return true;
            }
        }
        let l2 = self.l2.lock().unwrap_or_else(|e| e.into_inner());
        l2.entries.contains_key(key)
    }

    pub fn begin_in_flight(self: &Arc<Self>, key: &str) -> InFlightOutcome {
        let mut map = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(notify) = map.get(key) {
            return InFlightOutcome::Waiter(Arc::clone(notify));
        }
        let notify = Arc::new(Notify::new());
        map.insert(key.to_string(), notify);
        InFlightOutcome::Leader(InFlightGuard {
            cache: Arc::clone(self),
            key: key.to_string(),
        })
    }

    pub fn lookup(&self, key: &str, caller_is_verified: bool) -> Option<CacheHit> {
        {
            let mut l1 = self.l1.lock().unwrap_or_else(|e| e.into_inner());
            if l1.entries.contains_key(key) {
                l1.seq = l1.seq.wrapping_add(1);
                let seq = l1.seq;
                if let Some(entry) = l1.entries.get_mut(key) {
                    if entry.meta.requires_auth && !caller_is_verified {
                        return None;
                    }
                    entry.last_seq = seq;
                    return Some(CacheHit::Ram {
                        meta: entry.meta.clone(),
                        data: entry.data.clone(),
                    });
                }
            }
        }

        if self.disk_dir.is_some() {
            let mut l2 = self.l2.lock().unwrap_or_else(|e| e.into_inner());
            if l2.entries.contains_key(key) {
                l2.seq = l2.seq.wrapping_add(1);
                let seq = l2.seq;
                if let Some(entry) = l2.entries.get_mut(key) {
                    if entry.meta.requires_auth && !caller_is_verified {
                        return None;
                    }
                    entry.last_seq = seq;
                    return Some(CacheHit::Disk {
                        meta: entry.meta.clone(),
                        path: entry.path.clone(),
                        data_offset: entry.data_offset,
                    });
                }
            }
        }

        None
    }

    pub fn promote_to_l1(&self, key: &str, meta: CachedMediaMeta, data: Bytes) {
        if self.ram_max_bytes == 0
            || data.len() > self.ram_max_item_bytes
            || data.len() > self.ram_max_bytes
        {
            return;
        }
        let mut l1 = self.l1.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = l1.entries.remove(key) {
            l1.total_bytes = l1.total_bytes.saturating_sub(prev.data.len());
        }
        let mut evicted = 0u64;
        while l1.total_bytes.saturating_add(data.len()) > self.ram_max_bytes
            && !l1.entries.is_empty()
        {
            if let Some(oldest_key) = l1
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seq)
                .map(|(k, _)| k.clone())
                && let Some(removed) = l1.entries.remove(&oldest_key)
            {
                l1.total_bytes = l1.total_bytes.saturating_sub(removed.data.len());
                evicted += 1;
            } else {
                break;
            }
        }
        l1.seq = l1.seq.wrapping_add(1);
        let seq = l1.seq;
        l1.total_bytes = l1.total_bytes.saturating_add(data.len());
        l1.entries.insert(
            key.to_string(),
            L1Entry {
                meta,
                data,
                last_seq: seq,
            },
        );
        self.metrics
            .media_cache_ram_bytes
            .store(l1.total_bytes as u64, Ordering::Relaxed);
        if evicted > 0 {
            self.metrics
                .media_cache_evictions_total
                .fetch_add(evicted, Ordering::Relaxed);
        }
    }

    pub async fn store(&self, key: String, meta: CachedMediaMeta, data: Bytes) {
        if data.len() > self.max_item_bytes {
            return;
        }

        let mut stored_anywhere = false;
        if self.ram_max_bytes > 0
            && data.len() <= self.ram_max_item_bytes
            && data.len() <= self.ram_max_bytes
        {
            self.promote_to_l1(&key, meta.clone(), data.clone());
            stored_anywhere = true;
        }

        if let Some(disk_dir) = &self.disk_dir
            && self.disk_max_bytes > 0
            && (data.len() as u64) < self.disk_max_bytes
        {
            let dir = disk_dir.clone();
            let key_clone = key.clone();
            let meta_clone = meta.clone();
            let data_clone = data.clone();
            let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
            match tokio::task::spawn_blocking(move || {
                write_disk_cache_file(&dir, &key_clone, &meta_clone, &data_clone, seq)
            })
            .await
            {
                Ok(Ok((final_path, file_bytes, data_offset))) => {
                    stored_anywhere = true;
                    let paths_to_delete = {
                        let mut l2 = self.l2.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(prev) = l2.entries.remove(&key) {
                            l2.total_bytes = l2.total_bytes.saturating_sub(prev.file_bytes);
                        }
                        let mut delete_list = Vec::new();
                        while l2.total_bytes.saturating_add(file_bytes) > self.disk_max_bytes
                            && !l2.entries.is_empty()
                        {
                            if let Some(oldest_key) = l2
                                .entries
                                .iter()
                                .min_by_key(|(_, e)| e.last_seq)
                                .map(|(k, _)| k.clone())
                                && let Some(removed) = l2.entries.remove(&oldest_key)
                            {
                                l2.total_bytes = l2.total_bytes.saturating_sub(removed.file_bytes);
                                delete_list.push(removed.path);
                            } else {
                                break;
                            }
                        }
                        l2.seq = l2.seq.wrapping_add(1);
                        let access_seq = l2.seq;
                        l2.total_bytes = l2.total_bytes.saturating_add(file_bytes);
                        l2.entries.insert(
                            key,
                            L2Entry {
                                meta,
                                path: final_path,
                                file_bytes,
                                data_offset,
                                last_seq: access_seq,
                            },
                        );
                        self.metrics
                            .media_cache_disk_bytes
                            .store(l2.total_bytes, Ordering::Relaxed);
                        delete_list
                    };

                    if !paths_to_delete.is_empty() {
                        self.metrics
                            .media_cache_evictions_total
                            .fetch_add(paths_to_delete.len() as u64, Ordering::Relaxed);
                        let _ = tokio::task::spawn_blocking(move || {
                            for p in paths_to_delete {
                                let _ = std::fs::remove_file(p);
                            }
                        })
                        .await;
                    }
                }
                Ok(Err(err)) => {
                    warn!(error = %format!("{err:#}"), "failed to write media object to L2 disk cache");
                }
                Err(err) => {
                    warn!(error = %err, "L2 disk cache writer task panicked");
                }
            }
        }

        if stored_anywhere {
            self.metrics
                .media_cache_stores_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn build_hit_response(
        self: &Arc<Self>,
        key: &str,
        hit: CacheHit,
        method: &Method,
        req_headers: &HeaderMap,
    ) -> Result<Response<Body>> {
        let meta = hit.meta().clone();
        let cache_tag = if hit.is_ram() { "HIT-RAM" } else { "HIT-DISK" };

        if let Some(inm) = req_headers
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            && etag_matches(inm, &meta.etag)
        {
            return Ok(build_common_media_headers(
                Response::builder().status(StatusCode::NOT_MODIFIED),
                &meta,
                cache_tag,
                false,
            )
            .body(Body::empty())?);
        }

        if *method == Method::HEAD {
            return Ok(build_common_media_headers(
                Response::builder().status(StatusCode::OK),
                &meta,
                cache_tag,
                true,
            )
            .header(http::header::CONTENT_LENGTH, meta.body_len.to_string())
            .body(Body::empty())?);
        }

        let range_req = req_headers
            .get(http::header::RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| parse_http_byte_range(raw, meta.body_len));

        if let Some(RangeParse::Unsatisfiable) = range_req {
            return Ok(build_common_media_headers(
                Response::builder().status(StatusCode::RANGE_NOT_SATISFIABLE),
                &meta,
                cache_tag,
                false,
            )
            .header(
                http::header::CONTENT_RANGE,
                format!("bytes */{}", meta.body_len),
            )
            .body(Body::empty())?);
        }

        match (hit, range_req) {
            (CacheHit::Ram { data, .. }, Some(RangeParse::Satisfiable(start, end))) => {
                let start_usize = start as usize;
                let end_usize = end as usize;
                let slice = data.slice(start_usize..=end_usize);
                Ok(build_common_media_headers(
                    Response::builder().status(StatusCode::PARTIAL_CONTENT),
                    &meta,
                    cache_tag,
                    true,
                )
                .header(
                    http::header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", meta.body_len),
                )
                .header(http::header::CONTENT_LENGTH, slice.len().to_string())
                .body(Body::from(slice))?)
            }
            (CacheHit::Ram { data, .. }, None) => Ok(build_common_media_headers(
                Response::builder().status(StatusCode::OK),
                &meta,
                cache_tag,
                true,
            )
            .header(http::header::CONTENT_LENGTH, data.len().to_string())
            .body(Body::from(data))?),
            (
                CacheHit::Disk {
                    path, data_offset, ..
                },
                Some(RangeParse::Satisfiable(start, end)),
            ) => {
                let slice_len = end - start + 1;
                let mut file = tokio::fs::File::open(&path)
                    .await
                    .with_context(|| format!("failed to open L2 cache file {}", path.display()))?;
                file.seek(SeekFrom::Start(data_offset + start)).await?;
                let body = stream_file_region(file, slice_len);
                Ok(build_common_media_headers(
                    Response::builder().status(StatusCode::PARTIAL_CONTENT),
                    &meta,
                    cache_tag,
                    true,
                )
                .header(
                    http::header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", meta.body_len),
                )
                .header(http::header::CONTENT_LENGTH, slice_len.to_string())
                .body(body)?)
            }
            (
                CacheHit::Disk {
                    path, data_offset, ..
                },
                None,
            ) => {
                let mut file = tokio::fs::File::open(&path)
                    .await
                    .with_context(|| format!("failed to open L2 cache file {}", path.display()))?;
                file.seek(SeekFrom::Start(data_offset)).await?;

                if self.ram_max_bytes > 0
                    && meta.body_len <= self.ram_max_item_bytes as u64
                    && meta.body_len <= self.ram_max_bytes as u64
                {
                    let mut buf = Vec::with_capacity(meta.body_len as usize);
                    file.take(meta.body_len).read_to_end(&mut buf).await?;
                    if buf.len() as u64 == meta.body_len {
                        let bytes = Bytes::from(buf);
                        self.promote_to_l1(key, meta.clone(), bytes.clone());
                        return Ok(build_common_media_headers(
                            Response::builder().status(StatusCode::OK),
                            &meta,
                            cache_tag,
                            true,
                        )
                        .header(http::header::CONTENT_LENGTH, bytes.len().to_string())
                        .body(Body::from(bytes))?);
                    }
                    // Truncated disk entry: drop from L2 index and report error so caller falls back to upstream.
                    self.remove_l2_entry(key);
                    return Err(anyhow!("truncated L2 disk cache entry"));
                }

                let body = stream_file_region(file, meta.body_len);
                Ok(build_common_media_headers(
                    Response::builder().status(StatusCode::OK),
                    &meta,
                    cache_tag,
                    true,
                )
                .header(http::header::CONTENT_LENGTH, meta.body_len.to_string())
                .body(body)?)
            }
            (_, Some(RangeParse::Unsatisfiable)) => unreachable!(),
        }
    }

    pub fn remove_l2_entry(&self, key: &str) {
        let removed_path = {
            let mut l2 = self.l2.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = l2.entries.remove(key) {
                l2.total_bytes = l2.total_bytes.saturating_sub(entry.file_bytes);
                self.metrics
                    .media_cache_disk_bytes
                    .store(l2.total_bytes, Ordering::Relaxed);
                Some(entry.path)
            } else {
                None
            }
        };
        if let Some(p) = removed_path {
            let _ = std::fs::remove_file(p);
        }
    }

    pub fn stats_json(&self) -> Value {
        let (l1_entries, l1_bytes) = {
            let l1 = self.l1.lock().unwrap_or_else(|e| e.into_inner());
            (l1.entries.len(), l1.total_bytes)
        };
        let (l2_entries, l2_bytes) = {
            let l2 = self.l2.lock().unwrap_or_else(|e| e.into_inner());
            (l2.entries.len(), l2.total_bytes)
        };
        serde_json::json!({
            "enabled": true,
            "disk_enabled": self.disk_dir.is_some(),
            "ram_max_mb": self.config.ram_max_mb,
            "ram_max_item_kb": self.config.ram_max_item_kb,
            "disk_max_mb": self.config.disk_max_mb,
            "max_item_mb": self.config.max_item_mb,
            "auth_cache_ttl_secs": self.config.auth_cache_ttl_secs,
            "l1_entries": l1_entries,
            "l1_bytes": l1_bytes,
            "l2_entries": l2_entries,
            "l2_bytes": l2_bytes,
            "hits_ram_total": self.metrics.media_cache_hits_ram_total.load(Ordering::Relaxed),
            "hits_disk_total": self.metrics.media_cache_hits_disk_total.load(Ordering::Relaxed),
            "misses_total": self.metrics.media_cache_misses_total.load(Ordering::Relaxed),
            "stores_total": self.metrics.media_cache_stores_total.load(Ordering::Relaxed),
            "evictions_total": self.metrics.media_cache_evictions_total.load(Ordering::Relaxed),
            "preload_enqueued_total": self.metrics.media_preload_enqueued_total.load(Ordering::Relaxed),
            "preload_completed_total": self.metrics.media_preload_completed_total.load(Ordering::Relaxed),
            "preload_skipped_total": self.metrics.media_preload_skipped_total.load(Ordering::Relaxed),
            "preload_errors_total": self.metrics.media_preload_errors_total.load(Ordering::Relaxed),
        })
    }
}

fn build_common_media_headers(
    mut builder: axum::http::response::Builder,
    meta: &CachedMediaMeta,
    cache_tag: &'static str,
    include_representation_headers: bool,
) -> axum::http::response::Builder {
    builder = builder
        .header(http::header::CACHE_CONTROL, IMMUTABLE_MEDIA_CACHE_CONTROL)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::ETAG, &meta.etag)
        .header("x-matrix-proxy-cache", cache_tag)
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(
            http::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        )
        .header(
            http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "X-Requested-With, Content-Type, Authorization, Date, Origin, Accept",
        );

    if include_representation_headers {
        builder = builder.header(http::header::CONTENT_TYPE, &meta.content_type);
        if let Some(disp) = &meta.content_disposition
            && let Ok(hv) = HeaderValue::from_str(disp)
        {
            builder = builder.header(http::header::CONTENT_DISPOSITION, hv);
        }
    }
    builder
}

fn stream_file_region(file: tokio::fs::File, total_len: u64) -> Body {
    let stream = futures_util::stream::unfold((file, total_len), |(mut f, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let to_read = (remaining as usize).min(DISK_STREAM_CHUNK_BYTES);
        let mut buf = vec![0u8; to_read];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((
                    Ok::<Bytes, std::io::Error>(Bytes::from(buf)),
                    (f, remaining - n as u64),
                ))
            }
            Err(err) => Some((Err(err), (f, 0))),
        }
    });
    Body::from_stream(stream)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeParse {
    Satisfiable(u64, u64),
    Unsatisfiable,
}

/// Parses single-range RFC 9110 `Range: bytes=...` headers.
/// Returns `None` for non-bytes or multi-range headers (falling back to standard 200 OK).
pub fn parse_http_byte_range(raw: &str, total_len: u64) -> Option<RangeParse> {
    let trimmed = raw.trim();
    let spec = trimmed
        .strip_prefix("bytes=")
        .or_else(|| trimmed.strip_prefix("BYTES="))?;
    if spec.contains(',') {
        return None;
    }
    let (start_str, end_str) = spec.split_once('-')?;
    let start_str = start_str.trim();
    let end_str = end_str.trim();

    if total_len == 0 {
        return Some(RangeParse::Unsatisfiable);
    }

    if start_str.is_empty() {
        let suffix: u64 = end_str.parse().ok()?;
        if suffix == 0 {
            return Some(RangeParse::Unsatisfiable);
        }
        let start = total_len.saturating_sub(suffix);
        return Some(RangeParse::Satisfiable(start, total_len - 1));
    }

    let start: u64 = start_str.parse().ok()?;
    if start >= total_len {
        return Some(RangeParse::Unsatisfiable);
    }

    let end = if end_str.is_empty() {
        total_len - 1
    } else {
        let parsed_end: u64 = end_str.parse().ok()?;
        if parsed_end < start {
            return Some(RangeParse::Unsatisfiable);
        }
        parsed_end.min(total_len - 1)
    };

    Some(RangeParse::Satisfiable(start, end))
}

fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    let norm_target = strip_weak_etag(etag);
    for raw in if_none_match.split(',') {
        let candidate = raw.trim();
        if candidate == "*" || strip_weak_etag(candidate) == norm_target {
            return true;
        }
    }
    false
}

fn strip_weak_etag(etag: &str) -> &str {
    etag.trim()
        .strip_prefix("W/")
        .or_else(|| etag.trim().strip_prefix("w/"))
        .unwrap_or_else(|| etag.trim())
}

fn init_disk_cache_dir(dir: &Path, disk_max_bytes: u64) -> Result<(PathBuf, L2State)> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create media cache directory {}", dir.display()))?;

    // Verify directory is writable immediately (important for `read_only: true` containers).
    let probe_path = dir.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe_path, b"ok")
        .with_context(|| format!("media cache directory {} is not writable", dir.display()))?;
    let _ = std::fs::remove_file(&probe_path);

    let mut items: Vec<(String, L2Entry, SystemTime)> = Vec::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to scan media cache directory {}", dir.display()))?;
    for entry in entries.flatten() {
        let sub_path = entry.path();
        if !sub_path.is_dir() {
            continue;
        }
        let Ok(sub_entries) = std::fs::read_dir(&sub_path) else {
            continue;
        };
        for file_entry in sub_entries.flatten() {
            let p = file_entry.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.contains(".tmp.") {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            let Some(key) = name.strip_suffix(".cache") else {
                continue;
            };
            if key.len() != 64 {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            match read_disk_cache_header(&p) {
                Ok((meta, file_bytes, data_offset, mtime)) => {
                    items.push((
                        key.to_string(),
                        L2Entry {
                            meta,
                            path: p,
                            file_bytes,
                            data_offset,
                            last_seq: 0,
                        },
                        mtime,
                    ));
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }

    // Order oldest-first so oldest items get lower `last_seq` and get evicted first on overflow.
    items.sort_by_key(|(_, _, mtime)| *mtime);
    let mut state = L2State::default();
    for (key, mut entry, _) in items {
        state.seq = state.seq.wrapping_add(1);
        entry.last_seq = state.seq;
        state.total_bytes = state.total_bytes.saturating_add(entry.file_bytes);
        state.entries.insert(key, entry);
    }

    while state.total_bytes > disk_max_bytes && !state.entries.is_empty() {
        if let Some(oldest_key) = state
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seq)
            .map(|(k, _)| k.clone())
            && let Some(removed) = state.entries.remove(&oldest_key)
        {
            state.total_bytes = state.total_bytes.saturating_sub(removed.file_bytes);
            let _ = std::fs::remove_file(removed.path);
        } else {
            break;
        }
    }

    Ok((dir.to_path_buf(), state))
}

fn read_disk_cache_header(path: &Path) -> Result<(CachedMediaMeta, u64, u64, SystemTime)> {
    let mut f = std::fs::File::open(path)?;
    let fs_meta = f.metadata()?;
    let file_bytes = fs_meta.len();
    let mtime = fs_meta.modified().unwrap_or(UNIX_EPOCH);

    let mut prefix = [0u8; 12];
    f.read_exact(&mut prefix)?;
    if &prefix[..8] != DISK_CACHE_MAGIC {
        anyhow::bail!("invalid media cache header magic");
    }
    let meta_len = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as usize;
    if meta_len == 0 || meta_len > 64 * 1024 {
        anyhow::bail!("invalid media cache metadata length");
    }
    let mut meta_bytes = vec![0u8; meta_len];
    f.read_exact(&mut meta_bytes)?;
    let meta: CachedMediaMeta = serde_json::from_slice(&meta_bytes)?;
    let data_offset = 12u64 + meta_len as u64;
    if data_offset + meta.body_len != file_bytes {
        anyhow::bail!("truncated media cache file");
    }
    Ok((meta, file_bytes, data_offset, mtime))
}

fn write_disk_cache_file(
    dir: &Path,
    key: &str,
    meta: &CachedMediaMeta,
    data: &[u8],
    seq: u64,
) -> Result<(PathBuf, u64, u64)> {
    let shard = &key[..2];
    let shard_dir = dir.join(shard);
    std::fs::create_dir_all(&shard_dir)?;

    let meta_bytes = serde_json::to_vec(meta)?;
    let meta_len = u32::try_from(meta_bytes.len()).context("media cache metadata too large")?;
    let data_offset = 12u64 + meta_bytes.len() as u64;
    let file_bytes = data_offset + data.len() as u64;

    let tmp_path = shard_dir.join(format!("{key}.tmp.{}.{}", std::process::id(), seq));
    let final_path = shard_dir.join(format!("{key}.cache"));

    let write_res = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(DISK_CACHE_MAGIC)?;
        f.write_all(&meta_len.to_be_bytes())?;
        f.write_all(&meta_bytes)?;
        f.write_all(data)?;
        f.flush()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    Ok((final_path, file_bytes, data_offset))
}

/// Zero-latency stream wrapper that yields every chunk straight to the client while accumulating a
/// bounded copy to commit into `MediaCache` once the upstream stream completes cleanly.
pub struct MediaCacheTeeStream<S> {
    inner: Pin<Box<S>>,
    cache: Arc<MediaCache>,
    key: String,
    meta: CachedMediaMeta,
    max_bytes: usize,
    buf: Option<BytesMut>,
    in_flight: Option<InFlightGuard>,
    finished: bool,
}

impl<S> MediaCacheTeeStream<S> {
    pub fn new(
        inner: S,
        cache: Arc<MediaCache>,
        key: String,
        meta: CachedMediaMeta,
        max_bytes: usize,
        initial_capacity: usize,
        in_flight: Option<InFlightGuard>,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            cache,
            key,
            meta,
            max_bytes,
            buf: Some(BytesMut::with_capacity(
                initial_capacity.min(max_bytes).min(256 * 1024),
            )),
            in_flight,
            finished: false,
        }
    }
}

impl<S, E> Stream for MediaCacheTeeStream<S>
where
    S: Stream<Item = std::result::Result<Bytes, E>>,
{
    type Item = std::result::Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(buf) = &mut this.buf {
                    if buf.len().saturating_add(chunk.len()) <= this.max_bytes {
                        buf.extend_from_slice(&chunk);
                    } else {
                        // Oversized stream without Content-Length: release buffer & singleflight guard immediately.
                        this.buf = None;
                        this.in_flight = None;
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.buf = None;
                this.in_flight = None;
                this.finished = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if !this.finished {
                    this.finished = true;
                    if let Some(buf) = this.buf.take() {
                        let data = buf.freeze();
                        let cache = Arc::clone(&this.cache);
                        let key = this.key.clone();
                        let mut meta = this.meta.clone();
                        meta.body_len = data.len() as u64;
                        let guard = this.in_flight.take();
                        tokio::spawn(async move {
                            cache.store(key, meta, data).await;
                            drop(guard);
                        });
                    } else {
                        this.in_flight = None;
                    }
                }
                Poll::Ready(None)
            }
        }
    }
}

/// Zero-latency stream wrapper that tees up to `max_bytes` of `/sync`, Sliding Sync, or room JSON
/// responses so the proactive background preloader can extract `mxc://` URLs with zero client delay.
pub struct PreloadScanTeeStream<S> {
    inner: Pin<Box<S>>,
    max_bytes: usize,
    buf: Option<Vec<u8>>,
    on_complete: Option<Box<dyn FnOnce(Vec<u8>) + Send + 'static>>,
}

impl<S> PreloadScanTeeStream<S> {
    pub fn new<F>(inner: S, max_bytes: usize, on_complete: F) -> Self
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        Self {
            inner: Box::pin(inner),
            max_bytes,
            buf: Some(Vec::new()),
            on_complete: Some(Box::new(on_complete)),
        }
    }
}

impl<S, E> Stream for PreloadScanTeeStream<S>
where
    S: Stream<Item = std::result::Result<Bytes, E>>,
{
    type Item = std::result::Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(buf) = &mut this.buf {
                    if buf.len().saturating_add(chunk.len()) <= this.max_bytes {
                        buf.extend_from_slice(&chunk);
                    } else {
                        this.buf = None;
                        this.on_complete = None;
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.buf = None;
                this.on_complete = None;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if let (Some(buf), Some(cb)) = (this.buf.take(), this.on_complete.take())
                    && !buf.is_empty()
                {
                    cb(buf);
                }
                Poll::Ready(None)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MxcHint {
    /// Room avatar or user/hero avatar (plaintext even in E2EE rooms).
    Avatar { server: String, media_id: String },
    /// Unencrypted image, sticker, or video/image thumbnail URL.
    MediaDownload { server: String, media_id: String },
}

/// Decompresses an optional `gzip`/`deflate`/`br`/`zstd` JSON response (bounded at 8 MiB) and
/// extracts safe `mxc://` avatar & unencrypted media preload hints.
pub fn extract_mxc_hints_from_response(
    raw: &[u8],
    content_encoding: &str,
    max_preload_bytes: u64,
) -> Vec<MxcHint> {
    let decoded = match decode_response_for_scan(raw, content_encoding) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let Ok(val) = serde_json::from_slice::<Value>(&decoded) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_mxc_hints(&val, max_preload_bytes, 0, &mut seen, &mut out);
    out
}

fn decode_response_for_scan(raw: &[u8], content_encoding: &str) -> Option<Vec<u8>> {
    let enc = content_encoding
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match enc.as_str() {
        "" | "identity" => {
            if raw.len() <= MAX_DECOMPRESSED_SCAN_BYTES {
                Some(raw.to_vec())
            } else {
                None
            }
        }
        "gzip" | "x-gzip" => read_bounded(GzDecoder::new(raw), MAX_DECOMPRESSED_SCAN_BYTES),
        "deflate" => read_bounded(ZlibDecoder::new(raw), MAX_DECOMPRESSED_SCAN_BYTES)
            .or_else(|| read_bounded(DeflateDecoder::new(raw), MAX_DECOMPRESSED_SCAN_BYTES)),
        "br" => read_bounded(
            brotli::Decompressor::new(raw, 4096),
            MAX_DECOMPRESSED_SCAN_BYTES,
        ),
        "zstd" => {
            let decoder = ruzstd::decoding::StreamingDecoder::new(raw).ok()?;
            read_bounded(decoder, MAX_DECOMPRESSED_SCAN_BYTES)
        }
        _ => None,
    }
}

fn read_bounded<R: Read>(reader: R, max_bytes: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes as u64) + 1);
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() > max_bytes {
        return None;
    }
    Some(buf)
}

fn collect_mxc_hints(
    val: &Value,
    max_preload_bytes: u64,
    depth: usize,
    seen: &mut HashSet<MxcHint>,
    out: &mut Vec<MxcHint>,
) {
    if depth > 32 || out.len() >= MAX_HINTS_PER_PAYLOAD {
        return;
    }
    match val {
        Value::Object(map) => {
            // Check for Matrix `m.room.avatar` state event (`{"type": "m.room.avatar", "content": {"url": "mxc://..."}}`).
            let is_room_avatar_event = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t == "m.room.avatar");
            if is_room_avatar_event
                && let Some(url) = map
                    .get("content")
                    .and_then(|c| c.get("url"))
                    .and_then(Value::as_str)
                && let Some((server, media_id)) = parse_mxc_uri(url)
            {
                push_hint(MxcHint::Avatar { server, media_id }, seen, out);
                return;
            }

            // Check avatar fields (`avatar`, `avatar_url`) — always plaintext even in E2EE rooms!
            for avatar_key in ["avatar", "avatar_url"] {
                if let Some(url) = map.get(avatar_key).and_then(Value::as_str)
                    && let Some((server, media_id)) = parse_mxc_uri(url)
                {
                    push_hint(MxcHint::Avatar { server, media_id }, seen, out);
                }
            }

            // Check `thumbnail_url` (usually small preview image for images/videos/stickers).
            if let Some(url) = map.get("thumbnail_url").and_then(Value::as_str)
                && let Some((server, media_id)) = parse_mxc_uri(url)
            {
                push_hint(MxcHint::MediaDownload { server, media_id }, seen, out);
            }

            // Check unencrypted media `url` on images/stickers (skip large videos/files).
            if let Some(url) = map.get("url").and_then(Value::as_str)
                && let Some((server, media_id)) = parse_mxc_uri(url)
            {
                let msgtype = map.get("msgtype").and_then(Value::as_str);
                let info = map.get("info").and_then(Value::as_object);
                let mimetype = info
                    .and_then(|i| i.get("mimetype"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let size_opt = info.and_then(|i| i.get("size")).and_then(Value::as_u64);

                let is_image_like = matches!(msgtype, Some("m.image" | "m.sticker"))
                    || mimetype.starts_with("image/")
                    || (msgtype.is_none()
                        && info.is_some_and(|i| i.contains_key("w") && i.contains_key("h"))
                        && !mimetype.starts_with("video/"));

                let within_size = size_opt.map(|sz| sz <= max_preload_bytes).unwrap_or(true);
                if is_image_like && within_size {
                    push_hint(MxcHint::MediaDownload { server, media_id }, seen, out);
                }
            }

            for child in map.values() {
                if out.len() >= MAX_HINTS_PER_PAYLOAD {
                    break;
                }
                if matches!(child, Value::Object(_) | Value::Array(_)) {
                    collect_mxc_hints(child, max_preload_bytes, depth + 1, seen, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                if out.len() >= MAX_HINTS_PER_PAYLOAD {
                    break;
                }
                if matches!(item, Value::Object(_) | Value::Array(_)) {
                    collect_mxc_hints(item, max_preload_bytes, depth + 1, seen, out);
                }
            }
        }
        _ => {}
    }
}

fn push_hint(hint: MxcHint, seen: &mut HashSet<MxcHint>, out: &mut Vec<MxcHint>) {
    if out.len() < MAX_HINTS_PER_PAYLOAD && seen.insert(hint.clone()) {
        out.push(hint);
    }
}

pub fn parse_mxc_uri(raw: &str) -> Option<(String, String)> {
    let rest = raw.trim().strip_prefix("mxc://")?;
    let (server, media_id) = rest.split_once('/')?;
    if !is_safe_mxc_segment(server) || !is_safe_mxc_segment(media_id) {
        return None;
    }
    Some((server.to_string(), media_id.to_string()))
}

#[derive(Debug, Clone)]
struct PreloadJob {
    cache_key: String,
    target_url: Url,
    requires_auth: bool,
    bearer_token: Option<String>,
    client: ClientInfo,
}

/// Bounded proactive background preloader for a single `ProxyInstance`.
/// Worker exits cleanly when `ProxyInstance` is dropped (e.g. during hot reload or shutdown).
pub struct MediaPreloader {
    profile: Arc<ProxyProfile>,
    cache: Arc<MediaCache>,
    metrics: Arc<ProxyMetrics>,
    tx: mpsc::Sender<PreloadJob>,
    recent: Mutex<HashMap<String, Instant>>,
}

impl MediaPreloader {
    pub fn spawn(
        profile: Arc<ProxyProfile>,
        cache: Arc<MediaCache>,
        metrics: Arc<ProxyMetrics>,
        stream_client: reqwest::Client,
        ppv2_client: Option<Arc<Ppv2Client>>,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<PreloadJob>(PRELOAD_QUEUE_CAPACITY);
        let concurrency = profile.media.preload_concurrency.clamp(1, 16);
        let max_bytes = profile
            .media
            .preload_max_item_bytes()
            .min(cache.max_item_bytes());
        let sem = Arc::new(Semaphore::new(concurrency));

        let worker_profile = Arc::clone(&profile);
        let worker_cache = Arc::clone(&cache);
        let worker_metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                if worker_cache.contains_key(&job.cache_key) {
                    worker_metrics
                        .media_preload_skipped_total
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                    break;
                };
                let prof = Arc::clone(&worker_profile);
                let cache = Arc::clone(&worker_cache);
                let metrics = Arc::clone(&worker_metrics);
                let client = stream_client.clone();
                let ppv2 = ppv2_client.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    execute_preload_job(
                        &prof,
                        &cache,
                        &metrics,
                        &client,
                        ppv2.as_deref(),
                        max_bytes,
                        job,
                    )
                    .await;
                });
            }
        });

        Arc::new(Self {
            profile,
            cache,
            metrics,
            tx,
            recent: Mutex::new(HashMap::new()),
        })
    }

    /// Extracts `mxc://` hints from a Matrix JSON payload and enqueues uncached items in background.
    pub fn enqueue_from_json_payload(
        self: &Arc<Self>,
        raw_bytes: Vec<u8>,
        content_encoding: String,
        upstream_matrix_url: Url,
        bearer_token: Option<String>,
        client: ClientInfo,
    ) {
        let this = Arc::clone(self);
        let max_preload_bytes = this.profile.media.preload_max_item_bytes() as u64;
        tokio::spawn(async move {
            let hints = tokio::task::spawn_blocking(move || {
                extract_mxc_hints_from_response(&raw_bytes, &content_encoding, max_preload_bytes)
            })
            .await
            .unwrap_or_default();

            if hints.is_empty() {
                return;
            }

            let upstream_origin = crate::config::origin_string(&upstream_matrix_url);
            let avatar_sizes = this.cache.effective_avatar_sizes(
                &this.profile.name,
                &this.profile.media.preload_avatar_sizes,
            );
            let use_auth_v1 = bearer_token.is_some();
            let base_prefix = if use_auth_v1 {
                MediaEndpointFamily::ClientV1.base_prefix()
            } else {
                MediaEndpointFamily::MediaV3.base_prefix()
            };

            for hint in hints {
                match hint {
                    MxcHint::Avatar { server, media_id } => {
                        for spec in &avatar_sizes {
                            let key = cache_key_for_thumbnail(
                                &this.profile.name,
                                &upstream_origin,
                                &server,
                                &media_id,
                                spec,
                            );
                            let path_q = format!(
                                "{base_prefix}/thumbnail/{server}/{media_id}?width={}&height={}&method={}",
                                spec.width, spec.height, spec.method
                            );
                            let url = build_upstream_target_url(&upstream_matrix_url, &path_q);
                            this.try_enqueue(PreloadJob {
                                cache_key: key,
                                target_url: url,
                                requires_auth: use_auth_v1,
                                bearer_token: bearer_token.clone(),
                                client: client.clone(),
                            });
                        }
                    }
                    MxcHint::MediaDownload { server, media_id } => {
                        let key = cache_key_for_download(
                            &this.profile.name,
                            &upstream_origin,
                            &server,
                            &media_id,
                        );
                        let path = format!("{base_prefix}/download/{server}/{media_id}");
                        let url = build_upstream_target_url(&upstream_matrix_url, &path);
                        this.try_enqueue(PreloadJob {
                            cache_key: key,
                            target_url: url,
                            requires_auth: use_auth_v1,
                            bearer_token: bearer_token.clone(),
                            client: client.clone(),
                        });
                    }
                }
            }
        });
    }

    /// Triggered when a client fetches a `/thumbnail/{server}/{id}`: warms `/download/{server}/{id}`
    /// in background so tapping an image opens instantaneously from edge cache.
    pub fn enqueue_full_download_for_thumbnail(
        &self,
        route: &MediaRouteInfo,
        upstream_matrix_url: &Url,
        bearer_token: Option<String>,
        client: &ClientInfo,
    ) {
        if !self.profile.media.preload_on_thumbnail || !route.is_thumbnail {
            return;
        }
        let upstream_origin = crate::config::origin_string(upstream_matrix_url);
        let key = cache_key_for_download(
            &self.profile.name,
            &upstream_origin,
            &route.server_name,
            &route.media_id,
        );
        let path = route.full_download_upstream_path();
        let url = build_upstream_target_url(upstream_matrix_url, &path);
        self.try_enqueue(PreloadJob {
            cache_key: key,
            target_url: url,
            requires_auth: route.requires_auth() || bearer_token.is_some(),
            bearer_token,
            client: client.clone(),
        });
    }

    fn try_enqueue(&self, job: PreloadJob) {
        if self.cache.contains_key(&job.cache_key) {
            self.metrics
                .media_preload_skipped_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let now = Instant::now();
        {
            let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ts) = recent.get(&job.cache_key)
                && now.duration_since(*ts) < PRELOAD_RECENT_TTL
            {
                self.metrics
                    .media_preload_skipped_total
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            if recent.len() >= PRELOAD_RECENT_MAX_ENTRIES {
                recent.retain(|_, ts| now.duration_since(*ts) < PRELOAD_RECENT_TTL);
                if recent.len() >= PRELOAD_RECENT_MAX_ENTRIES {
                    recent.clear();
                }
            }
            recent.insert(job.cache_key.clone(), now);
        }

        match self.tx.try_send(job) {
            Ok(()) => {
                self.metrics
                    .media_preload_enqueued_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics
                    .media_preload_skipped_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn execute_preload_job(
    profile: &ProxyProfile,
    cache: &Arc<MediaCache>,
    metrics: &ProxyMetrics,
    stream_client: &reqwest::Client,
    ppv2_client: Option<&Ppv2Client>,
    max_bytes: usize,
    job: PreloadJob,
) {
    if cache.contains_key(&job.cache_key) {
        metrics
            .media_preload_skipped_total
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    let _guard = match cache.begin_in_flight(&job.cache_key) {
        InFlightOutcome::Leader(g) => g,
        InFlightOutcome::Waiter(_) => {
            metrics
                .media_preload_skipped_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    out_headers.insert(
        http::header::USER_AGENT,
        HeaderValue::from_static("matrix-proxy-preloader/1.6"),
    );
    if let Some(token) = &job.bearer_token
        && let Ok(hv) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        out_headers.insert(http::header::AUTHORIZATION, hv);
    }
    apply_upstream_client_ip_headers(
        &mut out_headers,
        &job.client,
        profile.upstream.client_ip_mode,
    );

    let matrix_pp = profile.matrix_proxy_protocol();
    let host_override = profile.upstream.upstream_matrix_host_header.as_deref();
    let timeout = Duration::from_secs(15);

    let fetch_res = if matrix_pp.is_enabled()
        && let Some(ppv2) = ppv2_client
    {
        fetch_preload_ppv2(
            ppv2,
            &job.target_url,
            host_override,
            out_headers,
            matrix_pp,
            job.client.client_socket_addr(),
            max_bytes,
            timeout,
        )
        .await
    } else {
        fetch_preload_reqwest(
            stream_client,
            &job.target_url,
            host_override,
            out_headers,
            max_bytes,
            timeout,
        )
        .await
    };

    match fetch_res {
        Ok(PreloadFetchResult::Data {
            content_type,
            content_disposition,
            etag,
            data,
        }) => {
            let meta = CachedMediaMeta {
                content_type,
                content_disposition,
                etag: etag.unwrap_or_else(|| format!("\"{}\"", &job.cache_key[..24])),
                requires_auth: job.requires_auth || job.bearer_token.is_some(),
                body_len: data.len() as u64,
                stored_epoch_secs: now_epoch_secs(),
            };
            cache.store(job.cache_key, meta, data).await;
            metrics
                .media_preload_completed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(PreloadFetchResult::Skipped) => {
            metrics
                .media_preload_skipped_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(err) => {
            metrics
                .media_preload_errors_total
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                profile = %profile.name,
                url = %job.target_url,
                error = %format!("{err:#}"),
                "background media preload failed"
            );
        }
    }
}

enum PreloadFetchResult {
    Data {
        content_type: String,
        content_disposition: Option<String>,
        etag: Option<String>,
        data: Bytes,
    },
    Skipped,
}

async fn fetch_preload_reqwest(
    client: &reqwest::Client,
    url: &Url,
    host_override: Option<&str>,
    headers: HeaderMap,
    max_bytes: usize,
    timeout: Duration,
) -> Result<PreloadFetchResult> {
    let mut req = client.get(url.clone()).timeout(timeout);
    if let Some(h) = host_override {
        req = req.header(reqwest::header::HOST, h);
    }
    for (k, v) in &headers {
        req = req.header(k, v);
    }
    let resp = req.send().await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("upstream returned HTTP {}", resp.status()));
    }
    let resp_headers = resp.headers().clone();
    if !is_cacheable_media_headers(&resp_headers, max_bytes) {
        return Ok(PreloadFetchResult::Skipped);
    }
    let (content_type, content_disposition, etag) = extract_cache_meta_headers(&resp_headers);
    let mut buf = BytesMut::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(PreloadFetchResult::Skipped);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(PreloadFetchResult::Data {
        content_type,
        content_disposition,
        etag,
        data: buf.freeze(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn fetch_preload_ppv2(
    ppv2: &Ppv2Client,
    url: &Url,
    host_override: Option<&str>,
    headers: HeaderMap,
    proxy_protocol: crate::config::ProxyProtocol,
    client_addr: SocketAddr,
    max_bytes: usize,
    timeout: Duration,
) -> Result<PreloadFetchResult> {
    let resp = tokio::time::timeout(
        timeout,
        ppv2.send_request(
            Method::GET,
            url,
            host_override,
            headers,
            Body::empty(),
            proxy_protocol,
            Some(client_addr),
        ),
    )
    .await
    .context("PPv2 preload request timed out")??;

    if resp.status() != StatusCode::OK {
        return Err(anyhow!("upstream returned HTTP {}", resp.status()));
    }
    let resp_headers = resp.headers().clone();
    if !is_cacheable_media_headers(&resp_headers, max_bytes) {
        return Ok(PreloadFetchResult::Skipped);
    }
    let (content_type, content_disposition, etag) = extract_cache_meta_headers(&resp_headers);
    let mut buf = BytesMut::new();
    let mut body = resp.into_body();
    let read_res = tokio::time::timeout(timeout, async {
        while let Some(frame) = body.frame().await {
            let frame = frame.context("PPv2 preload frame read error")?;
            if let Ok(chunk) = frame.into_data() {
                if buf.len().saturating_add(chunk.len()) > max_bytes {
                    return Ok::<bool, anyhow::Error>(false);
                }
                buf.extend_from_slice(&chunk);
            }
        }
        Ok(true)
    })
    .await
    .context("PPv2 preload body timed out")??;

    if !read_res {
        return Ok(PreloadFetchResult::Skipped);
    }
    Ok(PreloadFetchResult::Data {
        content_type,
        content_disposition,
        etag,
        data: buf.freeze(),
    })
}

pub fn is_cacheable_media_headers(headers: &HeaderMap, max_bytes: usize) -> bool {
    if let Some(ce) = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        let enc = ce.trim().to_ascii_lowercase();
        if !enc.is_empty() && enc != "identity" {
            return false;
        }
    }
    if let Some(cl) = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && cl > max_bytes
    {
        return false;
    }
    true
}

pub fn extract_cache_meta_headers(headers: &HeaderMap) -> (String, Option<String>, Option<String>) {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream")
        .to_string();
    let content_disposition = headers
        .get(http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let etag = headers
        .get(http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    (content_type, content_disposition, etag)
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn token_hash(profile: &str, token: &str) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(profile.as_bytes());
    ctx.update(b"\0");
    ctx.update(token.as_bytes());
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn sha256_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let d = digest::digest(&digest::SHA256, input);
    let mut out = String::with_capacity(64);
    for &b in d.as_ref() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    #[test]
    fn media_route_canonicalizes_thumbnail_queries_and_auth_flags() {
        let u1 = Url::parse(
            "https://hs.example.org/_matrix/client/v1/media/thumbnail/example.org/abc123?width=96&method=CROP&height=96&allow_remote=true&timeout_ms=20000&animated=false",
        )
        .unwrap();
        let u2 = Url::parse(
            "https://hs.example.org/_matrix/client/unstable/org.matrix.msc3916/media/thumbnail/example.org/abc123?height=96&width=96&method=crop",
        )
        .unwrap();
        let u_anim = Url::parse(
            "https://hs.example.org/_matrix/client/v1/media/thumbnail/example.org/abc123?height=96&width=96&method=crop&animated=true",
        )
        .unwrap();
        let r1 = parse_matrix_media_route(&Method::GET, &u1).unwrap();
        let r2 = parse_matrix_media_route(&Method::GET, &u2).unwrap();
        let r_anim = parse_matrix_media_route(&Method::GET, &u_anim).unwrap();
        assert!(r1.requires_auth());
        assert!(r2.requires_auth());
        assert_eq!(
            r1.cache_key("p", "https://hs.example.org"),
            r2.cache_key("p", "https://hs.example.org")
        );
        assert_ne!(
            r1.cache_key("p", "https://hs.example.org"),
            r_anim.cache_key("p", "https://hs.example.org")
        );
        assert_eq!(
            r1.cache_key("p", "https://hs.example.org"),
            cache_key_for_thumbnail(
                "p",
                "https://hs.example.org",
                "example.org",
                "abc123",
                &AvatarThumbSpec::parse("96x96:crop").unwrap(),
            )
        );
        assert_eq!(
            r1.full_download_upstream_path(),
            "/_matrix/client/v1/media/download/example.org/abc123"
        );
    }

    #[test]
    fn http_byte_range_parsing_handles_standard_and_edge_cases() {
        assert_eq!(
            parse_http_byte_range("bytes=0-9", 100),
            Some(RangeParse::Satisfiable(0, 9))
        );
        assert_eq!(
            parse_http_byte_range("bytes=90-", 100),
            Some(RangeParse::Satisfiable(90, 99))
        );
        assert_eq!(
            parse_http_byte_range("bytes=-15", 100),
            Some(RangeParse::Satisfiable(85, 99))
        );
        assert_eq!(
            parse_http_byte_range("bytes=100-110", 100),
            Some(RangeParse::Unsatisfiable)
        );
        assert_eq!(parse_http_byte_range("bytes=0-1,2-3", 100), None);
    }

    #[test]
    fn extracts_mxc_hints_from_plain_and_gzip_sliding_sync_json() {
        let payload = serde_json::json!({
            "rooms": {
                "!r1:example.org": {
                    "avatar": "mxc://example.org/roomAvatar1",
                    "heroes": [
                        { "user_id": "@alice:example.org", "avatar": "mxc://example.org/aliceAva" }
                    ],
                    "timeline": [
                        {
                            "type": "m.room.avatar",
                            "content": { "url": "mxc://example.org/stateRoomAva" }
                        },
                        {
                            "type": "m.room.message",
                            "content": {
                                "msgtype": "m.image",
                                "url": "mxc://example.org/photoSmall",
                                "info": { "mimetype": "image/jpeg", "size": 250000, "thumbnail_url": "mxc://example.org/photoThumb" }
                            }
                        },
                        {
                            "type": "m.room.message",
                            "content": {
                                "msgtype": "m.video",
                                "url": "mxc://example.org/hugeVideo",
                                "info": { "mimetype": "video/mp4", "size": 50000000, "thumbnail_url": "mxc://example.org/videoThumb" }
                            }
                        }
                    ]
                }
            }
        });
        let raw = serde_json::to_vec(&payload).unwrap();
        let hints = extract_mxc_hints_from_response(&raw, "", 4 * 1024 * 1024);
        assert!(hints.contains(&MxcHint::Avatar {
            server: "example.org".to_string(),
            media_id: "roomAvatar1".to_string(),
        }));
        assert!(hints.contains(&MxcHint::Avatar {
            server: "example.org".to_string(),
            media_id: "aliceAva".to_string(),
        }));
        assert!(hints.contains(&MxcHint::Avatar {
            server: "example.org".to_string(),
            media_id: "stateRoomAva".to_string(),
        }));
        assert!(hints.contains(&MxcHint::MediaDownload {
            server: "example.org".to_string(),
            media_id: "photoSmall".to_string(),
        }));
        assert!(hints.contains(&MxcHint::MediaDownload {
            server: "example.org".to_string(),
            media_id: "videoThumb".to_string(),
        }));
        // Huge video raw URL must NOT be preloaded
        assert!(!hints.contains(&MxcHint::MediaDownload {
            server: "example.org".to_string(),
            media_id: "hugeVideo".to_string(),
        }));

        // Verify gzip decompression path too
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&raw).unwrap();
        let gz_bytes = gz.finish().unwrap();
        let gz_hints = extract_mxc_hints_from_response(&gz_bytes, "gzip", 4 * 1024 * 1024);
        assert_eq!(gz_hints.len(), hints.len());
    }

    #[tokio::test]
    async fn l1_ram_and_l2_disk_lru_evict_strictly_within_caps_and_enforce_auth() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "matrix-proxy-media-cache-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        let metrics = Arc::new(ProxyMetrics::new());
        let cfg = MediaCacheConfig {
            enabled: true,
            dir: Some(tmp_dir.to_string_lossy().to_string()),
            ram_max_mb: 1,
            ram_max_item_kb: 512,
            disk_max_mb: 2,
            max_item_mb: 2,
            auth_cache_ttl_secs: 60,
        };
        let cache = MediaCache::new(cfg, Arc::clone(&metrics));

        let payload_a = Bytes::from(vec![b'A'; 400 * 1024]);
        let payload_b = Bytes::from(vec![b'B'; 400 * 1024]);
        let payload_c = Bytes::from(vec![b'C'; 400 * 1024]);
        let key_a = sha256_hex(b"key-a");
        let key_b = sha256_hex(b"key-b");
        let key_c = sha256_hex(b"key-c");

        for (k, d, auth) in [
            (&key_a, &payload_a, true),
            (&key_b, &payload_b, true),
            (&key_c, &payload_c, false),
        ] {
            cache
                .store(
                    k.clone(),
                    CachedMediaMeta {
                        content_type: "image/png".to_string(),
                        content_disposition: None,
                        etag: format!("\"{}\"", &k[..16]),
                        requires_auth: auth,
                        body_len: d.len() as u64,
                        stored_epoch_secs: now_epoch_secs(),
                    },
                    d.clone(),
                )
                .await;
        }

        // L1 RAM cap is 1 MiB, so inserting 3x400 KiB must evict key_a from L1 RAM (still on L2 disk!).
        assert!(metrics.media_cache_ram_bytes.load(Ordering::Relaxed) <= 1024 * 1024);
        // Unverified caller MUST NOT get key_a or key_b (requires_auth = true)
        assert!(cache.lookup(&key_a, false).is_none());
        assert!(cache.lookup(&key_b, false).is_none());
        // Public key_c is readable without auth
        assert!(matches!(
            cache.lookup(&key_c, false),
            Some(CacheHit::Ram { .. })
        ));
        // Verified caller gets key_a from L2 disk and key_b from L1 RAM
        assert!(matches!(
            cache.lookup(&key_a, true),
            Some(CacheHit::Disk { .. })
        ));
        assert!(matches!(
            cache.lookup(&key_b, true),
            Some(CacheHit::Ram { .. })
        ));

        // Token verification + immediate revocation
        assert!(!cache.is_token_verified("prof", "syt_secret"));
        cache.record_verified_token("prof", "syt_secret");
        assert!(cache.is_token_verified("prof", "syt_secret"));
        cache.revoke_token("prof", "syt_secret");
        assert!(!cache.is_token_verified("prof", "syt_secret"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
