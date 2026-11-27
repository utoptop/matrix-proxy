use crate::client_ip::{ClientInfo, apply_upstream_client_ip_headers};
use crate::config::{AvatarThumbSpec, MediaCacheConfig, ProxyProfile};
use crate::metrics::ProxyMetrics;
use crate::ppv2_client::Ppv2Client;
use crate::rewrite::build_upstream_target_url;
use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use bytes::{Bytes, BytesMut};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures_util::{Stream, StreamExt};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{Notify, Semaphore, mpsc};
use tracing::{debug, info, warn};
use url::Url;

const DISK_CACHE_MAGIC: &[u8; 8] = b"MPMC01\0\0";
const CACHE_SHARDS: usize = 16;
const MAX_VERIFIED_TOKENS_PER_SHARD: usize = 256; // 4096 total across 16 shards
const NEGATIVE_404_TTL: Duration = Duration::from_secs(300);
const MAX_NEGATIVE_404_PER_SHARD: usize = 256; // 4096 total across 16 shards (~180 KiB max)
const MAX_OBSERVED_AVATAR_SIZES: usize = 2;
const MAX_EFFECTIVE_AVATAR_SIZES: usize = 2;
const MAX_DECOMPRESSED_SCAN_BYTES: usize = 8 * 1024 * 1024;
const STREAM_SCAN_CHUNK_BYTES: usize = 32 * 1024;
const STREAM_SCAN_OVERLAP_BYTES: usize = 1024;
pub const MAX_PRELOAD_SCAN_RAW_BYTES: usize = 2 * 1024 * 1024;
const PRELOAD_QUEUE_CAPACITY: usize = 128;
const PRELOAD_RECENT_TTL: Duration = Duration::from_secs(600);
const PRELOAD_RECENT_MAX_ENTRIES: usize = 4096;
const MAX_HINTS_PER_PAYLOAD: usize = 24;
const DISK_STREAM_CHUNK_BYTES: usize = 64 * 1024;
pub const IMMUTABLE_MEDIA_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// Fixed-size binary SHA-256 cache key (32 bytes inline, zero heap allocations).
pub type CacheKey = [u8; 32];

#[inline]
fn shard_of(key: &CacheKey) -> usize {
    (key[0] as usize) & (CACHE_SHARDS - 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePolicy {
    /// Real client fetch: populate both L1 hot RAM (if small enough) and L2 disk.
    ClientHot,
    /// Background proactive preloader: write L2 disk ONLY when disk is enabled (never evict
    /// hot L1 RAM items); falls back to L1 only in RAM-only mode without disk.
    BackgroundPreload,
}

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

    pub fn cache_key(&self, profile_name: &str, upstream_origin: &str) -> CacheKey {
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

    /// Returns true if this thumbnail looks like a small square avatar (`width == height <= 256`),
    /// which clients almost never tap to fetch a multi-MB full download.
    pub fn is_avatar_sized_thumbnail(&self) -> bool {
        self.is_thumbnail
            && self
                .thumbnail_spec
                .as_ref()
                .is_some_and(|s| s.width == s.height && s.width <= 256)
    }
}

pub fn cache_key_for_download(
    profile_name: &str,
    upstream_origin: &str,
    server_name: &str,
    media_id: &str,
) -> CacheKey {
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
) -> CacheKey {
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
) -> CacheKey {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(profile_name.as_bytes());
    ctx.update(b"\0");
    ctx.update(upstream_origin.as_bytes());
    ctx.update(b"\0");
    ctx.update(kind.as_bytes());
    ctx.update(b"\0");
    ctx.update(server_name.as_bytes());
    ctx.update(b"\0");
    ctx.update(media_id.as_bytes());
    ctx.update(b"\0");
    ctx.update(extra.as_bytes());
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
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
    let mut params: BTreeMap<&'static str, String> = BTreeMap::new();
    if let Some(q) = query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            let key_lower = k.to_ascii_lowercase();
            match key_lower.as_str() {
                "width" => {
                    let val = v.trim().to_ascii_lowercase();
                    if !val.is_empty() {
                        params.insert("width", val);
                    }
                }
                "height" => {
                    let val = v.trim().to_ascii_lowercase();
                    if !val.is_empty() {
                        params.insert("height", val);
                    }
                }
                // Per Matrix spec (MSC2705 / v1.11+), omitting `animated` defaults to `false`;
                // normalize `animated=false` / `0` away so preloaded thumbnails match Element X / matrix-rust-sdk.
                "animated" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "true" || val == "1" {
                        params.insert("animated", "true".to_string());
                    }
                }
                "allow_redirect" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "true" || val == "1" {
                        params.insert("allow_redirect", "true".to_string());
                    }
                }
                "method" => {
                    let val = v.trim().to_ascii_lowercase();
                    if val == "crop" || val == "scale" {
                        params.insert("method", val);
                    }
                }
                // Strip transport-only parameters (`allow_remote`, `timeout_ms`).
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

/// On-disk JSON metadata format (100% compatible with v1.6.x `.cache` files).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMediaMeta {
    pub content_type: String,
    pub content_disposition: Option<String>,
    pub etag: String,
    pub requires_auth: bool,
    pub body_len: u64,
    pub stored_epoch_secs: u64,
}

/// Zero-heap-allocation MIME representation for 99.9% of Matrix media entries in RAM.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompactMime {
    ImagePng,
    ImageJpeg,
    ImageWebp,
    ImageGif,
    ImageAvif,
    ImageSvg,
    VideoMp4,
    VideoWebm,
    AudioOgg,
    AudioMpeg,
    AudioMp4,
    AppOctetStream,
    AppPdf,
    Other(Box<str>),
}

impl CompactMime {
    fn from_str(raw: &str) -> Self {
        match raw {
            "image/png" => Self::ImagePng,
            "image/jpeg" | "image/jpg" => Self::ImageJpeg,
            "image/webp" => Self::ImageWebp,
            "image/gif" => Self::ImageGif,
            "image/avif" => Self::ImageAvif,
            "image/svg+xml" => Self::ImageSvg,
            "video/mp4" => Self::VideoMp4,
            "video/webm" => Self::VideoWebm,
            "audio/ogg" => Self::AudioOgg,
            "audio/mpeg" => Self::AudioMpeg,
            "audio/mp4" => Self::AudioMp4,
            "application/octet-stream" => Self::AppOctetStream,
            "application/pdf" => Self::AppPdf,
            other => Self::Other(other.into()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::ImagePng => "image/png",
            Self::ImageJpeg => "image/jpeg",
            Self::ImageWebp => "image/webp",
            Self::ImageGif => "image/gif",
            Self::ImageAvif => "image/avif",
            Self::ImageSvg => "image/svg+xml",
            Self::VideoMp4 => "video/mp4",
            Self::VideoWebm => "video/webm",
            Self::AudioOgg => "audio/ogg",
            Self::AudioMpeg => "audio/mpeg",
            Self::AudioMp4 => "audio/mp4",
            Self::AppOctetStream => "application/octet-stream",
            Self::AppPdf => "application/pdf",
            Self::Other(s) => s,
        }
    }
}

/// Compact in-memory metadata (~56 bytes inline, 0 heap allocs for standard thumbnails/avatars).
#[derive(Debug, Clone)]
pub struct CompactMeta {
    mime: CompactMime,
    content_disposition: Option<Box<str>>,
    /// `None` means default deterministic ETag (`"<first 24 hex chars of key>"`), saving heap allocs.
    custom_etag: Option<Box<str>>,
    pub requires_auth: bool,
    pub body_len: u64,
    pub stored_epoch_secs: u64,
}

impl CompactMeta {
    pub fn from_cached(key: &CacheKey, meta: &CachedMediaMeta) -> Self {
        let default_etag = default_etag_for_key(key);
        let custom_etag = if meta.etag == default_etag {
            None
        } else {
            Some(meta.etag.clone().into_boxed_str())
        };
        Self {
            mime: CompactMime::from_str(&meta.content_type),
            content_disposition: meta
                .content_disposition
                .as_deref()
                .map(|s| s.to_string().into_boxed_str()),
            custom_etag,
            requires_auth: meta.requires_auth,
            body_len: meta.body_len,
            stored_epoch_secs: meta.stored_epoch_secs,
        }
    }

    pub fn content_type(&self) -> &str {
        self.mime.as_str()
    }

    pub fn etag(&self, key: &CacheKey) -> String {
        match &self.custom_etag {
            Some(e) => e.to_string(),
            None => default_etag_for_key(key),
        }
    }

    pub fn to_disk_meta(&self, key: &CacheKey) -> CachedMediaMeta {
        CachedMediaMeta {
            content_type: self.mime.as_str().to_string(),
            content_disposition: self.content_disposition.as_deref().map(ToString::to_string),
            etag: self.etag(key),
            requires_auth: self.requires_auth,
            body_len: self.body_len,
            stored_epoch_secs: self.stored_epoch_secs,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheHit {
    Ram {
        meta: CompactMeta,
        data: Bytes,
    },
    Disk {
        meta: CompactMeta,
        path: PathBuf,
        data_offset: u64,
    },
}

impl CacheHit {
    pub fn meta(&self) -> &CompactMeta {
        match self {
            Self::Ram { meta, .. } | Self::Disk { meta, .. } => meta,
        }
    }

    pub fn is_ram(&self) -> bool {
        matches!(self, Self::Ram { .. })
    }
}

// =============================================================================
// Strict O(1) Safe Doubly-Linked Arena LRU Map (Zero Unsafe, Zero Linear Scans)
// =============================================================================

const LRU_NONE: usize = usize::MAX;

struct LruNode<V> {
    key: CacheKey,
    value: V,
    bytes: u64,
    prev: usize,
    next: usize,
}

struct LruMap<V> {
    index: AHashMap<CacheKey, usize>,
    nodes: Vec<Option<LruNode<V>>>,
    free_slots: Vec<usize>,
    head: usize, // MRU
    tail: usize, // LRU (evicted in O(1))
    total_bytes: u64,
}

impl<V> Default for LruMap<V> {
    fn default() -> Self {
        Self {
            index: AHashMap::new(),
            nodes: Vec::new(),
            free_slots: Vec::new(),
            head: LRU_NONE,
            tail: LRU_NONE,
            total_bytes: 0,
        }
    }
}

impl<V> LruMap<V> {
    fn len(&self) -> usize {
        self.index.len()
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn contains_key(&self, key: &CacheKey) -> bool {
        self.index.contains_key(key)
    }

    fn get_and_touch(&mut self, key: &CacheKey) -> Option<&V> {
        let &slot = self.index.get(key)?;
        self.move_to_front(slot);
        self.nodes[slot].as_ref().map(|n| &n.value)
    }

    fn insert(&mut self, key: CacheKey, value: V, bytes: u64) -> Option<(CacheKey, V, u64)> {
        let prev = self.remove(&key);
        let slot = if let Some(free) = self.free_slots.pop() {
            self.nodes[free] = Some(LruNode {
                key,
                value,
                bytes,
                prev: LRU_NONE,
                next: self.head,
            });
            free
        } else {
            let slot = self.nodes.len();
            self.nodes.push(Some(LruNode {
                key,
                value,
                bytes,
                prev: LRU_NONE,
                next: self.head,
            }));
            slot
        };
        if self.head != LRU_NONE
            && let Some(old_head) = self.nodes[self.head].as_mut()
        {
            old_head.prev = slot;
        } else {
            self.tail = slot;
        }
        self.head = slot;
        self.index.insert(key, slot);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        prev
    }

    fn remove(&mut self, key: &CacheKey) -> Option<(CacheKey, V, u64)> {
        let slot = self.index.remove(key)?;
        let node = self.nodes[slot].take()?;
        self.unlink_links(node.prev, node.next);
        self.free_slots.push(slot);
        self.total_bytes = self.total_bytes.saturating_sub(node.bytes);
        Some((node.key, node.value, node.bytes))
    }

    fn pop_lru(&mut self) -> Option<(CacheKey, V, u64)> {
        if self.tail == LRU_NONE {
            return None;
        }
        let slot = self.tail;
        let node = self.nodes[slot].take()?;
        self.index.remove(&node.key);
        self.unlink_links(node.prev, node.next);
        self.free_slots.push(slot);
        self.total_bytes = self.total_bytes.saturating_sub(node.bytes);
        Some((node.key, node.value, node.bytes))
    }

    fn move_to_front(&mut self, slot: usize) {
        if self.head == slot {
            return;
        }
        let (prev, next) = match self.nodes[slot].as_ref() {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        self.unlink_links(prev, next);
        if let Some(node) = self.nodes[slot].as_mut() {
            node.prev = LRU_NONE;
            node.next = self.head;
        }
        if self.head != LRU_NONE
            && let Some(old_head) = self.nodes[self.head].as_mut()
        {
            old_head.prev = slot;
        } else {
            self.tail = slot;
        }
        self.head = slot;
    }

    fn unlink_links(&mut self, prev: usize, next: usize) {
        if prev != LRU_NONE {
            if let Some(p) = self.nodes[prev].as_mut() {
                p.next = next;
            }
        } else {
            self.head = next;
        }
        if next != LRU_NONE {
            if let Some(n) = self.nodes[next].as_mut() {
                n.prev = prev;
            }
        } else {
            self.tail = prev;
        }
    }
}

struct L1Entry {
    meta: CompactMeta,
    data: Bytes,
}

struct L2Entry {
    meta: CompactMeta,
    data_offset: u64,
}

#[derive(Clone, Copy)]
struct Negative404Entry {
    cached_at: Instant,
    requires_auth: bool,
}

pub enum InFlightOutcome {
    Leader(InFlightGuard),
    Waiter(Arc<Notify>),
}

pub struct InFlightGuard {
    cache: Arc<MediaCache>,
    key: CacheKey,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let notify = self.cache.in_flight[shard_of(&self.key)]
            .lock()
            .remove(&self.key);
        if let Some(n) = notify {
            n.notify_waiters();
        }
    }
}

/// Auth-safe 16-shard O(1) two-tier immutable Matrix media cache:
/// - L1 hot RAM LRU (16 shards, strict O(1) eviction, ONLY populated by real client traffic unless RAM-only)
/// - L2 optional persistent SSD/disk LRU (16 shards, compact ~64B/entry index with zero PathBuf storage)
/// - 16-shard singleflight miss coalescing + SHA-256 verified Bearer token cache.
pub struct MediaCache {
    config: MediaCacheConfig,
    metrics: Arc<ProxyMetrics>,
    ram_max_bytes: u64,
    ram_shard_cap: u64,
    ram_max_item_bytes: usize,
    disk_max_bytes: u64,
    disk_shard_cap: u64,
    max_item_bytes: usize,
    auth_ttl: Duration,
    l1_shards: Vec<Mutex<LruMap<L1Entry>>>,
    disk_dir: Option<PathBuf>,
    l2_shards: Vec<Mutex<LruMap<L2Entry>>>,
    negative_404: Vec<Mutex<AHashMap<CacheKey, Negative404Entry>>>,
    verified_tokens: Vec<Mutex<AHashMap<CacheKey, Instant>>>,
    observed_avatar_sizes: Mutex<AHashMap<String, VecDeque<AvatarThumbSpec>>>,
    in_flight: Vec<Mutex<AHashMap<CacheKey, Arc<Notify>>>>,
    tmp_seq: AtomicU64,
}

impl MediaCache {
    pub fn new(config: MediaCacheConfig, metrics: Arc<ProxyMetrics>) -> Arc<Self> {
        let ram_max_bytes = config.ram_max_bytes() as u64;
        let ram_max_item_bytes = config.ram_max_item_bytes();
        let disk_max_bytes = config.disk_max_bytes();
        let max_item_bytes = config.max_item_bytes();
        let auth_ttl = Duration::from_secs(config.auth_cache_ttl_secs.clamp(5, 3600));

        let ram_shard_cap = if ram_max_bytes == 0 {
            0
        } else {
            (ram_max_bytes / CACHE_SHARDS as u64).max(ram_max_item_bytes as u64)
        };
        let disk_shard_cap = if disk_max_bytes == 0 {
            0
        } else {
            (disk_max_bytes / CACHE_SHARDS as u64).max(max_item_bytes as u64)
        };

        let mut l2_shards: Vec<LruMap<L2Entry>> =
            (0..CACHE_SHARDS).map(|_| LruMap::default()).collect();
        let mut initial_disk_bytes = 0u64;

        let disk_dir = if disk_max_bytes > 0
            && let Some(raw_dir) = config
                .dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            match init_disk_cache_dir(Path::new(raw_dir), disk_shard_cap, &mut l2_shards) {
                Ok((dir, entries, total_bytes)) => {
                    initial_disk_bytes = total_bytes;
                    info!(
                        dir = %dir.display(),
                        existing_entries = entries,
                        existing_bytes = initial_disk_bytes,
                        disk_max_mb = config.disk_max_mb,
                        ram_max_mb = config.ram_max_mb,
                        shards = CACHE_SHARDS,
                        "media edge cache initialized (16-shard O(1) L1 RAM + L2 disk)"
                    );
                    Some(dir)
                }
                Err(err) => {
                    warn!(
                        dir = raw_dir,
                        error = %format!("{err:#}"),
                        "media edge cache disk directory unavailable; falling back to L1 RAM cache only"
                    );
                    None
                }
            }
        } else {
            info!(
                ram_max_mb = config.ram_max_mb,
                ram_max_item_kb = config.ram_max_item_kb,
                shards = CACHE_SHARDS,
                "media edge cache initialized (16-shard O(1) L1 RAM only)"
            );
            None
        };

        metrics.media_cache_ram_bytes.store(0, Ordering::Relaxed);
        metrics
            .media_cache_disk_bytes
            .store(initial_disk_bytes, Ordering::Relaxed);

        let l1_shards = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(LruMap::default()))
            .collect();
        let l2_shards = l2_shards.into_iter().map(Mutex::new).collect();
        let negative_404 = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(AHashMap::with_capacity(16)))
            .collect();
        let verified_tokens = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(AHashMap::with_capacity(16)))
            .collect();
        let in_flight = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(AHashMap::with_capacity(8)))
            .collect();

        Arc::new(Self {
            config,
            metrics,
            ram_max_bytes,
            ram_shard_cap,
            ram_max_item_bytes,
            disk_max_bytes,
            disk_shard_cap,
            max_item_bytes,
            auth_ttl,
            l1_shards,
            disk_dir,
            l2_shards,
            negative_404,
            verified_tokens,
            observed_avatar_sizes: Mutex::new(AHashMap::with_capacity(8)),
            in_flight,
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
        let mut map = self.verified_tokens[shard_of(&hash)].lock();
        if map.len() >= MAX_VERIFIED_TOKENS_PER_SHARD && !map.contains_key(&hash) {
            let ttl = self.auth_ttl;
            map.retain(|_, ts| now.duration_since(*ts) < ttl);
            if map.len() >= MAX_VERIFIED_TOKENS_PER_SHARD {
                map.clear();
            }
        }
        map.insert(hash, now);
    }

    pub fn revoke_token(&self, profile: &str, token: &str) {
        let hash = token_hash(profile, token);
        self.verified_tokens[shard_of(&hash)].lock().remove(&hash);
    }

    pub fn is_token_verified(&self, profile: &str, token: &str) -> bool {
        let hash = token_hash(profile, token);
        let now = Instant::now();
        let mut map = self.verified_tokens[shard_of(&hash)].lock();
        match map.get(&hash).copied() {
            Some(ts) if now.duration_since(ts) < self.auth_ttl => true,
            Some(_) => {
                map.remove(&hash);
                false
            }
            None => false,
        }
    }

    /// Records a bounded short-TTL (5m) negative cache entry for upstream `404 Not Found` media
    /// responses so client retry loops for missing/deleted avatars never hammer upstream homeservers.
    pub fn record_negative_404(&self, key: &CacheKey, requires_auth: bool) {
        let now = Instant::now();
        let mut map = self.negative_404[shard_of(key)].lock();
        if map.len() >= MAX_NEGATIVE_404_PER_SHARD && !map.contains_key(key) {
            map.retain(|_, e| now.saturating_duration_since(e.cached_at) < NEGATIVE_404_TTL);
            if map.len() >= MAX_NEGATIVE_404_PER_SHARD {
                map.clear();
            }
        }
        map.insert(
            *key,
            Negative404Entry {
                cached_at: now,
                requires_auth,
            },
        );
    }

    /// Returns true if `key` recently returned `404 Not Found` and caller is authorized to see it.
    pub fn is_negatively_cached(&self, key: &CacheKey, caller_is_verified: bool) -> bool {
        let now = Instant::now();
        let mut map = self.negative_404[shard_of(key)].lock();
        match map.get(key).copied() {
            Some(entry) if now.saturating_duration_since(entry.cached_at) < NEGATIVE_404_TTL => {
                !entry.requires_auth || caller_is_verified
            }
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    /// Returns true if `key` is negatively cached (used by background preloader to skip dead media).
    pub fn has_any_negative_404(&self, key: &CacheKey) -> bool {
        let now = Instant::now();
        let mut map = self.negative_404[shard_of(key)].lock();
        match map.get(key).copied() {
            Some(entry) if now.saturating_duration_since(entry.cached_at) < NEGATIVE_404_TTL => {
                true
            }
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    pub fn clear_negative_404(&self, key: &CacheKey) {
        self.negative_404[shard_of(key)].lock().remove(key);
    }

    /// Builds an instant `<0.1ms` Matrix `M_NOT_FOUND` response for a negative-cache hit.
    pub fn build_negative_404_response(method: &Method) -> Response<Body> {
        const BODY_BYTES: &[u8] = b"{\"errcode\":\"M_NOT_FOUND\",\"error\":\"Media not found\"}";
        let body = if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(Bytes::from_static(BODY_BYTES))
        };
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::CONTENT_LENGTH, BODY_BYTES.len().to_string())
            .header(http::header::CACHE_CONTROL, "public, max-age=300")
            .header("x-matrix-proxy-cache", "NEG-404")
            .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(
                http::header::ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            )
            .header(
                http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                "X-Requested-With, Content-Type, Authorization, Date, Origin, Accept",
            )
            .body(body)
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    /// Adaptively remembers the most recent square avatar thumbnail sizes actually requested by
    /// clients on this profile so the preloader warms the exact DPR/dimensions clients ask for.
    pub fn observe_avatar_thumb_size(&self, profile: &str, spec: &AvatarThumbSpec) {
        if spec.width != spec.height || !(24..=256).contains(&spec.width) {
            return;
        }
        let mut map = self.observed_avatar_sizes.lock();
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
            let map = self.observed_avatar_sizes.lock();
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

    pub fn contains_key(&self, key: &CacheKey) -> bool {
        let s = shard_of(key);
        if self.l1_shards[s].lock().contains_key(key) {
            return true;
        }
        self.disk_dir.is_some() && self.l2_shards[s].lock().contains_key(key)
    }

    pub fn begin_in_flight(self: &Arc<Self>, key: &CacheKey) -> InFlightOutcome {
        let mut map = self.in_flight[shard_of(key)].lock();
        if let Some(notify) = map.get(key) {
            return InFlightOutcome::Waiter(Arc::clone(notify));
        }
        let notify = Arc::new(Notify::new());
        map.insert(*key, notify);
        InFlightOutcome::Leader(InFlightGuard {
            cache: Arc::clone(self),
            key: *key,
        })
    }

    pub fn lookup(&self, key: &CacheKey, caller_is_verified: bool) -> Option<CacheHit> {
        let s = shard_of(key);
        {
            let mut l1 = self.l1_shards[s].lock();
            if let Some(entry) = l1.get_and_touch(key) {
                if entry.meta.requires_auth && !caller_is_verified {
                    return None;
                }
                return Some(CacheHit::Ram {
                    meta: entry.meta.clone(),
                    data: entry.data.clone(),
                });
            }
        }

        if let Some(dir) = &self.disk_dir {
            let mut l2 = self.l2_shards[s].lock();
            if let Some(entry) = l2.get_and_touch(key) {
                if entry.meta.requires_auth && !caller_is_verified {
                    return None;
                }
                return Some(CacheHit::Disk {
                    meta: entry.meta.clone(),
                    path: disk_path_for_key(dir, key),
                    data_offset: entry.data_offset,
                });
            }
        }

        None
    }

    pub fn promote_to_l1(&self, key: &CacheKey, meta: CompactMeta, data: Bytes) {
        let item_len = data.len() as u64;
        if self.ram_max_bytes == 0
            || data.len() > self.ram_max_item_bytes
            || item_len > self.ram_shard_cap
        {
            return;
        }
        let s = shard_of(key);
        let mut l1 = self.l1_shards[s].lock();
        let before = l1.total_bytes();
        let _ = l1.remove(key);

        let mut evicted = 0u64;
        while l1.total_bytes().saturating_add(item_len) > self.ram_shard_cap
            && l1.pop_lru().is_some()
        {
            evicted += 1;
        }
        l1.insert(*key, L1Entry { meta, data }, item_len);
        let after = l1.total_bytes();
        drop(l1);

        update_atomic_gauge(&self.metrics.media_cache_ram_bytes, before, after);
        if evicted > 0 {
            self.metrics
                .media_cache_evictions_total
                .fetch_add(evicted, Ordering::Relaxed);
        }
    }

    pub async fn store(&self, key: CacheKey, meta: CompactMeta, data: Bytes, policy: StorePolicy) {
        if data.len() > self.max_item_bytes {
            return;
        }

        let mut stored_anywhere = false;
        let should_promote_l1 = match policy {
            StorePolicy::ClientHot => true,
            // Background preload NEVER evicts hot L1 RAM when L2 disk is active.
            StorePolicy::BackgroundPreload => self.disk_dir.is_none(),
        };

        if should_promote_l1
            && self.ram_max_bytes > 0
            && data.len() <= self.ram_max_item_bytes
            && (data.len() as u64) <= self.ram_shard_cap
        {
            self.promote_to_l1(&key, meta.clone(), data.clone());
            stored_anywhere = true;
        }

        if let Some(disk_dir) = &self.disk_dir
            && self.disk_max_bytes > 0
            && (data.len() as u64) < self.disk_shard_cap
        {
            let dir = disk_dir.clone();
            let disk_meta = meta.to_disk_meta(&key);
            let data_clone = data.clone();
            let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
            match tokio::task::spawn_blocking(move || {
                write_disk_cache_file(&dir, &key, &disk_meta, &data_clone, seq)
            })
            .await
            {
                Ok(Ok((file_bytes, data_offset))) => {
                    stored_anywhere = true;
                    let s = shard_of(&key);
                    let mut keys_to_delete: Vec<CacheKey> = Vec::new();
                    let (before, after) = {
                        let mut l2 = self.l2_shards[s].lock();
                        let before = l2.total_bytes();
                        let _ = l2.remove(&key);
                        while l2.total_bytes().saturating_add(file_bytes) > self.disk_shard_cap {
                            if let Some((evicted_key, _, _)) = l2.pop_lru() {
                                keys_to_delete.push(evicted_key);
                            } else {
                                break;
                            }
                        }
                        l2.insert(key, L2Entry { meta, data_offset }, file_bytes);
                        (before, l2.total_bytes())
                    };
                    update_atomic_gauge(&self.metrics.media_cache_disk_bytes, before, after);

                    if !keys_to_delete.is_empty() {
                        self.metrics
                            .media_cache_evictions_total
                            .fetch_add(keys_to_delete.len() as u64, Ordering::Relaxed);
                        let dir_for_rm = disk_dir.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            for k in keys_to_delete {
                                let _ = std::fs::remove_file(disk_path_for_key(&dir_for_rm, &k));
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
            self.clear_negative_404(&key);
            self.metrics
                .media_cache_stores_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn build_hit_response(
        self: &Arc<Self>,
        key: &CacheKey,
        hit: CacheHit,
        method: &Method,
        req_headers: &HeaderMap,
    ) -> Result<Response<Body>> {
        let meta = hit.meta().clone();
        let etag = meta.etag(key);
        let cache_tag = if hit.is_ram() { "HIT-RAM" } else { "HIT-DISK" };

        if let Some(inm) = req_headers
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            && etag_matches(inm, &etag)
        {
            return Ok(build_common_media_headers(
                Response::builder().status(StatusCode::NOT_MODIFIED),
                &meta,
                &etag,
                cache_tag,
                false,
            )
            .body(Body::empty())?);
        }

        if *method == Method::HEAD {
            return Ok(build_common_media_headers(
                Response::builder().status(StatusCode::OK),
                &meta,
                &etag,
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
                &etag,
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
                let slice = data.slice((start as usize)..=(end as usize));
                Ok(build_common_media_headers(
                    Response::builder().status(StatusCode::PARTIAL_CONTENT),
                    &meta,
                    &etag,
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
                &etag,
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
                    &etag,
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

                // Promote genuinely client-accessed small items from L2 SSD into L1 hot RAM!
                if self.ram_max_bytes > 0
                    && meta.body_len <= self.ram_max_item_bytes as u64
                    && meta.body_len <= self.ram_shard_cap
                {
                    let mut buf = Vec::with_capacity(meta.body_len as usize);
                    file.take(meta.body_len).read_to_end(&mut buf).await?;
                    if buf.len() as u64 == meta.body_len {
                        let bytes = Bytes::from(buf);
                        self.promote_to_l1(key, meta.clone(), bytes.clone());
                        return Ok(build_common_media_headers(
                            Response::builder().status(StatusCode::OK),
                            &meta,
                            &etag,
                            cache_tag,
                            true,
                        )
                        .header(http::header::CONTENT_LENGTH, bytes.len().to_string())
                        .body(Body::from(bytes))?);
                    }
                    self.remove_l2_entry(key);
                    return Err(anyhow!("truncated L2 disk cache entry"));
                }

                let body = stream_file_region(file, meta.body_len);
                Ok(build_common_media_headers(
                    Response::builder().status(StatusCode::OK),
                    &meta,
                    &etag,
                    cache_tag,
                    true,
                )
                .header(http::header::CONTENT_LENGTH, meta.body_len.to_string())
                .body(body)?)
            }
            (_, Some(RangeParse::Unsatisfiable)) => unreachable!(),
        }
    }

    pub fn remove_l2_entry(&self, key: &CacheKey) {
        let s = shard_of(key);
        let (before, after, removed) = {
            let mut l2 = self.l2_shards[s].lock();
            let before = l2.total_bytes();
            let removed = l2.remove(key).is_some();
            (before, l2.total_bytes(), removed)
        };
        if removed {
            update_atomic_gauge(&self.metrics.media_cache_disk_bytes, before, after);
            if let Some(dir) = &self.disk_dir {
                let _ = std::fs::remove_file(disk_path_for_key(dir, key));
            }
        }
    }

    pub fn stats_json(&self) -> Value {
        let mut l1_entries = 0usize;
        let mut l1_bytes = 0u64;
        for shard in &self.l1_shards {
            let g = shard.lock();
            l1_entries += g.len();
            l1_bytes += g.total_bytes();
        }
        let mut l2_entries = 0usize;
        let mut l2_bytes = 0u64;
        for shard in &self.l2_shards {
            let g = shard.lock();
            l2_entries += g.len();
            l2_bytes += g.total_bytes();
        }
        let mut negative_entries = 0usize;
        for shard in &self.negative_404 {
            negative_entries += shard.lock().len();
        }
        serde_json::json!({
            "enabled": true,
            "shards": CACHE_SHARDS,
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
            "negative_entries": negative_entries,
            "hits_ram_total": self.metrics.media_cache_hits_ram_total.load(Ordering::Relaxed),
            "hits_disk_total": self.metrics.media_cache_hits_disk_total.load(Ordering::Relaxed),
            "negative_hits_total": self.metrics.media_cache_negative_hits_total.load(Ordering::Relaxed),
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

fn update_atomic_gauge(gauge: &AtomicU64, before: u64, after: u64) {
    if after >= before {
        gauge.fetch_add(after - before, Ordering::Relaxed);
    } else {
        let delta = before - after;
        let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            Some(cur.saturating_sub(delta))
        });
    }
}

fn build_common_media_headers(
    mut builder: axum::http::response::Builder,
    meta: &CompactMeta,
    etag: &str,
    cache_tag: &'static str,
    include_representation_headers: bool,
) -> axum::http::response::Builder {
    builder = builder
        .header(http::header::CACHE_CONTROL, IMMUTABLE_MEDIA_CACHE_CONTROL)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::ETAG, etag)
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
        builder = builder.header(http::header::CONTENT_TYPE, meta.content_type());
        if let Some(disp) = meta.content_disposition.as_deref()
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

fn disk_path_for_key(dir: &Path, key: &CacheKey) -> PathBuf {
    let hex = encode_hex(key);
    dir.join(&hex[..2]).join(format!("{hex}.cache"))
}

fn init_disk_cache_dir(
    dir: &Path,
    disk_shard_cap: u64,
    shards: &mut [LruMap<L2Entry>],
) -> Result<(PathBuf, usize, u64)> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create media cache directory {}", dir.display()))?;

    let probe_path = dir.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe_path, b"ok")
        .with_context(|| format!("media cache directory {} is not writable", dir.display()))?;
    let _ = std::fs::remove_file(&probe_path);

    let mut items: Vec<(CacheKey, CompactMeta, u64, u64, SystemTime)> = Vec::new();
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
            let Some(hex_key) = name.strip_suffix(".cache") else {
                continue;
            };
            let Some(key) = decode_hex_key(hex_key) else {
                let _ = std::fs::remove_file(&p);
                continue;
            };
            match read_disk_cache_header(&p) {
                Ok((meta, file_bytes, data_offset, mtime)) => {
                    let compact = CompactMeta::from_cached(&key, &meta);
                    items.push((key, compact, file_bytes, data_offset, mtime));
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }

    // Insert oldest-first so oldest items naturally sit at each shard's LRU tail.
    items.sort_by_key(|(_, _, _, _, mtime)| *mtime);
    for (key, meta, file_bytes, data_offset, _) in items {
        let shard = &mut shards[shard_of(&key)];
        shard.insert(key, L2Entry { meta, data_offset }, file_bytes);
    }

    let mut total_entries = 0usize;
    let mut total_bytes = 0u64;
    for shard in shards.iter_mut() {
        while shard.total_bytes() > disk_shard_cap {
            if let Some((evicted_key, _, _)) = shard.pop_lru() {
                let _ = std::fs::remove_file(disk_path_for_key(dir, &evicted_key));
            } else {
                break;
            }
        }
        total_entries += shard.len();
        total_bytes = total_bytes.saturating_add(shard.total_bytes());
    }

    Ok((dir.to_path_buf(), total_entries, total_bytes))
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
    key: &CacheKey,
    meta: &CachedMediaMeta,
    data: &[u8],
    seq: u64,
) -> Result<(u64, u64)> {
    let hex = encode_hex(key);
    let shard_dir = dir.join(&hex[..2]);
    std::fs::create_dir_all(&shard_dir)?;

    let meta_bytes = serde_json::to_vec(meta)?;
    let meta_len = u32::try_from(meta_bytes.len()).context("media cache metadata too large")?;
    let data_offset = 12u64 + meta_bytes.len() as u64;
    let file_bytes = data_offset + data.len() as u64;

    let tmp_path = shard_dir.join(format!("{hex}.tmp.{}.{}", std::process::id(), seq));
    let final_path = shard_dir.join(format!("{hex}.cache"));

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

    Ok((file_bytes, data_offset))
}

/// Zero-latency stream wrapper that yields every chunk straight to the client while accumulating a
/// bounded copy to commit into `MediaCache` once the upstream stream completes cleanly.
pub struct MediaCacheTeeStream<S> {
    inner: Pin<Box<S>>,
    cache: Arc<MediaCache>,
    key: CacheKey,
    meta: CompactMeta,
    max_bytes: usize,
    buf: Option<BytesMut>,
    in_flight: Option<InFlightGuard>,
    finished: bool,
}

impl<S> MediaCacheTeeStream<S> {
    pub fn new(
        inner: S,
        cache: Arc<MediaCache>,
        key: CacheKey,
        meta: CompactMeta,
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
                        let key = this.key;
                        let mut meta = this.meta.clone();
                        meta.body_len = data.len() as u64;
                        let guard = this.in_flight.take();
                        tokio::spawn(async move {
                            cache.store(key, meta, data, StorePolicy::ClientHot).await;
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
/// responses so the zero-DOM streaming scanner can extract `mxc://` URLs with zero client delay.
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

/// Zero-DOM streaming byte scanner: decompresses `gzip`/`deflate`/`br`/`zstd`/plain responses
/// incrementally into a fixed 32 KiB sliding window (peak ~32 KiB RAM instead of 30+ MiB
/// `serde_json::Value` DOM trees!) and extracts safe `mxc://` avatar & unencrypted media hints.
pub fn extract_mxc_hints_from_response(
    raw: &[u8],
    content_encoding: &str,
    max_preload_bytes: u64,
) -> Vec<MxcHint> {
    let enc = content_encoding
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match enc.as_str() {
        "" | "identity" => scan_mxc_hints_reader(raw, max_preload_bytes),
        "gzip" | "x-gzip" => scan_mxc_hints_reader(GzDecoder::new(raw), max_preload_bytes),
        "deflate" => {
            let out = scan_mxc_hints_reader(ZlibDecoder::new(raw), max_preload_bytes);
            if !out.is_empty() {
                out
            } else {
                scan_mxc_hints_reader(DeflateDecoder::new(raw), max_preload_bytes)
            }
        }
        "br" => scan_mxc_hints_reader(brotli::Decompressor::new(raw, 4096), max_preload_bytes),
        "zstd" => match ruzstd::decoding::StreamingDecoder::new(raw) {
            Ok(dec) => scan_mxc_hints_reader(dec, max_preload_bytes),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Streams chunks of decompressed JSON through a fixed 32 KiB buffer with 512-byte overlap
/// so `mxc://` references and their enclosing JSON key/context are classified in O(N) time
/// with ~32 KiB constant memory and zero JSON DOM allocations.
fn scan_mxc_hints_reader<R: Read>(mut reader: R, max_preload_bytes: u64) -> Vec<MxcHint> {
    let mut out = Vec::new();
    let mut seen: AHashSet<MxcHint> = AHashSet::with_capacity(MAX_HINTS_PER_PAYLOAD);
    let mut window = vec![0u8; STREAM_SCAN_CHUNK_BYTES + STREAM_SCAN_OVERLAP_BYTES];
    let mut carry = 0usize;
    let mut total_read = 0usize;

    loop {
        if out.len() >= MAX_HINTS_PER_PAYLOAD || total_read >= MAX_DECOMPRESSED_SCAN_BYTES {
            break;
        }
        let max_to_read = (MAX_DECOMPRESSED_SCAN_BYTES - total_read).min(STREAM_SCAN_CHUNK_BYTES);
        let n = match reader.read(&mut window[carry..carry + max_to_read]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total_read += n;
        let filled = carry + n;
        let slice = &window[..filled];

        scan_mxc_slice(slice, max_preload_bytes, &mut seen, &mut out);

        if filled > STREAM_SCAN_OVERLAP_BYTES {
            let keep_start = filled - STREAM_SCAN_OVERLAP_BYTES;
            window.copy_within(keep_start..filled, 0);
            carry = STREAM_SCAN_OVERLAP_BYTES;
        } else {
            carry = filled;
        }
    }

    out
}

fn scan_mxc_slice(
    data: &[u8],
    max_preload_bytes: u64,
    seen: &mut AHashSet<MxcHint>,
    out: &mut Vec<MxcHint>,
) {
    const NEEDLE: &[u8] = b"mxc://";
    let mut pos = 0usize;
    while pos + NEEDLE.len() < data.len() && out.len() < MAX_HINTS_PER_PAYLOAD {
        let Some(rel) = find_subslice(&data[pos..], NEEDLE) else {
            break;
        };
        let start = pos + rel;
        let uri_start = start + NEEDLE.len();
        let mut end = uri_start;
        while end < data.len()
            && end - uri_start < 512
            && !matches!(data[end], b'"' | b'\\' | b' ' | b'\n' | b'\r' | b'\t')
        {
            end += 1;
        }
        pos = end.max(uri_start);

        // Require closing quote so split URIs at chunk boundaries wait for the overlap pass.
        if end >= data.len() || data[end] != b'"' {
            continue;
        }

        let Ok(raw_uri) = std::str::from_utf8(&data[start..end]) else {
            continue;
        };
        let Some((server, media_id)) = parse_mxc_uri(raw_uri) else {
            continue;
        };

        if let Some(hint) =
            classify_mxc_in_json_context(data, start, end, server, media_id, max_preload_bytes)
            && seen.insert(hint.clone())
        {
            out.push(hint);
        }
    }
}

fn classify_mxc_in_json_context(
    data: &[u8],
    mxc_start: usize,
    _mxc_end: usize,
    server: String,
    media_id: String,
    max_preload_bytes: u64,
) -> Option<MxcHint> {
    // Walk backward from `"mxc://..."` across optional whitespace and `:` to find the JSON key name.
    if mxc_start < 3 || data[mxc_start - 1] != b'"' {
        return None;
    }
    let mut i = mxc_start - 1;
    while i > 0 && matches!(data[i - 1], b' ' | b'\t' | b'\r' | b'\n') {
        i -= 1;
    }
    if i == 0 || data[i - 1] != b':' {
        return None;
    }
    let colon_pos = i - 1;
    i = colon_pos;
    while i > 0 && matches!(data[i - 1], b' ' | b'\t' | b'\r' | b'\n') {
        i -= 1;
    }
    if i == 0 || data[i - 1] != b'"' {
        return None;
    }
    let key_end = i - 1;
    let search_from = key_end.saturating_sub(48);
    let mut key_start = key_end;
    while key_start > search_from && data[key_start - 1] != b'"' {
        key_start -= 1;
    }
    if key_start == 0 || data[key_start - 1] != b'"' {
        return None;
    }
    let key = &data[key_start..key_end];

    match key {
        b"avatar" | b"avatar_url" => Some(MxcHint::Avatar { server, media_id }),
        b"thumbnail_url" => Some(MxcHint::MediaDownload { server, media_id }),
        b"url" => {
            // Bound inspection strictly to the enclosing `content` JSON object (and its parent
            // event object) so adjacent timeline events never bleed into classification.
            let (content_start, content_end) = enclosing_json_object(data, colon_pos, 1024)?;
            let content = &data[content_start..content_end];

            // `m.room.avatar` state events have `"type":"m.room.avatar"` on the parent event object
            // and no `"msgtype"` in `content`.
            if find_subslice(content, b"\"msgtype\"").is_none()
                && let Some((ev_start, ev_end)) = enclosing_json_object(data, content_start, 1024)
            {
                let event = &data[ev_start..ev_end];
                if find_subslice(event, b"\"m.room.avatar\"").is_some() {
                    return Some(MxcHint::Avatar { server, media_id });
                }
                if find_subslice(event, b"\"m.sticker\"").is_some() {
                    if let Some(size) = extract_nearby_json_u64(content, b"\"size\"")
                        && size > max_preload_bytes
                    {
                        return None;
                    }
                    return Some(MxcHint::MediaDownload { server, media_id });
                }
            }

            // Skip videos, audio, and generic files so we never waste bandwidth preloading big binaries.
            if find_subslice(content, b"\"m.video\"").is_some()
                || find_subslice(content, b"\"m.audio\"").is_some()
                || find_subslice(content, b"\"m.file\"").is_some()
                || find_subslice(content, b"\"video/").is_some()
                || find_subslice(content, b"\"audio/").is_some()
            {
                return None;
            }
            if let Some(size) = extract_nearby_json_u64(content, b"\"size\"")
                && size > max_preload_bytes
            {
                return None;
            }
            let is_image_like = find_subslice(content, b"\"m.image\"").is_some()
                || find_subslice(content, b"\"m.sticker\"").is_some()
                || find_subslice(content, b"\"image/").is_some();
            if is_image_like {
                Some(MxcHint::MediaDownload { server, media_id })
            } else {
                None
            }
        }
        _ => None,
    }
}

#[inline]
fn is_unescaped_quote(data: &[u8], idx: usize) -> bool {
    if data[idx] != b'"' {
        return false;
    }
    let mut backslashes = 0usize;
    let mut j = idx;
    while j > 0 && data[j - 1] == b'\\' {
        backslashes += 1;
        j -= 1;
    }
    backslashes.is_multiple_of(2)
}

/// Finds the enclosing JSON `{ ... }` object around `outside_pos` (which must not be inside a
/// JSON string literal), bounded by `max_radius` bytes in each direction.
fn enclosing_json_object(
    data: &[u8],
    outside_pos: usize,
    max_radius: usize,
) -> Option<(usize, usize)> {
    let min_start = outside_pos.saturating_sub(max_radius);
    let mut i = outside_pos;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut obj_start = None;
    while i > min_start {
        i -= 1;
        let b = data[i];
        if in_str {
            if is_unescaped_quote(data, i) {
                in_str = false;
            }
        } else {
            match b {
                b'"' if is_unescaped_quote(data, i) => in_str = true,
                b'}' => depth += 1,
                b'{' => {
                    if depth == 0 {
                        obj_start = Some(i);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }
    let start = obj_start?;

    let max_end = (outside_pos + max_radius).min(data.len());
    let mut j = outside_pos;
    depth = 0;
    in_str = false;
    let mut obj_end = None;
    while j < max_end {
        let b = data[j];
        if in_str {
            if is_unescaped_quote(data, j) {
                in_str = false;
            }
        } else {
            match b {
                b'"' if is_unescaped_quote(data, j) => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    if depth == 0 {
                        obj_end = Some(j + 1);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        j += 1;
    }
    let end = obj_end.unwrap_or(max_end);
    Some((start, end))
}

fn extract_nearby_json_u64(ctx: &[u8], key: &[u8]) -> Option<u64> {
    let pos = find_subslice(ctx, key)?;
    let mut i = pos + key.len();
    while i < ctx.len() && matches!(ctx[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i >= ctx.len() || ctx[i] != b':' {
        return None;
    }
    i += 1;
    while i < ctx.len() && matches!(ctx[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    let start = i;
    while i < ctx.len() && ctx[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&ctx[start..i])
        .ok()?
        .parse::<u64>()
        .ok()
}

#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let nlen = needle.len();
    if haystack.len() < nlen {
        return None;
    }
    let mut i = 0;
    let limit = haystack.len() - nlen;
    while i <= limit {
        if haystack[i] == first && &haystack[i..i + nlen] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
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
    cache_key: CacheKey,
    target_url: Url,
    requires_auth: bool,
    bearer_token: Option<String>,
    client: ClientInfo,
}

/// Bounded proactive background preloader for a single `ProxyInstance`.
/// Writes preloaded objects to L2 disk ONLY (never evicting hot L1 RAM entries), and exits
/// cleanly when `ProxyInstance` is dropped on hot reload or shutdown.
pub struct MediaPreloader {
    profile: Arc<ProxyProfile>,
    cache: Arc<MediaCache>,
    metrics: Arc<ProxyMetrics>,
    tx: mpsc::Sender<PreloadJob>,
    recent: Mutex<AHashMap<CacheKey, Instant>>,
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
            recent: Mutex::new(AHashMap::with_capacity(256)),
        })
    }

    /// Scans a Matrix JSON payload via the zero-DOM 32 KiB streaming scanner and enqueues uncached items.
    pub fn enqueue_from_json_payload(
        self: &Arc<Self>,
        raw_bytes: Vec<u8>,
        content_encoding: String,
        upstream_matrix_url: Url,
        upstream_origin: String,
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

    /// Triggered when a client fetches a content `/thumbnail/{server}/{id}` (skips small square
    /// avatar thumbnails `<= 256px` that clients never open as full downloads): warms `/download`
    /// in background so tapping an inline photo opens instantaneously from edge cache.
    pub fn enqueue_full_download_for_thumbnail(
        &self,
        route: &MediaRouteInfo,
        upstream_matrix_url: &Url,
        upstream_origin: &str,
        bearer_token: Option<String>,
        client: &ClientInfo,
    ) {
        if !self.profile.media.preload_on_thumbnail
            || !route.is_thumbnail
            || route.is_avatar_sized_thumbnail()
        {
            return;
        }
        let key = cache_key_for_download(
            &self.profile.name,
            upstream_origin,
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
        if self.cache.contains_key(&job.cache_key)
            || self.cache.has_any_negative_404(&job.cache_key)
        {
            self.metrics
                .media_preload_skipped_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let now = Instant::now();
        {
            let mut recent = self.recent.lock();
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
            recent.insert(job.cache_key, now);
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
    if cache.contains_key(&job.cache_key) || cache.has_any_negative_404(&job.cache_key) {
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

    let mut out_headers = HeaderMap::with_capacity(6);
    out_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    out_headers.insert(
        http::header::USER_AGENT,
        HeaderValue::from_static("matrix-proxy-preloader/2.0"),
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
            let meta = CompactMeta {
                mime: CompactMime::from_str(&content_type),
                content_disposition: content_disposition.map(String::into_boxed_str),
                custom_etag: etag.map(String::into_boxed_str),
                requires_auth: job.requires_auth || job.bearer_token.is_some(),
                body_len: data.len() as u64,
                stored_epoch_secs: now_epoch_secs(),
            };
            cache
                .store(job.cache_key, meta, data, StorePolicy::BackgroundPreload)
                .await;
            metrics
                .media_preload_completed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(PreloadFetchResult::NotFound) => {
            cache.record_negative_404(
                &job.cache_key,
                job.requires_auth || job.bearer_token.is_some(),
            );
            metrics
                .media_preload_skipped_total
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
    NotFound,
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
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(PreloadFetchResult::NotFound);
    }
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("upstream returned HTTP {}", resp.status()));
    }
    if !is_cacheable_media_headers(resp.headers(), max_bytes) {
        return Ok(PreloadFetchResult::Skipped);
    }
    let (content_type, content_disposition, etag) = extract_cache_meta_headers(resp.headers());
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

    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(PreloadFetchResult::NotFound);
    }
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("upstream returned HTTP {}", resp.status()));
    }
    let (parts, mut body) = resp.into_parts();
    if !is_cacheable_media_headers(&parts.headers, max_bytes) {
        return Ok(PreloadFetchResult::Skipped);
    }
    let (content_type, content_disposition, etag) = extract_cache_meta_headers(&parts.headers);
    let mut buf = BytesMut::new();
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

pub fn build_compact_meta_from_headers(
    headers: &HeaderMap,
    requires_auth: bool,
    body_len: u64,
) -> CompactMeta {
    let (content_type, content_disposition, etag) = extract_cache_meta_headers(headers);
    CompactMeta {
        mime: CompactMime::from_str(&content_type),
        content_disposition: content_disposition.map(String::into_boxed_str),
        custom_etag: etag.map(String::into_boxed_str),
        requires_auth,
        body_len,
        stored_epoch_secs: now_epoch_secs(),
    }
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

fn token_hash(profile: &str, token: &str) -> CacheKey {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(profile.as_bytes());
    ctx.update(b"\0");
    ctx.update(token.as_bytes());
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn default_etag_for_key(key: &CacheKey) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(26);
    out.push('"');
    for &b in &key[..12] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out.push('"');
    out
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_key(s: &str) -> Option<CacheKey> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn sha256_key(input: &[u8]) -> CacheKey {
        let d = digest::digest(&digest::SHA256, input);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

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
        assert!(r1.is_avatar_sized_thumbnail());
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
    fn streaming_scanner_extracts_mxc_hints_from_plain_and_gzip_sliding_sync_json() {
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
        assert!(!hints.contains(&MxcHint::MediaDownload {
            server: "example.org".to_string(),
            media_id: "hugeVideo".to_string(),
        }));

        // Verify gzip streaming decompression path too
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&raw).unwrap();
        let gz_bytes = gz.finish().unwrap();
        let gz_hints = extract_mxc_hints_from_response(&gz_bytes, "gzip", 4 * 1024 * 1024);
        assert_eq!(gz_hints.len(), hints.len());
    }

    #[test]
    fn lru_map_evicts_least_recently_used_in_o1() {
        let mut lru: LruMap<u32> = LruMap::default();
        let k1 = sha256_key(b"1");
        let k2 = sha256_key(b"2");
        let k3 = sha256_key(b"3");
        lru.insert(k1, 1, 10);
        lru.insert(k2, 2, 10);
        lru.insert(k3, 3, 10);
        // Touch k1 -> order becomes [k1, k3, k2], so k2 is now LRU!
        assert_eq!(lru.get_and_touch(&k1), Some(&1));
        assert_eq!(lru.pop_lru().map(|(k, v, _)| (k, v)), Some((k2, 2)));
        assert_eq!(lru.pop_lru().map(|(k, v, _)| (k, v)), Some((k3, 3)));
        assert_eq!(lru.pop_lru().map(|(k, v, _)| (k, v)), Some((k1, 1)));
        assert!(lru.pop_lru().is_none());
        assert_eq!(lru.total_bytes(), 0);
    }

    #[tokio::test]
    async fn l1_ram_and_l2_disk_lru_enforce_caps_auth_and_background_preload_isolation() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "matrix-proxy-media-cache-v2-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        let metrics = Arc::new(ProxyMetrics::new());
        let cfg = MediaCacheConfig {
            enabled: true,
            dir: Some(tmp_dir.to_string_lossy().to_string()),
            ram_max_mb: 1,
            ram_max_item_kb: 256,
            disk_max_mb: 8,
            max_item_mb: 2,
            auth_cache_ttl_secs: 60,
        };
        let cache = MediaCache::new(cfg, Arc::clone(&metrics));

        let hot_data = Bytes::from(vec![b'H'; 32 * 1024]);
        let preload_data = Bytes::from(vec![b'P'; 32 * 1024]);
        let key_hot = sha256_key(b"hot-client");
        let key_bg = sha256_key(b"bg-preload");
        let key_pub = sha256_key(b"public-item");

        let mk_meta = |len: usize, auth: bool| CompactMeta {
            mime: CompactMime::ImagePng,
            content_disposition: None,
            custom_etag: None,
            requires_auth: auth,
            body_len: len as u64,
            stored_epoch_secs: now_epoch_secs(),
        };

        cache
            .store(
                key_hot,
                mk_meta(hot_data.len(), true),
                hot_data.clone(),
                StorePolicy::ClientHot,
            )
            .await;
        // Background preload MUST land on L2 disk ONLY (never polluting L1 RAM when disk is enabled!)
        cache
            .store(
                key_bg,
                mk_meta(preload_data.len(), true),
                preload_data.clone(),
                StorePolicy::BackgroundPreload,
            )
            .await;
        cache
            .store(
                key_pub,
                mk_meta(hot_data.len(), false),
                hot_data.clone(),
                StorePolicy::ClientHot,
            )
            .await;

        assert!(cache.lookup(&key_hot, false).is_none());
        assert!(cache.lookup(&key_bg, false).is_none());
        assert!(matches!(
            cache.lookup(&key_pub, false),
            Some(CacheHit::Ram { .. })
        ));
        assert!(matches!(
            cache.lookup(&key_hot, true),
            Some(CacheHit::Ram { .. })
        ));
        // Preloaded entry sits cleanly on L2 disk, NOT in L1 RAM!
        assert!(matches!(
            cache.lookup(&key_bg, true),
            Some(CacheHit::Disk { .. })
        ));

        // Token verification + immediate revocation
        assert!(!cache.is_token_verified("prof", "syt_secret"));
        cache.record_verified_token("prof", "syt_secret");
        assert!(cache.is_token_verified("prof", "syt_secret"));
        cache.revoke_token("prof", "syt_secret");
        assert!(!cache.is_token_verified("prof", "syt_secret"));

        // Negative 404 cache enforces auth isolation and clears cleanly once stored.
        let key_missing = sha256_key(b"missing-avatar");
        assert!(!cache.is_negatively_cached(&key_missing, true));
        cache.record_negative_404(&key_missing, true);
        assert!(!cache.is_negatively_cached(&key_missing, false));
        assert!(cache.is_negatively_cached(&key_missing, true));
        assert!(cache.has_any_negative_404(&key_missing));
        cache
            .store(
                key_missing,
                mk_meta(hot_data.len(), true),
                hot_data.clone(),
                StorePolicy::ClientHot,
            )
            .await;
        assert!(!cache.has_any_negative_404(&key_missing));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
