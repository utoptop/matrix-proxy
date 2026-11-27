use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Lock-free runtime metrics and hot-reload metadata (minimal ~1ns overhead per request).
#[derive(Debug)]
pub struct ProxyMetrics {
    started_at: Instant,
    pub requests_total: AtomicU64,
    pub requests_active: AtomicU64,
    pub upstream_errors_total: AtomicU64,
    pub proxy_protocol_retries_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub concurrency_rejected_total: AtomicU64,
    pub reloads_total: AtomicU64,
    pub reload_failures_total: AtomicU64,
    pub config_generation: AtomicU64,
    pub last_reload_epoch_secs: AtomicU64,
    pub media_cache_hits_ram_total: AtomicU64,
    pub media_cache_hits_disk_total: AtomicU64,
    pub media_cache_negative_hits_total: AtomicU64,
    pub media_cache_misses_total: AtomicU64,
    pub media_cache_stores_total: AtomicU64,
    pub media_cache_evictions_total: AtomicU64,
    pub media_cache_ram_bytes: AtomicU64,
    pub media_cache_disk_bytes: AtomicU64,
    pub media_preload_enqueued_total: AtomicU64,
    pub media_preload_completed_total: AtomicU64,
    pub media_preload_skipped_total: AtomicU64,
    pub media_preload_errors_total: AtomicU64,
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            requests_total: AtomicU64::new(0),
            requests_active: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            proxy_protocol_retries_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            concurrency_rejected_total: AtomicU64::new(0),
            reloads_total: AtomicU64::new(0),
            reload_failures_total: AtomicU64::new(0),
            config_generation: AtomicU64::new(1),
            last_reload_epoch_secs: AtomicU64::new(now_epoch_secs()),
            media_cache_hits_ram_total: AtomicU64::new(0),
            media_cache_hits_disk_total: AtomicU64::new(0),
            media_cache_negative_hits_total: AtomicU64::new(0),
            media_cache_misses_total: AtomicU64::new(0),
            media_cache_stores_total: AtomicU64::new(0),
            media_cache_evictions_total: AtomicU64::new(0),
            media_cache_ram_bytes: AtomicU64::new(0),
            media_cache_disk_bytes: AtomicU64::new(0),
            media_preload_enqueued_total: AtomicU64::new(0),
            media_preload_completed_total: AtomicU64::new(0),
            media_preload_skipped_total: AtomicU64::new(0),
            media_preload_errors_total: AtomicU64::new(0),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn record_reload_success(&self) -> u64 {
        self.reloads_total.fetch_add(1, Ordering::Relaxed);
        self.last_reload_epoch_secs
            .store(now_epoch_secs(), Ordering::Relaxed);
        self.config_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn record_reload_failure(&self) {
        self.reload_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn generation(&self) -> u64 {
        self.config_generation.load(Ordering::Acquire)
    }

    pub fn track_request(self: &Arc<Self>) -> ActiveRequestGuard {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.requests_active.fetch_add(1, Ordering::Relaxed);
        ActiveRequestGuard {
            metrics: Arc::clone(self),
        }
    }

    pub fn render_prometheus(&self, listeners: usize, profiles: usize) -> String {
        format!(
            concat!(
                "# HELP matrix_proxy_uptime_seconds Process uptime in seconds.\n",
                "# TYPE matrix_proxy_uptime_seconds gauge\n",
                "matrix_proxy_uptime_seconds {}\n",
                "# HELP matrix_proxy_config_generation Current active configuration generation (increments on hot reload).\n",
                "# TYPE matrix_proxy_config_generation gauge\n",
                "matrix_proxy_config_generation {}\n",
                "# HELP matrix_proxy_listeners Number of active listening ports.\n",
                "# TYPE matrix_proxy_listeners gauge\n",
                "matrix_proxy_listeners {}\n",
                "# HELP matrix_proxy_profiles Number of configured upstream Matrix proxy profiles on this listener.\n",
                "# TYPE matrix_proxy_profiles gauge\n",
                "matrix_proxy_profiles {}\n",
                "# HELP matrix_proxy_requests_total Total HTTP requests handled.\n",
                "# TYPE matrix_proxy_requests_total counter\n",
                "matrix_proxy_requests_total {}\n",
                "# HELP matrix_proxy_requests_active Currently in-flight HTTP requests.\n",
                "# TYPE matrix_proxy_requests_active gauge\n",
                "matrix_proxy_requests_active {}\n",
                "# HELP matrix_proxy_upstream_errors_total Upstream connection, timeout, or bad-gateway errors.\n",
                "# TYPE matrix_proxy_upstream_errors_total counter\n",
                "matrix_proxy_upstream_errors_total {}\n",
                "# HELP matrix_proxy_proxy_protocol_retries_total Stale pooled PROXY Protocol connections automatically retried.\n",
                "# TYPE matrix_proxy_proxy_protocol_retries_total counter\n",
                "matrix_proxy_proxy_protocol_retries_total {}\n",
                "# HELP matrix_proxy_rate_limited_total Requests rejected by per-IP rate limiter.\n",
                "# TYPE matrix_proxy_rate_limited_total counter\n",
                "matrix_proxy_rate_limited_total {}\n",
                "# HELP matrix_proxy_concurrency_rejected_total Requests rejected by max_concurrent_requests backpressure.\n",
                "# TYPE matrix_proxy_concurrency_rejected_total counter\n",
                "matrix_proxy_concurrency_rejected_total {}\n",
                "# HELP matrix_proxy_reloads_total Successful hot reloads completed.\n",
                "# TYPE matrix_proxy_reloads_total counter\n",
                "matrix_proxy_reloads_total {}\n",
                "# HELP matrix_proxy_reload_failures_total Failed hot reload attempts (previous config kept active).\n",
                "# TYPE matrix_proxy_reload_failures_total counter\n",
                "matrix_proxy_reload_failures_total {}\n",
                "# HELP matrix_proxy_media_cache_hits_ram_total Media requests served directly from L1 RAM cache.\n",
                "# TYPE matrix_proxy_media_cache_hits_ram_total counter\n",
                "matrix_proxy_media_cache_hits_ram_total {}\n",
                "# HELP matrix_proxy_media_cache_hits_disk_total Media requests served from L2 disk cache.\n",
                "# TYPE matrix_proxy_media_cache_hits_disk_total counter\n",
                "matrix_proxy_media_cache_hits_disk_total {}\n",
                "# HELP matrix_proxy_media_cache_negative_hits_total Media 404 requests short-circuited by bounded negative cache.\n",
                "# TYPE matrix_proxy_media_cache_negative_hits_total counter\n",
                "matrix_proxy_media_cache_negative_hits_total {}\n",
                "# HELP matrix_proxy_media_cache_misses_total Media requests forwarded to upstream on cache miss.\n",
                "# TYPE matrix_proxy_media_cache_misses_total counter\n",
                "matrix_proxy_media_cache_misses_total {}\n",
                "# HELP matrix_proxy_media_cache_stores_total Media objects stored in the edge cache.\n",
                "# TYPE matrix_proxy_media_cache_stores_total counter\n",
                "matrix_proxy_media_cache_stores_total {}\n",
                "# HELP matrix_proxy_media_cache_evictions_total Media objects evicted from RAM or disk LRU cache.\n",
                "# TYPE matrix_proxy_media_cache_evictions_total counter\n",
                "matrix_proxy_media_cache_evictions_total {}\n",
                "# HELP matrix_proxy_media_cache_ram_bytes Current bytes held in L1 RAM media cache.\n",
                "# TYPE matrix_proxy_media_cache_ram_bytes gauge\n",
                "matrix_proxy_media_cache_ram_bytes {}\n",
                "# HELP matrix_proxy_media_cache_disk_bytes Current bytes stored in L2 disk media cache.\n",
                "# TYPE matrix_proxy_media_cache_disk_bytes gauge\n",
                "matrix_proxy_media_cache_disk_bytes {}\n",
                "# HELP matrix_proxy_media_preload_enqueued_total Background media preload jobs enqueued.\n",
                "# TYPE matrix_proxy_media_preload_enqueued_total counter\n",
                "matrix_proxy_media_preload_enqueued_total {}\n",
                "# HELP matrix_proxy_media_preload_completed_total Background media preload jobs completed and cached.\n",
                "# TYPE matrix_proxy_media_preload_completed_total counter\n",
                "matrix_proxy_media_preload_completed_total {}\n",
                "# HELP matrix_proxy_media_preload_skipped_total Background media preload jobs skipped (already cached, oversized, or duplicate).\n",
                "# TYPE matrix_proxy_media_preload_skipped_total counter\n",
                "matrix_proxy_media_preload_skipped_total {}\n",
                "# HELP matrix_proxy_media_preload_errors_total Background media preload fetches that failed or returned non-200.\n",
                "# TYPE matrix_proxy_media_preload_errors_total counter\n",
                "matrix_proxy_media_preload_errors_total {}\n"
            ),
            self.uptime_secs(),
            self.generation(),
            listeners,
            profiles,
            self.requests_total.load(Ordering::Relaxed),
            self.requests_active.load(Ordering::Relaxed),
            self.upstream_errors_total.load(Ordering::Relaxed),
            self.proxy_protocol_retries_total.load(Ordering::Relaxed),
            self.rate_limited_total.load(Ordering::Relaxed),
            self.concurrency_rejected_total.load(Ordering::Relaxed),
            self.reloads_total.load(Ordering::Relaxed),
            self.reload_failures_total.load(Ordering::Relaxed),
            self.media_cache_hits_ram_total.load(Ordering::Relaxed),
            self.media_cache_hits_disk_total.load(Ordering::Relaxed),
            self.media_cache_negative_hits_total.load(Ordering::Relaxed),
            self.media_cache_misses_total.load(Ordering::Relaxed),
            self.media_cache_stores_total.load(Ordering::Relaxed),
            self.media_cache_evictions_total.load(Ordering::Relaxed),
            self.media_cache_ram_bytes.load(Ordering::Relaxed),
            self.media_cache_disk_bytes.load(Ordering::Relaxed),
            self.media_preload_enqueued_total.load(Ordering::Relaxed),
            self.media_preload_completed_total.load(Ordering::Relaxed),
            self.media_preload_skipped_total.load(Ordering::Relaxed),
            self.media_preload_errors_total.load(Ordering::Relaxed),
        )
    }
}

pub struct ActiveRequestGuard {
    metrics: Arc<ProxyMetrics>,
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.metrics.requests_active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
