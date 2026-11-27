use crate::ppv2_client::configure_tcp_socket;
use crate::ws::trim_ipv6_brackets;
use ahash::AHashMap;
use anyhow::{Context, Result, anyhow};
use parking_lot::{Mutex, RwLock};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tracing::debug;

const DNS_FRESH_TTL: Duration = Duration::from_secs(60);
const DNS_STALE_GRACE: Duration = Duration::from_secs(300);
const DNS_MAX_ENTRIES: usize = 512;
const HAPPY_EYEBALLS_STAGGER: Duration = Duration::from_millis(75);
const HAPPY_EYEBALLS_MAX_CANDIDATES: usize = 4;

#[derive(Clone)]
struct CachedDnsEntry {
    ips: Arc<[IpAddr]>,
    resolved_at: Instant,
}

/// Process-wide async TTL DNS cache with Stale-While-Revalidate (SWR), singleflight coalescing,
/// and Happy Eyeballs (RFC 8305) concurrent IPv4/IPv6 fast TCP connection racing.
///
/// Eliminates repeated `getaddrinfo` `spawn_blocking` syscalls and container DNS UDP RTT on
/// every cold upstream connection across `reqwest`, `Ppv2Client`, and WebSocket tunnels.
pub struct CachingDnsResolver {
    cache: RwLock<AHashMap<String, CachedDnsEntry>>,
    in_flight: Mutex<AHashMap<String, Arc<Notify>>>,
}

impl Default for CachingDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CachingDnsResolver {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(AHashMap::with_capacity(32)),
            in_flight: Mutex::new(AHashMap::with_capacity(8)),
        }
    }

    /// Resolves `host` into an interleaved IPv4/IPv6 slice with ~50ns hot-cache hits.
    pub async fn resolve_ips(self: &Arc<Self>, host: &str) -> Result<Arc<[IpAddr]>> {
        let clean = trim_ipv6_brackets(host.trim());
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Ok(Arc::from([ip]));
        }

        let key = clean.to_ascii_lowercase();
        let now = Instant::now();

        // 1. Hot cache read (~50ns, zero syscalls).
        let stale_fallback = {
            let guard = self.cache.read();
            if let Some(entry) = guard.get(&key) {
                let age = now.saturating_duration_since(entry.resolved_at);
                if age < DNS_FRESH_TTL {
                    return Ok(Arc::clone(&entry.ips));
                }
                if age < DNS_STALE_GRACE {
                    // Stale-While-Revalidate: return immediately and refresh asynchronously once.
                    self.spawn_background_refresh(key.clone());
                    return Ok(Arc::clone(&entry.ips));
                }
                Some(Arc::clone(&entry.ips))
            } else {
                None
            }
        };

        // 2. Cold path with singleflight coalescing.
        let waiter = {
            let mut inflight = self.in_flight.lock();
            if let Some(existing) = inflight.get(&key) {
                Some(Arc::clone(existing))
            } else {
                inflight.insert(key.clone(), Arc::new(Notify::new()));
                None
            }
        };

        if let Some(notify) = waiter {
            let _ = tokio::time::timeout(Duration::from_secs(5), notify.notified()).await;
            if let Some(entry) = self.cache.read().get(&key) {
                return Ok(Arc::clone(&entry.ips));
            }
        }

        match self.lookup_and_store(&key).await {
            Ok(ips) => Ok(ips),
            Err(err) => {
                if let Some(stale) = stale_fallback {
                    debug!(host = %key, error = %err, "DNS refresh failed; falling back to last known IP");
                    Ok(stale)
                } else {
                    Err(err)
                }
            }
        }
    }

    fn spawn_background_refresh(self: &Arc<Self>, key: String) {
        {
            let mut inflight = self.in_flight.lock();
            if inflight.contains_key(&key) {
                return;
            }
            inflight.insert(key.clone(), Arc::new(Notify::new()));
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _ = this.lookup_and_store(&key).await;
        });
    }

    async fn lookup_and_store(&self, key: &str) -> Result<Arc<[IpAddr]>> {
        let lookup_res = tokio::net::lookup_host((key, 0u16)).await;
        let finish = || {
            if let Some(n) = self.in_flight.lock().remove(key) {
                n.notify_waiters();
            }
        };

        let raw_addrs = match lookup_res {
            Ok(iter) => iter,
            Err(err) => {
                finish();
                return Err(err).with_context(|| format!("DNS resolution failed for '{key}'"));
            }
        };

        let ordered = interleave_dual_stack(raw_addrs.map(|sa| sa.ip()));
        if ordered.is_empty() {
            finish();
            return Err(anyhow!("DNS returned no IP addresses for '{key}'"));
        }

        let ips: Arc<[IpAddr]> = Arc::from(ordered);
        {
            let mut guard = self.cache.write();
            if guard.len() >= DNS_MAX_ENTRIES && !guard.contains_key(key) {
                let now = Instant::now();
                guard.retain(|_, v| now.saturating_duration_since(v.resolved_at) < DNS_STALE_GRACE);
                if guard.len() >= DNS_MAX_ENTRIES {
                    guard.clear();
                }
            }
            guard.insert(
                key.to_string(),
                CachedDnsEntry {
                    ips: Arc::clone(&ips),
                    resolved_at: Instant::now(),
                },
            );
        }
        finish();
        Ok(ips)
    }

    /// Pre-warms DNS resolution for `host` in the background (best-effort, non-blocking).
    pub fn prewarm(self: &Arc<Self>, host: &str) {
        let clean = trim_ipv6_brackets(host.trim());
        if clean.is_empty() || clean.parse::<IpAddr>().is_ok() {
            return;
        }
        let key = clean.to_ascii_lowercase();
        let is_fresh = self
            .cache
            .read()
            .get(&key)
            .is_some_and(|e| e.resolved_at.elapsed() < DNS_FRESH_TTL);
        if !is_fresh {
            self.spawn_background_refresh(key);
        }
    }

    /// Connects a tuned TCP stream using cached DNS and Happy Eyeballs (RFC 8305) racing so
    /// dual-stack or multi-A upstreams always complete on the lowest-latency reachable IP.
    pub async fn connect_tcp_fast(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        nodelay: bool,
        keepalive: Duration,
    ) -> Result<TcpStream> {
        let ips = self.resolve_ips(host).await?;
        if ips.len() == 1 {
            let addr = SocketAddr::new(ips[0], port);
            let stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("TCP connect to {host}:{port} ({addr}) failed"))?;
            configure_tcp_socket(&stream, nodelay, keepalive);
            return Ok(stream);
        }

        // Happy Eyeballs: launch candidates staggered by 75ms; first successful TCP handshake wins
        // and all losing attempts are immediately cancelled when JoinSet drops.
        let candidates: Vec<SocketAddr> = ips
            .iter()
            .take(HAPPY_EYEBALLS_MAX_CANDIDATES)
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();

        let mut set: JoinSet<std::io::Result<TcpStream>> = JoinSet::new();
        let mut next_idx = 0usize;
        let mut last_err: Option<std::io::Error> = None;

        if let Some(&first) = candidates.first() {
            next_idx = 1;
            set.spawn(async move { TcpStream::connect(first).await });
        }

        while !set.is_empty() || next_idx < candidates.len() {
            if next_idx < candidates.len() {
                tokio::select! {
                    biased;
                    joined = set.join_next(), if !set.is_empty() => {
                        match joined {
                            Some(Ok(Ok(stream))) => {
                                configure_tcp_socket(&stream, nodelay, keepalive);
                                return Ok(stream);
                            }
                            Some(Ok(Err(err))) => {
                                last_err = Some(err);
                                // Immediately launch next candidate when current fails fast (e.g., ECONNREFUSED).
                                let addr = candidates[next_idx];
                                next_idx += 1;
                                set.spawn(async move { TcpStream::connect(addr).await });
                            }
                            Some(Err(_)) | None => {}
                        }
                    }
                    _ = tokio::time::sleep(HAPPY_EYEBALLS_STAGGER) => {
                        let addr = candidates[next_idx];
                        next_idx += 1;
                        set.spawn(async move { TcpStream::connect(addr).await });
                    }
                }
            } else {
                match set.join_next().await {
                    Some(Ok(Ok(stream))) => {
                        configure_tcp_socket(&stream, nodelay, keepalive);
                        return Ok(stream);
                    }
                    Some(Ok(Err(err))) => {
                        last_err = Some(err);
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }

        Err(anyhow!(
            "TCP connect to {host}:{port} failed across {} resolved address(es): {}",
            candidates.len(),
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no reachable address".to_string())
        ))
    }
}

impl Resolve for CachingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // Reqwest calls `Resolve::resolve(&self)` through `Arc<CachingDnsResolver>`; delegate to
        // the process-wide singleton so cached entries are shared across reqwest, PPv2, and WS.
        let host = name.as_str().to_string();
        let resolver = global_dns_resolver();
        Box::pin(async move {
            let ips = resolver.resolve_ips(&host).await.map_err(|e| {
                Box::new(std::io::Error::other(e.to_string()))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect();
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Returns the shared process-wide async DNS cache singleton.
pub fn global_dns_resolver() -> Arc<CachingDnsResolver> {
    static RESOLVER: OnceLock<Arc<CachingDnsResolver>> = OnceLock::new();
    Arc::clone(RESOLVER.get_or_init(|| Arc::new(CachingDnsResolver::new())))
}

/// Interleaves IPv4 and IPv6 addresses (IPv4 first for predictable VPS routing, then IPv6,
/// alternating) while deduplicating so Happy Eyeballs probes both address families rapidly.
fn interleave_dual_stack(ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(_) if !v4.contains(&ip) => v4.push(ip),
            IpAddr::V6(_) if !v6.contains(&ip) => v6.push(ip),
            _ => {}
        }
    }
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    let max_len = v4.len().max(v6.len());
    for i in 0..max_len {
        if let Some(&a) = v4.get(i) {
            out.push(a);
        }
        if let Some(&b) = v6.get(i) {
            out.push(b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn interleave_dual_stack_alternates_v4_and_v6_and_deduplicates() {
        let input = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
        ];
        let out = interleave_dual_stack(input);
        assert_eq!(
            out,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    #[tokio::test]
    async fn resolver_handles_ip_literals_and_caches_localhost() {
        let resolver = Arc::new(CachingDnsResolver::new());
        let literal = resolver.resolve_ips("127.0.0.1").await.unwrap();
        assert_eq!(literal.as_ref(), &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        let bracketed = resolver.resolve_ips("[::1]").await.unwrap();
        assert_eq!(bracketed.as_ref(), &[IpAddr::V6(Ipv6Addr::LOCALHOST)]);

        let first = resolver.resolve_ips("localhost").await.unwrap();
        assert!(!first.is_empty());
        let second = resolver.resolve_ips("LOCALHOST").await.unwrap();
        assert_eq!(first.as_ref(), second.as_ref());
    }
}
