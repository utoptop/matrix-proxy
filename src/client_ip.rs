use crate::config::{ClientIpMode, RuntimeConfig, canonical_ip};
use anyhow::{Context, Result, bail};
use http::{HeaderMap, HeaderValue};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Verified client network identity extracted from TCP peer + trusted proxy headers.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Physical TCP peer address (or address recovered by inbound PROXY protocol v2).
    pub peer_addr: SocketAddr,
    /// True whether `peer_addr.ip()` is in `server.trusted_proxies` (and `trust_forwarded_headers` is enabled).
    pub peer_is_trusted: bool,
    /// Authoritative real client IP (anti-spoofing protected).
    pub client_ip: IpAddr,
    /// Authoritative client source port (best-effort; falls back to peer port).
    pub client_port: u16,
    /// Effective client scheme (`"https"` or `"http"`).
    pub client_proto: String,
    /// Sanitized incoming `X-Forwarded-For` chain (only retained when `peer_is_trusted`).
    pub trusted_xff_chain: Option<String>,
}

impl ClientInfo {
    pub fn extract(
        runtime: &RuntimeConfig,
        peer_addr: SocketAddr,
        headers: &HeaderMap,
        listener_is_tls: bool,
    ) -> Self {
        let peer_ip = canonical_ip(peer_addr.ip());
        let peer_is_trusted =
            runtime.server.trust_forwarded_headers && runtime.is_trusted_proxy(peer_ip);

        let mut client_ip = peer_ip;
        let mut trusted_xff_chain: Option<String> = None;

        if peer_is_trusted {
            // 1. Check X-Forwarded-For right-to-left, skipping trusted proxy hops.
            if let Some(xff_raw) = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let mut valid_ips: Vec<IpAddr> = Vec::new();
                for part in xff_raw.split(',') {
                    if let Some(ip) = parse_header_ip(part) {
                        valid_ips.push(ip);
                    }
                }
                if !valid_ips.is_empty() {
                    trusted_xff_chain = Some(
                        valid_ips
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    // Rightmost untrusted IP is the authoritative client IP; fallback to leftmost if all trusted.
                    client_ip = valid_ips
                        .iter()
                        .rev()
                        .copied()
                        .find(|ip| !runtime.is_trusted_proxy(*ip))
                        .unwrap_or(valid_ips[0]);
                }
            }

            // 2. Fallback to CF-Connecting-IP / True-Client-IP / X-Real-IP / Forwarded `for=` if XFF didn't yield a non-peer IP.
            if client_ip == peer_ip || runtime.is_trusted_proxy(client_ip) {
                for hdr in ["cf-connecting-ip", "true-client-ip", "x-real-ip"] {
                    if let Some(raw) = headers.get(hdr).and_then(|v| v.to_str().ok())
                        && let Some(ip) = parse_header_ip(raw)
                    {
                        client_ip = ip;
                        break;
                    }
                }
            }
            if client_ip == peer_ip
                && let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok())
                && let Some(ip) = parse_forwarded_for(fwd)
            {
                client_ip = ip;
            }
        }

        let client_proto = if peer_is_trusted {
            headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
                .filter(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
                .map(|s| s.to_ascii_lowercase())
                .or_else(|| {
                    headers
                        .get("forwarded")
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_forwarded_proto)
                })
                .unwrap_or_else(|| if listener_is_tls { "https" } else { "http" }.to_string())
        } else {
            if listener_is_tls { "https" } else { "http" }.to_string()
        };

        Self {
            peer_addr: SocketAddr::new(peer_ip, peer_addr.port()),
            peer_is_trusted,
            client_ip,
            client_port: peer_addr.port(),
            client_proto,
            trusted_xff_chain,
        }
    }

    pub fn client_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.client_ip, self.client_port)
    }

    /// Computes `(X-Forwarded-For, X-Real-IP, Forwarded)` values to inject toward upstream.
    pub fn upstream_ip_headers(&self, mode: ClientIpMode) -> Option<(String, String, String)> {
        match mode {
            ClientIpMode::Off => None,
            ClientIpMode::Replace => {
                let ip_str = self.client_ip.to_string();
                let fwd = format_rfc7239_forwarded(self.client_ip, &self.client_proto);
                Some((ip_str.clone(), ip_str, fwd))
            }
            ClientIpMode::Append => {
                let ip_str = self.client_ip.to_string();
                let xff = match &self.trusted_xff_chain {
                    Some(chain) => {
                        let peer_str = self.peer_addr.ip().to_string();
                        if chain.ends_with(&peer_str) {
                            chain.clone()
                        } else {
                            format!("{chain}, {peer_str}")
                        }
                    }
                    None => ip_str.clone(),
                };
                let fwd = format_rfc7239_forwarded(self.client_ip, &self.client_proto);
                Some((xff, ip_str, fwd))
            }
        }
    }
}

pub fn apply_upstream_client_ip_headers(
    headers: &mut HeaderMap,
    client: &ClientInfo,
    mode: ClientIpMode,
) {
    headers.remove("x-forwarded-for");
    headers.remove("x-real-ip");
    headers.remove("forwarded");

    if let Some((xff, x_real_ip, forwarded)) = client.upstream_ip_headers(mode) {
        if let Ok(v) = HeaderValue::from_str(&xff) {
            headers.insert(http::header::HeaderName::from_static("x-forwarded-for"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&x_real_ip) {
            headers.insert(http::header::HeaderName::from_static("x-real-ip"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&forwarded) {
            headers.insert(http::header::HeaderName::from_static("forwarded"), v);
        }
    }
}

fn format_rfc7239_forwarded(ip: IpAddr, proto: &str) -> String {
    match ip {
        IpAddr::V4(v4) => format!("for={v4};proto={proto}"),
        IpAddr::V6(v6) => format!("for=\"[{v6}]\";proto={proto}"),
    }
}

fn parse_header_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    // Support `[ipv6]:port` or `ipv4:port`
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(canonical_ip(sock.ip()));
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return trimmed[1..trimmed.len() - 1]
            .parse::<IpAddr>()
            .ok()
            .map(canonical_ip);
    }
    None
}

fn parse_forwarded_for(raw: &str) -> Option<IpAddr> {
    for entry in raw.split(',') {
        for part in entry.split(';') {
            let mut kv = part.trim().splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next())
                && k.eq_ignore_ascii_case("for")
                && let Some(ip) = parse_header_ip(v)
            {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_forwarded_proto(raw: &str) -> Option<String> {
    if let Some(first) = raw.split(',').next() {
        for part in first.split(';') {
            let mut kv = part.trim().splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next())
                && k.eq_ignore_ascii_case("proto")
            {
                let clean = v.trim().trim_matches('"');
                if clean.eq_ignore_ascii_case("http") || clean.eq_ignore_ascii_case("https") {
                    return Some(clean.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

// =============================================================================
// HAProxy PROXY Protocol v2 Codec (Outbound Encoder + Inbound Decoder)
// Spec: https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt (Section 2.2)
// =============================================================================

pub const PPV2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Encodes a PROXY Protocol v2 `LOCAL` header (16 bytes) for proxy-originated probes.
pub fn encode_ppv2_local() -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&PPV2_SIGNATURE);
    buf.push(0x20); // Version 2 | Command LOCAL (0x0)
    buf.push(0x00); // AF_UNSPEC | UNSPEC
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

/// Encodes a PROXY Protocol v2 `PROXY` TCP header carrying the real client IP & port.
pub fn encode_ppv2_proxy(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let src_ip = canonical_ip(src.ip());
    let dst_ip = canonical_ip(dst.ip());
    let src_port = if src.port() == 0 { 1 } else { src.port() };
    let dst_port = dst.port();

    match src_ip {
        IpAddr::V4(src_v4) => {
            let dst_v4 = match dst_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };
            let mut buf = Vec::with_capacity(28);
            buf.extend_from_slice(&PPV2_SIGNATURE);
            buf.push(0x21); // Version 2 | Command PROXY (0x1)
            buf.push(0x11); // AF_INET | STREAM
            buf.extend_from_slice(&12u16.to_be_bytes());
            buf.extend_from_slice(&src_v4.octets());
            buf.extend_from_slice(&dst_v4.octets());
            buf.extend_from_slice(&src_port.to_be_bytes());
            buf.extend_from_slice(&dst_port.to_be_bytes());
            buf
        }
        IpAddr::V6(src_v6) => {
            let dst_v6 = match dst_ip {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            let mut buf = Vec::with_capacity(52);
            buf.extend_from_slice(&PPV2_SIGNATURE);
            buf.push(0x21); // Version 2 | Command PROXY (0x1)
            buf.push(0x21); // AF_INET6 | STREAM
            buf.extend_from_slice(&36u16.to_be_bytes());
            buf.extend_from_slice(&src_v6.octets());
            buf.extend_from_slice(&dst_v6.octets());
            buf.extend_from_slice(&src_port.to_be_bytes());
            buf.extend_from_slice(&dst_port.to_be_bytes());
            buf
        }
    }
}

/// Decodes an inbound PROXY Protocol v2 header from an accepted TCP stream.
/// Returns `Some(client_addr)` for `PROXY` frames, or `None` for `LOCAL` frames.
pub async fn read_ppv2_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<SocketAddr>> {
    let mut hdr = [0u8; 16];
    reader
        .read_exact(&mut hdr)
        .await
        .context("failed to read PROXY Protocol v2 fixed header")?;

    if hdr[..12] != PPV2_SIGNATURE {
        bail!("invalid PROXY Protocol v2 signature");
    }

    let ver = hdr[12] >> 4;
    let cmd = hdr[12] & 0x0F;
    if ver != 0x02 {
        bail!("unsupported PROXY Protocol version {ver}");
    }

    let fam_proto = hdr[13];
    let len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    if len > 4096 {
        bail!("PROXY Protocol v2 payload too large ({len} bytes)");
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("failed to read PROXY Protocol v2 address payload")?;
    }

    match cmd {
        0x00 => Ok(None), // LOCAL
        0x01 => {
            let family = fam_proto >> 4;
            match family {
                0x00 => Ok(None), // UNSPEC
                0x01 => {
                    if payload.len() < 12 {
                        bail!("truncated PROXY v2 IPv4 address payload");
                    }
                    let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                    let src_port = u16::from_be_bytes([payload[8], payload[9]]);
                    Ok(Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)))
                }
                0x02 => {
                    if payload.len() < 36 {
                        bail!("truncated PROXY v2 IPv6 address payload");
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&payload[..16]);
                    let src_ip = canonical_ip(IpAddr::V6(Ipv6Addr::from(octets)));
                    let src_port = u16::from_be_bytes([payload[32], payload[33]]);
                    Ok(Some(SocketAddr::new(src_ip, src_port)))
                }
                other => bail!("unsupported PROXY v2 address family 0x{other:x}"),
            }
        }
        other => bail!("unsupported PROXY Protocol v2 command 0x{other:x}"),
    }
}

// =============================================================================
// Bounded Per-IP Token-Bucket Rate Limiter (Zero External Crate Overhead)
// =============================================================================

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct IpRateLimiter {
    rps: f64,
    burst: f64,
    max_entries: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl IpRateLimiter {
    pub fn new(rps: u64, burst: u64) -> Option<Self> {
        if rps == 0 {
            return None;
        }
        let effective_burst = if burst == 0 { rps.max(1) } else { burst } as f64;
        Some(Self {
            rps: rps as f64,
            burst: effective_burst,
            max_entries: 65_536,
            buckets: Mutex::new(HashMap::with_capacity(1024)),
        })
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut guard = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if guard.len() >= self.max_entries {
            let stale_cutoff = Duration::from_secs(120);
            guard.retain(|_, b| now.duration_since(b.last_refill) < stale_cutoff);
            if guard.len() >= self.max_entries {
                guard.clear();
            }
        }

        let bucket = guard.entry(canonical_ip(ip)).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn untrusted_peer_cannot_spoof_xff_or_proto() {
        let cfg = Config::from_toml_str(
            r#"
            [upstream]
            matrix_url = "https://matrix.example.org"
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        hdrs.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));
        hdrs.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        // Public internet peer (not in trusted_proxies)
        let peer: SocketAddr = "203.0.113.55:44321".parse().unwrap();
        let info = ClientInfo::extract(&cfg, peer, &hdrs, false);
        assert!(!info.peer_is_trusted);
        assert_eq!(info.client_ip, "203.0.113.55".parse::<IpAddr>().unwrap());
        assert_eq!(info.client_proto, "http");
    }

    #[test]
    fn trusted_haproxy_peer_extracts_real_client_ip_and_formats_headers() {
        let cfg = Config::from_toml_str(
            r#"
            [upstream]
            matrix_url = "https://matrix.example.org"
            "#,
        )
        .unwrap()
        .into_runtime()
        .unwrap();

        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.42, 172.18.0.1"),
        );
        hdrs.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let peer: SocketAddr = "172.18.0.1:51000".parse().unwrap();
        let info = ClientInfo::extract(&cfg, peer, &hdrs, false);
        assert!(info.peer_is_trusted);
        assert_eq!(info.client_ip, "198.51.100.42".parse::<IpAddr>().unwrap());
        assert_eq!(info.client_proto, "https");

        let (xff, xrip, fwd) = info.upstream_ip_headers(ClientIpMode::Replace).unwrap();
        assert_eq!(xff, "198.51.100.42");
        assert_eq!(xrip, "198.51.100.42");
        assert_eq!(fwd, "for=198.51.100.42;proto=https");
    }

    #[tokio::test]
    async fn ppv2_roundtrip_ipv4_ipv6_and_local() {
        let src4: SocketAddr = "198.51.100.42:54321".parse().unwrap();
        let dst4: SocketAddr = "203.0.113.10:8443".parse().unwrap();
        let encoded4 = encode_ppv2_proxy(src4, dst4);
        assert_eq!(encoded4.len(), 28);
        let mut cursor = std::io::Cursor::new(encoded4);
        assert_eq!(read_ppv2_header(&mut cursor).await.unwrap(), Some(src4));

        let src6: SocketAddr = "[2001:db8::42]:60000".parse().unwrap();
        let dst6: SocketAddr = "[2001:db8:1::1]:8443".parse().unwrap();
        let encoded6 = encode_ppv2_proxy(src6, dst6);
        assert_eq!(encoded6.len(), 52);
        let mut cursor6 = std::io::Cursor::new(encoded6);
        assert_eq!(read_ppv2_header(&mut cursor6).await.unwrap(), Some(src6));

        let local = encode_ppv2_local();
        assert_eq!(local.len(), 16);
        let mut cursor_l = std::io::Cursor::new(local);
        assert_eq!(read_ppv2_header(&mut cursor_l).await.unwrap(), None);
    }

    #[test]
    fn rate_limiter_enforces_burst_per_ip() {
        let limiter = IpRateLimiter::new(10, 3).unwrap();
        let ip1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip2: IpAddr = "198.51.100.2".parse().unwrap();

        assert!(limiter.allow(ip1));
        assert!(limiter.allow(ip1));
        assert!(limiter.allow(ip1));
        assert!(!limiter.allow(ip1));
        // Independent IP still allowed
        assert!(limiter.allow(ip2));
    }
}
