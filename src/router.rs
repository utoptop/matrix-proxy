use crate::client_ip::ClientInfo;
use crate::config::{AuthRouteMode, ProxyProfile, strip_host_port};
use crate::discovery::ResolvedUpstreams;
use crate::rewrite::{PublicContext, is_safe_host_header, path_has_prefix, strip_path_prefix};
use http::HeaderMap;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    ProxyHealth,
    ProxyInfo,
    WellKnownMatrixClient,
    AuthMetadata {
        requested_path: String,
    },
    OidcDiscovery {
        upstream_path: String,
    },
    Matrix {
        upstream_path_and_query: String,
    },
    Auth {
        upstream_path_and_query: String,
        stripped_prefix: bool,
    },
    Rtc {
        upstream_path_and_query: String,
    },
}

/// Fast O(1) virtual-host router for one listening port (handles 1 dedicated profile OR N shared-port profiles).
pub struct VhostRouter<T> {
    exact: HashMap<String, Arc<T>>,
    wildcards: Vec<(String, Arc<T>)>,
    single_dedicated: Option<(Arc<T>, bool)>,
    default_fallback: Option<Arc<T>>,
    all_instances: Vec<Arc<T>>,
}

impl<T> VhostRouter<T> {
    pub fn build(entries: Vec<(Vec<String>, bool, bool, Arc<T>)>) -> Self {
        let mut exact = HashMap::new();
        let mut wildcards = Vec::new();
        let mut default_fallback = None;
        let mut all_instances = Vec::with_capacity(entries.len());

        let single_dedicated = if entries.len() == 1 {
            Some((Arc::clone(&entries[0].3), entries[0].2))
        } else {
            None
        };

        for (domains, is_default, _strict, inst) in entries {
            all_instances.push(Arc::clone(&inst));
            if is_default {
                default_fallback = Some(Arc::clone(&inst));
            }
            for domain in domains {
                let norm = domain.to_ascii_lowercase();
                if let Some(suffix) = norm.strip_prefix("*.") {
                    wildcards.push((format!(".{suffix}"), Arc::clone(&inst)));
                } else {
                    exact.insert(norm, Arc::clone(&inst));
                }
            }
        }

        // Longest wildcard suffix wins first (e.g. `*.sub.example.com` before `*.example.com`).
        wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self {
            exact,
            wildcards,
            single_dedicated,
            default_fallback,
            all_instances,
        }
    }

    pub fn instances(&self) -> &[Arc<T>] {
        &self.all_instances
    }

    pub fn is_shared_port(&self) -> bool {
        self.all_instances.len() > 1
    }

    pub fn resolve(&self, host: Option<&str>) -> Option<Arc<T>> {
        if let Some((inst, strict_host_match)) = &self.single_dedicated {
            if !strict_host_match {
                return Some(Arc::clone(inst));
            }
            if let Some(h) = host
                && self.match_domain(h).is_some()
            {
                return Some(Arc::clone(inst));
            }
            return None;
        }

        if let Some(h) = host
            && let Some(found) = self.match_domain(h)
        {
            return Some(found);
        }

        self.default_fallback.as_ref().map(Arc::clone)
    }

    fn match_domain(&self, raw_host: &str) -> Option<Arc<T>> {
        let host = strip_host_port(raw_host).to_ascii_lowercase();
        if let Some(found) = self.exact.get(&host) {
            return Some(Arc::clone(found));
        }
        for (suffix, inst) in &self.wildcards {
            if host.ends_with(suffix) && host.len() > suffix.len() {
                return Some(Arc::clone(inst));
            }
        }
        None
    }
}

/// Extracts the effective request host (trusting `X-Forwarded-Host` ONLY when `client.peer_is_trusted`).
pub fn extract_request_host(client: &ClientInfo, headers: &HeaderMap) -> Option<String> {
    if client.peer_is_trusted
        && let Some(xfh) = headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|s| is_safe_host_header(s))
    {
        return Some(xfh.to_string());
    }

    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| is_safe_host_header(s))
        .map(ToString::to_string)
}

pub fn classify_request(
    profile: &ProxyProfile,
    public: &PublicContext,
    upstreams: &ResolvedUpstreams,
    client: &ClientInfo,
    headers: &HeaderMap,
    path: &str,
    query: Option<&str>,
) -> RouteTarget {
    let pq = join_pq(path, query);

    let proxy_prefix = profile.routing.proxy_prefix.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(proxy_prefix) {
        if rest == "/health" || rest == "/health/" {
            return RouteTarget::ProxyHealth;
        }
        if rest == "/info" || rest == "/info/" {
            return RouteTarget::ProxyInfo;
        }
    }

    // Dual-domain host routing within one profile (`public_url` + `public_auth_url`)
    if public.dual_domain && is_request_for_auth_host(public, client, headers) {
        if let Some(disc_path) = match_oidc_discovery_path(path, None) {
            return RouteTarget::OidcDiscovery {
                upstream_path: disc_path,
            };
        }
        return RouteTarget::Auth {
            upstream_path_and_query: pq,
            stripped_prefix: false,
        };
    }

    if path == "/.well-known/matrix/client" {
        return RouteTarget::WellKnownMatrixClient;
    }

    if path == "/_matrix/client/v1/auth_metadata"
        || path == "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata"
    {
        return RouteTarget::AuthMetadata {
            requested_path: path.to_string(),
        };
    }

    if upstreams.rtc_url.is_some() && path_has_prefix(path, &profile.routing.rtc_prefix) {
        let stripped = strip_path_prefix(path, &profile.routing.rtc_prefix);
        return RouteTarget::Rtc {
            upstream_path_and_query: join_pq(stripped, query),
        };
    }

    let auth_prefix_opt = match profile.routing.auth_mode {
        AuthRouteMode::Prefix => Some(profile.routing.auth_prefix.as_str()),
        AuthRouteMode::Root => None,
    };
    if let Some(upstream_disc_path) = match_oidc_discovery_path(path, auth_prefix_opt) {
        return RouteTarget::OidcDiscovery {
            upstream_path: upstream_disc_path,
        };
    }

    for prefix in &profile.routing.auth_matrix_prefixes {
        if path_has_prefix(path, prefix) {
            return RouteTarget::Auth {
                upstream_path_and_query: pq,
                stripped_prefix: false,
            };
        }
    }

    if is_matrix_path(path, &profile.routing.matrix_extra_prefixes) {
        return RouteTarget::Matrix {
            upstream_path_and_query: pq,
        };
    }

    match profile.routing.auth_mode {
        AuthRouteMode::Root => RouteTarget::Auth {
            upstream_path_and_query: pq,
            stripped_prefix: false,
        },
        AuthRouteMode::Prefix => {
            if path_has_prefix(path, &profile.routing.auth_prefix) {
                let stripped = strip_path_prefix(path, &profile.routing.auth_prefix);
                RouteTarget::Auth {
                    upstream_path_and_query: join_pq(stripped, query),
                    stripped_prefix: true,
                }
            } else {
                RouteTarget::Matrix {
                    upstream_path_and_query: pq,
                }
            }
        }
    }
}

fn is_matrix_path(path: &str, extra_prefixes: &[String]) -> bool {
    if path == "/_matrix"
        || path.starts_with("/_matrix/")
        || path == "/.well-known/matrix/server"
        || path.starts_with("/.well-known/matrix/")
        || path.starts_with("/_synapse/")
        || path.starts_with("/_conduwuit/")
    {
        return true;
    }

    for extra in extra_prefixes {
        if path_has_prefix(path, extra) {
            return true;
        }
    }

    false
}

fn match_oidc_discovery_path(path: &str, auth_prefix: Option<&str>) -> Option<String> {
    if !path.contains(".well-known/") {
        return None;
    }
    const WELL_KNOWN_DOCS: [&str; 2] = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ];

    for doc in WELL_KNOWN_DOCS {
        if path == doc {
            return Some(doc.to_string());
        }
        if let Some(prefix) = auth_prefix
            && ((path.starts_with(prefix) && path[prefix.len()..] == *doc)
                || (path.starts_with(doc) && path[doc.len()..] == *prefix))
        {
            return Some(doc.to_string());
        }
    }

    None
}

fn is_request_for_auth_host(
    public: &PublicContext,
    client: &ClientInfo,
    headers: &HeaderMap,
) -> bool {
    let Some(auth_host) = public.auth_base.host_str() else {
        return false;
    };
    let matrix_host = public.matrix_base.host_str().unwrap_or_default();
    let auth_port = public.auth_base.port_or_known_default();
    let matrix_port = public.matrix_base.port_or_known_default();
    if auth_host.eq_ignore_ascii_case(matrix_host) && auth_port == matrix_port {
        return false;
    }

    let Some(req_host) = extract_request_host(client, headers) else {
        return false;
    };

    if !strip_host_port(&req_host).eq_ignore_ascii_case(auth_host) {
        return false;
    }

    // If Matrix & Auth share the same host/IP on different ports (e.g. `http://100.64.0.10:8081` vs `:8082`),
    // match the explicit port too so Matrix traffic isn't misrouted to Auth.
    if auth_host.eq_ignore_ascii_case(matrix_host) {
        let req_port = extract_host_port(&req_host).or_else(|| {
            Some(if client.client_proto == "https" {
                443
            } else {
                80
            })
        });
        return req_port == auth_port;
    }

    true
}

fn extract_host_port(host: &str) -> Option<u16> {
    if host.starts_with('[') {
        let after_bracket = host.split_once(']')?.1;
        after_bracket.strip_prefix(':')?.parse::<u16>().ok()
    } else {
        host.rsplit_once(':')?.1.parse::<u16>().ok()
    }
}

fn join_pq(path: &str, query: Option<&str>) -> String {
    let clean = if path.is_empty() { "/" } else { path };
    match query {
        Some(q) if !q.is_empty() => format!("{clean}?{q}"),
        _ => clean.to_string(),
    }
}
