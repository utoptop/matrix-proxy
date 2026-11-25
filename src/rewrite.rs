use crate::client_ip::ClientInfo;
use crate::config::{AuthRouteMode, ProxyProfile, normalized_base_url, origin_string};
use crate::discovery::ResolvedUpstreams;
use http::HeaderMap;
use serde_json::{Map, Value, json};
use url::Url;

/// All OAuth 2.0 / OIDC / Matrix auth_metadata URL fields that must route through the proxy.
const AUTH_METADATA_ENDPOINT_KEYS: &[&str] = &[
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "revocation_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
    "device_authorization_endpoint",
    "account_management_uri",
    "pushed_authorization_request_endpoint",
    "introspection_endpoint",
    "end_session_endpoint",
    "check_session_iframe",
    "service_documentation",
    "op_policy_uri",
    "op_tos_uri",
    "account",
];

#[derive(Debug, Clone)]
pub struct PublicContext {
    pub matrix_base: Url,
    pub auth_base: Url,
    pub rtc_base: Option<Url>,
    /// Present only in single-domain `prefix` mode (e.g. `"/_auth"`).
    pub auth_prefix: Option<String>,
    pub dual_domain: bool,
}

impl PublicContext {
    pub fn from_request(
        profile: &ProxyProfile,
        client: &ClientInfo,
        headers: &HeaderMap,
        has_rtc: bool,
    ) -> Self {
        let matrix_base = profile
            .public_url
            .clone()
            .unwrap_or_else(|| infer_public_url(client, headers));

        let (auth_base, auth_prefix, dual_domain) =
            if let Some(explicit_auth) = &profile.public_auth_url {
                (explicit_auth.clone(), None, true)
            } else {
                match profile.routing.auth_mode {
                    AuthRouteMode::Root => (matrix_base.clone(), None, false),
                    AuthRouteMode::Prefix => {
                        let base = format!(
                            "{}{}",
                            normalized_base_url(&matrix_base),
                            profile.routing.auth_prefix
                        );
                        let parsed = Url::parse(&base).unwrap_or_else(|_| matrix_base.clone());
                        (parsed, Some(profile.routing.auth_prefix.clone()), false)
                    }
                }
            };

        let rtc_base = if has_rtc {
            let base = format!(
                "{}{}",
                normalized_base_url(&matrix_base),
                profile.routing.rtc_prefix
            );
            Url::parse(&base).ok()
        } else {
            None
        };

        Self {
            matrix_base,
            auth_base,
            rtc_base,
            auth_prefix,
            dual_domain,
        }
    }

    pub fn matrix_origin(&self) -> String {
        origin_string(&self.matrix_base)
    }

    pub fn auth_origin(&self) -> String {
        origin_string(&self.auth_base)
    }

    pub fn public_is_https(&self) -> bool {
        self.matrix_base.scheme().eq_ignore_ascii_case("https")
    }
}

/// Infers public proxy URL safely: only trusts `X-Forwarded-Host` / `Forwarded` when `client.peer_is_trusted`,
/// and strictly sanitizes hostname characters to prevent host-header injection.
pub fn infer_public_url(client: &ClientInfo, headers: &HeaderMap) -> Url {
    let scheme = &client.client_proto;
    let mut host: Option<String> = None;

    if client.peer_is_trusted {
        if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok())
            && let Some(first) = forwarded.split(',').next()
        {
            for part in first.split(';') {
                let mut kv = part.trim().splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next())
                    && k.eq_ignore_ascii_case("host")
                {
                    let clean = v.trim().trim_matches('"');
                    if is_safe_host_header(clean) {
                        host = Some(clean.to_string());
                    }
                }
            }
        }

        if let Some(xfh) = headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|s| is_safe_host_header(s))
        {
            host = Some(xfh.to_string());
        }
    }

    if host.is_none() {
        host = headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| is_safe_host_header(s))
            .map(ToString::to_string);
    }

    let host = host.unwrap_or_else(|| "localhost".to_string());
    let candidate = format!("{scheme}://{host}");
    Url::parse(&candidate).unwrap_or_else(|_| Url::parse("http://localhost").unwrap())
}

pub fn is_safe_host_header(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && !host
            .bytes()
            .any(|b| b <= 0x20 || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#' | b'<' | b'>'))
}

pub struct RewriteEngine<'a> {
    pub profile: &'a ProxyProfile,
    pub public: &'a PublicContext,
    pub upstreams: &'a ResolvedUpstreams,
}

impl<'a> RewriteEngine<'a> {
    pub fn new(
        profile: &'a ProxyProfile,
        public: &'a PublicContext,
        upstreams: &'a ResolvedUpstreams,
    ) -> Self {
        Self {
            profile,
            public,
            upstreams,
        }
    }

    /// Rewrites a URL string if it points to one of our configured, discovered, or `rewrite_origins` upstreams.
    pub fn rewrite_url_str(&self, raw: &str, prefer_auth: bool) -> String {
        let Ok(parsed) = Url::parse(raw) else {
            return raw.to_string();
        };

        let raw_origin = origin_string(&parsed);
        let matrix_origin = self.upstreams.matrix_origin.as_str();
        let auth_origin = self.upstreams.auth_origin.as_str();
        let rtc_origin = self.upstreams.rtc_origin.as_deref();
        let wk_hs_origin = self.upstreams.wk_hs_origin.as_deref();

        let matches_extra_auth = self
            .upstreams
            .observed_auth_origins
            .iter()
            .any(|o| o == &raw_origin);
        let matches_configured_rewrite = self
            .profile
            .parsed_rewrite_origins
            .iter()
            .any(|o| o == &raw_origin);

        let target_base = if let (Some(ro), Some(rtc_base)) = (rtc_origin, &self.public.rtc_base) {
            if raw_origin == ro {
                Some(normalized_base_url(rtc_base))
            } else {
                None
            }
        } else {
            None
        }
        .or_else(|| {
            if (raw_origin == auth_origin && (raw_origin != matrix_origin || prefer_auth))
                || (prefer_auth && (matches_extra_auth || matches_configured_rewrite))
            {
                Some(normalized_base_url(&self.public.auth_base))
            } else if raw_origin == matrix_origin
                || wk_hs_origin == Some(raw_origin.as_str())
                || matches_configured_rewrite
                || matches_extra_auth
            {
                Some(normalized_base_url(&self.public.matrix_base))
            } else {
                None
            }
        });

        let Some(base) = target_base else {
            return raw.to_string();
        };

        let mut out = String::with_capacity(raw.len() + 32);
        out.push_str(&base);

        let path = parsed.path();
        if path == "/" {
            if raw.trim_end_matches(|c| c != '/').ends_with('/') && raw_has_trailing_root_slash(raw)
            {
                out.push('/');
            }
        } else if !path.is_empty() {
            out.push_str(path);
        }

        if let Some(q) = parsed.query() {
            out.push('?');
            out.push_str(q);
        }
        if let Some(f) = parsed.fragment() {
            out.push('#');
            out.push_str(f);
        }
        out
    }

    pub fn rewrite_auth_metadata(&self, mut doc: Value) -> Value {
        let Some(obj) = doc.as_object_mut() else {
            return doc;
        };

        for key in AUTH_METADATA_ENDPOINT_KEYS {
            if let Some(Value::String(val)) = obj.get(*key) {
                let rewritten = self.rewrite_url_str(val, true);
                obj.insert((*key).to_string(), Value::String(rewritten));
            }
        }

        if self.profile.discovery.rewrite_issuer
            && let Some(Value::String(issuer)) = obj.get("issuer")
        {
            let rewritten = self.rewrite_url_str(issuer, true);
            obj.insert("issuer".to_string(), Value::String(rewritten));
        }

        doc
    }

    pub fn build_well_known_client(&self) -> Value {
        let mut root: Map<String, Value> = if self.profile.discovery.merge_upstream_well_known {
            self.upstreams
                .upstream_well_known
                .as_ref()
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default()
        } else {
            Map::new()
        };

        let public_matrix_base = normalized_base_url(&self.public.matrix_base);

        let mut hs_obj = root
            .get("m.homeserver")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        hs_obj.insert("base_url".to_string(), Value::String(public_matrix_base));
        root.insert("m.homeserver".to_string(), Value::Object(hs_obj));

        if let Some(Value::Object(mut auth_obj)) = root.remove("org.matrix.msc2965.authentication")
        {
            if self.profile.discovery.rewrite_issuer
                && let Some(Value::String(issuer)) = auth_obj.get("issuer")
            {
                let rewritten = self.rewrite_url_str(issuer, true);
                auth_obj.insert("issuer".to_string(), Value::String(rewritten));
            }
            if let Some(Value::String(account)) = auth_obj.get("account") {
                let rewritten = self.rewrite_url_str(account, true);
                auth_obj.insert("account".to_string(), Value::String(rewritten));
            }
            root.insert(
                "org.matrix.msc2965.authentication".to_string(),
                Value::Object(auth_obj),
            );
        } else if self.profile.discovery.force_msc2965_well_known {
            let issuer = if let Some(discovered) = &self.upstreams.discovered_issuer {
                if self.profile.discovery.rewrite_issuer {
                    self.rewrite_url_str(discovered, true)
                } else {
                    discovered.clone()
                }
            } else {
                format!("{}/", normalized_base_url(&self.public.auth_base))
            };
            root.insert(
                "org.matrix.msc2965.authentication".to_string(),
                json!({ "issuer": issuer }),
            );
        }

        if let Some(rtc_base) = &self.public.rtc_base {
            let proxy_rtc_url = normalized_base_url(rtc_base);
            if let Some(Value::Array(mut foci)) = root.remove("org.matrix.msc4143.rtc_foci") {
                for focus in &mut foci {
                    if let Some(obj) = focus.as_object_mut()
                        && let Some(Value::String(url)) = obj.get("livekit_service_url")
                    {
                        let rewritten = self.rewrite_url_str(url, false);
                        let final_url = if rewritten == *url {
                            proxy_rtc_url.clone()
                        } else {
                            rewritten
                        };
                        obj.insert("livekit_service_url".to_string(), Value::String(final_url));
                    }
                }
                root.insert(
                    "org.matrix.msc4143.rtc_foci".to_string(),
                    Value::Array(foci),
                );
            } else {
                root.insert(
                    "org.matrix.msc4143.rtc_foci".to_string(),
                    json!([{
                        "type": "livekit",
                        "livekit_service_url": proxy_rtc_url
                    }]),
                );
            }
        }

        if let Some(id_url) = &self.profile.discovery.identity_server_url {
            root.insert(
                "m.identity_server".to_string(),
                json!({ "base_url": id_url.trim_end_matches('/') }),
            );
        }

        Value::Object(root)
    }

    pub fn rewrite_location_header(&self, location: &str, from_auth_upstream: bool) -> String {
        let trimmed = location.trim();

        if trimmed.starts_with('/') && !trimmed.starts_with("//") {
            if from_auth_upstream
                && let Some(prefix) = &self.public.auth_prefix
                && !path_has_prefix(trimmed, prefix)
            {
                return format!("{prefix}{trimmed}");
            }
            return trimmed.to_string();
        }

        let rewritten_origin = self.rewrite_url_str(trimmed, from_auth_upstream);
        if !self.profile.discovery.rewrite_issuer {
            return rewritten_origin;
        }

        self.rewrite_iss_param_in_url(&rewritten_origin)
    }

    fn rewrite_iss_param_in_url(&self, raw: &str) -> String {
        let Ok(mut parsed) = Url::parse(raw) else {
            return raw.to_string();
        };

        let mut changed = false;

        if parsed.query().is_some() {
            let pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == "iss" {
                        let new_v = self.rewrite_url_str(&v, true);
                        if new_v != v {
                            changed = true;
                        }
                        (k.into_owned(), new_v)
                    } else {
                        (k.into_owned(), v.into_owned())
                    }
                })
                .collect();

            if changed {
                let mut ser = url::form_urlencoded::Serializer::new(String::new());
                for (k, v) in pairs {
                    ser.append_pair(&k, &v);
                }
                parsed.set_query(Some(&ser.finish()));
            }
        }

        if let Some(fragment) = parsed.fragment().map(ToString::to_string)
            && fragment.contains("iss=")
        {
            let mut frag_changed = false;
            let pairs: Vec<(String, String)> = url::form_urlencoded::parse(fragment.as_bytes())
                .map(|(k, v)| {
                    if k == "iss" {
                        let new_v = self.rewrite_url_str(&v, true);
                        if new_v != v {
                            frag_changed = true;
                        }
                        (k.into_owned(), new_v)
                    } else {
                        (k.into_owned(), v.into_owned())
                    }
                })
                .collect();

            if frag_changed {
                let mut ser = url::form_urlencoded::Serializer::new(String::new());
                for (k, v) in pairs {
                    ser.append_pair(&k, &v);
                }
                parsed.set_fragment(Some(&ser.finish()));
                changed = true;
            }
        }

        if changed {
            parsed.to_string()
        } else {
            raw.to_string()
        }
    }

    pub fn rewrite_set_cookie(&self, raw: &str, from_auth_upstream: bool) -> String {
        let mut parts = raw.split(';');
        let Some(first) = parts.next() else {
            return raw.to_string();
        };

        let mut out = vec![first.trim().to_string()];
        let is_http = !self.public.public_is_https();

        for attr in parts {
            let trimmed = attr.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("domain=") {
                continue;
            }
            if is_http && lower == "secure" {
                continue;
            }
            if from_auth_upstream
                && let (Some(prefix), Some(rest)) = (
                    &self.public.auth_prefix,
                    strip_prefix_ignore_ascii_case(trimmed, "path="),
                )
            {
                let clean_path = rest.trim();
                if clean_path == "/" {
                    out.push(format!("Path={prefix}"));
                } else if clean_path.starts_with('/') && !path_has_prefix(clean_path, prefix) {
                    out.push(format!("Path={prefix}{clean_path}"));
                } else {
                    out.push(trimmed.to_string());
                }
                continue;
            }
            out.push(trimmed.to_string());
        }

        out.join("; ")
    }

    pub fn rewrite_csp_header(&self, csp: &str) -> String {
        let mut result = csp.to_string();
        let pub_auth = self.public.auth_origin();
        let pub_matrix = self.public.matrix_origin();

        for orig in self.all_auth_origins() {
            if orig != pub_auth && result.contains(orig) {
                result = result.replace(orig, &pub_auth);
            }
        }
        let matrix_origin = self.upstreams.matrix_origin.as_str();
        if matrix_origin != pub_matrix && result.contains(matrix_origin) {
            result = result.replace(matrix_origin, &pub_matrix);
        }
        result
    }

    pub fn rewrite_auth_text_body(&self, body: &str) -> String {
        let pub_auth_base = normalized_base_url(&self.public.auth_base);
        let pub_matrix_base = normalized_base_url(&self.public.matrix_base);
        let mut out = body.to_string();

        for orig in self.all_auth_origins() {
            if orig != pub_auth_base {
                if out.contains(orig) {
                    out = out.replace(orig, &pub_auth_base);
                }
                let escaped_from = orig.replace('/', "\\/");
                if out.contains(&escaped_from) {
                    let escaped_to = pub_auth_base.replace('/', "\\/");
                    out = out.replace(&escaped_from, &escaped_to);
                }
            }
        }

        let matrix_origin = self.upstreams.matrix_origin.as_str();
        if matrix_origin != pub_matrix_base {
            if out.contains(matrix_origin) {
                out = out.replace(matrix_origin, &pub_matrix_base);
            }
            let escaped_from = matrix_origin.replace('/', "\\/");
            if out.contains(&escaped_from) {
                let escaped_to = pub_matrix_base.replace('/', "\\/");
                out = out.replace(&escaped_from, &escaped_to);
            }
        }

        out
    }

    fn all_auth_origins(&self) -> Vec<&str> {
        let mut list = vec![self.upstreams.auth_origin.as_str()];
        for o in &self.upstreams.observed_auth_origins {
            if !list.contains(&o.as_str()) {
                list.push(o.as_str());
            }
        }
        for o in &self.profile.parsed_rewrite_origins {
            if !list.contains(&o.as_str()) {
                list.push(o.as_str());
            }
        }
        list
    }

    pub fn rewrite_request_origin_header(
        &self,
        header_val: &str,
        target_upstream: &Url,
        strip_auth_prefix: bool,
    ) -> Option<String> {
        let trimmed = header_val.trim();
        let target_origin = origin_string(target_upstream);

        for pub_origin in [self.public.auth_origin(), self.public.matrix_origin()] {
            if trimmed == pub_origin {
                return Some(target_origin);
            }
            if let Some(rest) = trimmed.strip_prefix(&pub_origin)
                && (rest.is_empty() || rest.starts_with('/'))
            {
                let clean_rest = if strip_auth_prefix {
                    if let Some(prefix) = &self.public.auth_prefix {
                        strip_path_prefix(rest, prefix)
                    } else {
                        rest
                    }
                } else {
                    rest
                };
                return Some(format!("{target_origin}{clean_rest}"));
            }
        }
        None
    }
}

pub fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .map(|r| r.starts_with('/') || r.starts_with('?'))
            .unwrap_or(false)
}

pub fn strip_path_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    if path == prefix {
        "/"
    } else if let Some(rest) = path.strip_prefix(prefix) {
        if rest.starts_with('/') || rest.starts_with('?') {
            rest
        } else {
            path
        }
    } else {
        path
    }
}

fn raw_has_trailing_root_slash(raw: &str) -> bool {
    let before_qf = raw.split(['?', '#']).next().unwrap_or(raw);
    if let Some(after_scheme) = before_qf.split("://").nth(1) {
        after_scheme.ends_with('/')
    } else {
        false
    }
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

pub fn build_upstream_target_url(upstream_base: &Url, path_and_query: &str) -> Url {
    let origin = origin_string(upstream_base);
    let base_path = upstream_base.path().trim_end_matches('/');

    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let clean_path = if path.is_empty() { "/" } else { path };

    let full_path =
        if base_path.is_empty() || base_path == "/" || path_has_prefix(clean_path, base_path) {
            clean_path.to_string()
        } else if clean_path == "/" {
            format!("{base_path}/")
        } else {
            format!("{base_path}{clean_path}")
        };

    let raw = match query {
        Some(q) => format!("{origin}{full_path}?{q}"),
        None => format!("{origin}{full_path}"),
    };
    Url::parse(&raw).unwrap_or_else(|_| upstream_base.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::redact_proxy_url;

    #[test]
    fn upstream_target_url_handles_root_and_subpath_without_double_prefix() {
        let root_base = Url::parse("https://auth.example.com").unwrap();
        assert_eq!(
            build_upstream_target_url(&root_base, "/oauth2/token?a=1").as_str(),
            "https://auth.example.com/oauth2/token?a=1"
        );

        let sub_base = Url::parse("https://sso.example.com/realms/matrix").unwrap();
        assert_eq!(
            build_upstream_target_url(&sub_base, "/realms/matrix/protocol/openid-connect/token")
                .as_str(),
            "https://sso.example.com/realms/matrix/protocol/openid-connect/token"
        );
        assert_eq!(
            build_upstream_target_url(&sub_base, "/.well-known/openid-configuration").as_str(),
            "https://sso.example.com/realms/matrix/.well-known/openid-configuration"
        );
    }

    #[test]
    fn proxy_url_redacts_password() {
        assert_eq!(
            redact_proxy_url("socks5h://alice:supersecret@127.0.0.1:1080"),
            "socks5h://alice:***@127.0.0.1:1080"
        );
        assert_eq!(
            redact_proxy_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/"
        );
    }

    #[test]
    fn safe_host_header_blocks_injection() {
        assert!(is_safe_host_header("proxy.example.com"));
        assert!(is_safe_host_header("proxy.example.com:443"));
        assert!(is_safe_host_header("[::1]:8080"));
        assert!(!is_safe_host_header("evil.com/path"));
        assert!(!is_safe_host_header("user@evil.com"));
        assert!(!is_safe_host_header("evil.com\r\nX-Injected: 1"));
    }
}
