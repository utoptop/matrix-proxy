use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use matrix_proxy::client_ip::read_ppv2_header;
use matrix_proxy::config::{AuthRouteMode, Config, ExposeInfoMode};
use matrix_proxy::proxy::{ListenerState, build_listener_router};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceExt;

struct MockCluster {
    matrix_url: String,
    auth_url: String,
    rtc_url: String,
}

async fn spawn_mock_cluster(tag: &'static str) -> MockCluster {
    // 1. Mock RTC server
    let rtc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rtc_addr = rtc_listener.local_addr().unwrap();
    let rtc_url = format!("http://{rtc_addr}");
    let rtc_app = Router::new().route(
        "/sfu/get",
        post(move || async move {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"url": "wss://livekit.internal", "jwt": format!("token-{tag}")})
                        .to_string(),
                ))
                .unwrap()
        }),
    );
    tokio::spawn(async move {
        axum::serve(rtc_listener, rtc_app).await.unwrap();
    });

    // 2. Mock Auth / MAS server
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_addr = auth_listener.local_addr().unwrap();
    let auth_url = format!("http://{auth_addr}");
    let auth_state = Arc::new(auth_url.clone());

    let auth_app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(base): State<Arc<String>>| async move {
                let doc = json!({
                    "issuer": format!("{base}/"),
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/oauth2/token"),
                    "registration_endpoint": format!("{base}/oauth2/registration"),
                    "jwks_uri": format!("{base}/oauth2/keys.json"),
                    "account_management_uri": format!("{base}/account"),
                    "authorization_response_iss_parameter_supported": true
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap()
            }),
        )
        .route(
            "/authorize",
            get(|State(_base): State<Arc<String>>| async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, "/login?next=%2Fauthorize%3Fclient_id%3Dabc")
                    .header(
                        header::SET_COOKIE,
                        "mas_session=sess123; Domain=127.0.0.1; Path=/; Secure; HttpOnly",
                    )
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/login",
            get(|State(base): State<Arc<String>>| async move {
                let html = format!(
                    r#"<html><body><form action="{base}/login" method="POST"><input name="u"/></form></body></html>"#
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(
                        "content-security-policy",
                        format!("default-src 'self'; form-action {base}"),
                    )
                    .body(Body::from(html))
                    .unwrap()
            })
            .post(|State(base): State<Arc<String>>, headers: HeaderMap| async move {
                let origin = headers
                    .get(header::ORIGIN)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                if origin != base.as_str() {
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(format!(
                            "CSRF origin mismatch: got {origin}, expected {base}"
                        )))
                        .unwrap();
                }
                let encoded_iss =
                    url::form_urlencoded::byte_serialize(format!("{base}/").as_bytes())
                        .collect::<String>();
                let callback = format!(
                    "io.element.elementx:/callback?code=CODE_XYZ&state=STATE_999&iss={encoded_iss}"
                );
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, callback)
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/oauth2/token",
            post(move || async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"access_token": format!("mat_tok_{tag}"), "token_type": "Bearer", "expires_in": 300}).to_string(),
                    ))
                    .unwrap()
            }),
        )
        .with_state(auth_state);

    tokio::spawn(async move {
        axum::serve(auth_listener, auth_app).await.unwrap();
    });

    // 3. Mock Matrix Homeserver
    let matrix_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matrix_addr = matrix_listener.local_addr().unwrap();
    let matrix_url = format!("http://{matrix_addr}");
    let hs_state = Arc::new((matrix_url.clone(), auth_url.clone(), rtc_url.clone(), tag));

    let matrix_app = Router::new()
        .route(
            "/.well-known/matrix/client",
            get(
                |State(st): State<Arc<(String, String, String, &'static str)>>| async move {
                    let (m, a, r, _) = st.as_ref();
                    let doc = json!({
                        "m.homeserver": { "base_url": m },
                        "m.identity_server": { "base_url": "https://vector.im" },
                        "org.matrix.msc2965.authentication": {
                            "issuer": format!("{a}/"),
                            "account": format!("{a}/account")
                        },
                        "org.matrix.msc4143.rtc_foci": [
                            { "type": "livekit", "livekit_service_url": r }
                        ]
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(doc.to_string()))
                        .unwrap()
                },
            ),
        )
        .route(
            "/_matrix/client/versions",
            get(
                |State(st): State<Arc<(String, String, String, &'static str)>>| async move {
                    let doc = json!({"versions": ["v1.15"], "cluster": st.3});
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(doc.to_string()))
                        .unwrap()
                },
            ),
        )
        .route(
            "/_matrix/client/v1/auth_metadata",
            get(
                |State(st): State<Arc<(String, String, String, &'static str)>>| async move {
                    let a = &st.1;
                    let doc = json!({
                        "issuer": format!("{a}/"),
                        "authorization_endpoint": format!("{a}/authorize"),
                        "token_endpoint": format!("{a}/oauth2/token"),
                        "registration_endpoint": format!("{a}/oauth2/registration"),
                        "revocation_endpoint": format!("{a}/oauth2/revoke"),
                        "jwks_uri": format!("{a}/oauth2/keys.json"),
                        "account_management_uri": format!("{a}/account"),
                        "authorization_response_iss_parameter_supported": true
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(doc.to_string()))
                        .unwrap()
                },
            ),
        )
        .route(
            "/_matrix/client/v3/sync",
            get(
                |State(st): State<Arc<(String, String, String, &'static str)>>,
                 headers: HeaderMap| async move {
                    let hdr = |k: &str| {
                        headers
                            .get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string()
                    };
                    let doc = json!({
                        "next_batch": format!("s_{}", st.3),
                        "seen_auth": hdr("authorization"),
                        "seen_xff": hdr("x-forwarded-for"),
                        "seen_x_real_ip": hdr("x-real-ip"),
                        "seen_forwarded": hdr("forwarded"),
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(doc.to_string()))
                        .unwrap()
                },
            ),
        )
        .route(
            "/_matrix/client/v3/login/sso/redirect",
            get(
                |State(st): State<Arc<(String, String, String, &'static str)>>| async move {
                    let a = &st.1;
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, format!("{a}/authorize?compat=1"))
                        .body(Body::empty())
                        .unwrap()
                },
            ),
        )
        .route(
            "/_matrix/media/v3/upload",
            post(|body: Body| async move {
                let bytes = body.collect().await.unwrap().to_bytes();
                let doc = json!({ "content_uri": "mxc://example.org/abc", "size": bytes.len() });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap()
            }),
        )
        .with_state(hs_state);

    tokio::spawn(async move {
        axum::serve(matrix_listener, matrix_app).await.unwrap();
    });

    MockCluster {
        matrix_url,
        auth_url,
        rtc_url,
    }
}

async fn build_single_listener_app(cfg: Config) -> Router {
    let runtime = Arc::new(cfg.into_runtime().unwrap());
    assert_eq!(runtime.listeners.len(), 1);
    let plan = runtime.listeners[0].clone();
    let state = ListenerState::build(runtime, plan).unwrap();
    state.warm_up_discovery().await.unwrap();
    build_listener_router(state)
}

async fn body_json(resp: Response<Body>) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_text(resp: Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn single_domain_root_mode_full_matrix_and_auth_flow() {
    let cluster = spawn_mock_cluster("a").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.server.expose_info = ExposeInfoMode::Always;
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());
    cfg.upstream.auth_url = Some(cluster.auth_url.clone());
    cfg.upstream.rtc_url = Some(cluster.rtc_url.clone());

    let app = build_single_listener_app(cfg).await;

    // 1. /.well-known/matrix/client
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "*"
    );
    let wk = body_json(resp).await;
    assert_eq!(wk["m.homeserver"]["base_url"], "https://proxy.example.com");
    assert_eq!(
        wk["org.matrix.msc2965.authentication"]["issuer"],
        "https://proxy.example.com/"
    );
    assert_eq!(
        wk["org.matrix.msc2965.authentication"]["account"],
        "https://proxy.example.com/account"
    );
    assert_eq!(
        wk["org.matrix.msc4143.rtc_foci"][0]["livekit_service_url"],
        "https://proxy.example.com/_rtc"
    );

    // 2. auth_metadata v1 & unstable fallback
    for path in [
        "/_matrix/client/v1/auth_metadata",
        "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let meta = body_json(resp).await;
        assert_eq!(meta["issuer"], "https://proxy.example.com/");
        assert_eq!(
            meta["authorization_endpoint"],
            "https://proxy.example.com/authorize"
        );
        assert_eq!(
            meta["token_endpoint"],
            "https://proxy.example.com/oauth2/token"
        );
    }

    // 3. /.well-known/openid-configuration
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let oidc = body_json(resp).await;
    assert_eq!(oidc["issuer"], "https://proxy.example.com/");

    // 4. GET /authorize -> Auth server, Set-Cookie strips upstream Domain
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorize?client_id=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!cookie.to_ascii_lowercase().contains("domain="));
    assert!(cookie.contains("mas_session=sess123"));

    // 5. GET /login -> HTML & CSP rewritten
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("form-action https://proxy.example.com"));
    let html = body_text(resp).await;
    assert!(html.contains(r#"action="https://proxy.example.com/login""#));

    // 6. POST /login -> Origin rewritten + RFC 9207 `iss` rewritten in callback
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::ORIGIN, "https://proxy.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let callback = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(callback.contains("iss=https%3A%2F%2Fproxy.example.com%2F"));

    // 7. POST /oauth2/token -> Auth server
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .body(Body::from("grant_type=authorization_code&code=CODE_XYZ"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["access_token"], "mat_tok_a");

    // 8. Matrix sync & media streaming
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v3/sync?timeout=30000")
                .header(header::AUTHORIZATION, "Bearer mat_tok_a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sync = body_json(resp).await;
    assert_eq!(sync["next_batch"], "s_a");
    assert_eq!(sync["seen_auth"], "Bearer mat_tok_a");

    let payload = vec![0xABu8; 64 * 1024];
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_matrix/media/v3/upload?filename=test.bin")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["size"], 65536);

    // 9. SSO redirect & RTC
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v3/login/sso/redirect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "https://proxy.example.com/authorize?compat=1"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_rtc/sfu/get")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["jwt"], "token-a");

    // 10. Health & info
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_proxy/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["upstream"]["auth_is_separate"], true);
}

#[tokio::test]
async fn single_domain_prefix_mode_and_rfc8414_discovery() {
    let cluster = spawn_mock_cluster("pref").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());
    cfg.upstream.auth_url = Some(cluster.auth_url.clone());
    cfg.routing.auth_mode = AuthRouteMode::Prefix;
    cfg.routing.auth_prefix = "/_auth".to_string();

    let app = build_single_listener_app(cfg).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], "https://proxy.example.com/_auth/");
    assert_eq!(
        meta["token_endpoint"],
        "https://proxy.example.com/_auth/oauth2/token"
    );

    for disc in [
        "/_auth/.well-known/openid-configuration",
        "/.well-known/openid-configuration/_auth",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(disc).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            body_json(resp).await["issuer"],
            "https://proxy.example.com/_auth/"
        );
    }

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_auth/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/_auth/login?next=%2Fauthorize%3Fclient_id%3Dabc"
    );
    assert!(
        resp.headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Path=/_auth")
    );
}

#[tokio::test]
async fn auto_discovers_separate_auth_upstream_without_explicit_auth_url() {
    let cluster = spawn_mock_cluster("auto").await;

    let mut cfg = Config::default();
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());

    let app = build_single_listener_app(cfg).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "edge-hk.example.net")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], "https://edge-hk.example.net/");
    assert_eq!(
        meta["token_endpoint"],
        "https://edge-hk.example.net/oauth2/token"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "edge-hk.example.net")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["access_token"], "mat_tok_auto");
}

#[tokio::test]
async fn preserve_issuer_mode_rewrites_endpoints_only() {
    let cluster = spawn_mock_cluster("pres").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());
    cfg.upstream.auth_url = Some(cluster.auth_url.clone());
    cfg.discovery.rewrite_issuer = false;

    let app = build_single_listener_app(cfg).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], format!("{}/", cluster.auth_url));
    assert_eq!(
        meta["authorization_endpoint"],
        "https://proxy.example.com/authorize"
    );
}

#[tokio::test]
async fn dual_domain_host_routing_mode() {
    let cluster = spawn_mock_cluster("dual").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://matrix-proxy.example.com".to_string());
    cfg.server.public_auth_url = Some("https://auth-proxy.example.com".to_string());
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());
    cfg.upstream.auth_url = Some(cluster.auth_url.clone());

    let app = build_single_listener_app(cfg).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .header(header::HOST, "matrix-proxy.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["token_endpoint"],
        "https://auth-proxy.example.com/oauth2/token"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(
                    header::HOST,
                    HeaderValue::from_static("auth-proxy.example.com"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["access_token"], "mat_tok_dual");
}

#[tokio::test]
async fn shared_port_vhost_routes_multiple_upstreams_by_domain() {
    let cluster_a = spawn_mock_cluster("alpha").await;
    let cluster_b = spawn_mock_cluster("beta").await;

    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"

        [[proxies]]
        name = "alpha"
        domains = ["a.proxy.test"]
        public_url = "https://a.proxy.test"
        matrix_url = "{}"
        auth_url = "{}"

        [[proxies]]
        name = "beta"
        domains = ["b.proxy.test", "*.b.proxy.test"]
        public_url = "https://b.proxy.test"
        matrix_url = "{}"
        auth_url = "{}"
        "#,
        cluster_a.matrix_url, cluster_a.auth_url, cluster_b.matrix_url, cluster_b.auth_url
    );

    let cfg = Config::from_toml_str(&toml_cfg).unwrap();
    let app = build_single_listener_app(cfg).await;

    // 1. Domain A -> Cluster A
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header("x-forwarded-host", "a.proxy.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["cluster"], "alpha");

    // 2. Domain B (and wildcard subdomain) -> Cluster B
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "edge.b.proxy.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["cluster"], "beta");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "b.proxy.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["m.homeserver"]["base_url"],
        "https://b.proxy.test"
    );

    // 3. Unknown domain -> 421 Misdirected Request
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "unknown.evil.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);

    // 4. Health check works without Host header
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_proxy/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["profiles"], 2);
}

#[tokio::test]
async fn client_ip_forwarding_anti_spoofing_and_expose_info_acl() {
    let cluster = spawn_mock_cluster("ip").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.server.expose_info = ExposeInfoMode::Trusted;
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());

    let app = build_single_listener_app(cfg).await;

    // 1. Trusted HAProxy peer (172.18.0.1) passes real client IP 198.51.100.42
    let mut req = Request::builder()
        .uri("/_matrix/client/v3/sync")
        .header("x-forwarded-for", "198.51.100.42")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "172.18.0.1:41234".parse::<SocketAddr>().unwrap(),
    ));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["seen_xff"], "198.51.100.42");
    assert_eq!(body["seen_x_real_ip"], "198.51.100.42");
    assert_eq!(body["seen_forwarded"], "for=198.51.100.42;proto=https");

    // 2. Untrusted public peer attempting to spoof X-Forwarded-For -> ignored!
    let mut req = Request::builder()
        .uri("/_matrix/client/v3/sync")
        .header("x-forwarded-for", "1.1.1.1")
        .header("x-real-ip", "8.8.8.8")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "203.0.113.9:55555".parse::<SocketAddr>().unwrap(),
    ));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["seen_xff"], "203.0.113.9");
    assert_eq!(body["seen_x_real_ip"], "203.0.113.9");

    // 3. Public client blocked from /_proxy/info under ExposeInfoMode::Trusted
    let mut req = Request::builder()
        .uri("/_proxy/info")
        .header("x-forwarded-for", "203.0.113.9")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "172.18.0.1:41234".parse::<SocketAddr>().unwrap(),
    ));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. Localhost direct check allowed on /_proxy/info
    let mut req = Request::builder()
        .uri("/_proxy/info")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
    ));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn outbound_proxy_protocol_v2_passes_real_client_ip_and_isolates_clients() {
    // Spawn a real TCP server that requires a valid HAProxy PROXY Protocol v2 header before HTTP/1.1!
    let ppv2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ppv2_addr = ppv2_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = ppv2_listener.accept().await {
            tokio::spawn(async move {
                let real_src = match read_ppv2_header(&mut stream).await {
                    Ok(src) => src,
                    Err(_) => return,
                };
                let src_ip_str = real_src
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| "LOCAL".to_string());
                let io = TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let ip = src_ip_str.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let body = if path == "/_matrix/client/v1/auth_metadata" {
                            json!({
                                "issuer": "https://auth.example.org/",
                                "authorization_endpoint": "https://auth.example.org/_tuwunel/oidc/authorize",
                                "token_endpoint": "https://auth.example.org/_tuwunel/oidc/token"
                            })
                        } else {
                            json!({
                                "ppv2_src_ip": ip,
                                "host": req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or(""),
                                "xff": req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or(""),
                            })
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(http_body_util::Full::new(bytes::Bytes::from(
                                    body.to_string(),
                                )))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"

        [[proxies]]
        name = "ppv2-matrix"
        public_url = "https://proxy.example.com"
        matrix_url = "http://{ppv2_addr}"
        auth_url = "http://{ppv2_addr}"
        matrix_host_header = "matrix.example.org"
        auth_host_header = "matrix.example.org"
        proxy_protocol = "v2"
        rewrite_origins = ["https://auth.example.org"]
        "#
    );

    let cfg = Config::from_toml_str(&toml_cfg).unwrap();
    let app = build_single_listener_app(cfg).await;

    // 1. auth_metadata over PPv2 LOCAL rewrites https://auth.example.org -> https://proxy.example.com!
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], "https://proxy.example.com/");
    assert_eq!(
        meta["authorization_endpoint"],
        "https://proxy.example.com/_tuwunel/oidc/authorize"
    );

    // 2. Client A (198.51.100.42) arrives via trusted HAProxy -> upstream sees PPv2 src 198.51.100.42 & Host: matrix.example.org!
    let mut req_a = Request::builder()
        .uri("/_matrix/client/v3/sync")
        .header("x-forwarded-for", "198.51.100.42")
        .body(Body::empty())
        .unwrap();
    req_a.extensions_mut().insert(ConnectInfo(
        "172.18.0.1:50001".parse::<SocketAddr>().unwrap(),
    ));
    let resp_a = app.clone().oneshot(req_a).await.unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    let body_a = body_json(resp_a).await;
    assert_eq!(body_a["ppv2_src_ip"], "198.51.100.42");
    assert_eq!(body_a["host"], "matrix.example.org");
    assert_eq!(body_a["xff"], "198.51.100.42");

    // 3. Client B (198.51.100.77) gets its own isolated PPv2 connection (NO cross-client IP leak!)
    let mut req_b = Request::builder()
        .uri("/_matrix/client/v3/sync")
        .header("x-forwarded-for", "198.51.100.77")
        .body(Body::empty())
        .unwrap();
    req_b.extensions_mut().insert(ConnectInfo(
        "172.18.0.1:50002".parse::<SocketAddr>().unwrap(),
    ));
    let resp_b = app.clone().oneshot(req_b).await.unwrap();
    assert_eq!(resp_b.status(), StatusCode::OK);
    let body_b = body_json(resp_b).await;
    assert_eq!(body_b["ppv2_src_ip"], "198.51.100.77");
}

#[tokio::test]
async fn rate_limit_enforced_per_client_ip() {
    let cluster = spawn_mock_cluster("rl").await;

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.server.rate_limit_rps = 1;
    cfg.server.rate_limit_burst = 2;
    cfg.upstream.matrix_url = Some(cluster.matrix_url.clone());

    let app = build_single_listener_app(cfg).await;

    for i in 0..3 {
        let mut req = Request::builder()
            .uri("/_matrix/client/versions")
            .header("x-forwarded-for", "198.51.100.10")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "172.18.0.1:50001".parse::<SocketAddr>().unwrap(),
        ));
        let resp = app.clone().oneshot(req).await.unwrap();
        if i < 2 {
            assert_eq!(resp.status(), StatusCode::OK);
        } else {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Different client IP is NOT rate-limited
    let mut req_other = Request::builder()
        .uri("/_matrix/client/versions")
        .header("x-forwarded-for", "198.51.100.20")
        .body(Body::empty())
        .unwrap();
    req_other.extensions_mut().insert(ConnectInfo(
        "172.18.0.1:50002".parse::<SocketAddr>().unwrap(),
    ));
    let resp_other = app.clone().oneshot(req_other).await.unwrap();
    assert_eq!(resp_other.status(), StatusCode::OK);
}

#[tokio::test]
async fn well_known_discovery_follows_301_redirect() {
    let cluster = spawn_mock_cluster("redir").await;
    let matrix_url_for_target = cluster.matrix_url.clone();

    let target_app = Router::new().route(
        "/.well-known/matrix/client",
        get(move || {
            let hs = matrix_url_for_target.clone();
            async move {
                let body = serde_json::to_vec(&json!({
                    "m.homeserver": { "base_url": hs },
                    "m.identity_server": { "base_url": "https://id.example.org" },
                    "org.matrix.msc4143.rtc_foci": [
                        { "type": "livekit", "livekit_service_url": "https://rtc.example.org" }
                    ]
                }))
                .unwrap();
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }
        }),
    );
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(target_listener, target_app).await;
    });

    let redirect_app = Router::new().route(
        "/.well-known/matrix/client",
        get(move || async move {
            Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(
                    header::LOCATION,
                    format!("http://{target_addr}/.well-known/matrix/client"),
                )
                .body(Body::empty())
                .unwrap()
        }),
    );
    let redir_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redir_addr = redir_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(redir_listener, redirect_app).await;
    });

    let mut cfg = Config::default();
    cfg.server.public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.server_name = Some(format!("http://{redir_addr}"));
    cfg.upstream.rtc_url = Some("https://rtc.example.org".to_string());

    let app = build_single_listener_app(cfg).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let wk = body_json(resp).await;
    assert_eq!(wk["m.homeserver"]["base_url"], "https://proxy.example.com");
    assert_eq!(
        wk["m.identity_server"]["base_url"],
        "https://id.example.org"
    );
    assert_eq!(
        wk["org.matrix.msc4143.rtc_foci"][0]["livekit_service_url"],
        "https://proxy.example.com/_rtc"
    );
}
