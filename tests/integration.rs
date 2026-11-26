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
}

async fn spawn_mock_cluster(tag: &'static str) -> MockCluster {
    // 1. Mock Auth / MAS server
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

    // 2. Mock Matrix Homeserver
    let matrix_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matrix_addr = matrix_listener.local_addr().unwrap();
    let matrix_url = format!("http://{matrix_addr}");
    let hs_state = Arc::new((matrix_url.clone(), auth_url.clone(), tag));

    let matrix_app = Router::new()
        .route(
            "/.well-known/matrix/client",
            get(
                |State(st): State<Arc<(String, String, &'static str)>>| async move {
                    let (m, a, _) = st.as_ref();
                    let doc = json!({
                        "m.homeserver": { "base_url": m },
                        "m.identity_server": { "base_url": "https://vector.im" },
                        "org.matrix.msc2965.authentication": {
                            "issuer": format!("{a}/"),
                            "account": format!("{a}/account")
                        },
                        "org.matrix.msc4143.rtc_foci": [
                            { "type": "livekit", "livekit_service_url": "https://upstream-rtc.example.org" }
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
                |State(st): State<Arc<(String, String, &'static str)>>| async move {
                    let doc = json!({"versions": ["v1.15"], "cluster": st.2});
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
                |State(st): State<Arc<(String, String, &'static str)>>| async move {
                    let a = &st.1;
                    let doc = json!({
                        "issuer": format!("{a}/"),
                        "authorization_endpoint": format!("{a}/authorize"),
                        "token_endpoint": format!("{a}/oauth2/token"),
                        "registration_endpoint": format!("{a}/oauth2/registration"),
                        "revocation_endpoint": format!("{a}/oauth2/revoke"),
                        "jwks_uri": format!("{a}/oauth2/keys.json"),
                        "account_management_uri": format!("{a}/account"),
                        "org.matrix.matrix-authentication-service.graphql_endpoint": format!("{a}/account/graphql"),
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
                |State(st): State<Arc<(String, String, &'static str)>>, headers: HeaderMap| async move {
                    let hdr = |k: &str| {
                        headers
                            .get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string()
                    };
                    let doc = json!({
                        "next_batch": format!("s_{}", st.2),
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
                |State(st): State<Arc<(String, String, &'static str)>>| async move {
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
            "/_matrix/client/v3/keys/device_signing/upload",
            post(
                |State(st): State<Arc<(String, String, &'static str)>>, headers: HeaderMap| async move {
                    let a = &st.1;
                    let doc = json!({
                        "session": "uia_sess_reset_1",
                        "flows": [{ "stages": ["m.oauth"] }],
                        "params": {
                            "m.oauth": {
                                "url": format!("{a}/account/?action=org.matrix.cross_signing_reset")
                            },
                            "org.matrix.cross_signing_reset": {
                                "approval_url": format!("{a}/account/reset-approval")
                            }
                        }
                    });
                    let body_bytes = doc.to_string().into_bytes();
                    let wants_gzip = headers
                        .get(header::ACCEPT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.contains("gzip"));
                    if wants_gzip {
                        use flate2::Compression;
                        use flate2::write::GzEncoder;
                        use std::io::Write;
                        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                        enc.write_all(&body_bytes).unwrap();
                        let gz = enc.finish().unwrap();
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::CONTENT_ENCODING, "gzip")
                            .body(Body::from(gz))
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body_bytes))
                            .unwrap()
                    }
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
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.server.expose_info = ExposeInfoMode::Always;
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());
    cfg.upstream.upstream_matrix_auth_url = Some(cluster.auth_url.clone());
    cfg.discovery.matrix_rtc_url = Some("https://mrtc.example.org".to_string());

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
        "https://mrtc.example.org"
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
        assert_eq!(
            meta["org.matrix.matrix-authentication-service.graphql_endpoint"],
            "https://proxy.example.com/account/graphql"
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

    // 9. SSO redirect
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
    let info = body_json(resp).await;
    assert_eq!(info["upstream"]["auth_is_separate"], true);
    assert_eq!(
        info["discovery"]["matrix_rtc"],
        json!(["https://mrtc.example.org"])
    );
}

#[tokio::test]
async fn single_domain_prefix_mode_and_rfc8414_discovery() {
    let cluster = spawn_mock_cluster("pref").await;

    let mut cfg = Config::default();
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());
    cfg.upstream.upstream_matrix_auth_url = Some(cluster.auth_url.clone());
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
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());

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
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());
    cfg.upstream.upstream_matrix_auth_url = Some(cluster.auth_url.clone());
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
    cfg.server.matrix_proxy_public_url = Some("https://matrix-proxy.example.com".to_string());
    cfg.server.matrix_proxy_public_auth_url = Some("https://auth-proxy.example.com".to_string());
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());
    cfg.upstream.upstream_matrix_auth_url = Some(cluster.auth_url.clone());

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
        matrix_proxy_public_url = "https://a.proxy.test"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"

        [[proxies]]
        name = "beta"
        matrix_proxy_public_url = "https://b.proxy.test"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
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

    // 2. Domain B -> Cluster B (routed automatically from matrix_proxy_public_url without a `domains` field)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "b.proxy.test:443")
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
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.server.expose_info = ExposeInfoMode::Trusted;
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());

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
        matrix_proxy_public_url = "https://proxy.example.com"
        upstream_matrix_server_url = "http://{ppv2_addr}"
        upstream_matrix_auth_url = "http://{ppv2_addr}"
        upstream_matrix_host_header = "matrix.example.org"
        upstream_auth_host_header = "matrix.example.org"
        upstream_proxy_protocol = "v2"
        upstream_rewrite_origins = ["https://auth.example.org"]
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
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.server.rate_limit_rps = 1;
    cfg.server.rate_limit_burst = 2;
    cfg.upstream.upstream_matrix_server_url = Some(cluster.matrix_url.clone());

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
    cfg.server.matrix_proxy_public_url = Some("https://proxy.example.com".to_string());
    cfg.upstream.upstream_matrix_server_name = Some(format!("http://{redir_addr}"));
    cfg.discovery.matrix_rtc_url = Some("https://mrtc.example.org".to_string());

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
        "https://mrtc.example.org"
    );
}

#[tokio::test]
async fn http_ip_port_tailscale_mode_without_domain_rewrites_cookies_csp_and_urls() {
    // Mock auth server returning Secure + SameSite=None cookie, upgrade-insecure-requests CSP, and HSTS
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_addr = auth_listener.local_addr().unwrap();
    let auth_url = format!("http://{auth_addr}");
    let auth_base_arc = Arc::new(auth_url.clone());

    let auth_app = Router::new()
        .route(
            "/authorize",
            get(|State(_b): State<Arc<String>>| async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, "/login")
                    .header(
                        header::SET_COOKIE,
                        "oidc_sess=abc; Domain=auth.internal; Path=/; Secure; SameSite=None; HttpOnly",
                    )
                    .header("strict-transport-security", "max-age=31536000")
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/login",
            get(|State(b): State<Arc<String>>| async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(
                        "content-security-policy",
                        format!("default-src 'self'; form-action {b}; upgrade-insecure-requests"),
                    )
                    .body(Body::from(format!(r#"<form action="{b}/login"></form>"#)))
                    .unwrap()
            }),
        )
        .with_state(auth_base_arc);
    tokio::spawn(async move {
        let _ = axum::serve(auth_listener, auth_app).await;
    });

    // Mock Matrix homeserver whose auth_metadata advertises the separate auth server
    let hs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hs_addr = hs_listener.local_addr().unwrap();
    let hs_url = format!("http://{hs_addr}");
    let auth_for_hs = auth_url.clone();
    let hs_app = Router::new()
        .route(
            "/_matrix/client/v1/auth_metadata",
            get(move || {
                let a = auth_for_hs.clone();
                async move {
                    let doc = json!({
                        "issuer": format!("{a}/"),
                        "authorization_endpoint": format!("{a}/authorize"),
                        "token_endpoint": format!("{a}/oauth2/token"),
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(doc.to_string()))
                        .unwrap()
                }
            }),
        )
        .route(
            "/_matrix/client/versions",
            get(|| async { r#"{"versions":["v1.15"]}"# }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(hs_listener, hs_app).await;
    });

    let toml_cfg = format!(
        r#"
        [[proxies]]
        name = "tailscale-node"
        listen = "0.0.0.0:8081"
        matrix_proxy_public_url = "http://100.64.0.10:8081"
        upstream_matrix_server_url = "{hs_url}"
        upstream_matrix_auth_url = "{auth_url}"
        matrix_rtc_url = "https://mrtc.example.org"
        "#
    );

    let cfg = Config::from_toml_str(&toml_cfg).unwrap();
    let app = build_single_listener_app(cfg).await;

    // 1. /.well-known/matrix/client exposes http://100.64.0.10:8081 and delegates directly to mrtc (never leaking private Tailscale IP!)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "100.64.0.10:8081")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let wk = body_json(resp).await;
    assert_eq!(wk["m.homeserver"]["base_url"], "http://100.64.0.10:8081");
    assert_eq!(
        wk["org.matrix.msc4143.rtc_foci"][0]["livekit_service_url"],
        "https://mrtc.example.org"
    );

    // 2. auth_metadata rewrites issuer & endpoints to http://100.64.0.10:8081
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .header(header::HOST, "100.64.0.10:8081")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], "http://100.64.0.10:8081/");
    assert_eq!(
        meta["authorization_endpoint"],
        "http://100.64.0.10:8081/authorize"
    );

    // 3. Plain HTTP cookie strips Secure & Domain, downgrades SameSite=None -> SameSite=Lax, strips HSTS
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header(header::HOST, "100.64.0.10:8081")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(resp.headers().get("strict-transport-security").is_none());
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!cookie.to_ascii_lowercase().contains("secure"));
    assert!(!cookie.to_ascii_lowercase().contains("domain="));
    assert!(cookie.contains("SameSite=Lax"));

    // 4. Plain HTTP CSP removes upgrade-insecure-requests and rewrites form-action to http://100.64.0.10:8081
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::HOST, "100.64.0.10:8081")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !csp.to_ascii_lowercase()
            .contains("upgrade-insecure-requests")
    );
    assert!(csp.contains("form-action http://100.64.0.10:8081"));
    let html = body_text(resp).await;
    assert!(html.contains(r#"action="http://100.64.0.10:8081/login""#));
}

#[tokio::test]
async fn global_http_and_socks5_outbound_proxies_with_direct_override() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Target mock Matrix homeserver
    let hs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hs_addr = hs_listener.local_addr().unwrap();
    let hs_app = Router::new().route(
        "/_matrix/client/versions",
        get(|| async {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"versions":["v1.15"],"via":"ok"}"#))
                .unwrap()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(hs_listener, hs_app).await;
    });

    // 1. Minimal mock HTTP forward proxy (handles absolute-URI HTTP proxy requests)
    let http_proxy_hits = Arc::new(AtomicUsize::new(0));
    let http_proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_proxy_addr = http_proxy_listener.local_addr().unwrap();
    let hits_clone = Arc::clone(&http_proxy_hits);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = http_proxy_listener.accept().await {
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let mut req_buf = Vec::new();
                let mut byte = [0u8; 1];
                while !req_buf.ends_with(b"\r\n\r\n") && req_buf.len() < 8192 {
                    if client.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    req_buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&req_buf);
                let first_line = head.lines().next().unwrap_or_default();
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                hits.fetch_add(1, Ordering::SeqCst);

                if method == "CONNECT" {
                    if let Ok(mut upstream) = TcpStream::connect(target).await {
                        let _ = client
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                } else if let Ok(url) = url::Url::parse(target)
                    && let (Some(h), Some(p)) = (url.host_str(), url.port_or_known_default())
                    && let Ok(mut upstream) = TcpStream::connect((h, p)).await
                {
                    let pq = match url.query() {
                        Some(q) => format!("{}?{q}", url.path()),
                        None => url.path().to_string(),
                    };
                    let forwarded = format!(
                        "{method} {pq} HTTP/1.1\r\nHost: {h}:{p}\r\nConnection: close\r\n\r\n"
                    );
                    let _ = upstream.write_all(forwarded.as_bytes()).await;
                    let _ = tokio::io::copy(&mut upstream, &mut client).await;
                }
            });
        }
    });

    // 2. Minimal mock SOCKS5 proxy with RFC 1929 username/password auth (alice:s3cr3t)
    let socks_hits = Arc::new(AtomicUsize::new(0));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_hits_clone = Arc::clone(&socks_hits);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = socks_listener.accept().await {
            let hits = Arc::clone(&socks_hits_clone);
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if client.read_exact(&mut hdr).await.is_err() || hdr[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; hdr[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                // Select username/password auth (0x02)
                if !methods.contains(&0x02) {
                    let _ = client.write_all(&[0x05, 0xFF]).await;
                    return;
                }
                let _ = client.write_all(&[0x05, 0x02]).await;

                // Read RFC 1929 auth
                let mut ver_ulen = [0u8; 2];
                if client.read_exact(&mut ver_ulen).await.is_err() {
                    return;
                }
                let mut user = vec![0u8; ver_ulen[1] as usize];
                if client.read_exact(&mut user).await.is_err() {
                    return;
                }
                let mut plen = [0u8; 1];
                if client.read_exact(&mut plen).await.is_err() {
                    return;
                }
                let mut pass = vec![0u8; plen[0] as usize];
                if client.read_exact(&mut pass).await.is_err() {
                    return;
                }
                if user != b"alice" || pass != b"s3cr3t" {
                    let _ = client.write_all(&[0x01, 0x01]).await;
                    return;
                }
                let _ = client.write_all(&[0x01, 0x00]).await;

                // Read CONNECT request
                let mut req = [0u8; 4];
                if client.read_exact(&mut req).await.is_err() || req[1] != 0x01 {
                    return;
                }
                let target_host = match req[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if client.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if client.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut dom = vec![0u8; len[0] as usize];
                        if client.read_exact(&mut dom).await.is_err() {
                            return;
                        }
                        String::from_utf8_lossy(&dom).into_owned()
                    }
                    _ => return,
                };
                let mut port_b = [0u8; 2];
                if client.read_exact(&mut port_b).await.is_err() {
                    return;
                }
                let port = u16::from_be_bytes(port_b);
                hits.fetch_add(1, Ordering::SeqCst);

                if let Ok(mut upstream) = TcpStream::connect((target_host.as_str(), port)).await {
                    let _ = client
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });

    // Global HTTP outbound proxy + per-profile SOCKS5 override + per-profile direct bypass
    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"
        outbound_proxy = "http://{http_proxy_addr}"

        [[proxies]]
        name = "via-global-http"
        matrix_proxy_public_url = "https://http-proxy.test"
        upstream_matrix_server_url = "http://{hs_addr}"
        merge_upstream_well_known = false

        [[proxies]]
        name = "via-socks5"
        matrix_proxy_public_url = "https://socks5.test"
        upstream_matrix_server_url = "http://{hs_addr}"
        outbound_proxy = "socks5h://alice:s3cr3t@{socks_addr}"
        merge_upstream_well_known = false

        [[proxies]]
        name = "direct-bypass"
        matrix_proxy_public_url = "https://direct.test"
        upstream_matrix_server_url = "http://{hs_addr}"
        outbound_proxy = "direct"
        merge_upstream_well_known = false
        "#
    );

    let cfg = Config::from_toml_str(&toml_cfg).unwrap();
    let app = build_single_listener_app(cfg).await;

    let http_before = http_proxy_hits.load(Ordering::SeqCst);
    let resp_http = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "http-proxy.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_http.status(), StatusCode::OK);
    assert_eq!(body_json(resp_http).await["via"], "ok");
    assert!(http_proxy_hits.load(Ordering::SeqCst) > http_before);

    let socks_before = socks_hits.load(Ordering::SeqCst);
    let resp_socks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "socks5.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_socks.status(), StatusCode::OK);
    assert_eq!(body_json(resp_socks).await["via"], "ok");
    assert!(socks_hits.load(Ordering::SeqCst) > socks_before);

    let http_before_direct = http_proxy_hits.load(Ordering::SeqCst);
    let socks_before_direct = socks_hits.load(Ordering::SeqCst);
    let resp_direct = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "direct.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_direct.status(), StatusCode::OK);
    assert_eq!(body_json(resp_direct).await["via"], "ok");
    assert_eq!(http_proxy_hits.load(Ordering::SeqCst), http_before_direct);
    assert_eq!(socks_hits.load(Ordering::SeqCst), socks_before_direct);

    // 4. Verify `outbound_no_proxy` CIDR (`127.0.0.0/8`) bypasses the global HTTP proxy via unified matcher
    let toml_no_proxy = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"
        outbound_proxy = "http://{http_proxy_addr}"
        outbound_no_proxy = ["127.0.0.0/8"]

        [[proxies]]
        name = "bypassed-by-cidr"
        matrix_proxy_public_url = "https://cidr-bypass.test"
        upstream_matrix_server_url = "http://{hs_addr}"
        merge_upstream_well_known = false
        "#
    );
    let app_cidr = build_single_listener_app(Config::from_toml_str(&toml_no_proxy).unwrap()).await;
    let hits_before_cidr = http_proxy_hits.load(Ordering::SeqCst);
    let resp_cidr = app_cidr
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "cidr-bypass.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_cidr.status(), StatusCode::OK);
    assert_eq!(body_json(resp_cidr).await["via"], "ok");
    assert_eq!(http_proxy_hits.load(Ordering::SeqCst), hits_before_cidr);
}

#[tokio::test]
async fn standard_upstream_timeout_returns_504_gateway_timeout() {
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let slow_app = Router::new().route(
        "/_matrix/client/versions",
        get(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            r#"{"versions":["v1.15"]}"#
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(slow_listener, slow_app).await;
    });

    let toml_cfg = format!(
        r#"
        [[proxies]]
        name = "slow-hs"
        matrix_proxy_public_url = "https://slow.test"
        upstream_matrix_server_url = "http://{slow_addr}"
        request_timeout_secs = 1
        merge_upstream_well_known = false
        "#
    );
    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/versions")
                .header(header::HOST, "slow.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn auth_proxy_mode_token_only_and_direct_preserve_interactive_login() {
    let cluster = spawn_mock_cluster("idp").await;

    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"
        expose_info = "always"

        [[proxies]]
        name = "mozilla-like-token-only"
        matrix_proxy_public_url = "https://token-only.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        matrix_rtc_url = "https://mrtc.example.org"
        auth_proxy_mode = "token_only"

        [[proxies]]
        name = "direct-auth"
        matrix_proxy_public_url = "https://direct-auth.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        matrix_rtc_url = "upstream"
        auth_proxy_mode = "direct"
        "#,
        cluster.matrix_url, cluster.auth_url, cluster.matrix_url, cluster.auth_url,
    );

    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    // --- 1. `token_only` mode ---
    // 1a. /.well-known/matrix/client rewrites homeserver, delegates mrtc directly, preserves official MSC2965 auth
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "token-only.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let wk = body_json(resp).await;
    assert_eq!(
        wk["m.homeserver"]["base_url"],
        "https://token-only.example.com"
    );
    assert_eq!(
        wk["org.matrix.msc4143.rtc_foci"][0]["livekit_service_url"],
        "https://mrtc.example.org"
    );
    assert_eq!(
        wk["org.matrix.msc2965.authentication"]["issuer"],
        format!("{}/", cluster.auth_url)
    );
    assert_eq!(
        wk["org.matrix.msc2965.authentication"]["account"],
        format!("{}/account", cluster.auth_url)
    );

    // 1b. auth_metadata keeps issuer + interactive endpoints on official Auth origin,
    //     while rewriting background token/registration/revocation/jwks endpoints to proxy
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .header(header::HOST, "token-only.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], format!("{}/", cluster.auth_url));
    assert_eq!(
        meta["authorization_endpoint"],
        format!("{}/authorize", cluster.auth_url)
    );
    assert_eq!(
        meta["account_management_uri"],
        format!("{}/account", cluster.auth_url)
    );
    assert_eq!(
        meta["org.matrix.matrix-authentication-service.graphql_endpoint"],
        format!("{}/account/graphql", cluster.auth_url)
    );
    assert_eq!(
        meta["token_endpoint"],
        "https://token-only.example.com/oauth2/token"
    );
    assert_eq!(
        meta["registration_endpoint"],
        "https://token-only.example.com/oauth2/registration"
    );
    assert_eq!(
        meta["revocation_endpoint"],
        "https://token-only.example.com/oauth2/revoke"
    );
    assert_eq!(
        meta["jwks_uri"],
        "https://token-only.example.com/oauth2/keys.json"
    );

    // 1c. SSO redirect Location stays on official Auth origin (doesn't trap multi-hop IdP)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v3/login/sso/redirect")
                .header(header::HOST, "token-only.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        format!("{}/authorize?compat=1", cluster.auth_url).as_str()
    );

    // 1d. Background token exchange & Matrix sync still proxy seamlessly through matrix-proxy
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header(header::HOST, "token-only.example.com")
                .body(Body::from("grant_type=refresh_token&refresh_token=rt_1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["access_token"], "mat_tok_idp");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_proxy/info")
                .header(header::HOST, "token-only.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["discovery"]["auth_proxy_mode"],
        "token_only"
    );

    // --- 2. `direct` mode ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "direct-auth.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wk_direct = body_json(resp).await;
    assert_eq!(
        wk_direct["m.homeserver"]["base_url"],
        "https://direct-auth.example.com"
    );
    assert_eq!(
        wk_direct["org.matrix.msc2965.authentication"]["issuer"],
        format!("{}/", cluster.auth_url)
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/auth_metadata")
                .header(header::HOST, "direct-auth.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let meta_direct = body_json(resp).await;
    assert_eq!(meta_direct["issuer"], format!("{}/", cluster.auth_url));
    assert_eq!(
        meta_direct["authorization_endpoint"],
        format!("{}/authorize", cluster.auth_url)
    );
    assert_eq!(
        meta_direct["token_endpoint"],
        format!("{}/oauth2/token", cluster.auth_url)
    );
    assert_eq!(
        meta_direct["org.matrix.matrix-authentication-service.graphql_endpoint"],
        format!("{}/account/graphql", cluster.auth_url)
    );
}

#[tokio::test]
async fn auth_metadata_cache_coalesces_upstream_fetches_and_preserves_dynamic_hosts() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let hs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hs_addr = hs_listener.local_addr().unwrap();
    let hs_url = format!("http://{hs_addr}");
    let hits_clone = Arc::clone(&hits);
    let hs_url_clone = hs_url.clone();

    let hs_app = Router::new().route(
        "/_matrix/client/v1/auth_metadata",
        get(move || {
            let hits = Arc::clone(&hits_clone);
            let base = hs_url_clone.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let doc = json!({
                    "issuer": format!("{base}/"),
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/oauth2/token"),
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap()
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(hs_listener, hs_app).await;
    });

    let mut cfg = Config::default();
    cfg.upstream.upstream_matrix_server_url = Some(hs_url.clone());
    cfg.upstream.upstream_matrix_auth_url = Some(hs_url);
    cfg.discovery.merge_upstream_well_known = false;
    cfg.discovery.cache_ttl_secs = 60;

    let app = build_single_listener_app(cfg).await;
    let hits_after_startup = hits.load(Ordering::SeqCst);

    // 5 consecutive requests across 2 different X-Forwarded-Host values should only trigger 1 upstream fetch
    for i in 0..5 {
        let host = if i % 2 == 0 {
            "edge-a.example.net"
        } else {
            "edge-b.example.net"
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/_matrix/client/v1/auth_metadata")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=60"
        );
        let meta = body_json(resp).await;
        assert_eq!(
            meta["token_endpoint"],
            format!("https://{host}/oauth2/token")
        );
    }

    assert_eq!(hits.load(Ordering::SeqCst) - hits_after_startup, 1);
}

#[tokio::test]
async fn matrix_401_uia_cross_signing_reset_rewrites_oauth_approval_url() {
    let cluster = spawn_mock_cluster("uia").await;

    let toml_cfg = format!(
        r#"
        [[proxies]]
        name = "full-node"
        matrix_proxy_public_url = "https://full-uia.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        auth_proxy_mode = "full"

        [[proxies]]
        name = "token-only-node"
        matrix_proxy_public_url = "https://token-uia.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        auth_proxy_mode = "token_only"
        "#,
        cluster.matrix_url, cluster.auth_url, cluster.matrix_url, cluster.auth_url
    );

    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    // 1. In `full` mode, Matrix 401 UIA `m.oauth.url` & `approval_url` (even gzipped!) are rewritten to proxy
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_matrix/client/v3/keys/device_signing/upload")
                .header(header::HOST, "full-uia.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT_ENCODING, "gzip, br")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    let uia = body_json(resp).await;
    assert_eq!(uia["session"], "uia_sess_reset_1");
    assert_eq!(
        uia["params"]["m.oauth"]["url"],
        "https://full-uia.example.com/account/?action=org.matrix.cross_signing_reset"
    );
    assert_eq!(
        uia["params"]["org.matrix.cross_signing_reset"]["approval_url"],
        "https://full-uia.example.com/account/reset-approval"
    );

    // 2. In `token_only` mode, Matrix 401 UIA interactive OAuth URL stays on official Auth origin
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_matrix/client/v3/keys/device_signing/upload")
                .header(header::HOST, "token-uia.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let uia_tok = body_json(resp).await;
    assert_eq!(
        uia_tok["params"]["m.oauth"]["url"],
        format!(
            "{}/account/?action=org.matrix.cross_signing_reset",
            cluster.auth_url
        )
    );
}

#[tokio::test]
async fn matrix_rtc_delegation_supports_defaults_upstream_off_and_multi_foci() {
    let cluster = spawn_mock_cluster("mrtc").await;

    let toml_cfg = format!(
        r#"
        [defaults]
        matrix_rtc_url = "https://global-mrtc.example.org"

        [[proxies]]
        name = "inherits-default"
        matrix_proxy_public_url = "https://a-mrtc.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"

        [[proxies]]
        name = "keeps-upstream"
        matrix_proxy_public_url = "https://b-mrtc.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        matrix_rtc_url = "upstream"

        [[proxies]]
        name = "disables-rtc"
        matrix_proxy_public_url = "https://c-mrtc.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        matrix_rtc_url = "off"

        [[proxies]]
        name = "multi-foci"
        matrix_proxy_public_url = "https://d-mrtc.example.com"
        upstream_matrix_server_url = "{}"
        upstream_matrix_auth_url = "{}"
        matrix_rtc_urls = ["https://mrtc-us.example.org", "https://mrtc-eu.example.org/"]
        "#,
        cluster.matrix_url,
        cluster.auth_url,
        cluster.matrix_url,
        cluster.auth_url,
        cluster.matrix_url,
        cluster.auth_url,
        cluster.matrix_url,
        cluster.auth_url,
    );

    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    // 1. Inherits [defaults].matrix_rtc_url directly
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "a-mrtc.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wk_a = body_json(resp).await;
    assert_eq!(
        wk_a["org.matrix.msc4143.rtc_foci"],
        json!([{ "type": "livekit", "livekit_service_url": "https://global-mrtc.example.org" }])
    );

    // 2. Overrides with "upstream" -> preserves upstream's original rtc_foci verbatim
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "b-mrtc.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wk_b = body_json(resp).await;
    assert_eq!(
        wk_b["org.matrix.msc4143.rtc_foci"],
        json!([{ "type": "livekit", "livekit_service_url": "https://upstream-rtc.example.org" }])
    );

    // 3. Overrides with "off" -> removes org.matrix.msc4143.rtc_foci
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "c-mrtc.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wk_c = body_json(resp).await;
    assert!(wk_c.get("org.matrix.msc4143.rtc_foci").is_none());

    // 4. Overrides with multi-foci list
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .header(header::HOST, "d-mrtc.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wk_d = body_json(resp).await;
    assert_eq!(
        wk_d["org.matrix.msc4143.rtc_foci"],
        json!([
            { "type": "livekit", "livekit_service_url": "https://mrtc-us.example.org" },
            { "type": "livekit", "livekit_service_url": "https://mrtc-eu.example.org" },
        ])
    );
}

#[tokio::test]
async fn media_edge_cache_enforces_auth_serves_ram_disk_range_and_304() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    let thumb_hits = Arc::new(AtomicUsize::new(0));
    let dl_hits = Arc::new(AtomicUsize::new(0));
    let token_valid = Arc::new(AtomicBool::new(true));

    let th_c = Arc::clone(&thumb_hits);
    let tv_th = Arc::clone(&token_valid);
    let dl_c = Arc::clone(&dl_hits);
    let tv_dl = Arc::clone(&token_valid);
    let tv_sync = Arc::clone(&token_valid);

    let big_payload = Arc::new((0u32..4096).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
    let big_for_route = Arc::clone(&big_payload);

    let hs_app = Router::new()
        .route(
            "/_matrix/client/v3/sync",
            get(move |headers: axum::http::HeaderMap| {
                let tv = Arc::clone(&tv_sync);
                async move {
                    let authed = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer syt_valid_tok")
                        && tv.load(Ordering::SeqCst);
                    if !authed {
                        return Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(r#"{"errcode":"M_UNKNOWN_TOKEN"}"#))
                            .unwrap();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"next_batch":"b1"}"#))
                        .unwrap()
                }
            }),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server}/{id}",
            get(move |headers: axum::http::HeaderMap| {
                let hits = Arc::clone(&th_c);
                let tv = Arc::clone(&tv_th);
                async move {
                    let authed = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer syt_valid_tok")
                        && tv.load(Ordering::SeqCst);
                    if !authed {
                        return Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(r#"{"errcode":"M_MISSING_TOKEN"}"#))
                            .unwrap();
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "image/webp")
                        .body(Body::from(b"WEBP-AVATAR-BYTES".to_vec()))
                        .unwrap()
                }
            }),
        )
        .route(
            "/_matrix/client/v1/media/download/{server}/{id}",
            get(move |headers: axum::http::HeaderMap| {
                let hits = Arc::clone(&dl_c);
                let tv = Arc::clone(&tv_dl);
                let payload = Arc::clone(&big_for_route);
                async move {
                    let authed = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer syt_valid_tok")
                        && tv.load(Ordering::SeqCst);
                    if !authed {
                        return Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(r#"{"errcode":"M_MISSING_TOKEN"}"#))
                            .unwrap();
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CONTENT_DISPOSITION, "inline; filename=\"blob.bin\"")
                        .body(Body::from((*payload).clone()))
                        .unwrap()
                }
            }),
        );

    let hs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hs_addr = hs_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(hs_listener, hs_app).await;
    });

    let cache_dir = std::env::temp_dir().join(format!(
        "matrix-proxy-int-media-cache-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&cache_dir);

    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"
        expose_info = "always"

        [server.media_cache]
        enabled = true
        dir = "{}"
        ram_max_mb = 2
        ram_max_item_kb = 1
        disk_max_mb = 4
        max_item_mb = 4
        auth_cache_ttl_secs = 120

        [[proxies]]
        name = "cached-hs"
        matrix_proxy_public_url = "https://media-cache.example.com"
        upstream_matrix_server_url = "http://{hs_addr}"
        merge_upstream_well_known = false
        "#,
        cache_dir.display()
    );
    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    // 1. Unauthenticated request MUST fail with 401
    let r_unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?width=96&height=96&method=crop")
                .header(header::HOST, "media-cache.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_unauth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(thumb_hits.load(Ordering::SeqCst), 0);

    // 2. First authenticated thumbnail fetch -> MISS (populates L1 RAM + L2 disk + verifies token)
    let r_miss = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?width=96&height=96&method=crop&allow_remote=true")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_miss.status(), StatusCode::OK);
    assert_eq!(
        r_miss.headers().get("x-matrix-proxy-cache").unwrap(),
        "MISS"
    );
    assert_eq!(
        r_miss.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(body_text(r_miss).await, "WEBP-AVATAR-BYTES");
    assert_eq!(thumb_hits.load(Ordering::SeqCst), 1);

    // Give the async tee-commit task a moment to complete L1/L2 store
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 3. Unauthenticated request MUST STILL get 401 even though media is cached!
    let r_unauth_after = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?width=96&height=96&method=crop")
                .header(header::HOST, "media-cache.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_unauth_after.status(), StatusCode::UNAUTHORIZED);

    // 4. Second authenticated fetch with reordered query params -> HIT-RAM (0 upstream hit!)
    let r_hit = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?height=96&method=CROP&width=96&timeout_ms=5000")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_hit.status(), StatusCode::OK);
    assert_eq!(
        r_hit.headers().get("x-matrix-proxy-cache").unwrap(),
        "HIT-RAM"
    );
    let etag = r_hit
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(body_text(r_hit).await, "WEBP-AVATAR-BYTES");
    assert_eq!(thumb_hits.load(Ordering::SeqCst), 1);

    // 5. Conditional GET with If-None-Match -> 304 Not Modified from cache
    let r_304 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?width=96&height=96&method=crop")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_304.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(thumb_hits.load(Ordering::SeqCst), 1);

    // 6. 4 KiB download (> ram_max_item_kb = 1 KiB) goes to L2 disk and serves Range 206!
    let r_big1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/download/hs.test/blob1")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_big1.status(), StatusCode::OK);
    assert_eq!(
        r_big1.headers().get("x-matrix-proxy-cache").unwrap(),
        "MISS"
    );
    let got_big1 = r_big1.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got_big1.as_ref(), big_payload.as_slice());
    assert_eq!(dl_hits.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(80)).await;

    let r_big_range = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/download/hs.test/blob1")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .header(header::RANGE, "bytes=10-29")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_big_range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        r_big_range.headers().get("x-matrix-proxy-cache").unwrap(),
        "HIT-DISK"
    );
    assert_eq!(
        r_big_range.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 10-29/4096"
    );
    let got_slice = r_big_range.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got_slice.as_ref(), &big_payload[10..=29]);
    assert_eq!(dl_hits.load(Ordering::SeqCst), 1);

    // 7. Token revocation: once upstream returns 401 on /sync, cached media is no longer served to that token!
    token_valid.store(false, Ordering::SeqCst);
    let r_sync_401 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_sync_401.status(), StatusCode::UNAUTHORIZED);

    let r_revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/ava1?width=96&height=96&method=crop")
                .header(header::HOST, "media-cache.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_valid_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_revoked.status(), StatusCode::UNAUTHORIZED);

    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[tokio::test]
async fn proactive_media_preloader_warms_avatars_images_and_thumbnail_downloads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let thumb_hits = Arc::new(AtomicUsize::new(0));
    let dl_hits = Arc::new(AtomicUsize::new(0));
    let th_c = Arc::clone(&thumb_hits);
    let dl_c = Arc::clone(&dl_hits);

    let hs_app = Router::new()
        .route(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            post(|| async {
                let doc = json!({
                    "pos": "1",
                    "rooms": {
                        "!room:hs.test": {
                            "avatar": "mxc://hs.test/roomAva1",
                            "heroes": [
                                { "user_id": "@bob:hs.test", "avatar": "mxc://hs.test/bobAva" }
                            ],
                            "timeline": [
                                {
                                    "type": "m.room.message",
                                    "content": {
                                        "msgtype": "m.image",
                                        "url": "mxc://hs.test/inlineImg1",
                                        "info": { "mimetype": "image/png", "size": 1024 }
                                    }
                                }
                            ]
                        }
                    }
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap()
            }),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server}/{id}",
            get(
                move |axum::extract::Path((_srv, id)): axum::extract::Path<(String, String)>,
                      headers: axum::http::HeaderMap| {
                    let hits = Arc::clone(&th_c);
                    async move {
                        if headers
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            != Some("Bearer syt_preload_tok")
                        {
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .body(Body::empty())
                                .unwrap();
                        }
                        hits.fetch_add(1, Ordering::SeqCst);
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "image/png")
                            .body(Body::from(format!("THUMB-{id}")))
                            .unwrap()
                    }
                },
            ),
        )
        .route(
            "/_matrix/client/v1/media/download/{server}/{id}",
            get(
                move |axum::extract::Path((_srv, id)): axum::extract::Path<(String, String)>,
                      headers: axum::http::HeaderMap| {
                    let hits = Arc::clone(&dl_c);
                    async move {
                        if headers
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            != Some("Bearer syt_preload_tok")
                        {
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .body(Body::empty())
                                .unwrap();
                        }
                        hits.fetch_add(1, Ordering::SeqCst);
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "image/png")
                            .body(Body::from(format!("FULL-{id}")))
                            .unwrap()
                    }
                },
            ),
        );

    let hs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hs_addr = hs_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(hs_listener, hs_app).await;
    });

    let toml_cfg = format!(
        r#"
        [server]
        listen = "0.0.0.0:8080"
        expose_info = "always"

        [server.media_cache]
        enabled = true
        ram_max_mb = 8
        ram_max_item_kb = 256

        [defaults]
        media_preload = true
        media_preload_concurrency = 4
        media_preload_max_item_mb = 4
        media_preload_on_thumbnail = true
        media_preload_avatar_sizes = ["96x96:crop"]

        [[proxies]]
        name = "preload-hs"
        matrix_proxy_public_url = "https://preload.example.com"
        upstream_matrix_server_url = "http://{hs_addr}"
        merge_upstream_well_known = false
        "#
    );
    let app = build_single_listener_app(Config::from_toml_str(&toml_cfg).unwrap()).await;

    // 1. Sliding Sync triggers background preloading of roomAva1, bobAva (96x96:crop) and inlineImg1 (/download)
    let sync_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync")
                .header(header::HOST, "preload.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_preload_tok")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sync_resp.status(), StatusCode::OK);
    // Must consume body so the streaming tee reaches EOF and fires the preload callback
    let _ = body_json(sync_resp).await;

    // Wait up to 2s for background preloader to finish warming all 3 objects
    for _ in 0..40 {
        if thumb_hits.load(Ordering::SeqCst) >= 2 && dl_hits.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Brief settle so cache.store completes
    tokio::time::sleep(Duration::from_millis(50)).await;
    let th_before = thumb_hits.load(Ordering::SeqCst);
    let dl_before = dl_hits.load(Ordering::SeqCst);
    assert!(th_before >= 2, "expected preloader to warm 2 avatars");
    assert!(dl_before >= 1, "expected preloader to warm inline image");

    // 2. Client's VERY FIRST request for room avatar (including Element X's `animated=false` default param) hits L1 RAM cache with 0 upstream calls!
    let r_ava = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/roomAva1?method=crop&width=96&height=96&animated=false")
                .header(header::HOST, "preload.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_preload_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_ava.status(), StatusCode::OK);
    assert_eq!(
        r_ava.headers().get("x-matrix-proxy-cache").unwrap(),
        "HIT-RAM"
    );
    assert_eq!(body_text(r_ava).await, "THUMB-roomAva1");
    assert_eq!(thumb_hits.load(Ordering::SeqCst), th_before);

    // 3. Client's VERY FIRST request for inline image hits L1 RAM cache with 0 upstream calls!
    let r_img = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/download/hs.test/inlineImg1")
                .header(header::HOST, "preload.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_preload_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_img.status(), StatusCode::OK);
    assert_eq!(
        r_img.headers().get("x-matrix-proxy-cache").unwrap(),
        "HIT-RAM"
    );
    assert_eq!(body_text(r_img).await, "FULL-inlineImg1");
    assert_eq!(dl_hits.load(Ordering::SeqCst), dl_before);

    // 4. Thumbnail-triggered full-download preload: fetching a new thumbnail warms `/download` in background
    let r_thumb = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/thumbnail/hs.test/tapPhoto?width=320&height=240&method=scale")
                .header(header::HOST, "preload.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_preload_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_thumb.status(), StatusCode::OK);
    assert_eq!(body_text(r_thumb).await, "THUMB-tapPhoto");

    for _ in 0..40 {
        if dl_hits.load(Ordering::SeqCst) > dl_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let dl_after_preload = dl_hits.load(Ordering::SeqCst);

    let r_full = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_matrix/client/v1/media/download/hs.test/tapPhoto")
                .header(header::HOST, "preload.example.com")
                .header(header::AUTHORIZATION, "Bearer syt_preload_tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_full.status(), StatusCode::OK);
    assert_eq!(
        r_full.headers().get("x-matrix-proxy-cache").unwrap(),
        "HIT-RAM"
    );
    assert_eq!(body_text(r_full).await, "FULL-tapPhoto");
    assert_eq!(dl_hits.load(Ordering::SeqCst), dl_after_preload);

    // 5. Verify /_proxy/info and /_proxy/metrics report media cache & preload counters
    let info_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_proxy/info")
                .header(header::HOST, "preload.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let info_json = body_json(info_resp).await;
    assert_eq!(info_json["media_cache"]["enabled"], true);
    assert!(info_json["media_cache"]["hits_ram_total"].as_u64().unwrap() >= 3);
    assert!(
        info_json["media_cache"]["preload_completed_total"]
            .as_u64()
            .unwrap()
            >= 4
    );

    let metrics_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_proxy/metrics")
                .header(header::HOST, "preload.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let metrics_text = body_text(metrics_resp).await;
    assert!(metrics_text.contains("matrix_proxy_media_cache_hits_ram_total"));
    assert!(metrics_text.contains("matrix_proxy_media_preload_completed_total"));
}
