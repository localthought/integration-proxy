mod auth;
mod catalog;
mod config;
mod oauth;
#[allow(dead_code)] // used by the provider OAuth routes introduced with issue #9
mod providers;
mod proxy;
mod security;
mod session;
mod templates;
mod tenant_secret;

use axum::{
    extract::{FromRef, State},
    response::Html,
    routing::{get, post},
    Router,
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};
use oauth2::basic::BasicClient;
use sha2::{Digest, Sha512};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use config::Config;

#[derive(Clone)]
struct AppState {
    oauth_client: BasicClient,
    http_client: reqwest::Client,
    key: Key,
    server_secret: String,
    base_url: String,
    catalog: catalog::Catalog,
    security: Option<security::Security>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

fn build_http_client() -> reqwest::Client {
    // GitHub's REST API requires a User-Agent on every request.
    reqwest::Client::builder()
        .user_agent("LocalThought-integration-proxy")
        .build()
        .expect("failed to build HTTP client")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    let oauth_client = auth::build_client(&config).expect("failed to build OAuth client");

    let key = match &config.session_secret {
        Some(secret) => Key::from(&Sha512::digest(secret.as_bytes())),
        None => {
            tracing::warn!(
                "SESSION_SECRET is not set; using a random key. Sessions will not survive a restart."
            );
            Key::generate()
        }
    };

    let http_client = build_http_client();
    let catalog = match catalog::Catalog::load(&config.catalog_path, &http_client).await {
        Ok(catalog) => catalog,
        Err(err) => {
            eprintln!("catalog configuration error: {err}");
            std::process::exit(1);
        }
    };
    let security = match security::Security::connect(
        &config.database_url,
        &config.encryption_key,
        config.revoked_subjects.clone(),
    )
    .await
    {
        Ok(security) => security,
        Err(err) => {
            eprintln!("security configuration error: {err}");
            std::process::exit(1);
        }
    };

    let port = config.port;
    let server_secret = config.server_secret.clone();
    let base_url = config.base_url.clone();
    let state = AppState {
        oauth_client,
        http_client,
        key,
        server_secret,
        base_url,
        catalog,
        security: Some(security),
    };

    let app = router(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("auth-proxy listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
}

// Bearer credentials are explicitly supplied by the browser. Never enable
// cookie credentials: login/consent remain top-level navigations.
fn browser_cors() -> tower_http::cors::CorsLayer {
    use axum::http::{header, HeaderName, Method};
    use tower_http::cors::{Any, CorsLayer};
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .expose_headers([
            HeaderName::from_static("x-connection-code"),
            header::LINK,
            header::RETRY_AFTER,
            header::ETAG,
            HeaderName::from_static("x-total-count"),
            HeaderName::from_static("x-next-page"),
        ])
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/logo.png", get(logo))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route(
            "/connect",
            get(proxy::connect_page).post(proxy::connect_confirm),
        )
        .route("/proxy", axum::routing::any(proxy::proxy))
        .route("/proxy/*path", axum::routing::any(proxy::forward))
        .route("/session", get(proxy::session_challenge))
        .route("/oauth/:provider/start", get(oauth::start))
        .route("/oauth/:provider/callback", get(oauth::callback))
        .route("/catalog", get(catalog::list))
        .route("/catalog/:file", get(catalog::document))
        .layer(browser_cors())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn logo() -> impl axum::response::IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_bytes!("../static/logo.png").as_slice(),
    )
}

async fn home(State(state): State<AppState>, jar: PrivateCookieJar) -> Html<String> {
    let user = session::read_session(&jar);
    let tenant_secret = user
        .as_ref()
        .map(|u| tenant_secret::derive(&state.server_secret, &u.google_sub));
    Html(templates::render_home(
        user.as_ref(),
        tenant_secret.as_deref(),
    ))
}

#[cfg(test)]
mod browser_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn browser_preflight_and_rotation_headers() {
        let app = Router::new()
            .route(
                "/proxy/pets",
                get(|| async {
                    (
                        [
                            ("x-connection-code", "rotated"),
                            ("link", "</next>; rel=next"),
                        ],
                        "[]",
                    )
                }),
            )
            .layer(browser_cors());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/proxy/pets")
                    .header("origin", "https://atomic.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(response.headers()["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .contains("authorization"));
        assert!(!response
            .headers()
            .contains_key("access-control-allow-credentials"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/proxy/pets")
                    .header("origin", "https://atomic.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let exposed = response.headers()["access-control-expose-headers"]
            .to_str()
            .unwrap();
        assert!(exposed.contains("x-connection-code"));
        assert!(exposed.contains("link"));
    }
}
