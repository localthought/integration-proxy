mod auth;
mod catalog;
mod config;
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
    catalog: catalog::Catalog,
    security: Option<security::Security>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
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

    let catalog = match catalog::Catalog::load(&config.catalog_path, &reqwest::Client::new()).await
    {
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
    let state = AppState {
        oauth_client,
        http_client: reqwest::Client::new(),
        key,
        server_secret,
        catalog,
        security: Some(security),
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route(
            "/connect",
            get(proxy::connect_page).post(proxy::connect_confirm),
        )
        .route("/proxy", axum::routing::any(proxy::proxy))
        .route("/session", get(proxy::session_challenge))
        .route("/catalog", get(catalog::list))
        .route("/catalog/{file}", get(catalog::document))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("auth-proxy listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
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
