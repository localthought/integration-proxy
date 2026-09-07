mod auth;
mod config;
mod session;
mod templates;

use axum::{
    extract::FromRef,
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

    let port = config.port;
    let state = AppState {
        oauth_client,
        http_client: reqwest::Client::new(),
        key,
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("auth-proxy listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
}

async fn home(jar: PrivateCookieJar) -> Html<String> {
    let user = session::read_session(&jar);
    Html(templates::render_home(user.as_ref()))
}
