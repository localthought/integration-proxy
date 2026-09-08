use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::{session, templates, tenant_secret, AppState};

/// Builds the path (with query string) to reopen `/connect` for a given
/// `redirect_uri`, used to send a user back here after a login detour.
pub fn connect_url(redirect_uri: &str) -> String {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", redirect_uri)
        .finish();
    format!("/connect?{query}")
}

fn parse_redirect_uri(raw: &str) -> Result<Url, ConnectError> {
    let url = Url::parse(raw).map_err(|_| ConnectError::InvalidRedirect)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ConnectError::InvalidRedirect);
    }
    Ok(url)
}

#[derive(Deserialize)]
pub struct ConnectParams {
    pub redirect_uri: String,
    pub ts: u64,
    pub challenge: String,
    pub tenant_id: String,
    pub user_id: String,
    pub user_id_sig: String,
    pub response: String,
}

#[derive(Serialize)]
pub struct SessionChallenge {
    ts: u64,
    challenge: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

fn challenge(server_secret: &str, ts: u64) -> String {
    tenant_secret::sign(server_secret, &ts.to_string())
}

pub async fn session_challenge(State(state): State<AppState>) -> Json<SessionChallenge> {
    let ts = now();
    Json(SessionChallenge {
        ts,
        challenge: challenge(&state.server_secret, ts),
    })
}

fn verify_connect(state: &AppState, params: &ConnectParams) -> Result<(), ConnectError> {
    if params.ts > now() || now().saturating_sub(params.ts) > 600 {
        return Err(ConnectError::InvalidSession);
    }
    if !tenant_secret::verify_signature(
        &state.server_secret,
        &params.ts.to_string(),
        &params.challenge,
    ) {
        return Err(ConnectError::InvalidSession);
    }
    let tenant_secret = tenant_secret::derive(&state.server_secret, &params.tenant_id);
    if !tenant_secret::verify_signature(&tenant_secret, &params.challenge, &params.response)
        || !tenant_secret::verify_signature(&tenant_secret, &params.user_id, &params.user_id_sig)
    {
        return Err(ConnectError::InvalidSession);
    }
    Ok(())
}

/// Shows the "connect this app" consent screen for a signed-in user, or
/// sends them to log in first (remembering where to come back to).
pub async fn connect_page(
    State(state): State<AppState>,
    Query(params): Query<ConnectParams>,
    jar: PrivateCookieJar,
) -> Result<Response, ConnectError> {
    parse_redirect_uri(&params.redirect_uri)?;
    verify_connect(&state, &params)?;

    match session::read_session(&jar) {
        Some(_) => Ok(Html(templates::render_connect(&params)).into_response()),
        None => {
            let jar = session::set_connect_redirect(jar, &params.redirect_uri);
            Ok((jar, Redirect::to("/auth/login")).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct ConnectConfirmForm {
    pub redirect_uri: String,
    pub ts: u64,
    pub challenge: String,
    pub tenant_id: String,
    pub user_id: String,
    pub user_id_sig: String,
    pub response: String,
}

/// Confirms the connection and redirects back to the caller with the
/// signed-in user's deterministic tenant secret attached as `?secret=`.
pub async fn connect_confirm(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Form(form): Form<ConnectConfirmForm>,
) -> Result<Redirect, ConnectError> {
    let params = ConnectParams {
        redirect_uri: form.redirect_uri,
        ts: form.ts,
        challenge: form.challenge,
        tenant_id: form.tenant_id,
        user_id: form.user_id,
        user_id_sig: form.user_id_sig,
        response: form.response,
    };
    let mut redirect_uri = parse_redirect_uri(&params.redirect_uri)?;
    verify_connect(&state, &params)?;
    let user = session::read_session(&jar).ok_or(ConnectError::NotLoggedIn)?;

    let secret = tenant_secret::derive(&state.server_secret, &user.google_sub);
    redirect_uri
        .query_pairs_mut()
        .append_pair("secret", &secret);

    Ok(Redirect::to(redirect_uri.as_str()))
}

/// Minimal authenticated endpoint other services (e.g. atomic-server) call
/// to check a tenant secret is legitimate.
pub async fn proxy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match token.and_then(|token| tenant_secret::verify(&state.server_secret, token)) {
        Some(_identity) => Json(json!({ "ok": true })).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "invalid or missing bearer token" })),
        )
            .into_response(),
    }
}

#[derive(Debug)]
pub enum ConnectError {
    InvalidRedirect,
    NotLoggedIn,
    InvalidSession,
}

impl IntoResponse for ConnectError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ConnectError::InvalidRedirect => (
                StatusCode::BAD_REQUEST,
                "redirect_uri is missing or invalid",
            ),
            ConnectError::NotLoggedIn => (StatusCode::UNAUTHORIZED, "please log in first"),
            ConnectError::InvalidSession => (
                StatusCode::UNAUTHORIZED,
                "invalid or expired tenant session",
            ),
        };
        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use axum_extra::extract::cookie::Key;

    fn test_state(server_secret: &str) -> AppState {
        let config = crate::config::Config {
            google_client_id: "test-client-id".to_string(),
            google_client_secret: "test-client-secret".to_string(),
            base_url: "http://localhost:8080".to_string(),
            port: 8080,
            session_secret: None,
            server_secret: server_secret.to_string(),
            catalog_path: "catalog.yaml".to_string(),
        };
        AppState {
            oauth_client: crate::auth::build_client(&config).unwrap(),
            http_client: reqwest::Client::new(),
            key: Key::generate(),
            server_secret: config.server_secret,
            catalog: crate::catalog::Catalog::default(),
        }
    }

    fn logged_in_jar(key: Key) -> (PrivateCookieJar, crate::session::SessionUser) {
        let user = crate::session::SessionUser::new(
            "google-sub-123".to_string(),
            "user@example.com".to_string(),
            "Test User".to_string(),
            None,
        );
        let jar = session::set_session(PrivateCookieJar::new(key), &user);
        (jar, user)
    }

    fn connect_params(state: &AppState, redirect_uri: &str) -> ConnectParams {
        let ts = now();
        let challenge = challenge(&state.server_secret, ts);
        let tenant_id = "tenant-123".to_string();
        let user_id = "user-123".to_string();
        let secret = tenant_secret::derive(&state.server_secret, &tenant_id);
        ConnectParams {
            redirect_uri: redirect_uri.to_string(),
            ts,
            challenge: challenge.clone(),
            tenant_id,
            user_id: user_id.clone(),
            user_id_sig: tenant_secret::sign(&secret, &user_id),
            response: tenant_secret::sign(&secret, &challenge),
        }
    }

    #[test]
    fn connect_url_encodes_the_redirect_uri() {
        let url = connect_url("https://example.com/cb?x=1&y=2");
        assert_eq!(
            url,
            "/connect?redirect_uri=https%3A%2F%2Fexample.com%2Fcb%3Fx%3D1%26y%3D2"
        );
    }

    #[tokio::test]
    async fn connect_page_rejects_invalid_redirect_uri() {
        let state = test_state("server-secret");
        let jar = PrivateCookieJar::new(Key::generate());
        let err = connect_page(
            State(state),
            Query(connect_params(&test_state("server-secret"), "not a url")),
            jar,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConnectError::InvalidRedirect));
    }

    #[tokio::test]
    async fn connect_page_sends_signed_out_visitor_to_login() {
        let state = test_state("server-secret");
        let jar = PrivateCookieJar::new(Key::generate());
        let response = connect_page(
            State(state.clone()),
            Query(connect_params(&state, "https://example.com/cb")),
            jar,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/auth/login"
        );
    }

    #[tokio::test]
    async fn connect_page_shows_consent_screen_when_signed_in() {
        let state = test_state("server-secret");
        let (jar, _) = logged_in_jar(Key::generate());
        let response = connect_page(
            State(state.clone()),
            Query(connect_params(&state, "https://example.com/cb")),
            jar,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn connect_confirm_rejects_an_invalid_tenant_session() {
        let jar = PrivateCookieJar::new(Key::generate());
        let state = test_state("server-secret");
        let err = connect_confirm(
            State(state),
            jar,
            Form(ConnectConfirmForm {
                redirect_uri: "https://example.com/cb".to_string(),
                ts: 0,
                challenge: "x".into(),
                tenant_id: "x".into(),
                user_id: "x".into(),
                user_id_sig: "x".into(),
                response: "x".into(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ConnectError::InvalidSession));
    }

    #[tokio::test]
    async fn connect_confirm_redirects_with_the_tenant_secret() {
        let key = Key::generate();
        let (jar, user) = logged_in_jar(key);
        let state = test_state("server-secret");
        let expected_secret = tenant_secret::derive(&state.server_secret, &user.google_sub);

        let redirect = connect_confirm(
            State(state),
            jar,
            Form(ConnectConfirmForm {
                redirect_uri: "https://example.com/cb?existing=1".to_string(),
                ts: now(),
                challenge: challenge("server-secret", now()),
                tenant_id: "tenant".into(),
                user_id: "user".into(),
                user_id_sig: tenant_secret::sign(
                    &tenant_secret::derive("server-secret", "tenant"),
                    "user",
                ),
                response: tenant_secret::sign(
                    &tenant_secret::derive("server-secret", "tenant"),
                    &challenge("server-secret", now()),
                ),
            }),
        )
        .await
        .unwrap();

        let location = redirect
            .into_response()
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let url = Url::parse(&location).unwrap();
        assert_eq!(url.origin().ascii_serialization(), "https://example.com");
        assert_eq!(url.path(), "/cb");
        let pairs: Vec<_> = url.query_pairs().collect();
        assert!(pairs.iter().any(|(k, v)| k == "existing" && v == "1"));
        assert!(pairs
            .iter()
            .any(|(k, v)| k == "secret" && v == expected_secret.as_str()));
    }

    #[tokio::test]
    async fn proxy_accepts_a_valid_bearer_secret() {
        let state = test_state("server-secret");
        let secret = tenant_secret::derive(&state.server_secret, "google-sub-123");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
        );

        let response = proxy(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn proxy_rejects_a_missing_bearer_header() {
        let state = test_state("server-secret");
        let response = proxy(State(state), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn proxy_rejects_an_invalid_bearer_secret() {
        let state = test_state("server-secret");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer garbage"));

        let response = proxy(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn proxy_rejects_a_secret_signed_with_a_different_server_secret() {
        let state = test_state("server-secret");
        let secret = tenant_secret::derive("a-different-secret", "google-sub-123");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
        );

        let response = proxy(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
