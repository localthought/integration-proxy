use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Form, Path, Query, RawQuery, State},
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

pub fn oauth_start_url(platform: &str, params: &ConnectParams) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &params.redirect_uri)
        .append_pair("ts", &params.ts.to_string())
        .append_pair("nonce", &params.nonce)
        .append_pair("challenge", &params.challenge)
        .append_pair("tenant_id", &params.tenant_id)
        .append_pair("user_id", &params.user_id)
        .append_pair("user_id_sig", &params.user_id_sig)
        .append_pair("response", &params.response)
        .finish();
    format!("/oauth/{platform}/start?{query}")
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
    pub nonce: String,
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
    nonce: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}
pub fn now_unix() -> u64 {
    now()
}

fn challenge(server_secret: &str, ts: u64, nonce: &str) -> String {
    tenant_secret::sign(server_secret, &format!("{ts}.{nonce}"))
}

pub async fn session_challenge(State(state): State<AppState>) -> Json<SessionChallenge> {
    let ts = now();
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    Json(SessionChallenge {
        ts,
        challenge: challenge(&state.server_secret, ts, &nonce),
        nonce,
    })
}

pub async fn verify_connect(state: &AppState, params: &ConnectParams) -> Result<(), ConnectError> {
    if params.ts > now() || now().saturating_sub(params.ts) > 600 {
        return Err(ConnectError::InvalidSession);
    }
    if !tenant_secret::verify_signature(
        &state.server_secret,
        &format!("{}.{}", params.ts, params.nonce),
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
    if state
        .security
        .as_ref()
        .is_some_and(|security| security.is_revoked(&params.tenant_id, &params.user_id))
    {
        return Err(ConnectError::Revoked);
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
    verify_connect(&state, &params).await?;

    match session::read_session(&jar) {
        Some(_) => {
            Ok(Html(templates::render_connect(&params, &state.catalog.names())).into_response())
        }
        None => {
            let mut target = url::Url::parse("https://localhost/connect").unwrap();
            target
                .query_pairs_mut()
                .append_pair("redirect_uri", &params.redirect_uri)
                .append_pair("ts", &params.ts.to_string())
                .append_pair("nonce", &params.nonce)
                .append_pair("challenge", &params.challenge)
                .append_pair("tenant_id", &params.tenant_id)
                .append_pair("user_id", &params.user_id)
                .append_pair("user_id_sig", &params.user_id_sig)
                .append_pair("response", &params.response);
            let jar = session::set_connect_redirect(
                jar,
                &format!("/connect?{}", target.query().unwrap()),
            );
            Ok((jar, Redirect::to("/auth/login")).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct ConnectConfirmForm {
    pub redirect_uri: String,
    pub ts: u64,
    pub nonce: String,
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
        nonce: form.nonce,
        challenge: form.challenge,
        tenant_id: form.tenant_id,
        user_id: form.user_id,
        user_id_sig: form.user_id_sig,
        response: form.response,
    };
    let mut redirect_uri = parse_redirect_uri(&params.redirect_uri)?;
    verify_connect(&state, &params).await?;
    if let Some(security) = &state.security {
        if !security
            .consume_nonce(&params.nonce)
            .await
            .map_err(|_| ConnectError::InvalidSession)?
        {
            return Err(ConnectError::InvalidSession);
        }
    }
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

#[derive(Deserialize, Serialize)]
struct Credential {
    provider: String,
    tenant_id: String,
    user_id: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct RefreshToken {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

async fn refresh_if_needed(state: &AppState, credential: &mut Credential) -> Result<(), ()> {
    if credential
        .expires_at
        .is_none_or(|expires| expires > now() + 30)
    {
        return Ok(());
    }
    let refresh_token = credential.refresh_token.as_deref().ok_or(())?;
    let provider = crate::providers::Provider::configured(&state.catalog, &credential.provider).map_err(|_| ())?;
    let response = provider
        .token_request(
            &state.http_client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let token = response.json::<RefreshToken>().await.map_err(|_| ())?;
    credential.access_token = token.access_token;
    if token.refresh_token.is_some() {
        credential.refresh_token = token.refresh_token;
    }
    credential.expires_at = token.expires_in.map(|seconds| now() + seconds);
    Ok(())
}

pub async fn forward(
    Path(path): Path<String>,
    RawQuery(query): RawQuery,
    State(state): State<AppState>,
    method: axum::http::Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((platform, path)) = path.split_once('/') else {
        return (
            StatusCode::NOT_FOUND,
            "proxy platform and path are required",
        )
            .into_response();
    };
    if body.len() > 1_048_576 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "request body is too large").into_response();
    }
    let Some(code) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "missing connection code").into_response();
    };
    let Some(security) = &state.security else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "security service unavailable",
        )
            .into_response();
    };
    let Ok(Some(envelope)) = security.take_connection_code(code).await else {
        return (
            StatusCode::UNAUTHORIZED,
            "invalid or expired connection code",
        )
            .into_response();
    };
    let Some(plaintext) = security.open(&envelope, b"connection-credential-v1") else {
        return (StatusCode::UNAUTHORIZED, "invalid connection code").into_response();
    };
    let Ok(mut credential) = serde_json::from_slice::<Credential>(&plaintext) else {
        return (StatusCode::UNAUTHORIZED, "invalid connection code").into_response();
    };
    if credential.provider != platform
        || security.is_revoked(&credential.tenant_id, &credential.user_id)
    {
        return (StatusCode::FORBIDDEN, "credential is not permitted").into_response();
    }
    if refresh_if_needed(&state, &mut credential).await.is_err() {
        return (StatusCode::UNAUTHORIZED, "credential refresh failed").into_response();
    }
    let request_path = format!("/{path}");
    let Some(mut target) = state
        .catalog
        .allows(platform, method.as_str(), &request_path)
    else {
        return (
            StatusCode::NOT_FOUND,
            "method or path is not in the catalog",
        )
            .into_response();
    };
    target.set_path(&request_path);
    let upstream = match upstream_request(
        &state.http_client,
        method.clone(),
        target.clone(),
        query.as_deref(),
        &credential.access_token,
        &headers,
        body,
    )
    .send()
    .await
    {
        Ok(response) => response,
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream request failed").into_response(),
    };
    let status = upstream.status();
    let mut forwarded_headers = upstream_response_headers(upstream.headers());
    normalize_pagination_links(
        &mut forwarded_headers,
        platform,
        &method,
        &request_path,
        &target,
    );
    let bytes = match upstream.bytes().await {
        Ok(bytes) if bytes.len() <= 10_485_760 => bytes,
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "upstream response failed or was too large",
            )
                .into_response()
        }
    };
    let mut response = Response::new(bytes.into());
    *response.status_mut() = status;
    *response.headers_mut() = forwarded_headers;
    let Ok(envelope) = security.seal(
        &serde_json::to_vec(&credential).unwrap(),
        b"connection-credential-v1",
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential rotation failed",
        )
            .into_response();
    };
    let mut new_code = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_code);
    let new_code = URL_SAFE_NO_PAD.encode(new_code);
    if security
        .store_connection_code(&new_code, &envelope)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential rotation failed",
        )
            .into_response();
    }
    response.headers_mut().insert(
        "x-connection-code",
        axum::http::HeaderValue::from_str(&new_code).unwrap(),
    );
    response
}

// Forward only representation/pagination metadata, never provider cookies or credentials.
fn upstream_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut result = HeaderMap::new();
    for name in [header::CONTENT_TYPE, header::LINK, header::RETRY_AFTER] {
        for value in headers.get_all(&name) {
            result.append(name.clone(), value.clone());
        }
    }
    result
}

fn normalize_pagination_links(
    headers: &mut HeaderMap,
    platform: &str,
    method: &axum::http::Method,
    request_path: &str,
    upstream: &Url,
) {
    if platform != "github-issues" || method != axum::http::Method::GET {
        return;
    }
    let Some(rest) = request_path.strip_prefix("/repos/") else {
        return;
    };
    let mut parts = rest.splitn(3, '/');
    let (Some(owner), Some(repository), Some(suffix)) = (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    if owner.is_empty() || repository.is_empty() || suffix.is_empty() {
        return;
    }
    let expected_suffix = format!("/{suffix}");
    let values: Vec<_> = headers.get_all(header::LINK).iter().cloned().collect();
    if values.is_empty() {
        return;
    }
    headers.remove(header::LINK);
    for value in values {
        let Ok(text) = value.to_str() else {
            headers.append(header::LINK, value);
            continue;
        };
        let mut rewritten = String::with_capacity(text.len());
        let mut remaining = text;
        while let Some(open) = remaining.find('<') {
            rewritten.push_str(&remaining[..=open]);
            remaining = &remaining[open + 1..];
            let Some(close) = remaining.find('>') else {
                rewritten.push_str(remaining);
                remaining = "";
                break;
            };
            let raw_url = &remaining[..close];
            let replacement = Url::parse(raw_url).ok().and_then(|mut url| {
                if url.origin() != upstream.origin()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return None;
                }
                let canonical = url.path().strip_prefix("/repositories/")?;
                let (repository_id, canonical_suffix) = canonical.split_once('/')?;
                if repository_id.is_empty()
                    || !repository_id.bytes().all(|byte| byte.is_ascii_digit())
                    || format!("/{canonical_suffix}") != expected_suffix
                {
                    return None;
                }
                url.set_path(request_path);
                Some(url.to_string())
            });
            rewritten.push_str(replacement.as_deref().unwrap_or(raw_url));
            rewritten.push('>');
            remaining = &remaining[close + 1..];
        }
        rewritten.push_str(remaining);
        headers.append(
            header::LINK,
            rewritten.parse().unwrap_or_else(|_| value.clone()),
        );
    }
}

fn upstream_request(
    client: &reqwest::Client,
    method: axum::http::Method,
    mut target: Url,
    query: Option<&str>,
    access_token: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> reqwest::RequestBuilder {
    target.set_query(query);
    let mut request = client.request(method, target).bearer_auth(access_token);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(etag) = headers.get(header::IF_MATCH) {
        request = request.header(header::IF_MATCH, etag);
    }
    request.body(body)
}

#[derive(Debug)]
pub enum ConnectError {
    InvalidRedirect,
    NotLoggedIn,
    InvalidSession,
    Revoked,
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
            ConnectError::Revoked => (StatusCode::FORBIDDEN, "tenant or user is revoked"),
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
            database_url: "postgres://unused".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            revoked_subjects: vec![],
        };
        AppState {
            oauth_client: crate::auth::build_client(&config).unwrap(),
            http_client: crate::build_http_client(),
            key: Key::generate(),
            server_secret: config.server_secret,
            base_url: config.base_url,
            catalog: crate::catalog::Catalog::default(),
            security: None,
        }
    }

    #[tokio::test]
    async fn forwarded_requests_include_server_owned_user_agent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/repos/owner/repo/issues",
            axum::routing::post(|axum::extract::OriginalUri(uri): axum::extract::OriginalUri, headers: HeaderMap, body: Bytes| async move {
                Json(json!({
                    "query": uri.query(),
                    "user_agent": headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()),
                    "authorization": headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()),
                    "content_type": headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
                    "if_match": headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()),
                    "body": String::from_utf8(body.to_vec()).unwrap(),
                }))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = crate::build_http_client();
        for caller_user_agent in [None, Some("caller-controlled-agent")] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            headers.insert(
                header::IF_MATCH,
                HeaderValue::from_static("\"event-version\""),
            );
            if let Some(value) = caller_user_agent {
                headers.insert(header::USER_AGENT, HeaderValue::from_static(value));
            }
            let response = upstream_request(
                &client,
                axum::http::Method::POST,
                Url::parse(&format!("http://{address}/repos/owner/repo/issues")).unwrap(),
                Some("state=all&page=2&per_page=1&labels=a%2Cb"),
                "test-provider-token",
                &headers,
                Bytes::from_static(b"{}"),
            )
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
            assert_eq!(
                response["query"],
                "state=all&page=2&per_page=1&labels=a%2Cb"
            );
            assert_eq!(response["user_agent"], "LocalThought-integration-proxy");
            assert_eq!(response["authorization"], "Bearer test-provider-token");
            assert_eq!(response["content_type"], "application/json");
            assert_eq!(response["body"], "{}");
            assert_eq!(response["if_match"], "\"event-version\"");
        }
        server.abort();
    }

    #[test]
    fn pagination_headers_survive_without_forwarding_provider_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.append(
            header::LINK,
            HeaderValue::from_static(
                "<https://api.github.com/repos/o/r/issues?page=2>; rel=\"next\"",
            ),
        );
        headers.append(
            header::LINK,
            HeaderValue::from_static(
                "<https://api.github.com/repos/o/r/issues?page=3>; rel=\"last\"",
            ),
        );
        headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_static("provider-session=private"),
        );
        headers.insert(
            "x-connection-code",
            HeaderValue::from_static("untrusted-provider-code"),
        );
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
        let forwarded = upstream_response_headers(&headers);
        assert_eq!(forwarded.get(header::RETRY_AFTER), Some(&HeaderValue::from_static("300")));
        assert_eq!(forwarded.get_all(header::LINK).iter().count(), 2);
        assert_eq!(forwarded[header::CONTENT_TYPE], "application/json");
        assert!(!forwarded.contains_key(header::SET_COOKIE));
        assert!(!forwarded.contains_key("x-connection-code"));
    }

    #[test]
    fn github_canonical_pagination_link_uses_the_allowlisted_repository_alias() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::LINK,
            HeaderValue::from_static(
                "<https://api.github.com/repositories/1360229799/issues?state=all&after=cursor&per_page=30&page=2>; rel=\"next\", <https://api.github.com/repositories/1360229799/issues?state=all&per_page=30&page=4>; rel=\"last\"",
            ),
        );

        normalize_pagination_links(
            &mut headers,
            "github-issues",
            &axum::http::Method::GET,
            "/repos/localthought/integration-proxy/issues",
            &Url::parse("https://api.github.com").unwrap(),
        );

        assert_eq!(
            headers[header::LINK],
            "<https://api.github.com/repos/localthought/integration-proxy/issues?state=all&after=cursor&per_page=30&page=2>; rel=\"next\", <https://api.github.com/repos/localthought/integration-proxy/issues?state=all&per_page=30&page=4>; rel=\"last\""
        );
    }

    #[test]
    fn github_link_normalization_does_not_change_other_endpoints_or_origins() {
        for (platform, method, request_path, link) in [
            (
                "github-issues",
                axum::http::Method::GET,
                "/repos/o/r/issues",
                "<https://api.github.com/repositories/123/pulls?page=2>; rel=\"next\"",
            ),
            (
                "github-issues",
                axum::http::Method::GET,
                "/repos/o/r/issues",
                "<https://example.com/repositories/123/issues?page=2>; rel=\"next\"",
            ),
            (
                "github-issues",
                axum::http::Method::GET,
                "/repos/o/r/issues",
                "<https://api.github.com/repositories/not-numeric/issues?page=2>; rel=\"next\"",
            ),
            (
                "google-calendar",
                axum::http::Method::GET,
                "/repos/o/r/issues",
                "<https://api.github.com/repositories/123/issues?page=2>; rel=\"next\"",
            ),
            (
                "github-issues",
                axum::http::Method::POST,
                "/repos/o/r/issues",
                "<https://api.github.com/repositories/123/issues?page=2>; rel=\"next\"",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::LINK, HeaderValue::from_str(link).unwrap());
            normalize_pagination_links(
                &mut headers,
                platform,
                &method,
                request_path,
                &Url::parse("https://api.github.com").unwrap(),
            );
            assert_eq!(headers[header::LINK], link);
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
        let nonce = "test-nonce".to_string();
        let challenge = challenge(&state.server_secret, ts, &nonce);
        let tenant_id = "tenant-123".to_string();
        let user_id = "user-123".to_string();
        let secret = tenant_secret::derive(&state.server_secret, &tenant_id);
        ConnectParams {
            redirect_uri: redirect_uri.to_string(),
            ts,
            nonce,
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
                nonce: "x".into(),
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
                nonce: "test-nonce".into(),
                challenge: challenge("server-secret", now(), "test-nonce"),
                tenant_id: "tenant".into(),
                user_id: "user".into(),
                user_id_sig: tenant_secret::sign(
                    &tenant_secret::derive("server-secret", "tenant"),
                    "user",
                ),
                response: tenant_secret::sign(
                    &tenant_secret::derive("server-secret", "tenant"),
                    &challenge("server-secret", now(), "test-nonce"),
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
