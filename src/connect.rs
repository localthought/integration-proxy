//! Browser bootstrap: application identity, explicit platform consent, and a PKCE handoff.
use crate::{oauth, providers::Provider, security::Security, session, templates, AppState};
use axum::{
    extract::{Form, OriginalUri, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const CONSENT_COOKIE: &str = "platform_consent";
const PROVIDER_COOKIE: &str = "platform_oauth";
const HANDOFF_AAD: &[u8] = b"platform-handoff-v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum Credentials {
    #[serde(rename = "connection")]
    Connection,
    #[serde(rename = "connection+tenant_secret")]
    ConnectionAndTenantSecret,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Request {
    pub platform: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub credentials: Credentials,
}

#[derive(Clone, Deserialize, Serialize)]
struct Consent {
    request: Request,
    csrf: String,
    expires: u64,
}

#[derive(Deserialize, Serialize)]
pub struct OAuthContext {
    pub request: Request,
    pub binding: String,
}

#[derive(Deserialize, Serialize)]
struct Handoff {
    platform: String,
    tenant_id: String,
    user_id: String,
    credential: String,
    include_tenant_secret: bool,
}

pub fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn pkce_challenge(verifier: &str) -> Option<String> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return None;
    }
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}

impl Request {
    fn validate(&self) -> Result<Url, &'static str> {
        let url = Url::parse(&self.redirect_uri).map_err(|_| "Invalid return address")?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if self.redirect_uri.len() > 1500
            || url.host_str().is_none()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url
                .query_pairs()
                .any(|(name, _)| matches!(name.as_ref(), "connection_code" | "error" | "secret"))
        {
            return Err("Invalid return address");
        }
        if self.user_id.is_empty()
            || self.user_id.len() > 512
            || self.code_challenge_method != "S256"
            || self.code_challenge.len() != 43
            || URL_SAFE_NO_PAD
                .decode(&self.code_challenge)
                .map_or(true, |b| b.len() != 32)
            || crate::config::Config::provider_env_prefix(&self.platform).is_err()
        {
            return Err("Invalid connection request");
        }
        Ok(url)
    }

    fn local_url(&self) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("platform", &self.platform)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("user_id", &self.user_id)
            .append_pair("code_challenge", &self.code_challenge)
            .append_pair("code_challenge_method", &self.code_challenge_method)
            .append_pair(
                "credentials",
                match self.credentials {
                    Credentials::Connection => "connection",
                    Credentials::ConnectionAndTenantSecret => "connection+tenant_secret",
                },
            );
        format!("/connect?{}", query.finish())
    }
}

/// Only a previously validated, cookie-stored bootstrap request can redirect a login cancellation.
pub fn cancel_login_target(target: &str) -> Option<String> {
    if !target.starts_with("/connect?") {
        return None;
    }
    let uri: axum::http::Uri = target.parse().ok()?;
    let Query(request) = Query::<Request>::try_from_uri(&uri).ok()?;
    let mut destination = request.validate().ok()?;
    destination
        .query_pairs_mut()
        .append_pair("error", "access_denied");
    Some(destination.into())
}

pub fn clear_consent(jar: PrivateCookieJar) -> PrivateCookieJar {
    jar.remove(Cookie::build(CONSENT_COOKIE).path("/").build())
}

pub(crate) fn protected(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response.headers_mut().insert("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https:; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    response
}

fn error(message: &'static str) -> Response {
    protected((StatusCode::BAD_REQUEST, message))
}

fn private_cookie(name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build()
}

pub async fn page(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    jar: PrivateCookieJar,
) -> Response {
    let is_browser =
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).any(|(key, _)| {
            matches!(
                key.as_ref(),
                "code_challenge" | "code_challenge_method" | "credentials"
            )
        });
    let request = if is_browser {
        match Query::<Request>::try_from_uri(&uri) {
            Ok(Query(request)) => request,
            Err(_) => return error("Invalid connection request"),
        }
    } else {
        let params = match Query::<crate::proxy::ConnectParams>::try_from_uri(&uri) {
            Ok(params) => params,
            Err(_) => return error("Invalid connection request; start again from your hub"),
        };
        return match crate::proxy::connect_page(State(state), params, jar).await {
            Ok(response) => protected(response),
            Err(err) => protected(err),
        };
    };
    let target = match request.validate() {
        Ok(target) => target,
        Err(message) => return error(message),
    };
    if !state.catalog.names().contains(&request.platform)
        || Provider::configured(&state.catalog, &request.platform).is_err()
    {
        return error("This platform is not available for connection");
    }
    let consent = Consent {
        request: request.clone(),
        csrf: random(),
        expires: crate::proxy::now_unix() + 600,
    };
    let user = session::read_session(&jar);
    let jar = jar.add(private_cookie(
        CONSENT_COOKIE,
        serde_json::to_string(&consent).unwrap(),
    ));
    // Preserve the entire selected-platform request through application authentication.
    let jar = if user.is_none() {
        session::set_connect_redirect(jar, &request.local_url())
    } else {
        jar
    };
    let mut response = protected((
        jar,
        Html(templates::render_platform_connect(
            user.as_ref(),
            &request.platform,
            &target.origin().ascii_serialization(),
            &consent.csrf,
            request.credentials == Credentials::ConnectionAndTenantSecret,
            &state.app_auth_label,
        )),
    ));
    // Keep the consent form's same-origin POST attributable while sending no
    // referrer to the configured identity provider or selected provider.
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "same-origin".parse().unwrap());
    // Chrome applies form-action to redirects too, including an already-authorized
    // provider returning straight through its callback to the hub.
    let provider = state.catalog.oauth_provider(&request.platform).unwrap();
    let provider_origin = Url::parse(&provider.authorization_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let policy = format!(
        "{}; form-action 'self' {} {}",
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap(),
        provider_origin,
        target.origin().ascii_serialization()
    );
    response
        .headers_mut()
        .insert("content-security-policy", policy.parse().unwrap());
    response
}

#[derive(Deserialize)]
pub struct Approval {
    csrf: String,
}

pub async fn authorize(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    Form(approval): Form<Approval>,
) -> Response {
    // Browser form origin is an extra defense; the encrypted cookie and random CSRF token are required.
    if headers
        .get(header::ORIGIN)
        .is_some_and(|origin| origin.to_str().ok() != Some(state.base_url.trim_end_matches('/')))
    {
        return error("Invalid connection approval");
    }
    let Some(cookie) = jar.get(CONSENT_COOKIE) else {
        return error("Connection request expired; start again from your hub");
    };
    let Ok(consent) = serde_json::from_str::<Consent>(cookie.value()) else {
        return error("Invalid connection approval");
    };
    if consent.expires <= crate::proxy::now_unix()
        || consent.csrf != approval.csrf
        || consent.request.validate().is_err()
    {
        return error("Connection request expired or invalid; start again from your hub");
    }
    let Some(user) = session::read_session(&jar) else {
        return error("Log in before connecting");
    };
    let Some(security) = &state.security else {
        return error("Connections are unavailable");
    };
    if security.is_revoked(&user.subject, &consent.request.user_id)
        || !matches!(
            security
                .consume_nonce(&format!("consent:{}", consent.csrf))
                .await,
            Ok(true)
        )
    {
        return error("Connection approval expired or already used");
    }
    let context = OAuthContext {
        request: consent.request.clone(),
        binding: random(),
    };
    let Ok(sealed_context) =
        security.seal(&serde_json::to_vec(&context).unwrap(), b"platform-oauth-v1")
    else {
        return error("Could not start connection");
    };
    let binding = context.binding;
    let request = consent.request;
    let result = oauth::begin(
        &state,
        &request.platform,
        &request.redirect_uri,
        &user.subject,
        &request.user_id,
        Some(sealed_context),
    )
    .await;
    let url = match result {
        Ok(url) => url,
        Err(()) => return error("Could not start platform authorization"),
    };
    let jar = jar
        .remove(Cookie::build(CONSENT_COOKIE).path("/").build())
        .add(private_cookie(PROVIDER_COOKIE, binding));
    protected((jar, Redirect::to(&url)))
}

pub fn oauth_context(
    security: &Security,
    value: &str,
    jar: &PrivateCookieJar,
    tenant_id: &str,
) -> Option<OAuthContext> {
    let context: OAuthContext =
        serde_json::from_slice(&security.open(value, b"platform-oauth-v1")?).ok()?;
    let user = session::read_session(jar)?;
    if jar.get(PROVIDER_COOKIE)?.value() != context.binding || user.subject != tenant_id {
        return None;
    }
    Some(context)
}

pub fn clear_provider_cookie(jar: PrivateCookieJar) -> PrivateCookieJar {
    jar.remove(Cookie::build(PROVIDER_COOKIE).path("/").build())
}

pub async fn handoff(
    security: &Security,
    context: &OAuthContext,
    tenant_id: &str,
    credential: &str,
) -> Result<String, ()> {
    let handoff = Handoff {
        platform: context.request.platform.clone(),
        tenant_id: tenant_id.into(),
        user_id: context.request.user_id.clone(),
        credential: credential.into(),
        include_tenant_secret: context.request.credentials
            == Credentials::ConnectionAndTenantSecret,
    };
    let envelope = security
        .seal(&serde_json::to_vec(&handoff).map_err(|_| ())?, HANDOFF_AAD)
        .map_err(|_| ())?;
    let code = random();
    security
        .store_handoff(&code, &context.request.code_challenge, &envelope)
        .await
        .map_err(|_| ())?;
    Ok(code)
}

#[derive(Deserialize)]
pub struct Redemption {
    code: String,
    code_verifier: String,
}

pub async fn redeem(State(state): State<AppState>, Json(request): Json<Redemption>) -> Response {
    let Some(challenge) = pkce_challenge(&request.code_verifier) else {
        return error("Invalid or expired connection code");
    };
    if request.code.len() != 43 {
        return error("Invalid or expired connection code");
    }
    let Some(security) = &state.security else {
        return error("Connections are unavailable");
    };
    let Ok(Some(envelope)) = security.take_handoff(&request.code, &challenge).await else {
        return error("Invalid or expired connection code");
    };
    let Some(plaintext) = security.open(&envelope, HANDOFF_AAD) else {
        return error("Invalid connection code");
    };
    let Ok(handoff) = serde_json::from_slice::<Handoff>(&plaintext) else {
        return error("Invalid connection code");
    };
    if security.is_revoked(&handoff.tenant_id, &handoff.user_id) {
        return error("Connection is revoked");
    }
    let code = random();
    if security
        .store_connection_code(&code, &handoff.credential)
        .await
        .is_err()
    {
        return error("Could not finish connecting; reconnect from your hub");
    }
    let mut body = serde_json::json!({"connection_code": code, "platform": handoff.platform});
    if handoff.include_tenant_secret {
        body["tenant_secret"] =
            crate::tenant_secret::derive(&state.server_secret, &handoff.tenant_id).into();
    }
    protected(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request { platform: "github-issues".into(), redirect_uri: "https://hub.example/app/integrations?integration_state=state&platform=github-issues".into(), user_id: "did:ad:agent:test".into(), code_challenge: pkce_challenge(&"a".repeat(43)).unwrap(), code_challenge_method: "S256".into(), credentials: Credentials::Connection }
    }
    #[test]
    fn bootstrap_requires_no_tenant_proof_and_preserves_all_login_context() {
        let request = request();
        assert!(request.validate().is_ok());
        let query = request.local_url();
        let parsed: std::collections::HashMap<_, _> =
            Url::parse(&format!("https://localthought.io{query}"))
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect();
        assert_eq!(parsed["platform"], "github-issues");
        assert_eq!(parsed["redirect_uri"], request.redirect_uri);
        assert_eq!(parsed["code_challenge"], request.code_challenge);
        assert_eq!(parsed["credentials"], "connection");
        assert!(!parsed.contains_key("tenant_id"));
    }
    #[test]
    fn return_address_rejects_insecure_or_ambiguous_credentials() {
        for value in [
            "http://hub.example/cb",
            "javascript:alert(1)",
            "https://user:pass@hub.example/cb",
            "https://hub.example/cb#fragment",
            "https://hub.example/cb?connection_code=evil",
            "https://hub.example/cb?secret=evil",
        ] {
            let mut request = request();
            request.redirect_uri = value.into();
            assert!(request.validate().is_err(), "{value}");
        }
        let mut request = request();
        request.redirect_uri = "http://localhost:6747/app/integrations".into();
        assert!(request.validate().is_ok());
    }
    #[test]
    fn pkce_uses_rfc7636_s256_and_rejects_weak_input() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(pkce_challenge("short").is_none());
        assert!(pkce_challenge(&"!".repeat(43)).is_none());
        let mut request = request();
        request.code_challenge_method = "plain".into();
        assert!(request.validate().is_err());
    }
    fn state(security: Option<Security>) -> AppState {
        AppState {
            oauth_client: oauth2::basic::BasicClient::new(
                oauth2::ClientId::new("fixture-google".into()),
                None,
                oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".into())
                    .unwrap(),
                None,
            ),
            app_auth_userinfo_url: "https://accounts.example/userinfo".into(),
            app_auth_label: "OIDC".into(),
            http_client: crate::build_http_client(),
            key: axum_extra::extract::cookie::Key::generate(),
            server_secret: "fixture-server-secret".into(),
            base_url: "https://localthought.io".into(),
            catalog: crate::catalog::Catalog::for_test("github-issues"),
            security,
        }
    }

    #[tokio::test]
    async fn router_accepts_bootstrap_without_tenant_fields() {
        use tower::ServiceExt;
        // An unconfigured provider is a product error, not a missing-tenant query rejection.
        let app = crate::router(state(None));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(request().local_url())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        if status == StatusCode::OK {
            let policy = response.headers()["content-security-policy"]
                .to_str()
                .unwrap();
            assert!(policy.contains("form-action 'self' https://auth.example https://hub.example"));
            assert!(!policy.contains("spotify"));
            assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
        }
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("deserialize"));
        assert!(
            status == StatusCode::OK || String::from_utf8_lossy(&body).contains("not available")
        );
    }

    #[tokio::test]
    async fn consent_rejects_missing_cookie_and_google_session() {
        let s = state(None);
        let jar = PrivateCookieJar::new(s.key.clone());
        let result = authorize(
            State(s.clone()),
            jar.clone(),
            HeaderMap::new(),
            Form(Approval {
                csrf: "wrong".into(),
            }),
        )
        .await;
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let consent = Consent {
            request: request(),
            csrf: "valid".into(),
            expires: crate::proxy::now_unix() + 600,
        };
        let jar = jar.add(private_cookie(
            CONSENT_COOKIE,
            serde_json::to_string(&consent).unwrap(),
        ));
        let result = authorize(
            State(s),
            jar,
            HeaderMap::new(),
            Form(Approval {
                csrf: "valid".into(),
            }),
        )
        .await;
        let body = axum::body::to_bytes(result.into_body(), 16384)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Log in before connecting"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; CI runs with --include-ignored"]
    async fn postgres_handoff_is_pkce_bound_single_use_expiring_and_grant_scoped() {
        let db = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated test database");
        let security =
            Security::connect(&db, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", vec![])
                .await
                .unwrap();
        let s = state(Some(security.clone()));
        let verifier = "a".repeat(43);
        let mut context = OAuthContext {
            request: request(),
            binding: random(),
        };
        let credential = security.seal(br#"{"provider":"github-issues","tenant_id":"tenant","user_id":"did:ad:agent:test","access_token":"fixture-token","refresh_token":null,"expires_at":null}"#, b"connection-credential-v1").unwrap();
        let handoff_code = handoff(&security, &context, "tenant", &credential)
            .await
            .unwrap();
        let wrong = redeem(
            State(s.clone()),
            Json(Redemption {
                code: handoff_code.clone(),
                code_verifier: "b".repeat(43),
            }),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        let response = redeem(
            State(s.clone()),
            Json(Redemption {
                code: handoff_code.clone(),
                code_verifier: verifier.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["platform"], "github-issues");
        assert!(body.get("tenant_secret").is_none());
        assert!(!body.to_string().contains("fixture-token"));
        let rotating = body["connection_code"].as_str().unwrap();
        assert_eq!(
            security.take_connection_code(rotating).await.unwrap(),
            Some(credential.clone())
        );
        assert!(security
            .take_connection_code(rotating)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            redeem(
                State(s.clone()),
                Json(Redemption {
                    code: handoff_code,
                    code_verifier: verifier.clone()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );

        context.request.credentials = Credentials::ConnectionAndTenantSecret;
        let code = handoff(&security, &context, "tenant", &credential)
            .await
            .unwrap();
        let response = redeem(
            State(s.clone()),
            Json(Redemption {
                code,
                code_verifier: verifier.clone(),
            }),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["tenant_secret"],
            crate::tenant_secret::derive(&s.server_secret, "tenant")
        );

        // Two simultaneous valid exchanges cannot mint two rotating credentials.
        let code = handoff(&security, &context, "tenant", &credential)
            .await
            .unwrap();
        let challenge = pkce_challenge(&verifier).unwrap();
        let (first, second) = tokio::join!(
            security.take_handoff(&code, &challenge),
            security.take_handoff(&code, &challenge)
        );
        assert_ne!(first.unwrap().is_some(), second.unwrap().is_some());

        let code = handoff(&security, &context, "tenant", &credential)
            .await
            .unwrap();
        let (client, connection) = tokio_postgres::connect(&db, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        client.execute("UPDATE connection_handoffs SET expires_at = NOW() - INTERVAL '1 second' WHERE code = $1", &[&code]).await.unwrap();
        assert!(security
            .take_handoff(&code, &challenge)
            .await
            .unwrap()
            .is_none());

        let user = session::SessionUser::new(
            "tenant".into(),
            "fixture@example.com".into(),
            "Fixture".into(),
            None,
        );
        let jar = session::set_session(PrivateCookieJar::new(s.key.clone()), &user)
            .add(private_cookie(PROVIDER_COOKIE, context.binding.clone()));
        let envelope = security
            .seal(&serde_json::to_vec(&context).unwrap(), b"platform-oauth-v1")
            .unwrap();
        assert!(oauth_context(&security, &envelope, &jar, "tenant").is_some());
        assert!(oauth_context(&security, &envelope, &jar, "another-tenant").is_none());
        assert!(oauth_context(
            &security,
            &envelope,
            &PrivateCookieJar::new(s.key.clone()),
            "tenant"
        )
        .is_none());

        let code = handoff(&security, &context, "tenant", &credential)
            .await
            .unwrap();
        let revoked = Security::connect(
            &db,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            vec!["tenant".into()],
        )
        .await
        .unwrap();
        assert_eq!(
            redeem(
                State(state(Some(revoked))),
                Json(Redemption {
                    code,
                    code_verifier: verifier
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn router_preserves_legacy_numeric_query_parsing() {
        use tower::ServiceExt;
        let s = state(None);
        let ts = crate::proxy::now_unix();
        let nonce = random();
        let challenge = crate::tenant_secret::sign(&s.server_secret, &format!("{ts}.{nonce}"));
        let secret = crate::tenant_secret::derive(&s.server_secret, "tenant");
        let mut query = Url::parse("https://localthought.io/connect").unwrap();
        query
            .query_pairs_mut()
            .append_pair("redirect_uri", "https://hub.example/cb")
            .append_pair("ts", &ts.to_string())
            .append_pair("nonce", &nonce)
            .append_pair("challenge", &challenge)
            .append_pair("tenant_id", "tenant")
            .append_pair("user_id", "actor")
            .append_pair("user_id_sig", &crate::tenant_secret::sign(&secret, "actor"))
            .append_pair("response", &crate::tenant_secret::sign(&secret, &challenge));
        let response = crate::router(s)
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/connect?{}", query.query().unwrap()))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL and fixture OAuth configuration; CI runs it"]
    async fn postgres_consent_binds_google_identity_and_provider_callback_to_browser() {
        use tower::ServiceExt;
        let db = std::env::var("TEST_DATABASE_URL").unwrap();
        let security =
            Security::connect(&db, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", vec![])
                .await
                .unwrap();
        let s = state(Some(security.clone()));
        let user = session::SessionUser::new(
            "fixture-google-tenant".into(),
            "fixture@example.com".into(),
            "Fixture".into(),
            None,
        );
        let mut consent = Consent {
            request: request(),
            csrf: random(),
            expires: crate::proxy::now_unix() + 600,
        };
        let jar = session::set_session(PrivateCookieJar::new(s.key.clone()), &user).add(
            private_cookie(CONSENT_COOKIE, serde_json::to_string(&consent).unwrap()),
        );
        assert_eq!(
            authorize(
                State(s.clone()),
                jar.clone(),
                HeaderMap::new(),
                Form(Approval {
                    csrf: "wrong".into()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let mut foreign = HeaderMap::new();
        foreign.insert(header::ORIGIN, "https://foreign.example".parse().unwrap());
        assert_eq!(
            authorize(
                State(s.clone()),
                jar.clone(),
                foreign,
                Form(Approval {
                    csrf: consent.csrf.clone()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let mut opaque = HeaderMap::new();
        opaque.insert(header::ORIGIN, "null".parse().unwrap());
        assert_eq!(
            authorize(
                State(s.clone()),
                jar.clone(),
                opaque,
                Form(Approval {
                    csrf: consent.csrf.clone()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let response = authorize(
            State(s.clone()),
            jar.clone(),
            HeaderMap::new(),
            Form(Approval {
                csrf: consent.csrf.clone(),
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "configure fixture OAUTH_GITHUB_ISSUES_CLIENT_ID and CLIENT_SECRET"
        );
        let destination =
            Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(destination.host_str(), Some("auth.example"));
        let provider_state = destination
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        let stored = security
            .take_oauth_state(&provider_state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.tenant_id, user.subject);
        assert_eq!(stored.user_id, consent.request.user_id);
        assert_eq!(stored.provider, "github-issues");
        assert_eq!(stored.redirect_uri, consent.request.redirect_uri);
        assert!(security
            .take_oauth_state(&provider_state)
            .await
            .unwrap()
            .is_none());
        security
            .store_oauth_state(&provider_state, &stored)
            .await
            .unwrap();
        // Keep both the authenticated Google session and the newly set provider binding cookie.
        let original_cookies = jar
            .into_response()
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .collect::<Vec<_>>();
        let mut cookies = original_cookies;
        cookies.extend(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| {
                    let value = v.to_str().unwrap();
                    value
                        .starts_with("platform_oauth=")
                        .then(|| value.split(';').next().unwrap().to_string())
                }),
        );
        let response = crate::router(s.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!(
                        "/oauth/github-issues/callback?state={provider_state}&error=access_denied"
                    ))
                    .header(header::COOKIE, cookies.join("; "))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(target.origin().ascii_serialization(), "https://hub.example");
        assert!(target
            .query_pairs()
            .any(|(k, v)| k == "integration_state" && v == "state"));
        assert!(target
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied"));
        assert!(!target.query_pairs().any(|(k, _)| k == "connection_code"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(security
            .take_oauth_state(&provider_state)
            .await
            .unwrap()
            .is_none());
        // Approval cannot be replayed even if a browser retains its original consent cookie.
        let jar = session::set_session(PrivateCookieJar::new(s.key.clone()), &user).add(
            private_cookie(CONSENT_COOKIE, serde_json::to_string(&consent).unwrap()),
        );
        assert_eq!(
            authorize(
                State(s.clone()),
                jar,
                HeaderMap::new(),
                Form(Approval {
                    csrf: consent.csrf.clone()
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        consent.csrf = random();
        consent.expires = 0;
        let jar = session::set_session(PrivateCookieJar::new(s.key.clone()), &user).add(
            private_cookie(CONSENT_COOKIE, serde_json::to_string(&consent).unwrap()),
        );
        assert_eq!(
            authorize(
                State(s),
                jar,
                HeaderMap::new(),
                Form(Approval { csrf: consent.csrf })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
