use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::PrivateCookieJar;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

use crate::{
    config::Config,
    session::{self, OAuthState, SessionUser},
    AppState,
};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

pub fn build_client(config: &Config) -> Result<BasicClient, String> {
    let auth_url = AuthUrl::new(GOOGLE_AUTH_URL.to_string()).map_err(|e| e.to_string())?;
    let token_url = TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).map_err(|e| e.to_string())?;
    let redirect_url = RedirectUrl::new(config.redirect_url()).map_err(|e| e.to_string())?;

    Ok(BasicClient::new(
        ClientId::new(config.google_client_id.clone()),
        Some(ClientSecret::new(config.google_client_secret.clone())),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url))
}

/// Redirects the browser to Google's consent screen, stashing the CSRF token
/// and PKCE verifier in a short-lived encrypted cookie (no server memory).
pub async fn login(State(state): State<AppState>, jar: PrivateCookieJar) -> impl IntoResponse {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let jar = session::set_oauth_state(
        jar,
        &OAuthState {
            csrf_token: csrf_token.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        },
    );

    (jar, Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

/// Exchanges the authorization code for tokens, fetches the user's profile,
/// and sets the session cookie. No user data is ever persisted server-side.
pub async fn callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(params): Query<CallbackParams>,
) -> Result<impl IntoResponse, AuthError> {
    let oauth_state = session::read_oauth_state(&jar).ok_or(AuthError::InvalidState)?;
    let jar = session::clear_oauth_state(jar);

    if oauth_state.csrf_token != params.state {
        return Err(AuthError::InvalidState);
    }

    let token = state
        .oauth_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(PkceCodeVerifier::new(oauth_state.pkce_verifier))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|_| AuthError::TokenExchangeFailed)?;

    let userinfo: GoogleUserInfo = state
        .http_client
        .get(GOOGLE_USERINFO_URL)
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|_| AuthError::UserInfoFailed)?
        .error_for_status()
        .map_err(|_| AuthError::UserInfoFailed)?
        .json()
        .await
        .map_err(|_| AuthError::UserInfoFailed)?;

    let user = SessionUser::new(
        userinfo.sub,
        userinfo.email.clone(),
        userinfo.name.unwrap_or(userinfo.email),
        userinfo.picture,
    );
    let jar = session::set_session(jar, &user);

    // If login was triggered by a `/connect` request, send the user back
    // there instead of the home page so they can finish the handshake.
    if let Some(redirect_uri) = session::read_connect_redirect(&jar) {
        let jar = session::clear_connect_redirect(jar);
        let target = crate::proxy::connect_url(&redirect_uri);
        return Ok((jar, Redirect::to(&target)));
    }

    Ok((jar, Redirect::to("/")))
}

/// Clears the session cookie, logging the user out. Stateless by design:
/// there is nothing to invalidate anywhere else.
pub async fn logout(jar: PrivateCookieJar) -> impl IntoResponse {
    let jar = session::clear_session(jar);
    (jar, Redirect::to("/"))
}

#[derive(Debug)]
pub enum AuthError {
    InvalidState,
    TokenExchangeFailed,
    UserInfoFailed,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidState => (
                StatusCode::BAD_REQUEST,
                "Login session expired or invalid, please try again.",
            ),
            AuthError::TokenExchangeFailed => (
                StatusCode::BAD_GATEWAY,
                "Could not complete login with Google.",
            ),
            AuthError::UserInfoFailed => (
                StatusCode::BAD_GATEWAY,
                "Could not fetch your Google profile.",
            ),
        };
        (status, message).into_response()
    }
}
