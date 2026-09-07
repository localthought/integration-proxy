use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use time::Duration;

pub const SESSION_COOKIE: &str = "session";
pub const OAUTH_STATE_COOKIE: &str = "oauth_state";
const SESSION_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7; // 7 days

/// Everything the server knows about a logged-in user. This is the entire
/// session: it lives only inside the encrypted cookie, never on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub expires_at: u64,
}

impl SessionUser {
    pub fn new(email: String, name: String, picture: Option<String>) -> Self {
        let expires_at = now() + SESSION_LIFETIME_SECS;
        Self {
            email,
            name,
            picture,
            expires_at,
        }
    }

    fn is_expired(&self) -> bool {
        now() > self.expires_at
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs()
}

/// Reads and validates the session user from the private cookie jar, if any.
pub fn read_session(jar: &PrivateCookieJar) -> Option<SessionUser> {
    let cookie = jar.get(SESSION_COOKIE)?;
    let user: SessionUser = serde_json::from_str(cookie.value()).ok()?;
    if user.is_expired() {
        None
    } else {
        Some(user)
    }
}

/// Sets the session cookie for a freshly authenticated user.
pub fn set_session(jar: PrivateCookieJar, user: &SessionUser) -> PrivateCookieJar {
    let value = serde_json::to_string(user).expect("SessionUser always serializes");
    let cookie = Cookie::build((SESSION_COOKIE, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .build();
    jar.add(cookie)
}

/// Removes the session cookie, logging the user out.
pub fn clear_session(jar: PrivateCookieJar) -> PrivateCookieJar {
    jar.remove(Cookie::build(SESSION_COOKIE).path("/").build())
}

/// Stores the CSRF token + PKCE verifier for the in-flight OAuth handshake in
/// a short-lived private cookie, so the callback can validate them without
/// any server-side storage.
pub fn set_oauth_state(jar: PrivateCookieJar, state: &OAuthState) -> PrivateCookieJar {
    let value = serde_json::to_string(state).expect("OAuthState always serializes");
    let cookie = Cookie::build((OAUTH_STATE_COOKIE, value))
        .path("/auth")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(Duration::minutes(10))
        .build();
    jar.add(cookie)
}

pub fn read_oauth_state(jar: &PrivateCookieJar) -> Option<OAuthState> {
    let cookie = jar.get(OAUTH_STATE_COOKIE)?;
    serde_json::from_str(cookie.value()).ok()
}

pub fn clear_oauth_state(jar: PrivateCookieJar) -> PrivateCookieJar {
    jar.remove(Cookie::build(OAUTH_STATE_COOKIE).path("/auth").build())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub csrf_token: String,
    pub pkce_verifier: String,
}
