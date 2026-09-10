use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use time::Duration;

pub const SESSION_COOKIE: &str = "session";
pub const OAUTH_STATE_COOKIE: &str = "oauth_state";
pub const CONNECT_REDIRECT_COOKIE: &str = "connect_redirect";
const SESSION_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7; // 7 days

/// Everything the server knows about a logged-in user. This is the entire
/// session: it lives only inside the encrypted cookie, never on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    /// Google's stable, unique identifier for the account (the OIDC `sub`
    /// claim). Used as the identity for the tenant secret, since unlike
    /// email it never changes or gets reused.
    pub google_sub: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub expires_at: u64,
}

impl SessionUser {
    pub fn new(google_sub: String, email: String, name: String, picture: Option<String>) -> Self {
        let expires_at = now() + SESSION_LIFETIME_SECS;
        Self {
            google_sub,
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

/// Stashes the complete relative `/connect?...` request in a short-lived
/// private cookie, preserving platform and PKCE context through Google login.
/// Older cookies containing only an external return URI remain readable.
pub fn set_connect_redirect(jar: PrivateCookieJar, redirect_uri: &str) -> PrivateCookieJar {
    let cookie = Cookie::build((CONNECT_REDIRECT_COOKIE, redirect_uri.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .max_age(Duration::minutes(10))
        .build();
    jar.add(cookie)
}

pub fn read_connect_redirect(jar: &PrivateCookieJar) -> Option<String> {
    jar.get(CONNECT_REDIRECT_COOKIE)
        .map(|cookie| cookie.value().to_string())
}

pub fn clear_connect_redirect(jar: PrivateCookieJar) -> PrivateCookieJar {
    jar.remove(Cookie::build(CONNECT_REDIRECT_COOKIE).path("/").build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::Key;

    fn test_user() -> SessionUser {
        SessionUser::new(
            "google-sub-123".to_string(),
            "user@example.com".to_string(),
            "Test User".to_string(),
            None,
        )
    }

    #[test]
    fn set_then_read_session_round_trips() {
        let jar = PrivateCookieJar::new(Key::generate());
        let jar = set_session(jar, &test_user());

        let user = read_session(&jar).expect("session should be present");
        assert_eq!(user.google_sub, "google-sub-123");
        assert_eq!(user.email, "user@example.com");
    }

    #[test]
    fn read_session_is_none_when_no_cookie_set() {
        let jar = PrivateCookieJar::new(Key::generate());
        assert!(read_session(&jar).is_none());
    }

    #[test]
    fn clear_session_removes_the_cookie() {
        let jar = PrivateCookieJar::new(Key::generate());
        let jar = set_session(jar, &test_user());
        let jar = clear_session(jar);

        assert!(read_session(&jar).is_none());
    }

    #[test]
    fn expired_session_is_not_read_back() {
        let mut user = test_user();
        user.expires_at = 0; // already expired

        let jar = PrivateCookieJar::new(Key::generate());
        let jar = set_session(jar, &user);

        assert!(read_session(&jar).is_none());
    }

    #[test]
    fn oauth_state_round_trips_and_clears() {
        let jar = PrivateCookieJar::new(Key::generate());
        let state = OAuthState {
            csrf_token: "csrf".to_string(),
            pkce_verifier: "verifier".to_string(),
        };
        let jar = set_oauth_state(jar, &state);

        let read_back = read_oauth_state(&jar).expect("oauth state should be present");
        assert_eq!(read_back.csrf_token, "csrf");
        assert_eq!(read_back.pkce_verifier, "verifier");

        let jar = clear_oauth_state(jar);
        assert!(read_oauth_state(&jar).is_none());
    }

    #[test]
    fn connect_redirect_round_trips_and_clears() {
        let jar = PrivateCookieJar::new(Key::generate());
        let jar = set_connect_redirect(jar, "https://example.com/callback");

        assert_eq!(
            read_connect_redirect(&jar),
            Some("https://example.com/callback".to_string())
        );

        let jar = clear_connect_redirect(jar);
        assert!(read_connect_redirect(&jar).is_none());
    }

    #[test]
    fn connect_redirect_is_none_when_not_set() {
        let jar = PrivateCookieJar::new(Key::generate());
        assert!(read_connect_redirect(&jar).is_none());
    }
}
