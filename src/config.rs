use std::env;
use url::Url;

fn identity_namespace(value: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let url = Url::parse(&value)
        .map_err(|_| "APP_AUTH_IDENTITY_NAMESPACE must be an HTTPS URI".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value.contains('{')
    {
        return Err("APP_AUTH_IDENTITY_NAMESPACE must be a fixed credential-free HTTPS URI".into());
    }
    Ok(Some(value))
}

/// Runtime configuration, loaded entirely from environment variables so the
/// server itself stays stateless and container-friendly.
#[derive(Clone)]
pub struct Config {
    pub app_auth_client_id: String,
    pub app_auth_client_secret: String,
    pub app_auth_authorization_url: String,
    pub app_auth_token_url: String,
    pub app_auth_userinfo_url: String,
    pub app_auth_label: String,
    /// Optional namespace which makes a legacy APP_AUTH OIDC subject compatible
    /// with an explicitly trusted provider-scoped catalog identity.
    pub app_auth_identity_namespace: Option<String>,
    /// Public URL the server is reachable at, used to build the OAuth
    /// redirect URL (e.g. `https://auth.example.com`).
    pub base_url: String,
    pub port: u16,
    /// 64-byte secret used to sign/encrypt session cookies. If unset, a
    /// random key is generated at startup: sessions stay valid for the life
    /// of the process but are invalidated on restart.
    pub session_secret: Option<String>,
    /// Secret used to deterministically derive each tenant's secret (see
    /// `tenant_secret`). Must stay constant across restarts and instances,
    /// or previously issued tenant secrets stop verifying.
    pub server_secret: String,
    /// Local file or immutable HTTPS URL listing the pinned OADs and overlays.
    pub catalog_path: String,
    /// PostgreSQL connection used for one-time challenge consumption.
    pub database_url: String,
    /// Base64url-encoded 32-byte key for OAuth credential envelopes.
    pub encryption_key: String,
    /// Comma-separated tenant or user identifiers denied access.
    pub revoked_subjects: Vec<String>,
}

/// Immutable pinned revision of `localthought/overlays`' `catalog.json` used
/// when `CATALOG_PATH` is not set. Shared with tests that need to validate
/// the exact catalog the application would load by default.
pub const DEFAULT_CATALOG_PATH: &str = "https://raw.githubusercontent.com/localthought/overlays/ecf53a4c73dfe79c5b9948709c5a048e3c05ea13/catalog.json";

/// Reads a required environment variable and rejects it if unset or blank,
/// so a blank `.env` value fails configuration explicitly instead of being
/// silently accepted (e.g. as a reproducible empty secret).
fn require_env(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(format!("{name} must be set")),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let app_auth_client_id = require_env("APP_AUTH_CLIENT_ID")?;
        let app_auth_client_secret = require_env("APP_AUTH_CLIENT_SECRET")?;
        let app_auth_authorization_url = require_env("APP_AUTH_AUTHORIZATION_URL")?;
        let app_auth_token_url = require_env("APP_AUTH_TOKEN_URL")?;
        let app_auth_userinfo_url = require_env("APP_AUTH_USERINFO_URL")?;
        let app_auth_label = env::var("APP_AUTH_LABEL").unwrap_or_else(|_| "OIDC".to_string());
        let app_auth_identity_namespace =
            identity_namespace(env::var("APP_AUTH_IDENTITY_NAMESPACE").ok())?;
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        // An empty SESSION_SECRET is treated as unset, so it triggers random
        // key generation instead of being hashed into a reproducible,
        // guessable cookie-encryption key.
        let session_secret = env::var("SESSION_SECRET")
            .ok()
            .filter(|value| !value.is_empty());
        let server_secret = require_env("SERVER_SECRET")?;
        let catalog_path =
            env::var("CATALOG_PATH").unwrap_or_else(|_| DEFAULT_CATALOG_PATH.to_string());
        let database_url = require_env("DATABASE_URL")
            .map_err(|_| "DATABASE_URL must be set for replay protection".to_string())?;
        let encryption_key = require_env("ENCRYPTION_KEY")?;
        let revoked_subjects = env::var("REVOKED_SUBJECTS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        Ok(Self {
            app_auth_client_id,
            app_auth_client_secret,
            app_auth_authorization_url,
            app_auth_token_url,
            app_auth_userinfo_url,
            app_auth_label,
            app_auth_identity_namespace,
            base_url,
            port,
            session_secret,
            server_secret,
            catalog_path,
            database_url,
            encryption_key,
            revoked_subjects,
        })
    }

    pub fn redirect_url(&self) -> String {
        format!("{}/auth/callback", self.base_url.trim_end_matches('/'))
    }

    /// OAuth callback and credential variable names are deterministic from the
    /// catalog platform name, e.g. `google-calendar` becomes
    /// `OAUTH_GOOGLE_CALENDAR_CLIENT_ID` and `/oauth/google-calendar/callback`.
    #[allow(dead_code)] // used by provider OAuth routes as they are enabled
    pub fn provider_redirect_url(&self, provider: &str) -> String {
        format!(
            "{}/oauth/{provider}/callback",
            self.base_url.trim_end_matches('/')
        )
    }

    #[allow(dead_code)] // used by provider OAuth routes as they are enabled
    pub fn provider_env_prefix(provider: &str) -> Result<String, String> {
        if provider.is_empty()
            || !provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(
                "provider names may contain only lowercase letters, digits, and hyphens"
                    .to_string(),
            );
        }
        Ok(format!(
            "OAUTH_{}",
            provider.replace('-', "_").to_ascii_uppercase()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_produce_predictable_environment_prefixes() {
        assert_eq!(
            Config::provider_env_prefix("google-calendar").unwrap(),
            "OAUTH_GOOGLE_CALENDAR"
        );
        assert!(Config::provider_env_prefix("Google Calendar").is_err());
    }

    #[test]
    fn require_env_rejects_missing_and_blank_values() {
        let name = "INTEGRATION_PROXY_TEST_REQUIRE_ENV_VAR";
        env::remove_var(name);
        assert!(require_env(name).is_err());
        env::set_var(name, "");
        assert!(require_env(name).is_err());
        env::set_var(name, "a-value");
        assert_eq!(require_env(name).unwrap(), "a-value");
        env::remove_var(name);
    }

    #[test]
    fn legacy_identity_namespace_is_blank_or_fixed_https_only() {
        assert_eq!(identity_namespace(Some("  ".into())).unwrap(), None);
        assert_eq!(
            identity_namespace(Some("https://accounts.example".into())).unwrap(),
            Some("https://accounts.example".into())
        );
        for invalid in [
            "http://accounts.example",
            "https://u@accounts.example",
            "https://accounts.example?x=1",
            "https://accounts.example#x",
            "https://accounts.example/{tenant}",
        ] {
            assert!(identity_namespace(Some(invalid.into())).is_err());
        }
    }
}
