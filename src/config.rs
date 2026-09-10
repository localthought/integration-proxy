use std::env;

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

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let app_auth_client_id = env::var("APP_AUTH_CLIENT_ID")
            .map_err(|_| "APP_AUTH_CLIENT_ID must be set".to_string())?;
        let app_auth_client_secret = env::var("APP_AUTH_CLIENT_SECRET")
            .map_err(|_| "APP_AUTH_CLIENT_SECRET must be set".to_string())?;
        let app_auth_authorization_url = env::var("APP_AUTH_AUTHORIZATION_URL")
            .map_err(|_| "APP_AUTH_AUTHORIZATION_URL must be set".to_string())?;
        let app_auth_token_url = env::var("APP_AUTH_TOKEN_URL")
            .map_err(|_| "APP_AUTH_TOKEN_URL must be set".to_string())?;
        let app_auth_userinfo_url = env::var("APP_AUTH_USERINFO_URL")
            .map_err(|_| "APP_AUTH_USERINFO_URL must be set".to_string())?;
        let app_auth_label = env::var("APP_AUTH_LABEL").unwrap_or_else(|_| "OIDC".to_string());
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let session_secret = env::var("SESSION_SECRET").ok();
        let server_secret =
            env::var("SERVER_SECRET").map_err(|_| "SERVER_SECRET must be set".to_string())?;
        let catalog_path = env::var("CATALOG_PATH").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/localthought/overlays/d83c3ce0afd9f8ca0e4c42e142fa89d5fa9d8f70/catalog.json".to_string()
        });
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL must be set for replay protection".to_string())?;
        let encryption_key =
            env::var("ENCRYPTION_KEY").map_err(|_| "ENCRYPTION_KEY must be set".to_string())?;
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
}
