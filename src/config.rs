use std::env;

/// Runtime configuration, loaded entirely from environment variables so the
/// server itself stays stateless and container-friendly.
#[derive(Clone)]
pub struct Config {
    pub google_client_id: String,
    pub google_client_secret: String,
    /// Public URL the server is reachable at, used to build the OAuth
    /// redirect URL (e.g. `https://auth.example.com`).
    pub base_url: String,
    pub port: u16,
    /// 64-byte secret used to sign/encrypt session cookies. If unset, a
    /// random key is generated at startup: sessions stay valid for the life
    /// of the process but are invalidated on restart.
    pub session_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let google_client_id =
            env::var("GOOGLE_CLIENT_ID").map_err(|_| "GOOGLE_CLIENT_ID must be set".to_string())?;
        let google_client_secret = env::var("GOOGLE_CLIENT_SECRET")
            .map_err(|_| "GOOGLE_CLIENT_SECRET must be set".to_string())?;
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let session_secret = env::var("SESSION_SECRET").ok();

        Ok(Self {
            google_client_id,
            google_client_secret,
            base_url,
            port,
            session_secret,
        })
    }

    pub fn redirect_url(&self) -> String {
        format!("{}/auth/callback", self.base_url.trim_end_matches('/'))
    }
}
