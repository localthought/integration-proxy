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
    /// Secret used to deterministically derive each user's per-identity
    /// user secret (see `user_secret`). Must stay constant across restarts
    /// and instances, or previously issued user secrets stop verifying.
    pub server_secret: String,
    /// File listing the pinned OADs and overlays to expose under `/catalog`.
    pub catalog_path: String,
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
        let server_secret =
            env::var("SERVER_SECRET").map_err(|_| "SERVER_SECRET must be set".to_string())?;
        let catalog_path = env::var("CATALOG_PATH").unwrap_or_else(|_| "catalog.yaml".to_string());

        Ok(Self {
            google_client_id,
            google_client_secret,
            base_url,
            port,
            session_secret,
            server_secret,
            catalog_path,
        })
    }

    pub fn redirect_url(&self) -> String {
        format!("{}/auth/callback", self.base_url.trim_end_matches('/'))
    }
}
