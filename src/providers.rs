use std::env;

use crate::config::Config;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub name: &'static str,
    pub authorization_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static [&'static str],
}

impl Provider {
    pub fn configured(name: &str) -> Result<ConfiguredProvider, String> {
        let provider = known(name).ok_or_else(|| "unsupported OAuth provider".to_string())?;
        let prefix = Config::provider_env_prefix(name)?;
        let client_id = env::var(format!("{prefix}_CLIENT_ID"))
            .map_err(|_| format!("{prefix}_CLIENT_ID must be set"))?;
        let client_secret = env::var(format!("{prefix}_CLIENT_SECRET"))
            .map_err(|_| format!("{prefix}_CLIENT_SECRET must be set"))?;
        Ok(ConfiguredProvider {
            provider,
            client_id,
            client_secret,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ConfiguredProvider {
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: String,
}

pub fn known(name: &str) -> Option<Provider> {
    match name {
        "google-calendar" => Some(Provider {
            name: "google-calendar",
            authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            scopes: &[
                "https://www.googleapis.com/auth/calendar.events",
                "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
            ],
        }),
        "github-issues" => Some(Provider {
            name: "github-issues",
            authorization_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            scopes: &["repo"],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn providers_are_server_owned_and_narrowly_scoped() {
        let google = known("google-calendar").unwrap();
        assert_eq!(
            google.authorization_url,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            google.scopes,
            [
                "https://www.googleapis.com/auth/calendar.events",
                "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
            ]
        );
        assert!(known("https://attacker.example").is_none());
    }
}
