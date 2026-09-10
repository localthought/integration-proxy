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
        let client_secret = if name == "spotify" {
            String::new()
        } else {
            env::var(format!("{prefix}_CLIENT_SECRET"))
                .map_err(|_| format!("{prefix}_CLIENT_SECRET must be set"))?
        };
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

impl ConfiguredProvider {
    /// Spotify uses the PKCE flow: client_id and verifier, without a secret.
    /// Keep the existing form authentication for the other providers.
    pub fn token_request(
        &self,
        client: &reqwest::Client,
        params: &[(&str, &str)],
    ) -> reqwest::RequestBuilder {
        let mut form = params.to_vec();
        form.push(("client_id", self.client_id.as_str()));
        if self.provider.name != "spotify" {
            form.push(("client_secret", self.client_secret.as_str()));
        }
        client
            .post(self.provider.token_url)
            .form(&form)
            .header("accept", "application/json")
    }
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
        "spotify" => Some(Provider {
            name: "spotify",
            authorization_url: "https://accounts.spotify.com/authorize",
            token_url: "https://accounts.spotify.com/api/token",
            scopes: &["playlist-read-private", "playlist-read-collaborative"],
        }),
        "moneybird" => Some(Provider {
            name: "moneybird",
            authorization_url: "https://moneybird.com/oauth/authorize",
            token_url: "https://moneybird.com/oauth/token",
            // Moneybird has no contacts-only scope; sales_invoices grants contacts access.
            scopes: &["sales_invoices"],
        }),
        "todoist" => Some(Provider {
            name: "todoist",
            authorization_url: "https://app.todoist.com/oauth/authorize",
            token_url: "https://api.todoist.com/oauth/access_token",
            scopes: &["data:read"],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn todoist_uses_read_only_scope_and_official_oauth_endpoints() {
        let provider = known("todoist").expect("Todoist must be supported");
        assert_eq!(
            provider.authorization_url,
            "https://app.todoist.com/oauth/authorize"
        );
        assert_eq!(
            provider.token_url,
            "https://api.todoist.com/oauth/access_token"
        );
        assert_eq!(provider.scopes, ["data:read"]);
        assert_eq!(
            Config::provider_env_prefix(provider.name).unwrap(),
            "OAUTH_TODOIST"
        );
    }

    #[test]
    fn spotify_pkce_exchange_and_refresh_do_not_send_client_secret() {
        let provider = ConfiguredProvider {
            provider: known("spotify").unwrap(),
            client_id: "test-client".into(),
            client_secret: "must-not-be-sent".into(),
        };
        assert_eq!(
            provider.provider.authorization_url,
            "https://accounts.spotify.com/authorize"
        );
        assert_eq!(
            provider.provider.scopes,
            ["playlist-read-private", "playlist-read-collaborative"]
        );
        assert_eq!(
            Config::provider_env_prefix("spotify").unwrap(),
            "OAUTH_SPOTIFY"
        );
        for params in [
            vec![
                ("grant_type", "authorization_code"),
                ("code", "test-code"),
                ("code_verifier", "test-verifier"),
            ],
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", "test-refresh"),
            ],
        ] {
            let request = provider
                .token_request(&reqwest::Client::new(), &params)
                .build()
                .unwrap();
            assert_eq!(
                request.url().as_str(),
                "https://accounts.spotify.com/api/token"
            );
            let body = request.body().unwrap().as_bytes().unwrap();
            let form: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(body).into_owned().collect();
            assert_eq!(form.get("client_id").unwrap(), "test-client");
            assert!(!form.contains_key("client_secret"));
            for (key, value) in params {
                assert_eq!(form.get(key).unwrap(), value);
            }
        }
    }

    #[test]
    fn existing_providers_keep_form_client_authentication() {
        let provider = ConfiguredProvider {
            provider: known("moneybird").unwrap(),
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
        };
        let request = provider
            .token_request(&reqwest::Client::new(), &[("grant_type", "refresh_token")])
            .build()
            .unwrap();
        let form: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap())
                .into_owned()
                .collect();
        assert_eq!(form.get("client_secret").unwrap(), "test-secret");
    }

    #[test]
    fn moneybird_uses_contacts_scope_and_official_oauth_endpoints() {
        let provider = known("moneybird").expect("Moneybird must be supported");
        assert_eq!(
            provider.authorization_url,
            "https://moneybird.com/oauth/authorize"
        );
        assert_eq!(provider.token_url, "https://moneybird.com/oauth/token");
        assert_eq!(provider.scopes, ["sales_invoices"]);
        assert_eq!(
            Config::provider_env_prefix(provider.name).unwrap(),
            "OAUTH_MONEYBIRD"
        );
    }

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
