use std::{collections::BTreeMap, fs};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;

#[derive(Clone, Default)]
pub struct Catalog {
    documents: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct CatalogConfig {
    platforms: Vec<PlatformConfig>,
}

#[derive(Deserialize)]
struct PlatformConfig {
    name: String,
    openapi: String,
    #[serde(default)]
    overlays: Vec<String>,
}

#[derive(Deserialize)]
struct Overlay {
    actions: Vec<Action>,
}

#[derive(Deserialize)]
struct Action {
    target: String,
    update: Value,
}

impl Catalog {
    pub async fn load(path: &str, client: &reqwest::Client) -> Result<Self, String> {
        let config: CatalogConfig = serde_yaml::from_str(
            &fs::read_to_string(path).map_err(|err| format!("cannot read {path}: {err}"))?,
        )
        .map_err(|err| format!("cannot parse {path}: {err}"))?;
        let mut documents = BTreeMap::new();

        for platform in config.platforms {
            valid_platform_name(&platform.name)?;
            let base = fetch_yaml(client, &platform.openapi).await?;
            let mut document: Value = serde_yaml::from_str(&base)
                .map_err(|err| format!("cannot parse OAD for {}: {err}", platform.name))?;
            for overlay_url in platform.overlays {
                let overlay: Overlay = serde_yaml::from_str(
                    &fetch_yaml(client, &overlay_url).await?,
                )
                .map_err(|err| format!("cannot parse overlay for {}: {err}", platform.name))?;
                for action in overlay.actions {
                    merge_at_target(&mut document, &action.target, action.update)?;
                }
            }
            documents.insert(
                platform.name,
                serde_yaml::to_string(&document).map_err(|err| err.to_string())?,
            );
        }
        Ok(Self { documents })
    }

    pub fn names(&self) -> Vec<String> {
        self.documents.keys().cloned().collect()
    }
    pub fn allows(&self, platform: &str, method: &str, path: &str) -> Option<url::Url> {
        let document: Value = serde_yaml::from_str(self.documents.get(platform)?).ok()?;
        let server = document
            .get("servers")?
            .as_array()?
            .first()?
            .get("url")?
            .as_str()?;
        let server_url = url::Url::parse(server).ok()?;
        // OpenAPI paths are relative to the server URL, which can include an API prefix.
        let base_path = server_url.path().trim_end_matches('/');
        let relative_path = path.strip_prefix(base_path)?;
        if !relative_path.starts_with('/') {
            return None;
        }
        let paths = document.get("paths")?.as_object()?;
        let template = paths
            .keys()
            .find(|template| path_matches(template, relative_path))?;
        if !paths
            .get(template)?
            .get(method.to_ascii_lowercase())?
            .is_object()
        {
            return None;
        }
        Some(server_url)
    }
    fn get(&self, platform: &str) -> Option<&str> {
        self.documents.get(platform).map(String::as_str)
    }
}

fn path_matches(template: &str, path: &str) -> bool {
    let left: Vec<_> = template.trim_matches('/').split('/').collect();
    let right: Vec<_> = path.trim_matches('/').split('/').collect();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(template, path)| path_segment_matches(template, path))
}

fn path_segment_matches(template: &str, path: &str) -> bool {
    let Some(open) = template.find('{') else {
        return template == path;
    };
    let Some(close) = template[open + 1..].find('}') else {
        return false;
    };
    let close = open + 1 + close;
    // Keep the grammar deliberately small: one nonempty variable surrounded by
    // literal text. This avoids treating arbitrary braces as a regex.
    if template[close + 1..].contains(['{', '}'])
        || template[..open].contains('}')
        || template[open + 1..close].contains('{')
        || template[open + 1..close].is_empty()
    {
        return false;
    }
    let prefix = &template[..open];
    let suffix = &template[close + 1..];
    path.starts_with(prefix)
        && path.ends_with(suffix)
        && path.len() >= prefix.len() + suffix.len()
        && !path[prefix.len()..path.len() - suffix.len()].is_empty()
}

async fn fetch_yaml(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let url = url::Url::parse(url).map_err(|err| format!("invalid catalog URL: {err}"))?;
    if url.scheme() != "https" {
        return Err("catalog sources must use HTTPS".to_string());
    }
    client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .text()
        .await
        .map_err(|err| err.to_string())
}

fn valid_platform_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(())
    } else {
        Err(format!("invalid platform name {name:?}"))
    }
}

fn merge_at_target(document: &mut Value, target: &str, update: Value) -> Result<(), String> {
    let keys = parse_target(target)?;
    let mut current = document;
    for key in keys {
        current = current
            .get_mut(&key)
            .ok_or_else(|| format!("overlay target {target:?} does not exist"))?;
    }
    merge(current, update);
    Ok(())
}

fn parse_target(target: &str) -> Result<Vec<String>, String> {
    let mut rest = target
        .strip_prefix('$')
        .ok_or_else(|| format!("unsupported overlay target {target:?}"))?;
    let mut keys = Vec::new();
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('.') {
            let end = after.find(['.', '[']).unwrap_or(after.len());
            if end == 0 {
                return Err(format!("unsupported overlay target {target:?}"));
            }
            keys.push(after[..end].to_string());
            rest = &after[end..];
        } else if let Some(after) = rest.strip_prefix("['") {
            let end = after
                .find("']")
                .ok_or_else(|| format!("unsupported overlay target {target:?}"))?;
            keys.push(after[..end].to_string());
            rest = &after[end + 2..];
        } else {
            return Err(format!("unsupported overlay target {target:?}"));
        }
    }
    Ok(keys)
}

fn merge(destination: &mut Value, update: Value) {
    match (destination, update) {
        (Value::Object(destination), Value::Object(update)) => {
            for (key, value) in update {
                merge(destination.entry(key).or_insert(Value::Null), value);
            }
        }
        (destination, update) => *destination = update,
    }
}

pub async fn list(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.catalog.names())
}

pub async fn document(Path(file): Path<String>, State(state): State<AppState>) -> Response {
    let Some(platform) = file.strip_suffix(".yaml") else {
        return (StatusCode::NOT_FOUND, "catalog platform not found").into_response();
    };
    match state.catalog.get(platform) {
        Some(document) => (
            [("content-type", "application/yaml; charset=utf-8")],
            document.to_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "catalog platform not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "downloads the pinned production catalog sources"]
    async fn pinned_discord_catalog_composes_and_allows_only_user_reads() {
        let catalog = Catalog::load("catalog.yaml", &crate::build_http_client())
            .await
            .unwrap();
        let document: Value = serde_yaml::from_str(catalog.get("discord").unwrap()).unwrap();
        assert!(document
            .pointer("/components/crudResources/guild")
            .is_some());
        for path in ["/api/v10/users/@me", "/api/v10/users/@me/guilds"] {
            assert_eq!(
                catalog.allows("discord", "GET", path).unwrap().as_str(),
                "https://discord.com/api/v10"
            );
            assert!(catalog.allows("discord", "POST", path).is_none());
        }
        assert!(catalog
            .allows("discord", "GET", "/api/v10/channels/123/messages")
            .is_none());
        assert!(catalog
            .allows("discord", "GET", "/users/@me/guilds")
            .is_none());
    }

    #[test]
    fn discord_only_allows_profile_and_membership_reads_with_api_prefix() {
        let catalog = Catalog { documents: BTreeMap::from([("discord".into(),
            "servers:\n  - url: https://discord.com/api/v10\npaths:\n  /users/@me:\n    get: {}\n  /users/@me/guilds:\n    get: {}\n".into())]) };
        for path in ["/api/v10/users/@me", "/api/v10/users/@me/guilds"] {
            assert_eq!(
                catalog.allows("discord", "GET", path).unwrap().as_str(),
                "https://discord.com/api/v10"
            );
            assert!(catalog.allows("discord", "POST", path).is_none());
            assert!(catalog.allows("discord", "DELETE", path).is_none());
        }
        for path in [
            "/users/@me",
            "/api/v100/users/@me",
            "/api/v10/users/123",
            "/api/v10/channels/123/messages",
        ] {
            assert!(catalog.allows("discord", "GET", path).is_none());
        }
    }

    #[test]
    fn matches_moneybird_parameterized_contact_paths() {
        let template = "/{administration_id}/contacts/{id}.json";
        assert!(path_matches(template, "/123/contacts/456.json"));
        assert!(!path_matches(template, "/123/contacts/.json"));
        assert!(!path_matches(template, "/123/contacts/456.xml"));
        assert!(!path_matches(template, "/123/invoices/456.json"));
    }

    #[test]
    fn rejects_malformed_or_ambiguous_path_variables() {
        assert!(!path_matches("/{id", "/123"));
        assert!(!path_matches("/{{id}", "/123"));
        assert!(!path_matches("/{id}/{other}{third}", "/123/456789"));
        assert!(!path_matches("/{id}/contacts", "//contacts"));
    }

    #[tokio::test]
    #[ignore = "downloads the pinned production catalog sources"]
    async fn pinned_moneybird_catalog_composes_and_allows_contacts() {
        let catalog = Catalog::load("catalog.yaml", &crate::build_http_client())
            .await
            .unwrap();
        assert!(catalog.names().contains(&"moneybird".to_string()));
        let document: Value = serde_yaml::from_str(catalog.get("moneybird").unwrap()).unwrap();
        assert!(document
            .pointer("/components/crudResources/contact/collections/contacts")
            .is_some());
        let schema_ref = document
            .pointer("/components/crudResources/contact/schema/$ref")
            .and_then(Value::as_str)
            .expect("contacts must declare their schema");
        let schema = document
            .pointer(schema_ref.strip_prefix('#').unwrap())
            .expect("contacts schema reference must resolve");
        assert!(schema.pointer("/properties/company_name").is_some());
        let upstream = catalog
            .allows("moneybird", "GET", "/api/v2/123/contacts.json")
            .expect("Moneybird contacts path must include the server base path");
        assert_eq!(upstream.as_str(), "https://moneybird.com/api/v2");
        assert!(catalog
            .allows("moneybird", "GET", "/api/v2/123/contacts/456.json")
            .is_some());
        assert!(catalog
            .allows("moneybird", "POST", "/api/v2/123/contacts.json")
            .is_none());
        assert!(catalog
            .allows("moneybird", "GET", "/123/contacts.json")
            .is_none());
        assert!(catalog
            .allows("moneybird", "GET", "/api/v20/123/contacts.json")
            .is_none());
    }
    #[test]
    fn validates_google_endpoints_relative_to_server_base_path() {
        for server in [
            "https://www.googleapis.com/calendar/v3",
            "https://www.googleapis.com/calendar/v3/",
        ] {
            let catalog = Catalog { documents: BTreeMap::from([("google-calendar".into(), format!("servers:\n  - url: {server}\npaths:\n  /users/me/calendarList:\n    get: {{}}\n  /calendars/{{calendarId}}/events:\n    get: {{}}\n"))]) };
            assert!(catalog
                .allows(
                    "google-calendar",
                    "GET",
                    "/calendar/v3/users/me/calendarList"
                )
                .is_some());
            assert!(catalog
                .allows(
                    "google-calendar",
                    "GET",
                    "/calendar/v3/calendars/a%40example.com/events"
                )
                .is_some());
            assert!(catalog
                .allows("google-calendar", "GET", "/users/me/calendarList")
                .is_none());
            assert!(catalog
                .allows(
                    "google-calendar",
                    "GET",
                    "/calendar/v30/users/me/calendarList"
                )
                .is_none());
            assert!(catalog
                .allows(
                    "google-calendar",
                    "POST",
                    "/calendar/v3/users/me/calendarList"
                )
                .is_none());
        }
    }

    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn test_router() -> axum::Router {
        let config: CatalogConfig = serde_yaml::from_str(include_str!("../catalog.yaml")).unwrap();
        let documents = config
            .platforms
            .into_iter()
            .map(|platform| {
                (
                    platform.name,
                    "openapi: 3.0.0\ninfo: {title: Test, version: '1'}\npaths: {}\n".to_string(),
                )
            })
            .collect();
        crate::router(AppState {
            oauth_client: oauth2::basic::BasicClient::new(
                oauth2::ClientId::new("test".into()),
                None,
                oauth2::AuthUrl::new("https://example.com/auth".into()).unwrap(),
                None,
            ),
            http_client: crate::build_http_client(),
            key: axum_extra::extract::cookie::Key::generate(),
            server_secret: "test".into(),
            base_url: "http://localhost".into(),
            catalog: Catalog { documents },
            security: None,
        })
    }

    #[tokio::test]
    async fn router_serves_every_advertised_catalog_document() {
        let app = test_router();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let names: Vec<String> =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(!names.is_empty());
        for name in names {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/catalog/{name}.yaml"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            let document: Value =
                serde_yaml::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(document["openapi"], "3.0.0");
            assert!(document["paths"].is_object());
        }
        for path in ["/catalog/unknown.yaml", "/catalog/github-issues.json"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn router_reaches_parameterized_oauth_handlers() {
        let app = test_router();
        for provider in ["github-issues", "google-calendar", "moneybird", "discord"] {
            for (action, query) in [
                ("start", "redirect_uri=https%3A%2F%2Fexample.com&ts=0&nonce=test&challenge=test&tenant_id=test&user_id=test&user_id_sig=test&response=test"),
                ("callback", "code=test&state=test"),
            ] {
                let response = app.clone().oneshot(Request::builder().uri(format!("/oauth/{provider}/{action}?{query}")).body(Body::empty()).unwrap()).await.unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{provider}/{action}");
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert_eq!(&body[..], b"OAuth request could not be completed");
            }
        }
    }

    #[test]
    fn target_parser_supports_overlay_paths() {
        assert_eq!(
            parse_target("$.paths['/things/{id}'].get").unwrap(),
            ["paths", "/things/{id}", "get"]
        );
    }
    #[test]
    fn merge_preserves_existing_document_fields() {
        let mut document = serde_json::json!({"components": {"schemas": {"old": true}}});
        merge_at_target(
            &mut document,
            "$.components",
            serde_json::json!({"securitySchemes": {"token": {"type": "http"}}}),
        )
        .unwrap();
        assert_eq!(document["components"]["schemas"]["old"], true);
        assert_eq!(
            document["components"]["securitySchemes"]["token"]["type"],
            "http"
        );
    }
}
