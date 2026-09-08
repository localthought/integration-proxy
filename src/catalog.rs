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
        let paths = document.get("paths")?.as_object()?;
        let template = paths.keys().find(|template| path_matches(template, path))?;
        if !paths
            .get(template)?
            .get(method.to_ascii_lowercase())?
            .is_object()
        {
            return None;
        }
        url::Url::parse(server).ok()
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
            .all(|(a, b)| (a.starts_with('{') && a.ends_with('}')) || *a == b)
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
