use std::{collections::BTreeSet, env};
use serde_json::Value;
use crate::{catalog::Catalog, config::Config};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub authorization_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
}

impl Provider {
    /// Read API capabilities from the composed document, never from platform names.
    pub fn from_document(document: &Value) -> Result<Self, String> {
        let schemes = document.pointer("/components/securitySchemes")
            .and_then(Value::as_object).ok_or("missing security schemes")?;
        let candidates: Vec<_> = schemes.iter().filter_map(|(name, scheme)| {
            (scheme.get("type")?.as_str()? == "oauth2")
                .then(|| scheme.pointer("/flows/authorizationCode").map(|flow| (name, flow)))?
        }).collect();
        let [(scheme_name, flow)] = candidates.as_slice() else {
            return Err("exactly one OAuth authorization-code scheme is required".into());
        };
        let endpoint = |key: &str| -> Result<String, String> {
            let value = flow.get(key).and_then(Value::as_str).ok_or("missing OAuth endpoint")?;
            let url = url::Url::parse(value).map_err(|_| "invalid OAuth endpoint")?;
            if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty()
                || url.password().is_some() || url.fragment().is_some() {
                return Err("OAuth endpoints must be credential-free HTTPS URLs".into());
            }
            Ok(value.into())
        };
        let declared = flow.get("scopes").and_then(Value::as_object).ok_or("missing OAuth scopes")?;
        let mut scopes = BTreeSet::new();
        let mut add_requirements = |requirements: Option<&Value>| -> Result<(), String> {
            let Some(requirements) = requirements else { return Ok(()); };
            let requirements = requirements.as_array().ok_or("invalid security requirements")?;
            if requirements.is_empty() || requirements.iter().any(|r| r.as_object().is_some_and(|r| r.is_empty())) {
                return Ok(());
            }
            // Alternatives are OR; choose a supported single-scheme alternative.
            let requirement = requirements.iter().find(|r| r.as_object().is_some_and(|r|
                r.len() == 1 && r.contains_key(*scheme_name)))
                .ok_or("operation requires an unsupported authentication combination")?;
            for scope in requirement[*scheme_name].as_array().ok_or("invalid scope requirements")? {
                let scope = scope.as_str().ok_or("invalid OAuth scope")?;
                if !declared.contains_key(scope) { return Err("required OAuth scope is not declared".into()); }
                scopes.insert(scope.to_string());
            }
            Ok(())
        };
        if let Some(paths) = document.get("paths").and_then(Value::as_object) {
            for path in paths.values().filter_map(Value::as_object) {
                for method in ["get", "put", "post", "delete", "options", "head", "patch", "trace"] {
                    if let Some(operation) = path.get(method) {
                        add_requirements(operation.get("security").or_else(|| document.get("security")))?;
                    }
                }
            }
        }
        Ok(Self { authorization_url: endpoint("authorizationUrl")?, token_url: endpoint("tokenUrl")?, scopes: scopes.into_iter().collect() })
    }

    pub fn configured(catalog: &Catalog, name: &str) -> Result<ConfiguredProvider, String> {
        let provider = catalog.oauth_provider(name)?;
        let prefix = Config::provider_env_prefix(name)?;
        let client_id = env::var(format!("{prefix}_CLIENT_ID"))
            .map_err(|_| format!("{prefix}_CLIENT_ID must be set"))?;
        // Client registration chooses authentication; this is not an API capability.
        let method = env::var(format!("{prefix}_CLIENT_AUTH_METHOD")).unwrap_or_else(|_| "client_secret_post".into());
        let client_auth = ClientAuth::parse(&method)?;
        let client_secret = if client_auth == ClientAuth::None { String::new() } else {
            env::var(format!("{prefix}_CLIENT_SECRET"))
                .map_err(|_| format!("{prefix}_CLIENT_SECRET must be set"))?
        };
        Ok(ConfiguredProvider { provider, client_id, client_secret, client_auth })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAuth { None, SecretPost, SecretBasic }
impl ClientAuth {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::SecretPost),
            "client_secret_basic" => Ok(Self::SecretBasic),
            _ => Err("unsupported client authentication method".into()),
        }
    }
}
#[derive(Clone, Debug)]
pub struct ConfiguredProvider {
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: String,
    pub client_auth: ClientAuth,
}
impl ConfiguredProvider {
    pub fn token_request(&self, client: &reqwest::Client, params: &[(&str, &str)]) -> reqwest::RequestBuilder {
        let mut form = params.to_vec();
        let mut request = client.post(&self.provider.token_url);
        if self.client_auth == ClientAuth::SecretBasic {
            // RFC 6749 section 2.3.1 requires form encoding before HTTP Basic encoding.
            let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
            request = request.basic_auth(encode(&self.client_id), Some(encode(&self.client_secret)));
        } else {
            form.push(("client_id", &self.client_id));
            if self.client_auth == ClientAuth::SecretPost { form.push(("client_secret", &self.client_secret)); }
        }
        request.form(&form).header("accept", "application/json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> Value {
        serde_json::json!({"components":{"securitySchemes":{"auth":{"type":"oauth2","flows":{"authorizationCode":{
            "authorizationUrl":"https://auth.example/authorize","tokenUrl":"https://auth.example/token",
            "scopes":{"read":"Read","write":"Write","unused":"Optional"}}}}}},
            "security":[{"auth":["read"]}],"paths":{"/records":{"get":{},"post":{"security":[{"auth":["write"]}]}}}})
    }
    #[test]
    fn required_scopes_follow_operation_overrides_without_requesting_all_supported_scopes() {
        let mut doc = document();
        assert_eq!(Provider::from_document(&doc).unwrap().scopes, ["read", "write"]);
        doc["paths"]["/records"]["post"]["security"] = serde_json::json!([]);
        assert_eq!(Provider::from_document(&doc).unwrap().scopes, ["read"]);
        doc["paths"]["/records"]["get"]["security"] = serde_json::json!([{}]);
        assert!(Provider::from_document(&doc).unwrap().scopes.is_empty());
    }
    #[test]
    fn rejects_invalid_endpoints_ambiguous_schemes_and_unknown_scopes() {
        for endpoint in ["http://auth.example/token", "https://secret@auth.example/token", "https://auth.example/token#fragment"] {
            let mut doc = document(); doc["components"]["securitySchemes"]["auth"]["flows"]["authorizationCode"]["tokenUrl"] = endpoint.into();
            assert!(Provider::from_document(&doc).is_err());
        }
        let mut doc = document(); doc["security"] = serde_json::json!([{"auth":["undeclared"]}]);
        assert!(Provider::from_document(&doc).is_err());
        let mut doc = document(); doc["components"]["securitySchemes"]["second"] = doc["components"]["securitySchemes"]["auth"].clone();
        assert!(Provider::from_document(&doc).is_err());
    }
    #[test]
    fn client_registration_selects_token_authentication_for_exchange_and_refresh() {
        use base64::Engine;
        for client_auth in [ClientAuth::None, ClientAuth::SecretPost, ClientAuth::SecretBasic] {
            let provider = ConfiguredProvider { provider: Provider::from_document(&document()).unwrap(), client_id: "client:id".into(), client_secret:"secret+value".into(), client_auth:client_auth.clone() };
            for grant in ["authorization_code", "refresh_token"] {
                let request = provider.token_request(&reqwest::Client::new(), &[("grant_type",grant)]).build().unwrap();
                let form: std::collections::HashMap<_,_> = url::form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap()).into_owned().collect();
                assert_eq!(form.get("grant_type").unwrap(), grant);
                assert_eq!(form.contains_key("client_secret"), client_auth == ClientAuth::SecretPost);
                assert_eq!(form.contains_key("client_id"), client_auth != ClientAuth::SecretBasic);
                if client_auth == ClientAuth::SecretBasic {
                    let header = request.headers()["authorization"].to_str().unwrap();
                    assert_eq!(base64::engine::general_purpose::STANDARD.decode(header.strip_prefix("Basic ").unwrap()).unwrap(), b"client%3Aid:secret%2Bvalue");
                } else { assert!(!request.headers().contains_key("authorization")); }
            }
        }
        assert!(ClientAuth::parse("unknown").is_err());
    }
}
