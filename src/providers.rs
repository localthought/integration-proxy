use crate::{catalog::Catalog, config::Config};
use serde_json::Value;
use std::{collections::BTreeSet, env};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub authorization_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub authorization_params: Vec<(String, String)>,
    pub use_pkce: bool,
    supported_client_auth: Option<BTreeSet<String>>,
}

impl Provider {
    /// Read API capabilities from the composed document, never from platform names.
    pub fn from_document(document: &Value, selected_scheme: Option<&str>) -> Result<Self, String> {
        let schemes = document
            .pointer("/components/securitySchemes")
            .and_then(Value::as_object)
            .ok_or("missing security schemes")?;
        let candidates: Vec<_> = schemes
            .iter()
            .filter_map(|(name, scheme)| {
                (scheme.get("type")?.as_str()? == "oauth2").then(|| {
                    scheme
                        .pointer("/flows/authorizationCode")
                        .map(|flow| (name, flow))
                })?
            })
            .collect();
        let (scheme_name, flow) = match selected_scheme {
            Some(selected) => candidates
                .iter()
                .find(|(name, _)| name.as_str() == selected)
                .copied()
                .ok_or("selected OAuth security scheme is not an authorization-code scheme")?,
            None => match candidates.as_slice() {
                [candidate] => *candidate,
                _ => return Err(
                    "oauthSecurityScheme selection is required when multiple authorization-code schemes exist"
                        .into(),
                ),
            },
        };
        let scheme = &schemes[scheme_name];
        let endpoint = |key: &str| -> Result<String, String> {
            let value = flow
                .get(key)
                .and_then(Value::as_str)
                .ok_or("missing OAuth endpoint")?;
            let url = url::Url::parse(value).map_err(|_| "invalid OAuth endpoint")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err("OAuth endpoints must be credential-free HTTPS URLs".into());
            }
            Ok(value.into())
        };
        let declared = flow
            .get("scopes")
            .and_then(Value::as_object)
            .ok_or("missing OAuth scopes")?;
        let mut scopes = BTreeSet::new();
        let mut add_requirements = |requirements: Option<&Value>| -> Result<(), String> {
            let Some(requirements) = requirements else {
                return Ok(());
            };
            let requirements = requirements
                .as_array()
                .ok_or("invalid security requirements")?;
            if requirements.is_empty()
                || requirements
                    .iter()
                    .any(|r| r.as_object().is_some_and(|r| r.is_empty()))
            {
                return Ok(());
            }
            // Alternatives are OR; choose a supported single-scheme alternative.
            let requirement = requirements
                .iter()
                .find(|r| {
                    r.as_object()
                        .is_some_and(|r| r.len() == 1 && r.contains_key(scheme_name))
                })
                .ok_or("operation requires an unsupported authentication combination")?;
            for scope in requirement[scheme_name]
                .as_array()
                .ok_or("invalid scope requirements")?
            {
                let scope = scope.as_str().ok_or("invalid OAuth scope")?;
                if !declared.contains_key(scope) {
                    return Err("required OAuth scope is not declared".into());
                }
                scopes.insert(scope.to_string());
            }
            Ok(())
        };
        if let Some(paths) = document.get("paths").and_then(Value::as_object) {
            for path in paths.values().filter_map(Value::as_object) {
                for method in [
                    "get", "put", "post", "delete", "options", "head", "patch", "trace",
                ] {
                    if let Some(operation) = path.get(method) {
                        add_requirements(
                            operation
                                .get("security")
                                .or_else(|| document.get("security")),
                        )?;
                    }
                }
            }
        }
        Ok(Self {
            authorization_url: endpoint("authorizationUrl")?,
            token_url: endpoint("tokenUrl")?,
            scopes: scopes.into_iter().collect(),
            authorization_params: authorization_params(document, scheme)?,
            use_pkce: pkce_behavior(scheme)?,
            supported_client_auth: supported_client_auth(scheme)?,
        })
    }

    pub fn configured(catalog: &Catalog, name: &str) -> Result<ConfiguredProvider, String> {
        let provider = catalog.oauth_provider(name)?;
        let prefix = Config::provider_env_prefix(name)?;
        let client_id = env::var(format!("{prefix}_CLIENT_ID"))
            .map_err(|_| format!("{prefix}_CLIENT_ID must be set"))?;
        // Client registration chooses authentication; this is not an API capability.
        let method = env::var(format!("{prefix}_CLIENT_AUTH_METHOD"))
            .unwrap_or_else(|_| "client_secret_post".into());
        let client_auth = ClientAuth::parse(&method)?;
        if provider
            .supported_client_auth
            .as_ref()
            .is_some_and(|supported| !supported.contains(client_auth.registered_name()))
        {
            return Err("configured client authentication method is not supported by the authorization server".into());
        }
        let client_secret = if client_auth == ClientAuth::None {
            String::new()
        } else {
            env::var(format!("{prefix}_CLIENT_SECRET"))
                .map_err(|_| format!("{prefix}_CLIENT_SECRET must be set"))?
        };
        Ok(ConfiguredProvider {
            provider,
            client_id,
            client_secret,
            client_auth,
        })
    }
}

const RESERVED_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "client_id",
    "client_secret",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "code",
    "code_challenge",
    "code_challenge_method",
    "code_verifier",
];

fn authentication_details(scheme: &Value) -> Option<&Value> {
    scheme.get("x-oauth-authentication-details")
}

fn supported_client_auth(scheme: &Value) -> Result<Option<BTreeSet<String>>, String> {
    let Some(value) = authentication_details(scheme).and_then(|details| {
        details.pointer("/authorizationServerMetadata/token_endpoint_auth_methods_supported")
    }) else {
        return Ok(None);
    };
    let methods = value
        .as_array()
        .ok_or("invalid token endpoint authentication methods")?;
    if methods.is_empty() {
        return Err("token endpoint authentication methods must not be empty".into());
    }
    methods
        .iter()
        .map(|method| {
            method
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid token endpoint authentication method".into())
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map(Some)
}

fn pkce_behavior(scheme: &Value) -> Result<bool, String> {
    let Some(details) = authentication_details(scheme) else {
        // Preserve the proxy's established secure behavior when metadata is absent.
        return Ok(true);
    };
    let requirement = details
        .pointer("/authorizationCode/pkce/requirement")
        .and_then(Value::as_str);
    if requirement == Some("unsupported") {
        return Ok(false);
    }
    if !matches!(
        requirement,
        None | Some("required" | "optional" | "conditional")
    ) {
        return Err("invalid PKCE requirement".into());
    }
    let methods = details
        .pointer("/authorizationServerMetadata/code_challenge_methods_supported")
        .and_then(Value::as_array);
    if requirement.is_some()
        && !methods.is_some_and(|methods| methods.iter().any(|method| method == "S256"))
    {
        return Err(
            "S256 is required by the proxy but is not supported by the authorization server".into(),
        );
    }
    Ok(true)
}

fn authorization_params(document: &Value, scheme: &Value) -> Result<Vec<(String, String)>, String> {
    let Some(parameters) = authentication_details(scheme)
        .and_then(|details| details.pointer("/authorizationCode/profile/parameters"))
    else {
        return Ok(Vec::new());
    };
    let parameters = parameters
        .as_array()
        .ok_or("invalid authorization parameters")?;
    let mut output = Vec::new();
    let mut names = BTreeSet::new();
    for entry in parameters {
        let parameter = entry
            .get("parameter")
            .ok_or("missing authorization parameter")?;
        let parameter = resolve_parameter(document, parameter)?;
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .ok_or("authorization parameter has no name")?;
        if parameter.get("in").and_then(Value::as_str) != Some("query")
            || RESERVED_AUTHORIZATION_PARAMETERS.contains(&name)
            || !names.insert(name.to_owned())
        {
            return Err("invalid or duplicate authorization query parameter".into());
        }
        let value = entry
            .get("value")
            .ok_or("authorization parameter has no value")?;
        validate_schema(value, parameter.get("schema"))?;
        serialize_parameter(name, value, parameter, &mut output)?;
    }
    Ok(output)
}

fn resolve_parameter<'a>(document: &'a Value, parameter: &'a Value) -> Result<&'a Value, String> {
    let Some(reference) = parameter.get("$ref").and_then(Value::as_str) else {
        return Ok(parameter);
    };
    let pointer = reference
        .strip_prefix('#')
        .ok_or("authorization parameter references must be local")?;
    document
        .pointer(pointer)
        .ok_or_else(|| "authorization parameter reference does not resolve".into())
}

fn validate_schema(value: &Value, schema: Option<&Value>) -> Result<(), String> {
    let Some(schema) = schema else {
        return Err("authorization parameter schema is required".into());
    };
    let valid_type = match schema.get("type").and_then(Value::as_str) {
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.as_i64().is_some() || value.as_u64().is_some(),
        Some("number") => value.is_number(),
        Some("array") => value.is_array(),
        Some("object") => value.is_object(),
        _ => false,
    };
    if !valid_type
        || schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
    {
        return Err("authorization parameter value does not match its schema".into());
    }
    Ok(())
}

fn scalar(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err("authorization parameter contains a non-scalar value".into()),
    }
}

fn serialize_parameter(
    name: &str,
    value: &Value,
    parameter: &Value,
    output: &mut Vec<(String, String)>,
) -> Result<(), String> {
    let style = parameter
        .get("style")
        .and_then(Value::as_str)
        .unwrap_or("form");
    let explode = parameter
        .get("explode")
        .and_then(Value::as_bool)
        .unwrap_or(style == "form");
    match value {
        Value::Array(values) => {
            let values = values.iter().map(scalar).collect::<Result<Vec<_>, _>>()?;
            if style == "form" && explode {
                output.extend(values.into_iter().map(|value| (name.to_owned(), value)));
            } else {
                let delimiter = match style {
                    "form" => ",",
                    "spaceDelimited" => " ",
                    "pipeDelimited" => "|",
                    _ => return Err("unsupported authorization parameter serialization".into()),
                };
                output.push((name.to_owned(), values.join(delimiter)));
            }
        }
        Value::Object(values) => {
            if style == "deepObject" {
                for (key, value) in values {
                    output.push((format!("{name}[{key}]"), scalar(value)?));
                }
            } else if style == "form" && explode {
                for (key, value) in values {
                    if RESERVED_AUTHORIZATION_PARAMETERS.contains(&key.as_str()) {
                        return Err(
                            "authorization object parameter expands to a reserved name".into()
                        );
                    }
                    output.push((key.clone(), scalar(value)?));
                }
            } else if style == "form" {
                let mut flattened = Vec::new();
                for (key, value) in values {
                    flattened.push(key.clone());
                    flattened.push(scalar(value)?);
                }
                output.push((name.to_owned(), flattened.join(",")));
            } else {
                return Err("unsupported authorization parameter serialization".into());
            }
        }
        _ if style == "form" => output.push((name.to_owned(), scalar(value)?)),
        _ => return Err("unsupported authorization parameter serialization".into()),
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    None,
    SecretPost,
    SecretBasic,
}
impl ClientAuth {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::SecretPost),
            "client_secret_basic" => Ok(Self::SecretBasic),
            _ => Err("unsupported client authentication method".into()),
        }
    }
    fn registered_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SecretPost => "client_secret_post",
            Self::SecretBasic => "client_secret_basic",
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
    pub fn token_request(
        &self,
        client: &reqwest::Client,
        params: &[(&str, &str)],
    ) -> reqwest::RequestBuilder {
        let mut form = params.to_vec();
        let mut request = client.post(&self.provider.token_url);
        if self.client_auth == ClientAuth::SecretBasic {
            // RFC 6749 section 2.3.1 requires form encoding before HTTP Basic encoding.
            let encode = |value: &str| {
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            };
            request =
                request.basic_auth(encode(&self.client_id), Some(encode(&self.client_secret)));
        } else {
            form.push(("client_id", &self.client_id));
            if self.client_auth == ClientAuth::SecretPost {
                form.push(("client_secret", &self.client_secret));
            }
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
        assert_eq!(
            Provider::from_document(&doc, None).unwrap().scopes,
            ["read", "write"]
        );
        doc["paths"]["/records"]["post"]["security"] = serde_json::json!([]);
        assert_eq!(
            Provider::from_document(&doc, None).unwrap().scopes,
            ["read"]
        );
        doc["paths"]["/records"]["get"]["security"] = serde_json::json!([{}]);
        assert!(Provider::from_document(&doc, None)
            .unwrap()
            .scopes
            .is_empty());
    }
    #[test]
    fn rejects_invalid_endpoints_ambiguous_schemes_and_unknown_scopes() {
        for endpoint in [
            "http://auth.example/token",
            "https://secret@auth.example/token",
            "https://auth.example/token#fragment",
        ] {
            let mut doc = document();
            doc["components"]["securitySchemes"]["auth"]["flows"]["authorizationCode"]
                ["tokenUrl"] = endpoint.into();
            assert!(Provider::from_document(&doc, None).is_err());
        }
        let mut doc = document();
        doc["security"] = serde_json::json!([{"auth":["undeclared"]}]);
        assert!(Provider::from_document(&doc, None).is_err());
        let mut doc = document();
        doc["components"]["securitySchemes"]["second"] =
            doc["components"]["securitySchemes"]["auth"].clone();
        assert!(Provider::from_document(&doc, None).is_err());
    }
    #[test]
    fn trusted_scheme_selection_applies_fixed_parameters_and_pkce_capability() {
        let mut doc = document();
        doc["components"]["parameters"] = serde_json::json!({
            "accessType": {
                "name": "access_type", "in": "query",
                "schema": {"type": "string", "enum": ["online", "offline"]}
            },
            "audience": {
                "name": "audience", "in": "query", "style": "form", "explode": true,
                "schema": {"type": "array", "items": {"type": "string"}}
            }
        });
        let mut offline = doc["components"]["securitySchemes"]["auth"].clone();
        offline["x-oauth-authentication-details"] = serde_json::json!({
            "authorizationServerMetadata": {
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
            },
            "authorizationCode": {
                "pkce": {"requirement": "unsupported"},
                "profile": {"parameters": [
                    {"parameter": {"$ref": "#/components/parameters/accessType"}, "value": "offline"},
                    {"parameter": {"$ref": "#/components/parameters/audience"}, "value": ["one", "two"]}
                ]}
            }
        });
        doc["components"]["securitySchemes"]["offline"] = offline;
        doc["security"] = serde_json::json!([{"offline":["read"]}]);
        doc["paths"]["/records"]["post"]["security"] = serde_json::json!([{"offline":["write"]}]);
        let provider = Provider::from_document(&doc, Some("offline")).unwrap();
        assert_eq!(
            provider.authorization_params,
            [
                ("access_type".into(), "offline".into()),
                ("audience".into(), "one".into()),
                ("audience".into(), "two".into())
            ]
        );
        assert!(!provider.use_pkce);
        assert_eq!(
            provider.supported_client_auth.unwrap(),
            BTreeSet::from(["client_secret_post".into()])
        );
        assert!(Provider::from_document(&doc, None).is_err());
        assert!(Provider::from_document(&doc, Some("missing")).is_err());
    }
    #[test]
    fn rejects_reserved_fixed_parameters_and_incompatible_pkce_metadata() {
        let mut doc = document();
        doc["components"]["securitySchemes"]["auth"]["x-oauth-authentication-details"] = serde_json::json!({
            "authorizationCode": {
                "profile": {"parameters": [{
                    "parameter": {"name": "code_verifier", "in": "query", "schema": {"type": "string"}},
                    "value": "fixed"
                }]}
            }
        });
        assert!(Provider::from_document(&doc, None).is_err());

        doc["components"]["securitySchemes"]["auth"]["x-oauth-authentication-details"] = serde_json::json!({
            "authorizationServerMetadata": {"code_challenge_methods_supported": ["plain"]},
            "authorizationCode": {"pkce": {"requirement": "required"}}
        });
        assert!(Provider::from_document(&doc, None).is_err());
    }
    #[test]
    fn client_registration_selects_token_authentication_for_exchange_and_refresh() {
        use base64::Engine;
        for client_auth in [
            ClientAuth::None,
            ClientAuth::SecretPost,
            ClientAuth::SecretBasic,
        ] {
            let provider = ConfiguredProvider {
                provider: Provider::from_document(&document(), None).unwrap(),
                client_id: "client:id".into(),
                client_secret: "secret+value".into(),
                client_auth: client_auth.clone(),
            };
            for grant in ["authorization_code", "refresh_token"] {
                let request = provider
                    .token_request(&reqwest::Client::new(), &[("grant_type", grant)])
                    .build()
                    .unwrap();
                let form: std::collections::HashMap<_, _> =
                    url::form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap())
                        .into_owned()
                        .collect();
                assert_eq!(form.get("grant_type").unwrap(), grant);
                assert_eq!(
                    form.contains_key("client_secret"),
                    client_auth == ClientAuth::SecretPost
                );
                assert_eq!(
                    form.contains_key("client_id"),
                    client_auth != ClientAuth::SecretBasic
                );
                if client_auth == ClientAuth::SecretBasic {
                    let header = request.headers()["authorization"].to_str().unwrap();
                    assert_eq!(
                        base64::engine::general_purpose::STANDARD
                            .decode(header.strip_prefix("Basic ").unwrap())
                            .unwrap(),
                        b"client%3Aid:secret%2Bvalue"
                    );
                } else {
                    assert!(!request.headers().contains_key("authorization"));
                }
            }
        }
        assert!(ClientAuth::parse("unknown").is_err());
    }
}
