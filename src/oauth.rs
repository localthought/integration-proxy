use crate::{
    providers::Provider,
    proxy::{self, ConnectParams},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Deserialize)]
pub struct Start {
    redirect_uri: String,
    ts: u64,
    nonce: String,
    challenge: String,
    tenant_id: String,
    user_id: String,
    user_id_sig: String,
    response: String,
}
#[derive(Deserialize)]
pub struct Callback {
    code: String,
    state: String,
}
#[derive(Deserialize)]
struct Token {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}
#[derive(Serialize)]
struct Credential {
    provider: String,
    tenant_id: String,
    user_id: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
}

fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "OAuth request could not be completed",
    )
        .into_response()
}

pub async fn start(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Query(request): Query<Start>,
) -> Response {
    let proof = ConnectParams {
        redirect_uri: request.redirect_uri.clone(),
        ts: request.ts,
        nonce: request.nonce.clone(),
        challenge: request.challenge,
        tenant_id: request.tenant_id.clone(),
        user_id: request.user_id.clone(),
        user_id_sig: request.user_id_sig,
        response: request.response,
    };
    if proxy::verify_connect(&state, &proof).await.is_err() {
        return error();
    }
    let Ok(provider) = Provider::configured(&name) else {
        return error();
    };
    let Some(security) = &state.security else {
        return error();
    };
    if security.is_revoked(&request.tenant_id, &request.user_id) {
        return (StatusCode::FORBIDDEN, "tenant or user is revoked").into_response();
    }
    let oauth_state = random();
    let verifier = random();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let callback = format!(
        "{}/oauth/{}/callback",
        state.base_url.trim_end_matches('/'),
        name
    );
    if security
        .store_oauth_state(
            &oauth_state,
            &name,
            &request.redirect_uri,
            &request.tenant_id,
            &request.user_id,
            &verifier,
        )
        .await
        .is_err()
    {
        return error();
    }
    let mut url = match Url::parse(provider.provider.authorization_url) {
        Ok(url) => url,
        Err(_) => return error(),
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &provider.client_id)
            .append_pair("redirect_uri", &callback)
            .append_pair("scope", &provider.provider.scopes.join(" "))
            .append_pair("state", &oauth_state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
    }
    Redirect::to(url.as_str()).into_response()
}

pub async fn callback(
    Path(name): Path<String>,
    State(state): State<AppState>,
    Query(query): Query<Callback>,
) -> Response {
    let Ok(provider) = Provider::configured(&name) else {
        return error();
    };
    let Some(security) = &state.security else {
        return error();
    };
    let Ok(Some((stored, redirect_uri, tenant_id, user_id, verifier))) =
        security.take_oauth_state(&query.state).await
    else {
        return error();
    };
    if stored != name || security.is_revoked(&tenant_id, &user_id) {
        return error();
    }
    let callback = format!(
        "{}/oauth/{}/callback",
        state.base_url.trim_end_matches('/'),
        name
    );
    let response = match state
        .http_client
        .post(provider.provider.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("redirect_uri", callback.as_str()),
            ("client_id", provider.client_id.as_str()),
            ("client_secret", provider.client_secret.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return error(),
    };
    let Ok(response) = response.error_for_status() else {
        return error();
    };
    let Ok(token) = response.json::<Token>().await else {
        return error();
    };
    let credential = Credential {
        provider: name.clone(),
        tenant_id: tenant_id.clone(),
        user_id: user_id.clone(),
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: token
            .expires_in
            .map(|seconds| crate::proxy::now_unix() + seconds),
    };
    let aad = "connection-credential-v1";
    let Ok(envelope) = security.seal(&serde_json::to_vec(&credential).unwrap(), aad.as_bytes())
    else {
        return error();
    };
    let code = random();
    if security
        .store_connection_code(&code, &envelope)
        .await
        .is_err()
    {
        return error();
    }
    let Ok(mut redirect) = Url::parse(&redirect_uri) else {
        return error();
    };
    redirect
        .query_pairs_mut()
        .append_pair("connection_code", &code);
    Redirect::to(redirect.as_str()).into_response()
}
