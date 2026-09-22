use serde_json::json;

use crate::catalog::Catalog;

fn catalog(platform: &str, source: &str, selection: serde_json::Value) -> Catalog {
    Catalog::from_test_document(platform, serde_yaml::from_str(source).unwrap(), selection)
}

#[test]
fn composed_google_identity_keeps_data_scopes_and_legacy_subject() {
    let catalog = catalog(
        "google-calendar",
        include_str!("../tests/identity-catalog/google-calendar-composed.yaml"),
        json!({
        "oauthSecurityScheme": "googleOffline",
            "tenantIdentity": {"operationId": "getGoogleAuthenticatedPrincipal", "namespace": "https://accounts.google.com"}
        }),
    );
    let identity = catalog.tenant_identity("google-calendar").unwrap();
    assert_eq!(
        identity.url.as_str(),
        "https://openidconnect.googleapis.com/v1/userinfo"
    );
    assert_eq!(identity.subject, "/sub");
    let provider = catalog.oauth_provider("google-calendar").unwrap();
    assert_eq!(
        provider.scopes,
        vec![
            "email",
            "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
            "https://www.googleapis.com/auth/calendar.events",
            "openid",
            "profile"
        ]
    );
    let principal =
        crate::identity::resolve(&identity, &json!({"sub": "google-sub"}), "client").unwrap();
    assert_eq!(
        principal.legacy_subject_if_matches(Some("https://accounts.google.com")),
        Ok(Some("google-sub".into()))
    );
}

#[test]
fn composed_github_identity_uses_numeric_subject_without_google_legacy_mapping() {
    let catalog = catalog(
        "github-issues",
        include_str!("../tests/identity-catalog/github-issues-composed.yaml"),
        json!({
            "oauthSecurityScheme": "githubOAuth",
            "tenantIdentity": {"operationId": "getGitHubAuthenticatedPrincipal", "namespace": "https://github.com"}
        }),
    );
    let identity = catalog.tenant_identity("github-issues").unwrap();
    assert_eq!(identity.url.as_str(), "https://api.github.com/user");
    let provider = catalog.oauth_provider("github-issues").unwrap();
    assert_eq!(provider.scopes, vec!["repo"]);
    let principal = crate::identity::resolve(&identity, &json!({"id": 42}), "client").unwrap();
    assert_eq!(principal.subject, "42");
    assert_eq!(
        principal.legacy_subject_if_matches(Some("https://accounts.google.com")),
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "downloads the published catalog revision and its pinned OAD sources"]
async fn published_catalog_loads_trusted_google_and_github_identity_operations() {
    let catalog = Catalog::load(
        "https://raw.githubusercontent.com/localthought/overlays/ecf53a4c73dfe79c5b9948709c5a048e3c05ea13/catalog.json",
        &crate::build_http_client(),
    )
    .await
    .expect("published pinned catalog must load through the runtime loader");

    let google = catalog.tenant_identity("google-calendar").unwrap();
    assert_eq!(
        google.url.as_str(),
        "https://openidconnect.googleapis.com/v1/userinfo"
    );
    assert_eq!(google.namespace, "https://accounts.google.com");
    assert_eq!(
        catalog
            .identity_oauth_provider("google-calendar")
            .unwrap()
            .scopes,
        vec!["openid", "email", "profile"]
    );

    let github = catalog.tenant_identity("github-issues").unwrap();
    assert_eq!(github.url.as_str(), "https://api.github.com/user");
    assert_eq!(github.namespace, "https://github.com");
    assert!(catalog
        .identity_oauth_provider("github-issues")
        .unwrap()
        .scopes
        .is_empty());
}
