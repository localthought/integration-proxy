use crate::session::SessionUser;

/// Minimal, dependency-free HTML rendering. The GUI is intentionally tiny:
/// a login button when signed out, and the user's identity plus a logout
/// button when signed in.
pub fn render_home(user: Option<&SessionUser>, _tenant_secret: Option<&str>) -> String {
    if user.is_none() {
        return include_str!("../static/index.html").to_string();
    }
    let body = match user {
        Some(user) => signed_in_body(user),
        None => signed_out_body(),
    };

    page(&body)
}

/// Renders the browser connection consent screen for one selected platform.
pub fn render_platform_connect(
    user: Option<&SessionUser>,
    platform: &str,
    target_origin: &str,
    csrf: &str,
    include_tenant_secret: bool,
) -> String {
    let body = match user {
        None => format!(
            r#"
            <div class="card">
              <h1>Connect {platform}</h1>
              <p>Sign in with Google to continue.</p>
              <a class="button" href="/auth/login">Log in with Google</a>
            </div>
            "#,
            platform = escape(&platform_label(platform)),
        ),
        Some(user) => {
            let tenant_consent = if include_tenant_secret {
                "<p class=\"secret-help\">This also gives this hub your LocalThought account credential, allowing it to authorize future connections on your behalf.</p>"
            } else {
                ""
            };
            format!(
                r#"
                <div class="card">
                  <h1>Connect {platform}</h1>
                  <p>You are logged in with Google as <span class="email">{email}</span></p>
                  <p>Target Atomic Data Hub: <span class="email">{target_origin}</span></p>
                  {tenant_consent}
                  <form method="post" action="/connect/authorize">
                    <input type="hidden" name="csrf" value="{csrf}" />
                    <button class="button" type="submit">Use LocalThought to sync {platform} with your Atomic Data Hub</button>
                  </form>
                </div>
                "#,
                platform = escape(&platform_label(platform)),
                email = escape(&user.email),
                target_origin = escape(target_origin),
                csrf = escape(csrf),
                tenant_consent = tenant_consent,
            )
        }
    };
    page(&body)
}

/// Renders the "connect this app" consent screen shown at `/connect` to a
/// signed-in user, before they approve sharing their tenant secret.
pub fn render_connect(params: &crate::proxy::ConnectParams, platforms: &[String]) -> String {
    let buttons = platforms
        .iter()
        .map(|platform| {
            format!(
                r#"<a class="button" href="{}">Connect {}</a>"#,
                crate::proxy::oauth_start_url(platform, params),
                escape(platform)
            )
        })
        .collect::<String>();
    let body = format!(
        r#"
        <div class="card">
          <h1>Connect this app?</h1>
          <p>You'll be redirected back to:</p>
          <p class="email">{redirect_uri}</p>
          <form method="post" action="/connect">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
            <input type="hidden" name="ts" value="{ts}" />
            <input type="hidden" name="nonce" value="{nonce}" />
            <input type="hidden" name="challenge" value="{challenge}" />
            <input type="hidden" name="tenant_id" value="{tenant_id}" />
            <input type="hidden" name="user_id" value="{user_id}" />
            <input type="hidden" name="user_id_sig" value="{user_id_sig}" />
            <input type="hidden" name="response" value="{response}" />
            <button class="button" type="submit">OK</button>
          </form>
          <p>Connect a service:</p>{buttons}
        </div>
        "#,
        redirect_uri = escape(&params.redirect_uri),
        ts = params.ts,
        nonce = escape(&params.nonce),
        challenge = escape(&params.challenge),
        tenant_id = escape(&params.tenant_id),
        user_id = escape(&params.user_id),
        user_id_sig = escape(&params.user_id_sig),
        response = escape(&params.response),
        buttons = buttons,
    );

    page(&body)
}

fn signed_out_body() -> String {
    r#"
    <div class="card">
      <h1>auth-proxy</h1>
      <p>Sign in with your Google account to continue.</p>
      <a class="button" href="/auth/login">Log in with Google</a>
    </div>
    "#
    .to_string()
}

fn signed_in_body(user: &SessionUser) -> String {
    let avatar = user
        .picture
        .as_deref()
        .map(|src| format!(r#"<img class="avatar" src="{}" alt="" />"#, escape(src)))
        .unwrap_or_default();

    format!(
        r#"
        <div class="card">
          {avatar}
          <h1>You are logged in with Google as {email}</h1>
        </div>
        "#,
        avatar = avatar,
        email = escape(&user.email),
    )
}

fn platform_label(platform: &str) -> String {
    match platform {
        "github-issues" => "GitHub".to_string(),
        "google-calendar" => "Google Calendar".to_string(),
        other => other
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn page(body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LocalThought · Integrations</title>
  <link rel="icon" type="image/png" href="/logo.png" />
  <style>
    :root {{ color-scheme: light dark; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      margin: 0;
      background: #f5f5f7;
    }}
    .card {{
      background: white;
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
      padding: 2.5rem;
      text-align: center;
      max-width: 24rem;
    }}
    .avatar {{
      width: 4rem;
      height: 4rem;
      border-radius: 50%;
      margin-bottom: 1rem;
    }}
    .email {{ color: #666; margin-top: -0.5rem; }}
    .secret-help {{ color: #666; font-size: 0.85rem; }}
    .button {{
      display: inline-block;
      margin-top: 1rem;
      padding: 0.6rem 1.4rem;
      background: #1a73e8;
      color: white;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
      border: none;
      cursor: pointer;
      font-size: 1rem;
    }}
    .button-secondary {{ background: #5f6368; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #202124; }}
      .card {{ background: #303134; color: #e8eaed; }}
      .email {{ color: #9aa0a6; }}
      .secret-help {{ color: #9aa0a6; }}
    }}
  </style>
</head>
<body>
  <main>
    <a href="/" aria-label="LocalThought home" style="display:block;text-align:center;margin-bottom:1rem"><img src="/logo.png" alt="LocalThought" width="80" height="80" style="border-radius:8px" /></a>
    {body}
  </main>
</body>
</html>"#,
        body = body
    )
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> SessionUser {
        SessionUser::new(
            "google-sub-123".to_string(),
            "user@example.com".to_string(),
            "<script>alert(1)</script>".to_string(),
            None,
        )
    }

    #[test]
    fn signed_out_shows_login_link() {
        let html = render_home(None, None);
        assert!(html.contains("Log in with Google"));
        assert!(html.contains(r#"href="/auth/login""#));
    }

    #[test]
    fn signed_in_shows_google_identity_without_secrets() {
        let html = render_home(Some(&test_user()), Some("the-secret"));
        assert!(!html.contains("the-secret"));
        assert!(!html.contains("tenant secret"));
        assert!(html.contains("You are logged in with Google as"));
    }

    #[test]
    fn signed_in_escapes_untrusted_fields() {
        let mut user = test_user();
        user.email = "<script>alert(1)</script>".to_string();
        let html = render_home(Some(&user), Some("<b>not-html</b>"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<b>not-html</b>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn render_home_allows_missing_secret_while_signed_in() {
        render_home(Some(&test_user()), None);
    }

    #[test]
    fn platform_connect_shows_one_selected_platform_and_escapes_fields() {
        let html = render_platform_connect(
            Some(&test_user()),
            "google-calendar",
            "https://hub.example/\"><script>alert(1)</script>",
            "csrf&<\"",
            true,
        );
        assert!(html.contains("Google Calendar"));
        assert!(html.contains("Use LocalThought to sync Google Calendar with your Atomic Data Hub"));
        assert_eq!(html.matches(r#"action="/connect/authorize""#).count(), 1);
        assert!(html.contains("name=\"csrf\" value=\"csrf&amp;&lt;&quot;\""));
        assert!(!html.contains("<script>"));
        assert!(html.contains("account credential"));
        assert!(!html.contains("the-secret"));
    }

    #[test]
    fn connect_shows_the_redirect_target_and_a_confirm_form() {
        let html = render_connect(
            &crate::proxy::ConnectParams {
                redirect_uri: "https://example.com/callback".into(),
                ts: 1,
                nonce: "n".into(),
                challenge: "c".into(),
                tenant_id: "t".into(),
                user_id: "u".into(),
                user_id_sig: "s".into(),
                response: "r".into(),
            },
            &["google-calendar".into()],
        );
        assert!(html.contains("https://example.com/callback"));
        assert!(html.contains(r#"action="/connect""#));
        assert!(html.contains(r#"method="post""#));
    }

    #[test]
    fn connect_escapes_the_redirect_uri() {
        let html = render_connect(
            &crate::proxy::ConnectParams {
                redirect_uri: "https://example.com/\"><script>alert(1)</script>".into(),
                ts: 1,
                nonce: "n".into(),
                challenge: "c".into(),
                tenant_id: "t".into(),
                user_id: "u".into(),
                user_id_sig: "s".into(),
                response: "r".into(),
            },
            &[],
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
