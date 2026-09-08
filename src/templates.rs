use crate::session::SessionUser;

/// Minimal, dependency-free HTML rendering. The GUI is intentionally tiny:
/// a login button when signed out, and the user's identity plus a logout
/// button when signed in.
pub fn render_home(user: Option<&SessionUser>, user_secret: Option<&str>) -> String {
    let body = match user {
        Some(user) => signed_in_body(
            user,
            user_secret.expect("user_secret is set when signed in"),
        ),
        None => signed_out_body(),
    };

    page(&body)
}

/// Renders the "connect this app" consent screen shown at `/connect` to a
/// signed-in user, before they approve sharing their user secret.
pub fn render_connect(redirect_uri: &str) -> String {
    let body = format!(
        r#"
        <div class="card">
          <h1>Connect this app?</h1>
          <p>You'll be redirected back to:</p>
          <p class="email">{redirect_uri}</p>
          <form method="post" action="/connect">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
            <button class="button" type="submit">OK</button>
          </form>
        </div>
        "#,
        redirect_uri = escape(redirect_uri),
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

fn signed_in_body(user: &SessionUser, user_secret: &str) -> String {
    let avatar = user
        .picture
        .as_deref()
        .map(|src| format!(r#"<img class="avatar" src="{}" alt="" />"#, escape(src)))
        .unwrap_or_default();

    format!(
        r#"
        <div class="card">
          {avatar}
          <h1>Welcome, {name}</h1>
          <p class="email">{email}</p>
          <p class="secret-label">Your user secret:</p>
          <code class="secret">{user_secret}</code>
          <p class="secret-help">
            Set this as <code>USER_SECRET</code> in the environment of your
            atomic-server (running the <code>feat/api-plugins</code> branch)
            to authenticate requests on your behalf.
          </p>
          <form method="post" action="/auth/logout">
            <button class="button button-secondary" type="submit">Log out</button>
          </form>
        </div>
        "#,
        avatar = avatar,
        name = escape(&user.name),
        email = escape(&user.email),
        user_secret = escape(user_secret),
    )
}

fn page(body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>auth-proxy</title>
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
    .secret-label {{ margin-bottom: 0; font-weight: 600; }}
    .secret {{
      display: block;
      margin-top: 0.4rem;
      padding: 0.5rem;
      background: #f0f0f2;
      border-radius: 6px;
      font-size: 0.8rem;
      word-break: break-all;
    }}
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
      .secret {{ background: #3c4043; }}
      .secret-help {{ color: #9aa0a6; }}
    }}
  </style>
</head>
<body>
  {body}
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
    fn signed_in_shows_user_secret() {
        let html = render_home(Some(&test_user()), Some("the-secret"));
        assert!(html.contains("the-secret"));
        assert!(html.contains("USER_SECRET"));
    }

    #[test]
    fn signed_in_escapes_untrusted_fields() {
        let html = render_home(Some(&test_user()), Some("<b>not-html</b>"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<b>not-html</b>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;b&gt;not-html&lt;/b&gt;"));
    }

    #[test]
    #[should_panic]
    fn render_home_panics_if_secret_missing_while_signed_in() {
        render_home(Some(&test_user()), None);
    }

    #[test]
    fn connect_shows_the_redirect_target_and_a_confirm_form() {
        let html = render_connect("https://example.com/callback");
        assert!(html.contains("https://example.com/callback"));
        assert!(html.contains(r#"action="/connect""#));
        assert!(html.contains(r#"method="post""#));
    }

    #[test]
    fn connect_escapes_the_redirect_uri() {
        let html = render_connect("https://example.com/\"><script>alert(1)</script>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
