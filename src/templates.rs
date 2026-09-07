use crate::session::SessionUser;

/// Minimal, dependency-free HTML rendering. The GUI is intentionally tiny:
/// a login button when signed out, and the user's identity plus a logout
/// button when signed in.
pub fn render_home(user: Option<&SessionUser>) -> String {
    let body = match user {
        Some(user) => signed_in_body(user),
        None => signed_out_body(),
    };

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
          <h1>Welcome, {name}</h1>
          <p class="email">{email}</p>
          <form method="post" action="/auth/logout">
            <button class="button button-secondary" type="submit">Log out</button>
          </form>
        </div>
        "#,
        avatar = avatar,
        name = escape(&user.name),
        email = escape(&user.email),
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
