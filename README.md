# integration-proxy

A stateless Rust web server that lets a user log in with their Google
account. Sign-in sets an encrypted session cookie; there is a logout button
to clear it. No database, no server-side session store — the cookie *is*
the session, so any number of instances can run behind a load balancer with
no shared state.

Built with [axum](https://github.com/tokio-rs/axum) and the
[`oauth2`](https://docs.rs/oauth2) crate, following the OAuth 2.0
Authorization Code flow with PKCE.

## How it works

- `GET /` — shows a "Log in with Google" button, or, if a valid session
  cookie is present, the signed-in user's name/picture and a "Log out"
  button.
- `GET /auth/login` — starts the OAuth flow: generates a PKCE challenge and
  CSRF token, stores them in a short-lived encrypted cookie, and redirects
  to Google's consent screen.
- `GET /auth/callback` — Google redirects here with an authorization code.
  The server validates the CSRF token, exchanges the code for an access
  token, fetches the user's profile from Google's userinfo endpoint, and
  sets the session cookie.
- `POST /auth/logout` — clears the session cookie.
- `GET /catalog` — lists the available integration platform names.
- `GET /catalog/{platform}.yaml` — returns the OpenAPI document for that
  platform with its configured overlays applied.
- `GET /connect?redirect_uri=<url>` — a third party (e.g. atomic-server)
  sends the user here to obtain their user secret. If the user isn't signed
  in yet, they're sent to log in first and brought back here afterwards.
  Once signed in, they see a consent screen showing `redirect_uri` and an
  "OK" button.
- `POST /connect` — submitted by the consent screen's form. Redirects the
  browser to `redirect_uri` with the user's secret attached as
  `?secret=...`.
- `/proxy` — called by the third party with `Authorization: Bearer
  <secret>`. Returns `{"ok": true}` if the secret verifies, or `401` with
  an error body otherwise. Verification is a pure function of
  `SERVER_SECRET`, so it works without looking anything up.

Once signed in, the home page also displays a **user secret**: a value
deterministically derived from the account's Google identity and the
server's `SERVER_SECRET`. It's meant to be copied into the environment of
another service (e.g. an atomic-server instance running the
`feat/api-plugins` branch) so that service can later authenticate requests
made on the user's behalf. Because it's derived rather than stored, the
server never needs a database to look it up or validate it.

All cookies are set with `axum-extra`'s `PrivateCookieJar`, which
encrypts and authenticates their contents, so the server never needs to
persist anything to recognize a returning user.

## Setup

### 1. Create Google OAuth credentials

1. Go to the [Google Cloud Console credentials page](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth client ID** of type **Web application**.
3. Add an authorized redirect URI: `<BASE_URL>/auth/callback` (e.g.
   `http://localhost:8080/auth/callback` for local development).
4. Note the generated **Client ID** and **Client Secret**.

### 2. Configure environment variables

Copy `.env.example` to `.env` and fill it in (or export the variables
directly):

| Variable               | Required | Description                                                                 |
| ----------------------| -------- | ---------------------------------------------------------------------------- |
| `GOOGLE_CLIENT_ID`     | yes      | OAuth client ID from the Google Cloud Console.                              |
| `GOOGLE_CLIENT_SECRET` | yes      | OAuth client secret from the Google Cloud Console.                          |
| `BASE_URL`             | no       | Public URL of the server, no trailing slash. Defaults to `http://localhost:8080`. Must match the redirect URI registered with Google. |
| `PORT`                 | no       | Port to listen on. Defaults to `8080`.                                      |
| `SESSION_SECRET`       | no       | Secret used to encrypt session cookies. If unset, a random key is generated at startup and sessions are invalidated whenever the process restarts. Set this to a persistent random value in production. |
| `SERVER_SECRET`        | yes      | Secret used to deterministically derive each user's per-identity "user secret" (see above). Must stay constant across restarts and instances. |
| `CATALOG_PATH`         | no       | Path to the catalog configuration. Defaults to `catalog.yaml`. |

## Catalog

`catalog.yaml` is the source of the integration catalog. Each platform names
one pinned OpenAPI document and zero or more pinned Overlay Specification
documents. At startup the proxy downloads those HTTPS sources, applies each
overlay's `update` actions, and keeps the resulting YAML in memory. Edit this
file and restart the service to add, remove, or update a platform. The default
catalog pins GitHub Issues and Google Calendar to the revisions requested in
issue #6.

### 3. Run it

```sh
cargo run
```

Then open `http://localhost:8080` (or your configured `BASE_URL`) in a
browser.

## Development

```sh
cargo fmt --all       # format
cargo clippy --all-targets --all-features -- -D warnings   # lint
cargo build            # build
cargo test             # test
```

CI runs the same checks on every push and pull request (see
`.github/workflows/ci.yml`).

## Notes on statelessness

- Session data (email, name, picture, expiry) lives entirely inside the
  encrypted `session` cookie — nothing is written to disk or a database.
- The OAuth CSRF token and PKCE verifier for an in-flight login are also
  held in a short-lived encrypted cookie (`oauth_state`) rather than
  server memory, so the login flow works correctly even if requests land
  on different instances behind a load balancer.
- Cookies are marked `Secure`, so in production `BASE_URL` must use
  `https://`. `http://localhost` works during local development because
  browsers treat `localhost` as a secure context.
- The per-user secret is likewise never stored: it's an HMAC of the
  account's Google identity keyed by `SERVER_SECRET`, so any instance that
  knows `SERVER_SECRET` can derive or verify it on the fly.
- The pending `/connect` redirect (used to return to `/connect` after a
  login detour) is held in a short-lived encrypted cookie
  (`connect_redirect`), the same pattern as `oauth_state`.
