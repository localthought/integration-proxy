# integration-proxy

A stateless Rust web server that lets a user log in with a configured OIDC
provider. Sign-in sets an encrypted session cookie; there is a logout button
to clear it. No database, no server-side session store — the cookie *is*
the session, so any number of instances can run behind a load balancer with
no shared state.

Built with [axum](https://github.com/tokio-rs/axum) and the
[`oauth2`](https://docs.rs/oauth2) crate, following the OAuth 2.0
Authorization Code flow with PKCE.

## How it works

- `GET /` — shows a configurable application-login button, or, if a valid session
  cookie is present, the signed-in user's name/picture and a "Log out"
  button.
- `GET /auth/login` — starts the configured OIDC OAuth flow: generates a PKCE challenge and
  CSRF token, stores them in a short-lived encrypted cookie, and redirects
  to the provider's consent screen.
- `GET /auth/callback` — the configured provider redirects here with an authorization code.
  The server validates the CSRF token, exchanges the code for an access
  token, fetches the user's profile from Google's userinfo endpoint, and
  sets the session cookie.
- `POST /auth/logout` — clears the session cookie.
- `GET /catalog` — lists the available integration platform names.
- `GET /catalog/{platform}.yaml` — returns the OpenAPI document for that
  platform with its configured overlays applied.
- `GET /connect?platform=github-issues&redirect_uri=<url>&user_id=<actor>&code_challenge=<S256>&code_challenge_method=S256&credentials=connection` — starts a browser connection without a tenant secret. The page shows the configured application-login action, or the signed-in application identity and one action: **Use LocalThought to sync GitHub with your Atomic Data Hub**. The selected platform, return URL and PKCE challenge survive application login.
- `POST /connect/authorize` — approves the selected platform with a short-lived, cookie-bound CSRF token and starts provider OAuth. The authenticated application account determines the tenant; the caller supplies its local user/agent identifier. The consent page shows the destination hub origin and uses `Referrer-Policy: same-origin`, so its form submission retains a concrete origin without sending a referrer to the external OAuth provider.
- `POST /connect/redeem` — exchanges `{ "code": "<callback connection_code>", "code_verifier": "<original verifier>" }` for `{ "connection_code": "<rotating proxy credential>", "platform": "github-issues" }`. The handoff expires after five minutes, requires S256 PKCE, and is consumed atomically. Wrong verifiers do not consume a legitimate handoff. Responses have `Cache-Control: no-store`; browser requests omit cookies.
- Clients that also need the tenant credential explicitly request `credentials=connection+tenant_secret` (URL-encode the `+` as `%2B`). The consent page discloses this extra grant; redemption additionally returns `tenant_secret`. The browser-only Atomic Data Hub requests just `connection` and never needs to paste, receive, or store a tenant secret.
- The legacy signed `/connect` and `/oauth/{platform}/start` protocol remains available for existing clients. New clients should use the bootstrap flow above; it does not require the circular prerequisite of an already provisioned tenant secret.
- `/proxy` — called by the third party with `Authorization: Bearer
  <secret>`. Returns `{"ok": true}` if the tenant secret verifies, or `401` with
  an error body otherwise. Verification is a pure function of
  `SERVER_SECRET`, so it works without looking anything up.
- `GET /session` — returns a timestamp and a challenge signed with
  `SERVER_SECRET`. A tenant signs that challenge with its tenant secret and
  supplies that response, a tenant-vouched `user_id`, and its signature when
  opening `/connect`. The proof expires after ten minutes.

The signed-in home page displays the OIDC identity, without displaying credentials. Tenant secrets are deterministic HMAC credentials derived from the stable OIDC subject and `SERVER_SECRET`; existing credentials remain valid. Provider access/refresh tokens are encrypted at rest and never returned to the hub. The hub receives a rotating opaque proxy credential through the protected exchange.

The new consent, provider-state binding and one-time handoff work alongside the existing OAuth and proxy routes. The database migration adds a nullable OAuth context column and a `connection_handoffs` table without invalidating existing connection codes. Schema initialization runs in a transaction under a PostgreSQL advisory lock, so simultaneous app instances can safely start against an empty database. Google/provider OAuth app registrations and callback URLs do not change.

All cookies are set with `axum-extra`'s `PrivateCookieJar`, which
encrypts and authenticates their contents, so the server never needs to
persist anything to recognize a returning user.

## Setup

### 1. Configure application-login OIDC credentials

Configure an OIDC authorization-code client and register `<BASE_URL>/auth/callback` as its redirect URI. Supply its client credentials and authorization, token, and userinfo endpoint URLs through the `APP_AUTH_*` variables below. Application login requests the standard `openid`, `email`, and `profile` scopes.

### 2. Configure environment variables

Copy `.env.example` to `.env` and fill it in (or export the variables
directly):

| Variable               | Required | Description                                                                 |
| ----------------------| -------- | ---------------------------------------------------------------------------- |
| `APP_AUTH_CLIENT_ID`     | yes      | OIDC application-login client ID. |
| `APP_AUTH_CLIENT_SECRET` | yes      | OIDC application-login client secret. |
| `APP_AUTH_AUTHORIZATION_URL` | yes | OIDC authorization endpoint. |
| `APP_AUTH_TOKEN_URL` | yes | OIDC token endpoint. |
| `APP_AUTH_USERINFO_URL` | yes | OIDC userinfo endpoint. |
| `APP_AUTH_LABEL` | no | Login provider label shown in the UI. Defaults to `OIDC`. |
| `BASE_URL`             | no       | Public URL of the server, no trailing slash. Defaults to `http://localhost:8080`. Must match the redirect URI registered with the application-login provider. |
| `PORT`                 | no       | Port to listen on. Defaults to `8080`.                                      |
| `SESSION_SECRET`       | no       | Secret used to encrypt session cookies. If unset, a random key is generated at startup and sessions are invalidated whenever the process restarts. Set this to a persistent random value in production. |
| `SERVER_SECRET`        | yes      | Secret used to deterministically derive each tenant's secret (see above). Must stay constant across restarts and instances. |
| `CATALOG_PATH`         | no       | Local path or immutable HTTPS URL for the catalog JSON. Defaults to the pinned `localthought/overlays` `catalog.json` revision. |
| `DATABASE_URL`          | yes      | PostgreSQL connection URL. Stores short-lived, consumed challenge nonces to prevent replay. |
| `ENCRYPTION_KEY`        | yes      | Base64url-encoded, random 32-byte key for versioned XChaCha20-Poly1305 credential envelopes. |
| `REVOKED_SUBJECTS`      | no       | Comma-separated tenant and user IDs denied access. |

OAuth credentials are provider-specific. For a catalog platform named
`google-calendar`, configure `OAUTH_GOOGLE_CALENDAR_CLIENT_ID` and
`OAUTH_GOOGLE_CALENDAR_CLIENT_SECRET`; its callback URI is
`<BASE_URL>/oauth/google-calendar/callback`. Provider names use lowercase
letters, digits, and hyphens, and are converted to uppercase with hyphens
replaced by underscores for environment-variable names.

The server owns the OAuth endpoints and scopes. The built-in providers are
`google-calendar` (read-only Calendar scope) and `github-issues` (`repo`
scope); a request cannot supply a provider URL, token URL, or scope.

The PostgreSQL client validates the database TLS certificate. Heroku assigns
`DATABASE_URL` automatically when its Postgres add-on is attached.

Use the `connection_code` returned by the OAuth redirect as the Bearer token
for `/proxy/{platform}/{path}`. Each successful proxy response includes a new
single-use value in `X-Connection-Code`; use that value for the next request.
The proxy refreshes an expired provider access token when a refresh token is
available, and rotates the handoff code after every request. GitHub sometimes
returns repository pagination links using its canonical numeric repository
path; the proxy rewrites that metadata to the current allowlisted owner/repo
path only when the collection suffix matches.

## Catalog

Discord uses `OAUTH_DISCORD_CLIENT_ID` and `OAUTH_DISCORD_CLIENT_SECRET`,
with production callback `https://localthought.io/oauth/discord/callback`.
Register an OAuth application in the Discord Developer Portal. The initial
read-only integration uses `identify` and `guilds` to read your profile and
import server memberships; it does not import messages or require a bot token.
The guild import requests `limit=200`, covering Discord's documented maximum
number of guilds for a user. The profile endpoint is available as a read
operation, not an imported collection.
Discord access tokens expire and use the existing refresh-token flow.

Spotify uses `OAUTH_SPOTIFY_CLIENT_ID` and the callback
`https://localthought.io/oauth/spotify/callback` in production. Register a
Spotify Web API app with that exact redirect URI. The integration uses
Authorization Code with PKCE, so no client secret is required or transmitted.
It imports playlists with `playlist-read-private` and
`playlist-read-collaborative`; no write scopes are requested. No account ID
parameter is needed. Development-mode access is subject to Spotify's Premium
and app-user allowlist requirements. Access tokens refresh automatically;
expired or revoked refresh tokens require reconnecting through OAuth.


Moneybird uses `OAUTH_MONEYBIRD_CLIENT_ID` and
`OAUTH_MONEYBIRD_CLIENT_SECRET`, with callback
`https://localthought.io/oauth/moneybird/callback` in production. Register an
external OAuth application, rather than a personal API token. The
`sales_invoices` scope grants access to contacts (Moneybird has no contacts-only
scope). The initial integration imports contacts; supply the administration ID
from the Moneybird account when connecting. OAuth tokens without `expires_in`
remain usable until revoked; tokens with an expiry use the normal refresh flow.

`catalog.json` in the `localthought/overlays` repository is the source of the
integration catalog. The proxy defaults to an immutable raw GitHub URL for a
specific catalog commit; set `CATALOG_PATH` to another HTTPS revision for a
controlled rollout, or to a local fixture for development. Each platform names
one pinned OpenAPI document and zero or more pinned Overlay Specification
documents. At startup the proxy downloads those HTTPS sources, applies each
overlay's `update` actions, and keeps the resulting YAML in memory.

A catalog entry may also contain a `selection` object with consumer query
choices. `GET /catalog/{platform}.selection.json` returns that object (or `{}`
when absent). It remains separate from the composed OpenAPI document: choosing
to include archived records is client configuration, not an API default. The
proxy passes this configuration through and does not interpret its fields.

Publish catalog changes in this order: publish and verify the immutable OAD and
overlay pins, commit the root `catalog.json`, then update the proxy's pinned
catalog URL and restart the service. Keep each OAD and overlay URL pinned to a
commit so the generated `/catalog` documents change only through an explicit
catalog revision.

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

## Security

The current service provides catalog and tenant-session primitives. OAuth token
storage and the forwarding proxy remain deliberately unimplemented until the
controls in [SECURITY.md](SECURITY.md) are in place.

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
- The tenant secret is likewise never stored: it's an HMAC of the tenant
  identity keyed by `SERVER_SECRET`, so any instance that knows
  `SERVER_SECRET` can derive or verify it on the fly.
- The pending `/connect` redirect (used to return to `/connect` after a
  login detour) is held in a short-lived encrypted cookie
  (`connect_redirect`), the same pattern as `oauth_state`.

## Browser clients

CORS permits explicit bearer-token requests from browser frontends and answers
OPTIONS preflights. Responses expose `X-Connection-Code`, `Link`, `Retry-After`,
`ETag`, `X-Total-Count` and `X-Next-Page`. Clients must persist a rotated code
before continuing pagination and must never replay a consumed code after an
uncertain response. Cookie credentials are not enabled for CORS; provider
login and consent remain top-level browser navigations.

## Todoist

The `todoist` platform imports projects and active tasks through Todoist API v1
with the read-only `data:read` scope. Configure `OAUTH_TODOIST_CLIENT_ID` and
`OAUTH_TODOIST_CLIENT_SECRET`, and register
`https://localthought.io/oauth/todoist/callback` as the OAuth redirect URL.
New Todoist applications issue expiring access tokens and rotating refresh
tokens; the proxy stores and refreshes these through its existing credential flow.
Legacy non-expiring access tokens are also supported. No provider writes are exposed.

Provider documentation: https://developer.todoist.com/api/v1/

## Redirect-flow regression checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
# Isolated local PostgreSQL, never a production database:
TEST_DATABASE_URL='postgres://postgres@localhost:15439/connect_test?sslmode=disable' \
OAUTH_GITHUB_ISSUES_CLIENT_ID=fixture-client OAUTH_GITHUB_ISSUES_CLIENT_SECRET=fixture-secret \
  cargo test -- --include-ignored
```

CI provides PostgreSQL and includes the database tests. Coverage includes concurrent cold-start schema initialization, selected-platform rendering and escaping, credential-free sign-in, return-address validation, PKCE, consent/session requirements, handoff expiry, wrong-verifier refusal, concurrent/replayed redemption, optional tenant-secret grants, revocation and provider-cookie/account binding. Live Google/GitHub authorization and a hub read-only import must be verified against both matching deployed revisions; local fixture checks do not establish live access.

### OAuth client registration

Integration authorization and token endpoints and required scopes are read from the composed OpenAPI catalog. A platform must have exactly one OAuth authorization-code security scheme. Scopes are taken from operation security requirements (falling back to root requirements), not every scope supported by the server. Public operations require no scopes; unsupported authentication combinations fail closed.

`OAUTH_<PLATFORM>_CLIENT_AUTH_METHOD` selects the method registered for this client: `none`, `client_secret_post` (default), or `client_secret_basic`. Public clients use `none` and do not load or send a secret. Confidential clients require the corresponding `_CLIENT_SECRET`. This setting describes the client registration, not server-supported capabilities. Authorization uses S256 PKCE. Server capability extensions remain subject to the separate OpenAPI extension discussions.

When upgrading the previous deployment, copy its application-login client ID/secret to `APP_AUTH_CLIENT_ID` / `APP_AUTH_CLIENT_SECRET` and configure the same authorization, token, and userinfo endpoints before deploying. Keep the identity issuer stable: tenant identities are derived from its subject identifiers. Set the existing public PKCE client's `_CLIENT_AUTH_METHOD=none`. Existing credential envelopes, handoffs, callbacks, and provider credential variable names remain valid. Browser login sessions created by the earlier session schema require sign-in again.
