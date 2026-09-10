# Connection security

## Browser bootstrap and credential handoff

New browser clients request a specific catalog platform at `/connect`, with a return URI, local actor id, S256 PKCE challenge and explicit credential grant. The Google session supplies the tenant identity; first-time setup does not need a pre-existing tenant secret. The consent page shows the Google identity and destination origin, with one action for the requested platform. A tenant secret is included only for the explicit `connection+tenant_secret` grant and is disclosed during consent.

The complete request survives Google login inside a short-lived encrypted cookie. Consent requires a cookie-bound random CSRF token, a valid Google session and a single-use database nonce. Return URIs require HTTPS (HTTP only for loopback development), no embedded user credentials or fragment, and no pre-existing credential/error fields. The hub creates and validates its own return state and binds it to the actor, drive and platform.

Provider OAuth state binds the platform, tenant, user, callback, PKCE verifier and an encrypted bootstrap context. A separate Secure/HttpOnly/SameSite=Lax browser cookie and the same Google account are required at callback for the new flow. Provider cancellation returns only a generic error to the already validated hub URI. Existing signed OAuth flows retain their prior callback format.

A new callback returns only a random five-minute handoff code, never a token envelope or tenant secret. `/connect/redeem` requires the original PKCE verifier and atomically deletes the matching, unexpired handoff before issuing one rotating connection credential. Wrong verifiers do not burn a valid handoff; replays and concurrent second redemptions fail. The encrypted database payload carries platform/tenant/user identity and the exact requested grant. Revocation is checked again at redemption. Handoff codes cannot be used directly as proxy credentials. Redemption and consent responses are non-cacheable and use a no-referrer policy.

The browser clears callback parameters before further use, retains pending state outside graph resources, and removes its verifier when redeeming. A lost redemption response requires reconnecting rather than blindly retrying. The existing five-minute idle expiry and one-use rotation rules still apply to proxy credentials.

The legacy tenant-proof endpoints remain for compatibility. They are not used by the new hub flow. The legacy tenant-secret redirect is deprecated; new callers must request the optional grant through PKCE redemption. No existing tenant or provider secrets are rotated by this deployment.

## Tenant session

`/session` signs a timestamp and `/connect` checks a tenant response and a
tenant-vouched user id. This proves possession of the tenant secret, but it is
a bearer credential: anyone who obtains it can mint proofs for any user id.
Use a high-entropy `SERVER_SECRET`, give every tenant a distinct identity, and
rotate the server secret only with a migration plan. Challenges now contain a
random nonce and are consumed atomically in PostgreSQL when `/connect` is
confirmed; a second use is rejected. Expired nonce records are cleaned during
subsequent consumption.

## OAuth (#9)

Register a distinct redirect URI per provider and validate it exactly. Keep
the OAuth state and PKCE verifier in authenticated, short-lived, `Secure`,
`HttpOnly`, `SameSite=Lax` cookies. Bind the state to the tenant and user id;
reject callback requests whose binding does not match. Request narrowly scoped
tokens, never put access tokens, refresh tokens, or encrypted token bundles in
URLs, HTML, logs, referrers, or error messages.

An encrypted token bundle needs authenticated encryption (for example,
XChaCha20-Poly1305 or AES-256-GCM), a fresh random nonce for every encryption,
key versioning, and associated data binding it to the tenant id, user id,
provider, and expiry. A server-secret HMAC is not encryption. Prefer an
opaque, short-lived reference with server-side storage if revocation and
replay prevention are required.

## Validating proxy (#10)

The proxy must select its upstream only from a server-owned catalog entry;
never accept an upstream URL or host from the client. Resolve and validate the
requested method, path, parameters, body, and content type against the
published OAD before contacting the provider. Reject unknown paths and methods,
strip client-supplied `Authorization`, `Host`, forwarding, and proxy headers,
and apply request size, timeout, redirect, and response-size limits.

Refresh tokens only at the provider token endpoint configured for that
platform. Store rotated tokens atomically before returning a replacement
credential. Do not forward the upstream's cookies or authorization headers.
Rate-limit per tenant, audit token use without logging secrets, and return
generic authentication errors.

## Release gate

Provider callback URLs and credential variable names are now deterministic
from catalog platform names. The remaining gate for #9 and #10 is provider
registration, OAD request validation, SSRF tests, and an external review of
the token envelope format before live credentials are handled.
