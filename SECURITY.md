# Security review: issues #6–#10

The catalog and tenant-session protocol can be used as a basis for an OAuth
integration, but issues #9 and #10 must not be implemented as written until
the following controls are part of the design.

## Tenant session

`/session` signs a timestamp and `/connect` checks a tenant response and a
tenant-vouched user id. This proves possession of the tenant secret, but it is
a bearer credential: anyone who obtains it can mint proofs for any user id.
Use a high-entropy `SERVER_SECRET`, give every tenant a distinct identity, and
rotate the server secret only with a migration plan. The ten-minute challenge
limits replay but does not prevent replay inside that window without shared
state. A one-time challenge store, or a tenant-signed request with a unique
nonce and replay store, is required where replay protection matters.

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

Before implementing #9 or #10, add provider-specific client configuration,
redirect URI allowlists, key management, a token-revocation policy, replay
protection, SSRF tests, OpenAPI validation tests, and an external security
review of the token envelope format.
