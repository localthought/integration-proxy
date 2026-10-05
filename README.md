# integration-proxy (localthought.io deployment)

This repository is only the Heroku deployment wrapper for the integration
proxy at localthought.io. The proxy's source, documentation, security notes
and tests live in
[`ontola/atomic-plugins/integration-proxy`](https://github.com/ontola/atomic-plugins/tree/main/integration-proxy),
as the Rust crate `atomic-integration-proxy`. File issues and pull requests
for proxy behaviour there.

What is here:

| File | Purpose |
| --- | --- |
| `src/main.rs` | `atomic_integration_proxy::run().await`, nothing else. |
| `Cargo.toml` | Package/binary `auth-proxy`, depending on `atomic-integration-proxy` from crates.io, with the lowest release this deployment needs as the version requirement. |
| `Cargo.lock` | The exact versions Heroku builds. Commit it with every bump. |
| `Procfile` | `web: target/release/auth-proxy`. |
| `rust-toolchain` | `stable`, read by the `emk/rust` Heroku buildpack. |
| `.env.example` | The environment variables the proxy reads; see the crate's README for what each one does. |

## Deploying a newer proxy

Once the release is on crates.io (`ontola/atomic-plugins` publishes it from
a tag `integration-proxy-v<version>`), set the version requirement in
`Cargo.toml` to it when this deployment depends on its behaviour, then

```sh
cargo update -p atomic-integration-proxy
cargo build --release --locked
```

and commit `Cargo.toml` and `Cargo.lock`. Merging to `main` deploys.

## Running locally

```sh
cp .env.example .env   # fill in the values
set -a; . ./.env; set +a
cargo run --release
```

Without the required variables the binary exits with
`configuration error: <VARIABLE> must be set`.

## Catalog

Unless `CATALOG_PATH` is set, the proxy loads its catalog at startup from
`https://ontola.github.io/atomic-plugins/overlays/catalog/2026-10-02-auth-profiles.json`, which GitHub
Pages publishes from `ontola/atomic-plugins`' `main`. Dated catalogs and
the OAD-revision overlay filenames they select are immutable. Publish a new
dated catalog and explicitly switch `CATALOG_PATH` to opt into later revisions.

Version 0.2.5 supports authentication profiles (ontola/atomic-plugins#258).
Its default catalog differs from `2026-10-02.json` only in Discord, which
selects the `discordUser` profile, so the proxy offers a Discord connection
with the scopes `identify` and `guilds`.
