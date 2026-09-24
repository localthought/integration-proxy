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
| `Cargo.toml` | Package/binary `auth-proxy`, depending on `atomic-integration-proxy`. Until the crate is on crates.io this is a git dependency pinned to an `ontola/atomic-plugins` commit (`rev`). |
| `Cargo.lock` | The exact versions Heroku builds. Commit it with every bump. |
| `Procfile` | `web: target/release/auth-proxy`. |
| `rust-toolchain` | `stable`, read by the `emk/rust` Heroku buildpack. |
| `.env.example` | The environment variables the proxy reads; see the crate's README for what each one does. |

## Deploying a newer proxy

While the dependency is a git pin: set `rev` in `Cargo.toml` to the
`ontola/atomic-plugins` commit to deploy, then

```sh
cargo update -p atomic-integration-proxy
cargo build --release --locked
```

and commit `Cargo.toml` and `Cargo.lock`. Merging to `main` deploys.

Once `atomic-integration-proxy` is published, replace the git dependency with
`atomic-integration-proxy = "0.1"`, and bump releases with
`cargo update -p atomic-integration-proxy` alone.

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
`https://ontola.github.io/atomic-plugins/overlays/catalog.json`, which GitHub
Pages publishes from `ontola/atomic-plugins`' `main`. It is not pinned to a
commit: a restart picks up whatever `main` publishes at that moment.
