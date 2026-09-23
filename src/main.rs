//! localthought.io's integration proxy. All behavior is in the
//! `atomic-integration-proxy` crate; configuration comes from Heroku config
//! vars (see that crate's README for the full list).

#[tokio::main]
async fn main() -> std::process::ExitCode {
    atomic_integration_proxy::run().await
}
