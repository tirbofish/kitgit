mod auth;
mod config;
mod db;
mod git;
mod highlight;
mod markdown;
mod mfa;
mod og;
mod state;
mod web;
mod webhooks;

use crate::auth::AuthState;
use crate::config::Config;
use crate::state::AppState;
use anyhow::Result;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::load()?;
    let config = Arc::new(config);

    std::fs::create_dir_all(config.repos_dir())?;
    std::fs::create_dir_all(config.avatars_dir())?;
    std::fs::create_dir_all(config.releases_dir())?;
    std::fs::create_dir_all(config.data_dir.join("lfs"))?;
    std::fs::create_dir_all(&config.data_dir)?;

    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool, std::path::Path::new("./migrations")).await?;

    let auth = AuthState::new(pool.clone(), config.clone()).await?;
    let state = AppState {
        pool,
        config: config.clone(),
        auth,
    };

    let ssh_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = git::ssh::run_ssh(ssh_state).await {
            tracing::error!("ssh server exited: {e:#}");
        }
    });

    let app = web::app_router(state);
    let listener = tokio::net::TcpListener::bind(config.http_bind).await?;
    tracing::info!("http listening on {}", config.http_bind);
    axum::serve(listener, app).await?;
    Ok(())
}
