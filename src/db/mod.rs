pub mod deploy_keys;
pub mod models;
pub mod queries;

pub use deploy_keys::DeployKey;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::Path;

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
        .context("connect postgres")?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool, migrations_dir: &Path) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(pool)
    .await?;

    let mut files: Vec<_> = std::fs::read_dir(migrations_dir)
        .with_context(|| format!("read migrations {}", migrations_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("sql"))
        .collect();
    files.sort();

    for path in files {
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let applied: Option<(String,)> =
            sqlx::query_as("SELECT filename FROM schema_migrations WHERE filename = $1")
                .bind(&filename)
                .fetch_optional(pool)
                .await?;
        if applied.is_some() {
            continue;
        }
        let sql = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let sql = sql.strip_prefix('\u{feff}').unwrap_or(&sql);
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(sql)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("apply migration {filename}"))?;
        sqlx::query("INSERT INTO schema_migrations (filename) VALUES ($1)")
            .bind(&filename)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!("applied migration {filename}");
    }
    Ok(())
}
