//! Repo-scoped SSH deploy keys (read-only or read-write).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct DeployKey {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub read_only: bool,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl DeployKey {
    pub fn permission_label(&self) -> &'static str {
        if self.read_only {
            "Read-only"
        } else {
            "Read-write"
        }
    }
}

pub async fn add_deploy_key(
    pool: &PgPool,
    repo_id: Uuid,
    name: &str,
    public_key: &str,
    fingerprint: &str,
    read_only: bool,
    created_by: Option<Uuid>,
) -> Result<DeployKey> {
    let clash: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM ssh_keys WHERE rtrim(fingerprint, '=') = rtrim($1, '=') LIMIT 1",
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;
    if clash.is_some() {
        anyhow::bail!("fingerprint already registered as a user SSH key");
    }
    Ok(sqlx::query_as::<_, DeployKey>(
        r#"
        INSERT INTO deploy_keys (repo_id, name, public_key, fingerprint, read_only, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(name)
    .bind(public_key)
    .bind(fingerprint)
    .bind(read_only)
    .bind(created_by)
    .fetch_one(pool)
    .await?)
}

pub async fn list_deploy_keys(pool: &PgPool, repo_id: Uuid) -> Result<Vec<DeployKey>> {
    Ok(sqlx::query_as::<_, DeployKey>(
        "SELECT * FROM deploy_keys WHERE repo_id = $1 ORDER BY created_at",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await?)
}

pub async fn delete_deploy_key(pool: &PgPool, repo_id: Uuid, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM deploy_keys WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn deploy_key_by_fingerprint(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<DeployKey>> {
    let normalized = fingerprint.trim_end_matches('=');
    Ok(sqlx::query_as::<_, DeployKey>(
        r#"
        SELECT * FROM deploy_keys
        WHERE rtrim(fingerprint, '=') = $1
        "#,
    )
    .bind(normalized)
    .fetch_optional(pool)
    .await?)
}