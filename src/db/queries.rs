use super::models::*;
use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn upsert_user_from_oidc(
    pool: &PgPool,
    oidc_sub: &str,
    username: &str,
    display_name: &str,
    email: &str,
    avatar_url: Option<&str>,
) -> Result<User> {
    let avatar_url = avatar_url
        .filter(|u| !u.is_empty() && !u.starts_with("/avatars/"));
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (oidc_sub, username, display_name, email, avatar_url)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (oidc_sub) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            email = EXCLUDED.email,
            avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
            updated_at = now()
        RETURNING *
        "#,
    )
    .bind(oidc_sub)
    .bind(username)
    .bind(display_name)
    .bind(email)
    .bind(avatar_url)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn site_admin_count(pool: &PgPool) -> Result<i64> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_site_admin = TRUE")
            .fetch_one(pool)
            .await?;
    Ok(n)
}

pub async fn set_site_admin(pool: &PgPool, id: Uuid, is_admin: bool) -> Result<User> {
    Ok(sqlx::query_as::<_, User>(
        "UPDATE users SET is_site_admin = $2, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(is_admin)
    .fetch_one(pool)
    .await?)
}

pub async fn list_users(pool: &PgPool) -> Result<Vec<User>> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT * FROM users ORDER BY username",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    Ok(sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    Ok(
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn update_user_profile(
    pool: &PgPool,
    id: Uuid,
    display_name: &str,
    bio: &str,
    avatar_path: Option<&str>,
) -> Result<User> {
    Ok(sqlx::query_as::<_, User>(
        r#"
        UPDATE users SET
            display_name = $2,
            bio = $3,
            avatar_path = COALESCE($4, avatar_path),
            avatar_url = CASE WHEN $4 IS NOT NULL THEN NULL ELSE avatar_url END,
            updated_at = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(display_name)
    .bind(bio)
    .bind(avatar_path)
    .fetch_one(pool)
    .await?)
}

pub async fn get_setting(pool: &PgPool, key: &str) -> Result<String> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM site_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0).unwrap_or_default())
}

pub async fn set_setting(pool: &PgPool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO site_settings (key, value) VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        "#,
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

pub const DEFAULT_SIGNUP_DISABLED_MESSAGE: &str =
    "Unfortunately, the admin has disabled new signups. Sorry!";

pub async fn signups_enabled(pool: &PgPool) -> bool {
    let v = get_setting(pool, "signups_enabled")
        .await
        .unwrap_or_default();
    if v.is_empty() {
        return true;
    }
    matches!(v.as_str(), "true" | "1" | "yes" | "on")
}

pub async fn signup_disabled_message(pool: &PgPool) -> String {
    let v = get_setting(pool, "signup_disabled_message")
        .await
        .unwrap_or_default();
    let trimmed = v.trim();
    if trimmed.is_empty() {
        DEFAULT_SIGNUP_DISABLED_MESSAGE.to_string()
    } else {
        trimmed.to_string()
    }
}

pub async fn site_announcement(pool: &PgPool) -> String {
    get_setting(pool, "announcement")
        .await
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub async fn set_user_suspended(pool: &PgPool, id: Uuid, suspended: bool) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET is_suspended = $2, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(suspended)
    .fetch_one(pool)
    .await?;
    if suspended {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        let _ = delete_mfa_pending_for_user(pool, id).await;
    }
    Ok(user)
}

pub async fn search_users(
    pool: &PgPool,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<User>, i64)> {
    let q = query.map(|s| s.trim()).filter(|s| !s.is_empty());
    let (users, total): (Vec<User>, i64) = if let Some(term) = q {
        let like = format!("%{}%", term.replace('%', "\\%").replace('_', "\\_"));
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users
            WHERE username ILIKE $1 ESCAPE '\'
               OR email ILIKE $1 ESCAPE '\'
               OR display_name ILIKE $1 ESCAPE '\'
            ORDER BY username
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&like)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let (total,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM users
            WHERE username ILIKE $1 ESCAPE '\'
               OR email ILIKE $1 ESCAPE '\'
               OR display_name ILIKE $1 ESCAPE '\'
            "#,
        )
        .bind(&like)
        .fetch_one(pool)
        .await?;
        (users, total)
    } else {
        let users = sqlx::query_as::<_, User>(
            "SELECT * FROM users ORDER BY username LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(pool)
            .await?;
        (users, total)
    };
    Ok((users, total))
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteCode {
    pub id: Uuid,
    pub code: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub used_by: Option<Uuid>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub fn generate_invite_code() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    let mut out = String::with_capacity(10);
    for _ in 0..10 {
        let mut b = [0u8; 1];
        rng.fill(&mut b);
        out.push(ALPHABET[(b[0] as usize) % ALPHABET.len()] as char);
    }
    out
}

pub async fn create_invite(pool: &PgPool, created_by: Uuid) -> Result<InviteCode> {
    let code = generate_invite_code();
    Ok(sqlx::query_as::<_, InviteCode>(
        r#"
        INSERT INTO invite_codes (code, created_by)
        VALUES ($1, $2)
        RETURNING *
        "#,
    )
    .bind(code)
    .bind(created_by)
    .fetch_one(pool)
    .await?)
}

pub async fn list_active_invites(pool: &PgPool, limit: i64) -> Result<Vec<InviteCode>> {
    Ok(sqlx::query_as::<_, InviteCode>(
        r#"
        SELECT * FROM invite_codes
        WHERE used_at IS NULL AND revoked_at IS NULL
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

pub async fn revoke_invite(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE invite_codes SET revoked_at = now() WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the invite if it is unused and not revoked.
pub async fn get_valid_invite(pool: &PgPool, code: &str) -> Result<Option<InviteCode>> {
    let code = code.trim().to_uppercase();
    if code.is_empty() {
        return Ok(None);
    }
    Ok(sqlx::query_as::<_, InviteCode>(
        r#"
        SELECT * FROM invite_codes
        WHERE upper(code) = $1 AND used_at IS NULL AND revoked_at IS NULL
        "#,
    )
    .bind(code)
    .fetch_optional(pool)
    .await?)
}

pub async fn consume_invite(pool: &PgPool, invite_id: Uuid, user_id: Uuid) -> Result<bool> {
    let res = sqlx::query(
        r#"
        UPDATE invite_codes
        SET used_by = $2, used_at = now()
        WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL
        "#,
    )
    .bind(invite_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

#[derive(Debug, Clone)]
pub struct AdminStats {
    pub user_count: i64,
    pub repo_count: i64,
    pub public_repo_count: i64,
    pub recent_signups: i64,
    pub active_invites: i64,
    pub disk_bytes: u64,
}

pub async fn admin_stats(pool: &PgPool) -> Result<AdminStats> {
    let (user_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    let (repo_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories")
        .fetch_one(pool)
        .await?;
    let (public_repo_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM repositories WHERE visibility = 'public'")
            .fetch_one(pool)
            .await?;
    let (recent_signups,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE created_at > now() - interval '7 days'",
    )
    .fetch_one(pool)
    .await?;
    let (active_invites,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM invite_codes WHERE used_at IS NULL AND revoked_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    Ok(AdminStats {
        user_count,
        repo_count,
        public_repo_count,
        recent_signups,
        active_invites,
        disk_bytes: 0,
    })
}

pub async fn list_repos_admin(
    pool: &PgPool,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<(Repository, String)>, i64)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        owner_id: Uuid,
        name: String,
        description: String,
        visibility: String,
        default_branch: String,
        archived: bool,
        issues_enabled: bool,
        pulls_enabled: bool,
        releases_enabled: bool,
        allow_merge: bool,
        allow_squash: bool,
        allow_rebase: bool,
        default_merge_style: String,
        protect_default_branch: bool,
        protect_block_force_push: bool,
        fork_of_id: Option<Uuid>,
        stars_count: i32,
        watches_count: i32,
        forks_count: i32,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        owner_username: String,
    }

    let q = query.map(|s| s.trim()).filter(|s| !s.is_empty());
    let (rows, total): (Vec<Row>, i64) = if let Some(term) = q {
        let like = format!("%{}%", term.replace('%', "\\%").replace('_', "\\_"));
        let rows = sqlx::query_as(
            r#"
            SELECT r.*, u.username AS owner_username
            FROM repositories r
            JOIN users u ON u.id = r.owner_id
            WHERE r.name ILIKE $1 ESCAPE '\'
               OR r.description ILIKE $1 ESCAPE '\'
               OR u.username ILIKE $1 ESCAPE '\'
            ORDER BY r.updated_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&like)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let (total,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM repositories r
            JOIN users u ON u.id = r.owner_id
            WHERE r.name ILIKE $1 ESCAPE '\'
               OR r.description ILIKE $1 ESCAPE '\'
               OR u.username ILIKE $1 ESCAPE '\'
            "#,
        )
        .bind(&like)
        .fetch_one(pool)
        .await?;
        (rows, total)
    } else {
        let rows = sqlx::query_as(
            r#"
            SELECT r.*, u.username AS owner_username
            FROM repositories r
            JOIN users u ON u.id = r.owner_id
            ORDER BY r.updated_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories")
            .fetch_one(pool)
            .await?;
        (rows, total)
    };

    let repos = rows
        .into_iter()
        .map(|r| {
            (
                Repository {
                    id: r.id,
                    owner_id: r.owner_id,
                    name: r.name,
                    description: r.description,
                    visibility: r.visibility,
                    default_branch: r.default_branch,
                    archived: r.archived,
                    issues_enabled: r.issues_enabled,
                    pulls_enabled: r.pulls_enabled,
                    releases_enabled: r.releases_enabled,
                    allow_merge: r.allow_merge,
                    allow_squash: r.allow_squash,
                    allow_rebase: r.allow_rebase,
                    default_merge_style: r.default_merge_style,
                    protect_default_branch: r.protect_default_branch,
                    protect_block_force_push: r.protect_block_force_push,
                    fork_of_id: r.fork_of_id,
                    stars_count: r.stars_count,
                    watches_count: r.watches_count,
                    forks_count: r.forks_count,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                },
                r.owner_username,
            )
        })
        .collect();
    Ok((repos, total))
}

pub async fn set_repo_visibility(
    pool: &PgPool,
    id: Uuid,
    visibility: &str,
) -> Result<Repository> {
    Ok(sqlx::query_as::<_, Repository>(
        "UPDATE repositories SET visibility = $2, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(visibility)
    .fetch_one(pool)
    .await?)
}

pub async fn get_repo_by_id(pool: &PgPool, id: Uuid) -> Result<Option<(Repository, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        owner_id: Uuid,
        name: String,
        description: String,
        visibility: String,
        default_branch: String,
        archived: bool,
        issues_enabled: bool,
        pulls_enabled: bool,
        releases_enabled: bool,
        allow_merge: bool,
        allow_squash: bool,
        allow_rebase: bool,
        default_merge_style: String,
        protect_default_branch: bool,
        protect_block_force_push: bool,
        fork_of_id: Option<Uuid>,
        stars_count: i32,
        watches_count: i32,
        forks_count: i32,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        owner_username: String,
    }
    let row: Option<Row> = sqlx::query_as(
        r#"
        SELECT r.*, u.username AS owner_username
        FROM repositories r
        JOIN users u ON u.id = r.owner_id
        WHERE r.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        (
            Repository {
                id: r.id,
                owner_id: r.owner_id,
                name: r.name,
                description: r.description,
                visibility: r.visibility,
                default_branch: r.default_branch,
                archived: r.archived,
                issues_enabled: r.issues_enabled,
                pulls_enabled: r.pulls_enabled,
                releases_enabled: r.releases_enabled,
                allow_merge: r.allow_merge,
                allow_squash: r.allow_squash,
                allow_rebase: r.allow_rebase,
                default_merge_style: r.default_merge_style,
                protect_default_branch: r.protect_default_branch,
                protect_block_force_push: r.protect_block_force_push,
                fork_of_id: r.fork_of_id,
                stars_count: r.stars_count,
                watches_count: r.watches_count,
                forks_count: r.forks_count,
                created_at: r.created_at,
                updated_at: r.updated_at,
            },
            r.owner_username,
        )
    }))
}


pub async fn create_session(pool: &PgPool, user_id: Uuid, token_hash: &str, days: i64) -> Result<()> {
    let expires = Utc::now() + chrono::Duration::days(days);
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn user_from_session(pool: &PgPool, token_hash: &str) -> Result<Option<User>> {
    Ok(sqlx::query_as::<_, User>(
        r#"
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token_hash = $1
          AND s.expires_at > now()
          AND u.is_suspended = FALSE
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?)
}

pub async fn delete_session(pool: &PgPool, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn store_oidc_pending(
    pool: &PgPool,
    state: &str,
    pkce_verifier: &str,
    nonce: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oidc_pending (state, pkce_verifier, nonce) VALUES ($1, $2, $3)
         ON CONFLICT (state) DO UPDATE SET pkce_verifier = EXCLUDED.pkce_verifier, nonce = EXCLUDED.nonce",
    )
    .bind(state)
    .bind(pkce_verifier)
    .bind(nonce)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn take_oidc_pending(pool: &PgPool, state: &str) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM oidc_pending WHERE state = $1 RETURNING pkce_verifier, nonce",
    )
    .bind(state)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn create_repo(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
    description: &str,
    visibility: &str,
) -> Result<Repository> {
    let mut tx = pool.begin().await?;
    let repo = sqlx::query_as::<_, Repository>(
        r#"
        INSERT INTO repositories (owner_id, name, description, visibility)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(owner_id)
    .bind(name)
    .bind(description)
    .bind(visibility)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO repo_counters (repo_id) VALUES ($1)")
        .bind(repo.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO language_stats (repo_id) VALUES ($1)")
        .bind(repo.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(repo)
}

pub async fn get_repo(pool: &PgPool, owner: &str, name: &str) -> Result<Option<(Repository, User)>> {
    let owner_user = match get_user_by_username(pool, owner).await? {
        Some(u) => u,
        None => return Ok(None),
    };
    let repo = sqlx::query_as::<_, Repository>(
        "SELECT * FROM repositories WHERE owner_id = $1 AND name = $2",
    )
    .bind(owner_user.id)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(repo.map(|r| (r, owner_user)))
}

pub async fn list_user_repos(pool: &PgPool, owner_id: Uuid, viewer: Option<Uuid>) -> Result<Vec<Repository>> {
    Ok(sqlx::query_as::<_, Repository>(
        r#"
        SELECT r.* FROM repositories r
        WHERE r.owner_id = $1
          AND (
            r.visibility = 'public'
            OR r.owner_id = $2
            OR EXISTS (
              SELECT 1 FROM collaborators c
              WHERE c.repo_id = r.id AND c.user_id = $2
            )
          )
        ORDER BY r.updated_at DESC
        "#,
    )
    .bind(owner_id)
    .bind(viewer)
    .fetch_all(pool)
    .await?)
}

pub async fn list_public_repos(
    pool: &PgPool,
    search: Option<&str>,
    limit: i64,
) -> Result<Vec<(Repository, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        owner_id: Uuid,
        name: String,
        description: String,
        visibility: String,
        default_branch: String,
        archived: bool,
        issues_enabled: bool,
        pulls_enabled: bool,
        releases_enabled: bool,
        allow_merge: bool,
        allow_squash: bool,
        allow_rebase: bool,
        default_merge_style: String,
        protect_default_branch: bool,
        protect_block_force_push: bool,
        fork_of_id: Option<Uuid>,
        stars_count: i32,
        watches_count: i32,
        forks_count: i32,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        owner_username: String,
    }

    let q = search.map(|s| s.trim()).filter(|s| !s.is_empty());
    let rows: Vec<Row> = if let Some(term) = q {
        let like = format!("%{}%", term.replace('%', "\\%").replace('_', "\\_"));
        sqlx::query_as(
            r#"
            SELECT r.*, u.username AS owner_username
            FROM repositories r
            JOIN users u ON u.id = r.owner_id
            WHERE r.visibility = 'public'
              AND r.archived = false
              AND (
                r.name ILIKE $1 ESCAPE '\'
                OR r.description ILIKE $1 ESCAPE '\'
                OR u.username ILIKE $1 ESCAPE '\'
              )
            ORDER BY r.updated_at DESC
            LIMIT $2
            "#,
        )
        .bind(like)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT r.*, u.username AS owner_username
            FROM repositories r
            JOIN users u ON u.id = r.owner_id
            WHERE r.visibility = 'public'
              AND r.archived = false
            ORDER BY r.updated_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                Repository {
                    id: r.id,
                    owner_id: r.owner_id,
                    name: r.name,
                    description: r.description,
                    visibility: r.visibility,
                    default_branch: r.default_branch,
                    archived: r.archived,
                    issues_enabled: r.issues_enabled,
                    pulls_enabled: r.pulls_enabled,
                    releases_enabled: r.releases_enabled,
                    allow_merge: r.allow_merge,
                    allow_squash: r.allow_squash,
                    allow_rebase: r.allow_rebase,
                    default_merge_style: r.default_merge_style,
                    protect_default_branch: r.protect_default_branch,
                    protect_block_force_push: r.protect_block_force_push,
                    fork_of_id: r.fork_of_id,
                    stars_count: r.stars_count,
                    watches_count: r.watches_count,
                    forks_count: r.forks_count,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                },
                r.owner_username,
            )
        })
        .collect())
}

pub async fn delete_repo(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_repo_settings(
    pool: &PgPool,
    id: Uuid,
    description: &str,
    visibility: &str,
    default_branch: &str,
    issues_enabled: bool,
    pulls_enabled: bool,
    releases_enabled: bool,
    allow_merge: bool,
    allow_squash: bool,
    allow_rebase: bool,
    default_merge_style: &str,
    protect_default_branch: bool,
    protect_block_force_push: bool,
) -> Result<Repository> {
    Ok(sqlx::query_as::<_, Repository>(
        r#"
        UPDATE repositories SET
            description = $2,
            visibility = $3,
            default_branch = $4,
            issues_enabled = $5,
            pulls_enabled = $6,
            releases_enabled = $7,
            allow_merge = $8,
            allow_squash = $9,
            allow_rebase = $10,
            default_merge_style = $11,
            protect_default_branch = $12,
            protect_block_force_push = $13,
            updated_at = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(description)
    .bind(visibility)
    .bind(default_branch)
    .bind(issues_enabled)
    .bind(pulls_enabled)
    .bind(releases_enabled)
    .bind(allow_merge)
    .bind(allow_squash)
    .bind(allow_rebase)
    .bind(default_merge_style)
    .bind(protect_default_branch)
    .bind(protect_block_force_push)
    .fetch_one(pool)
    .await?)
}

pub async fn transfer_repo(pool: &PgPool, id: Uuid, new_owner_id: Uuid) -> Result<Repository> {
    Ok(sqlx::query_as::<_, Repository>(
        "UPDATE repositories SET owner_id = $2, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(new_owner_id)
    .fetch_one(pool)
    .await?)
}

pub async fn set_archived(pool: &PgPool, id: Uuid, archived: bool) -> Result<()> {
    sqlx::query("UPDATE repositories SET archived = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(archived)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn repo_access(pool: &PgPool, repo: &Repository, user_id: Option<Uuid>) -> Result<Access> {
    if let Some(uid) = user_id {
        if uid == repo.owner_id {
            return Ok(Access::Owner);
        }
        if let Some(c) = sqlx::query_as::<_, Collaborator>(
            "SELECT * FROM collaborators WHERE repo_id = $1 AND user_id = $2",
        )
        .bind(repo.id)
        .bind(uid)
        .fetch_optional(pool)
        .await?
        {
            return Ok(match c.role.as_str() {
                "admin" => Access::Admin,
                "write" => Access::Write,
                _ => Access::Read,
            });
        }
    }
    if repo.visibility == "public" {
        return Ok(Access::Read);
    }
    Ok(Access::None)
}

pub async fn add_collaborator(pool: &PgPool, repo_id: Uuid, user_id: Uuid, role: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO collaborators (repo_id, user_id, role) VALUES ($1, $2, $3)
        ON CONFLICT (repo_id, user_id) DO UPDATE SET role = EXCLUDED.role
        "#,
    )
    .bind(repo_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_collaborator(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM collaborators WHERE repo_id = $1 AND user_id = $2")
        .bind(repo_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_collaborators(pool: &PgPool, repo_id: Uuid) -> Result<Vec<(Collaborator, User)>> {
    let rows = sqlx::query_as::<_, Collaborator>(
        "SELECT * FROM collaborators WHERE repo_id = $1 ORDER BY created_at",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for c in rows {
        if let Some(u) = get_user_by_id(pool, c.user_id).await? {
            out.push((c, u));
        }
    }
    Ok(out)
}

pub fn normalize_ssh_key_usage(usage: &str) -> &'static str {
    match usage.trim().to_ascii_lowercase().as_str() {
        "signing" => "signing",
        "both" => "both",
        _ => "authentication",
    }
}

pub async fn add_ssh_key(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    public_key: &str,
    fingerprint: &str,
    key_usage: &str,
) -> Result<SshKey> {
    let key_usage = normalize_ssh_key_usage(key_usage);
    Ok(sqlx::query_as::<_, SshKey>(
        r#"
        INSERT INTO ssh_keys (user_id, name, public_key, fingerprint, key_usage)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(name)
    .bind(public_key)
    .bind(fingerprint)
    .bind(key_usage)
    .fetch_one(pool)
    .await?)
}

pub async fn list_ssh_keys(pool: &PgPool, user_id: Uuid) -> Result<Vec<SshKey>> {
    Ok(
        sqlx::query_as::<_, SshKey>("SELECT * FROM ssh_keys WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(pool)
            .await?,
    )
}

pub async fn delete_ssh_key(pool: &PgPool, user_id: Uuid, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_ssh_key_usage(
    pool: &PgPool,
    user_id: Uuid,
    id: Uuid,
    key_usage: &str,
) -> Result<()> {
    let key_usage = normalize_ssh_key_usage(key_usage);
    sqlx::query("UPDATE ssh_keys SET key_usage = $3 WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .bind(key_usage)
        .execute(pool)
        .await?;
    Ok(())
}

/// Git-over-SSH authentication: only authentication / both keys.
pub async fn user_by_ssh_fingerprint(pool: &PgPool, fingerprint: &str) -> Result<Option<User>> {
    // OpenSSH prints SHA256 fingerprints without `=` padding; tolerate either form.
    let normalized = fingerprint.trim_end_matches('=');
    Ok(sqlx::query_as::<_, User>(
        r#"
        SELECT u.* FROM users u
        JOIN ssh_keys k ON k.user_id = u.id
        WHERE rtrim(k.fingerprint, '=') = $1
          AND k.key_usage IN ('authentication', 'both')
        "#,
    )
    .bind(normalized)
    .fetch_optional(pool)
    .await?)
}

/// Commit signing: only signing / both keys.
pub async fn signing_ssh_key_by_fingerprint(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<SshKey>> {
    let normalized = fingerprint.trim_end_matches('=');
    Ok(sqlx::query_as::<_, SshKey>(
        r#"
        SELECT * FROM ssh_keys
        WHERE rtrim(fingerprint, '=') = $1
          AND key_usage IN ('signing', 'both')
        "#,
    )
    .bind(normalized)
    .fetch_optional(pool)
    .await?)
}

pub async fn user_owns_email(pool: &PgPool, user_id: Uuid, email: &str) -> Result<bool> {
    let email = email.trim().to_ascii_lowercase();
    let row: Option<(bool,)> = sqlx::query_as(
        r#"
        SELECT true FROM users
        WHERE id = $1 AND lower(email) = $2
        UNION
        SELECT true FROM user_emails
        WHERE user_id = $1 AND lower(email) = $2
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn list_all_gpg_keys(pool: &PgPool) -> Result<Vec<GpgKey>> {
    Ok(sqlx::query_as::<_, GpgKey>("SELECT * FROM gpg_keys ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?)
}

pub async fn record_activity(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    repo_id: Option<Uuid>,
    kind: &str,
    summary: &str,
    payload: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO activity_events (actor_id, repo_id, kind, summary, payload) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(actor_id)
    .bind(repo_id)
    .bind(kind)
    .bind(summary)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn latest_activity(pool: &PgPool, limit: i64) -> Result<Vec<(ActivityEvent, Option<User>, Option<Repository>, Option<String>)>> {
    let events = sqlx::query_as::<_, ActivityEvent>(
        "SELECT * FROM activity_events ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    hydrate_activity(pool, events).await
}

pub async fn latest_activity_for_user(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<(ActivityEvent, Option<User>, Option<Repository>, Option<String>)>> {
    let events = sqlx::query_as::<_, ActivityEvent>(
        "SELECT * FROM activity_events WHERE actor_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    hydrate_activity(pool, events).await
}

async fn hydrate_activity(
    pool: &PgPool,
    events: Vec<ActivityEvent>,
) -> Result<Vec<(ActivityEvent, Option<User>, Option<Repository>, Option<String>)>> {
    let mut out = Vec::new();
    for e in events {
        let actor = match e.actor_id {
            Some(id) => get_user_by_id(pool, id).await?,
            None => None,
        };
        let (repo, owner_name) = match e.repo_id {
            Some(id) => {
                let r = get_repo_by_id(pool, id).await?;
                match r {
                    Some((repo, owner_username)) => (Some(repo), Some(owner_username)),
                    None => (None, None),
                }
            }
            None => (None, None),
        };
        out.push((e, actor, repo, owner_name));
    }
    Ok(out)
}

pub async fn bump_commit_activity(pool: &PgPool, user_id: Uuid, day: NaiveDate, n: i32) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO commit_activity (user_id, day, count) VALUES ($1, $2, $3)
        ON CONFLICT (user_id, day) DO UPDATE SET count = commit_activity.count + EXCLUDED.count
        "#,
    )
    .bind(user_id)
    .bind(day)
    .bind(n)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn commit_graph(pool: &PgPool, user_id: Uuid, days: i64) -> Result<Vec<CommitDay>> {
    Ok(sqlx::query_as::<_, CommitDay>(
        r#"
        SELECT day, count FROM commit_activity
        WHERE user_id = $1 AND day >= (CURRENT_DATE - $2::int)
        ORDER BY day
        "#,
    )
    .bind(user_id)
    .bind(days as i32)
    .fetch_all(pool)
    .await?)
}

pub async fn set_language_stats(pool: &PgPool, repo_id: Uuid, stats: serde_json::Value) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO language_stats (repo_id, stats, updated_at) VALUES ($1, $2, now())
        ON CONFLICT (repo_id) DO UPDATE SET stats = EXCLUDED.stats, updated_at = now()
        "#,
    )
    .bind(repo_id)
    .bind(stats)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_language_stats(pool: &PgPool, repo_id: Uuid) -> Result<serde_json::Value> {
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT stats FROM language_stats WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0).unwrap_or_else(|| serde_json::json!({})))
}

pub async fn next_issue_number(pool: &PgPool, repo_id: Uuid) -> Result<i32> {
    let (n,): (i32,) = sqlx::query_as(
        "UPDATE repo_counters SET next_issue = next_issue + 1 WHERE repo_id = $1 RETURNING next_issue - 1",
    )
    .bind(repo_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn next_pull_number(pool: &PgPool, repo_id: Uuid) -> Result<i32> {
    let (n,): (i32,) = sqlx::query_as(
        "UPDATE repo_counters SET next_pull = next_pull + 1 WHERE repo_id = $1 RETURNING next_pull - 1",
    )
    .bind(repo_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn create_issue(
    pool: &PgPool,
    repo_id: Uuid,
    author_id: Uuid,
    number: i32,
    title: &str,
    body: &str,
) -> Result<Issue> {
    Ok(sqlx::query_as::<_, Issue>(
        r#"
        INSERT INTO issues (repo_id, number, author_id, title, body)
        VALUES ($1,$2,$3,$4,$5) RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(number)
    .bind(author_id)
    .bind(title)
    .bind(body)
    .fetch_one(pool)
    .await?)
}

pub async fn list_issues(pool: &PgPool, repo_id: Uuid, state: Option<&str>) -> Result<Vec<Issue>> {
    if let Some(s) = state {
        Ok(sqlx::query_as::<_, Issue>(
            "SELECT * FROM issues WHERE repo_id = $1 AND state = $2 ORDER BY number DESC",
        )
        .bind(repo_id)
        .bind(s)
        .fetch_all(pool)
        .await?)
    } else {
        Ok(sqlx::query_as::<_, Issue>(
            "SELECT * FROM issues WHERE repo_id = $1 ORDER BY number DESC",
        )
        .bind(repo_id)
        .fetch_all(pool)
        .await?)
    }
}

pub async fn get_issue(pool: &PgPool, repo_id: Uuid, number: i32) -> Result<Option<Issue>> {
    Ok(
        sqlx::query_as::<_, Issue>("SELECT * FROM issues WHERE repo_id = $1 AND number = $2")
            .bind(repo_id)
            .bind(number)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn set_issue_state(pool: &PgPool, id: Uuid, state: &str) -> Result<Issue> {
    let closed = if state == "closed" {
        Some(Utc::now())
    } else {
        None
    };
    Ok(sqlx::query_as::<_, Issue>(
        "UPDATE issues SET state = $2, closed_at = $3, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(state)
    .bind(closed)
    .fetch_one(pool)
    .await?)
}

pub async fn create_pull(
    pool: &PgPool,
    repo_id: Uuid,
    author_id: Uuid,
    number: i32,
    title: &str,
    body: &str,
    source: &str,
    target: &str,
) -> Result<PullRequest> {
    create_pull_ex(pool, repo_id, author_id, number, title, body, source, target, None).await
}

pub async fn create_pull_ex(
    pool: &PgPool,
    repo_id: Uuid,
    author_id: Uuid,
    number: i32,
    title: &str,
    body: &str,
    source: &str,
    target: &str,
    source_repo_id: Option<Uuid>,
) -> Result<PullRequest> {
    Ok(sqlx::query_as::<_, PullRequest>(
        r#"
        INSERT INTO pull_requests
          (repo_id, number, author_id, title, body, source_branch, target_branch, source_repo_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(number)
    .bind(author_id)
    .bind(title)
    .bind(body)
    .bind(source)
    .bind(target)
    .bind(source_repo_id)
    .fetch_one(pool)
    .await?)
}

pub async fn list_pulls(pool: &PgPool, repo_id: Uuid, state: Option<&str>) -> Result<Vec<PullRequest>> {
    if let Some(s) = state {
        Ok(sqlx::query_as::<_, PullRequest>(
            "SELECT * FROM pull_requests WHERE repo_id = $1 AND state = $2 ORDER BY number DESC",
        )
        .bind(repo_id)
        .bind(s)
        .fetch_all(pool)
        .await?)
    } else {
        Ok(sqlx::query_as::<_, PullRequest>(
            "SELECT * FROM pull_requests WHERE repo_id = $1 ORDER BY number DESC",
        )
        .bind(repo_id)
        .fetch_all(pool)
        .await?)
    }
}

pub async fn get_pull(pool: &PgPool, repo_id: Uuid, number: i32) -> Result<Option<PullRequest>> {
    Ok(sqlx::query_as::<_, PullRequest>(
        "SELECT * FROM pull_requests WHERE repo_id = $1 AND number = $2",
    )
    .bind(repo_id)
    .bind(number)
    .fetch_optional(pool)
    .await?)
}

pub async fn set_pull_state(
    pool: &PgPool,
    id: Uuid,
    state: &str,
    merge_commit: Option<&str>,
) -> Result<PullRequest> {
    let now = Utc::now();
    Ok(sqlx::query_as::<_, PullRequest>(
        r#"
        UPDATE pull_requests SET
            state = $2,
            merge_commit = COALESCE($3, merge_commit),
            merged_at = CASE WHEN $2 = 'merged' THEN $4 ELSE merged_at END,
            closed_at = CASE WHEN $2 IN ('closed','merged') THEN $4 ELSE NULL END,
            updated_at = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(state)
    .bind(merge_commit)
    .bind(now)
    .fetch_one(pool)
    .await?)
}

pub async fn add_comment(
    pool: &PgPool,
    repo_id: Uuid,
    author_id: Uuid,
    issue_id: Option<Uuid>,
    pull_id: Option<Uuid>,
    body: &str,
) -> Result<Comment> {
    Ok(sqlx::query_as::<_, Comment>(
        r#"
        INSERT INTO comments (repo_id, author_id, issue_id, pull_id, body)
        VALUES ($1,$2,$3,$4,$5) RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(author_id)
    .bind(issue_id)
    .bind(pull_id)
    .bind(body)
    .fetch_one(pool)
    .await?)
}

pub async fn list_issue_comments(pool: &PgPool, issue_id: Uuid) -> Result<Vec<Comment>> {
    Ok(sqlx::query_as::<_, Comment>(
        "SELECT * FROM comments WHERE issue_id = $1 ORDER BY created_at",
    )
    .bind(issue_id)
    .fetch_all(pool)
    .await?)
}

pub async fn list_pull_comments(pool: &PgPool, pull_id: Uuid) -> Result<Vec<Comment>> {
    Ok(sqlx::query_as::<_, Comment>(
        "SELECT * FROM comments WHERE pull_id = $1 ORDER BY created_at",
    )
    .bind(pull_id)
    .fetch_all(pool)
    .await?)
}

pub async fn create_release(
    pool: &PgPool,
    repo_id: Uuid,
    author_id: Uuid,
    tag_name: &str,
    title: &str,
    body: &str,
    is_prerelease: bool,
    is_draft: bool,
) -> Result<Release> {
    Ok(sqlx::query_as::<_, Release>(
        r#"
        INSERT INTO releases (repo_id, author_id, tag_name, title, body, is_prerelease, is_draft)
        VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(author_id)
    .bind(tag_name)
    .bind(title)
    .bind(body)
    .bind(is_prerelease)
    .bind(is_draft)
    .fetch_one(pool)
    .await?)
}

pub async fn update_release(
    pool: &PgPool,
    release_id: Uuid,
    tag_name: &str,
    title: &str,
    body: &str,
    is_prerelease: bool,
    is_draft: bool,
) -> Result<Release> {
    Ok(sqlx::query_as::<_, Release>(
        r#"
        UPDATE releases
        SET tag_name = $2,
            title = $3,
            body = $4,
            is_prerelease = $5,
            is_draft = $6,
            updated_at = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(release_id)
    .bind(tag_name)
    .bind(title)
    .bind(body)
    .bind(is_prerelease)
    .bind(is_draft)
    .fetch_one(pool)
    .await?)
}

pub async fn delete_release(pool: &PgPool, release_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM releases WHERE id = $1")
        .bind(release_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_releases(pool: &PgPool, repo_id: Uuid) -> Result<Vec<Release>> {
    Ok(sqlx::query_as::<_, Release>(
        "SELECT * FROM releases WHERE repo_id = $1 ORDER BY created_at DESC",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_release(pool: &PgPool, repo_id: Uuid, tag: &str) -> Result<Option<Release>> {
    Ok(sqlx::query_as::<_, Release>(
        "SELECT * FROM releases WHERE repo_id = $1 AND tag_name = $2",
    )
    .bind(repo_id)
    .bind(tag)
    .fetch_optional(pool)
    .await?)
}

pub async fn add_release_asset(
    pool: &PgPool,
    release_id: Uuid,
    filename: &str,
    stored_path: &str,
    size_bytes: i64,
    content_type: &str,
) -> Result<ReleaseAsset> {
    Ok(sqlx::query_as::<_, ReleaseAsset>(
        r#"
        INSERT INTO release_assets (release_id, filename, stored_path, size_bytes, content_type)
        VALUES ($1,$2,$3,$4,$5) RETURNING *
        "#,
    )
    .bind(release_id)
    .bind(filename)
    .bind(stored_path)
    .bind(size_bytes)
    .bind(content_type)
    .fetch_one(pool)
    .await?)
}

pub async fn list_release_assets(pool: &PgPool, release_id: Uuid) -> Result<Vec<ReleaseAsset>> {
    Ok(sqlx::query_as::<_, ReleaseAsset>(
        "SELECT * FROM release_assets WHERE release_id = $1 ORDER BY filename",
    )
    .bind(release_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_asset(pool: &PgPool, id: Uuid) -> Result<Option<ReleaseAsset>> {
    Ok(
        sqlx::query_as::<_, ReleaseAsset>("SELECT * FROM release_assets WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn delete_release_asset(pool: &PgPool, id: Uuid) -> Result<Option<ReleaseAsset>> {
    Ok(sqlx::query_as::<_, ReleaseAsset>(
        "DELETE FROM release_assets WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn rename_release_tag(
    pool: &PgPool,
    repo_id: Uuid,
    old_tag: &str,
    new_tag: &str,
) -> Result<Option<Release>> {
    Ok(sqlx::query_as::<_, Release>(
        r#"
        UPDATE releases
        SET tag_name = $3, updated_at = now()
        WHERE repo_id = $1 AND tag_name = $2
        RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(old_tag)
    .bind(new_tag)
    .fetch_optional(pool)
    .await?)
}

pub async fn rewrite_asset_paths_for_tag(
    pool: &PgPool,
    release_id: Uuid,
    old_prefix: &str,
    new_prefix: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE release_assets
        SET stored_path = $3 || substr(stored_path, length($2) + 1)
        WHERE release_id = $1 AND stored_path LIKE $2 || '%'
        "#,
    )
    .bind(release_id)
    .bind(old_prefix)
    .bind(new_prefix)
    .execute(pool)
    .await?;
    Ok(())
}


// ── stars / watches / forks ──────────────────────────────────────────────────

pub async fn toggle_star(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Result<bool> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM repo_stars WHERE repo_id = $1 AND user_id = $2",
    )
    .bind(repo_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if existing.is_some() {
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1 AND user_id = $2")
            .bind(repo_id)
            .bind(user_id)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE repositories SET stars_count = GREATEST(stars_count - 1, 0) WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await?;
        Ok(false)
    } else {
        sqlx::query("INSERT INTO repo_stars (repo_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(repo_id)
            .bind(user_id)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE repositories SET stars_count = stars_count + 1 WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await?;
        Ok(true)
    }
}

pub async fn is_starred(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Result<bool> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM repo_stars WHERE repo_id = $1 AND user_id = $2",
    )
    .bind(repo_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn toggle_watch(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Result<bool> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM repo_watches WHERE repo_id = $1 AND user_id = $2",
    )
    .bind(repo_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if existing.is_some() {
        sqlx::query("DELETE FROM repo_watches WHERE repo_id = $1 AND user_id = $2")
            .bind(repo_id)
            .bind(user_id)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE repositories SET watches_count = GREATEST(watches_count - 1, 0) WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await?;
        Ok(false)
    } else {
        sqlx::query("INSERT INTO repo_watches (repo_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(repo_id)
            .bind(user_id)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE repositories SET watches_count = watches_count + 1 WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await?;
        Ok(true)
    }
}

pub async fn is_watching(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Result<bool> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM repo_watches WHERE repo_id = $1 AND user_id = $2",
    )
    .bind(repo_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Public repos the user has starred (private stars are never returned).
pub async fn list_public_starred_repos(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<(Repository, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        owner_id: Uuid,
        name: String,
        description: String,
        visibility: String,
        default_branch: String,
        archived: bool,
        issues_enabled: bool,
        pulls_enabled: bool,
        releases_enabled: bool,
        allow_merge: bool,
        allow_squash: bool,
        allow_rebase: bool,
        default_merge_style: String,
        protect_default_branch: bool,
        protect_block_force_push: bool,
        fork_of_id: Option<Uuid>,
        stars_count: i32,
        watches_count: i32,
        forks_count: i32,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        owner_username: String,
    }

    let rows: Vec<Row> = sqlx::query_as(
        r#"
        SELECT r.*, u.username AS owner_username
        FROM repo_stars s
        JOIN repositories r ON r.id = s.repo_id
        JOIN users u ON u.id = r.owner_id
        WHERE s.user_id = $1
          AND r.visibility = 'public'
        ORDER BY s.created_at DESC
        LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                Repository {
                    id: r.id,
                    owner_id: r.owner_id,
                    name: r.name,
                    description: r.description,
                    visibility: r.visibility,
                    default_branch: r.default_branch,
                    archived: r.archived,
                    issues_enabled: r.issues_enabled,
                    pulls_enabled: r.pulls_enabled,
                    releases_enabled: r.releases_enabled,
                    allow_merge: r.allow_merge,
                    allow_squash: r.allow_squash,
                    allow_rebase: r.allow_rebase,
                    default_merge_style: r.default_merge_style,
                    protect_default_branch: r.protect_default_branch,
                    protect_block_force_push: r.protect_block_force_push,
                    fork_of_id: r.fork_of_id,
                    stars_count: r.stars_count,
                    watches_count: r.watches_count,
                    forks_count: r.forks_count,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                },
                r.owner_username,
            )
        })
        .collect())
}

/// Recent activity on public repos the user is watching.
pub async fn latest_activity_for_watched_repos(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<(ActivityEvent, Option<User>, Option<Repository>, Option<String>)>> {
    let events = sqlx::query_as::<_, ActivityEvent>(
        r#"
        SELECT ae.*
        FROM activity_events ae
        JOIN repo_watches w ON w.repo_id = ae.repo_id AND w.user_id = $1
        JOIN repositories r ON r.id = ae.repo_id AND r.visibility = 'public'
        ORDER BY ae.created_at DESC
        LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    hydrate_activity(pool, events).await
}

pub async fn create_fork(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
    description: &str,
    visibility: &str,
    fork_of_id: Uuid,
) -> Result<Repository> {
    let mut tx = pool.begin().await?;
    let repo = sqlx::query_as::<_, Repository>(
        r#"
        INSERT INTO repositories (owner_id, name, description, visibility, fork_of_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(owner_id)
    .bind(name)
    .bind(description)
    .bind(visibility)
    .bind(fork_of_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO repo_counters (repo_id) VALUES ($1)")
        .bind(repo.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO language_stats (repo_id) VALUES ($1)")
        .bind(repo.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE repositories SET forks_count = forks_count + 1 WHERE id = $1")
        .bind(fork_of_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(repo)
}

pub async fn get_fork_of_user(pool: &PgPool, fork_of_id: Uuid, owner_id: Uuid) -> Result<Option<Repository>> {
    Ok(sqlx::query_as::<_, Repository>(
        "SELECT * FROM repositories WHERE fork_of_id = $1 AND owner_id = $2",
    )
    .bind(fork_of_id)
    .bind(owner_id)
    .fetch_optional(pool)
    .await?)
}

// ── reactions ────────────────────────────────────────────────────────────────

pub async fn toggle_reaction(
    pool: &PgPool,
    comment_id: Uuid,
    user_id: Uuid,
    emoji: &str,
) -> Result<()> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM comment_reactions WHERE comment_id = $1 AND user_id = $2 AND emoji = $3",
    )
    .bind(comment_id)
    .bind(user_id)
    .bind(emoji)
    .fetch_optional(pool)
    .await?;
    if existing.is_some() {
        sqlx::query(
            "DELETE FROM comment_reactions WHERE comment_id = $1 AND user_id = $2 AND emoji = $3",
        )
        .bind(comment_id)
        .bind(user_id)
        .bind(emoji)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO comment_reactions (comment_id, user_id, emoji) VALUES ($1, $2, $3)",
        )
        .bind(comment_id)
        .bind(user_id)
        .bind(emoji)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn list_reaction_counts(
    pool: &PgPool,
    comment_id: Uuid,
    viewer: Option<Uuid>,
) -> Result<Vec<(String, i64, bool)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        emoji: String,
        count: i64,
        mine: bool,
    }
    let rows: Vec<Row> = sqlx::query_as(
        r#"
        SELECT emoji,
               COUNT(*)::bigint AS count,
               BOOL_OR(user_id = $2) AS mine
        FROM comment_reactions
        WHERE comment_id = $1
        GROUP BY emoji
        ORDER BY emoji
        "#,
    )
    .bind(comment_id)
    .bind(viewer)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.emoji, r.count, r.mine)).collect())
}

// ── branch rules ─────────────────────────────────────────────────────────────

pub async fn list_branch_rules(pool: &PgPool, repo_id: Uuid) -> Result<Vec<BranchRule>> {
    Ok(sqlx::query_as::<_, BranchRule>(
        "SELECT * FROM branch_rules WHERE repo_id = $1 ORDER BY pattern",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await?)
}

pub async fn add_branch_rule(
    pool: &PgPool,
    repo_id: Uuid,
    pattern: &str,
    require_pr: bool,
    block_force_push: bool,
    allow_deletions: bool,
) -> Result<BranchRule> {
    Ok(sqlx::query_as::<_, BranchRule>(
        r#"
        INSERT INTO branch_rules (repo_id, pattern, require_pr, block_force_push, allow_deletions)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(pattern)
    .bind(require_pr)
    .bind(block_force_push)
    .bind(allow_deletions)
    .fetch_one(pool)
    .await?)
}

pub async fn delete_branch_rule(pool: &PgPool, id: Uuid, repo_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM branch_rules WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── user emails / privacy / sessions / gpg ───────────────────────────────────

pub async fn update_username(pool: &PgPool, id: Uuid, username: &str) -> Result<User> {
    Ok(sqlx::query_as::<_, User>(
        "UPDATE users SET username = $2, updated_at = now() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(username)
    .fetch_one(pool)
    .await?)
}

pub async fn update_privacy(
    pool: &PgPool,
    id: Uuid,
    show_email: bool,
    vigilant_mode: bool,
) -> Result<User> {
    Ok(sqlx::query_as::<_, User>(
        r#"
        UPDATE users SET show_email = $2, vigilant_mode = $3, updated_at = now()
        WHERE id = $1 RETURNING *
        "#,
    )
    .bind(id)
    .bind(show_email)
    .bind(vigilant_mode)
    .fetch_one(pool)
    .await?)
}

pub async fn list_user_emails(pool: &PgPool, user_id: Uuid) -> Result<Vec<UserEmail>> {
    Ok(sqlx::query_as::<_, UserEmail>(
        "SELECT * FROM user_emails WHERE user_id = $1 ORDER BY is_primary DESC, email",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

pub async fn add_user_email(pool: &PgPool, user_id: Uuid, email: &str) -> Result<UserEmail> {
    Ok(sqlx::query_as::<_, UserEmail>(
        r#"
        INSERT INTO user_emails (user_id, email, verified, is_primary)
        VALUES ($1, $2, false, false)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(email)
    .fetch_one(pool)
    .await?)
}

pub async fn delete_user_email(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM user_emails WHERE id = $1 AND user_id = $2 AND is_primary = false")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn ensure_primary_email(pool: &PgPool, user_id: Uuid, email: &str) -> Result<()> {
    if email.trim().is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"
        INSERT INTO user_emails (user_id, email, verified, is_primary)
        VALUES ($1, $2, true, true)
        ON CONFLICT (user_id, email) DO UPDATE SET is_primary = true, verified = true
        "#,
    )
    .bind(user_id)
    .bind(email.trim())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_sessions(pool: &PgPool, user_id: Uuid) -> Result<Vec<Session>> {
    Ok(sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

pub async fn delete_session_by_id(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_other_sessions(pool: &PgPool, user_id: Uuid, keep_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user_id)
        .bind(keep_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_gpg_keys(pool: &PgPool, user_id: Uuid) -> Result<Vec<GpgKey>> {
    Ok(sqlx::query_as::<_, GpgKey>(
        "SELECT * FROM gpg_keys WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

pub async fn add_gpg_key(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    public_key: &str,
    fingerprint: &str,
) -> Result<GpgKey> {
    Ok(sqlx::query_as::<_, GpgKey>(
        r#"
        INSERT INTO gpg_keys (user_id, name, public_key, fingerprint)
        VALUES ($1, $2, $3, $4) RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(name)
    .bind(public_key)
    .bind(fingerprint)
    .fetch_one(pool)
    .await?)
}

pub async fn delete_gpg_key(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM gpg_keys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_user_mfa(pool: &PgPool, user_id: Uuid) -> Result<Option<UserMfa>> {
    Ok(sqlx::query_as::<_, UserMfa>("SELECT * FROM user_mfa WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn mfa_is_enabled(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT enabled FROM user_mfa WHERE user_id = $1 AND enabled = TRUE AND totp_secret IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn mfa_start_enroll(pool: &PgPool, user_id: Uuid, pending_secret: &str) -> Result<UserMfa> {
    Ok(sqlx::query_as::<_, UserMfa>(
        r#"
        INSERT INTO user_mfa (user_id, pending_secret, enabled, totp_secret, recovery_code_hashes, updated_at)
        VALUES ($1, $2, FALSE, NULL, '{}', now())
        ON CONFLICT (user_id) DO UPDATE SET
            pending_secret = EXCLUDED.pending_secret,
            updated_at = now()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(pending_secret)
    .fetch_one(pool)
    .await?)
}

pub async fn mfa_confirm_enroll(
    pool: &PgPool,
    user_id: Uuid,
    totp_secret: &str,
    recovery_hashes: &[String],
) -> Result<UserMfa> {
    Ok(sqlx::query_as::<_, UserMfa>(
        r#"
        UPDATE user_mfa SET
            totp_secret = $2,
            pending_secret = NULL,
            enabled = TRUE,
            recovery_code_hashes = $3,
            updated_at = now()
        WHERE user_id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(totp_secret)
    .bind(recovery_hashes)
    .fetch_one(pool)
    .await?)
}

pub async fn mfa_disable(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE user_mfa SET
            enabled = FALSE,
            totp_secret = NULL,
            pending_secret = NULL,
            recovery_code_hashes = '{}',
            updated_at = now()
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mfa_set_recovery_hashes(
    pool: &PgPool,
    user_id: Uuid,
    hashes: &[String],
) -> Result<()> {
    sqlx::query(
        "UPDATE user_mfa SET recovery_code_hashes = $2, updated_at = now() WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(hashes)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_mfa_pending_login(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    minutes: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO mfa_pending_logins (user_id, token_hash, expires_at)
        VALUES ($1, $2, now() + ($3::text || ' minutes')::interval)
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(minutes)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn take_mfa_pending_login(pool: &PgPool, token_hash: &str) -> Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        r#"
        DELETE FROM mfa_pending_logins
        WHERE token_hash = $1 AND expires_at > now()
        RETURNING user_id
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn delete_mfa_pending_for_user(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM mfa_pending_logins WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn export_user_data(pool: &PgPool, user_id: Uuid) -> Result<serde_json::Value> {
    let user = get_user_by_id(pool, user_id).await?.ok_or_else(|| anyhow::anyhow!("missing"))?;
    let emails = list_user_emails(pool, user_id).await?;
    let keys = sqlx::query_as::<_, SshKey>("SELECT * FROM ssh_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    let repos = sqlx::query_as::<_, Repository>("SELECT * FROM repositories WHERE owner_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    Ok(serde_json::json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "bio": user.bio,
            "show_email": user.show_email,
            "vigilant_mode": user.vigilant_mode,
            "created_at": user.created_at,
        },
        "emails": emails,
        "ssh_keys": keys.iter().map(|k| serde_json::json!({
            "name": k.name,
            "fingerprint": k.fingerprint,
            "key_usage": k.key_usage,
            "created_at": k.created_at,
        })).collect::<Vec<_>>(),
        "repositories": repos.iter().map(|r| serde_json::json!({
            "name": r.name,
            "description": r.description,
            "visibility": r.visibility,
            "created_at": r.created_at,
        })).collect::<Vec<_>>(),
    }))
}

pub async fn open_pull_for_branch(
    pool: &PgPool,
    repo_id: Uuid,
    source_branch: &str,
) -> Result<Option<i32>> {
    let row: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT number FROM pull_requests
        WHERE repo_id = $1 AND source_branch = $2 AND state = 'open'
        ORDER BY number DESC LIMIT 1
        "#,
    )
    .bind(repo_id)
    .bind(source_branch)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn register_lfs_object(pool: &PgPool, repo_id: Uuid, oid: &str, size: i64) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO lfs_objects (oid, size_bytes) VALUES ($1, $2)
        ON CONFLICT (oid) DO UPDATE SET size_bytes = EXCLUDED.size_bytes
        "#,
    )
    .bind(oid)
    .bind(size)
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO lfs_repo_objects (repo_id, oid) VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(repo_id)
    .bind(oid)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn lfs_object_size(pool: &PgPool, oid: &str) -> Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT size_bytes FROM lfs_objects WHERE oid = $1")
        .bind(oid)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

// ── webhooks ─────────────────────────────────────────────────────────────────

pub async fn list_webhooks(pool: &PgPool, repo_id: Uuid) -> Result<Vec<Webhook>> {
    Ok(sqlx::query_as::<_, Webhook>(
        "SELECT * FROM webhooks WHERE repo_id = $1 ORDER BY created_at DESC",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await?)
}

pub async fn list_active_webhooks_for_event(
    pool: &PgPool,
    repo_id: Uuid,
    event: &str,
) -> Result<Vec<Webhook>> {
    Ok(sqlx::query_as::<_, Webhook>(
        r#"
        SELECT * FROM webhooks
        WHERE repo_id = $1 AND active = TRUE AND $2 = ANY(events)
        ORDER BY created_at
        "#,
    )
    .bind(repo_id)
    .bind(event)
    .fetch_all(pool)
    .await?)
}

pub async fn get_webhook(pool: &PgPool, id: Uuid, repo_id: Uuid) -> Result<Option<Webhook>> {
    Ok(sqlx::query_as::<_, Webhook>(
        "SELECT * FROM webhooks WHERE id = $1 AND repo_id = $2",
    )
    .bind(id)
    .bind(repo_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn create_webhook(
    pool: &PgPool,
    repo_id: Uuid,
    url: &str,
    secret: &str,
    events: &[String],
) -> Result<Webhook> {
    Ok(sqlx::query_as::<_, Webhook>(
        r#"
        INSERT INTO webhooks (repo_id, url, secret, events)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(repo_id)
    .bind(url)
    .bind(secret)
    .bind(events)
    .fetch_one(pool)
    .await?)
}

pub async fn set_webhook_active(
    pool: &PgPool,
    id: Uuid,
    repo_id: Uuid,
    active: bool,
) -> Result<()> {
    sqlx::query("UPDATE webhooks SET active = $3 WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .bind(active)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_webhook(pool: &PgPool, id: Uuid, repo_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM webhooks WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_webhook_delivery(
    pool: &PgPool,
    webhook_id: Uuid,
    event: &str,
    action: &str,
    success: bool,
    status_code: Option<i32>,
    error: Option<&str>,
    duration_ms: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO webhook_deliveries
            (webhook_id, event, action, success, status_code, error, duration_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(webhook_id)
    .bind(event)
    .bind(action)
    .bind(success)
    .bind(status_code)
    .bind(error)
    .bind(duration_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_recent_webhook_deliveries(
    pool: &PgPool,
    repo_id: Uuid,
    limit: i64,
) -> Result<Vec<(WebhookDelivery, String)>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: i64,
        webhook_id: Uuid,
        event: String,
        action: String,
        success: bool,
        status_code: Option<i32>,
        error: Option<String>,
        duration_ms: Option<i32>,
        created_at: DateTime<Utc>,
        webhook_url: String,
    }
    let rows = sqlx::query_as::<_, Row>(
        r#"
        SELECT d.id, d.webhook_id, d.event, d.action, d.success, d.status_code,
               d.error, d.duration_ms, d.created_at, w.url AS webhook_url
        FROM webhook_deliveries d
        JOIN webhooks w ON w.id = d.webhook_id
        WHERE w.repo_id = $1
        ORDER BY d.created_at DESC
        LIMIT $2
        "#,
    )
    .bind(repo_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                WebhookDelivery {
                    id: r.id,
                    webhook_id: r.webhook_id,
                    event: r.event,
                    action: r.action,
                    success: r.success,
                    status_code: r.status_code,
                    error: r.error,
                    duration_ms: r.duration_ms,
                    created_at: r.created_at,
                },
                r.webhook_url,
            )
        })
        .collect())
}
