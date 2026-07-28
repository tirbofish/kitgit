use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub oidc_sub: String,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub bio: String,
    pub avatar_path: Option<String>,
    pub avatar_url: Option<String>,
    pub is_site_admin: bool,
    pub is_suspended: bool,
    pub show_email: bool,
    pub vigilant_mode: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct UserMfa {
    pub user_id: Uuid,
    pub totp_secret: Option<String>,
    pub pending_secret: Option<String>,
    pub enabled: bool,
    pub recovery_code_hashes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub default_branch: String,
    pub archived: bool,
    pub issues_enabled: bool,
    pub pulls_enabled: bool,
    pub releases_enabled: bool,
    pub allow_merge: bool,
    pub allow_squash: bool,
    pub allow_rebase: bool,
    pub default_merge_style: String,
    pub protect_default_branch: bool,
    pub protect_block_force_push: bool,
    pub fork_of_id: Option<Uuid>,
    pub stars_count: i32,
    pub watches_count: i32,
    pub forks_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserEmail {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub verified: bool,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct GpgKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BranchRule {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub pattern: String,
    pub require_pr: bool,
    pub block_force_push: bool,
    pub allow_deletions: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CommentReaction {
    pub comment_id: Uuid,
    pub user_id: Uuid,
    pub emoji: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct SshKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    /// `authentication`, `signing`, or `both`.
    pub key_usage: String,
    pub created_at: DateTime<Utc>,
}

impl SshKey {
    pub fn allows_authentication(&self) -> bool {
        self.key_usage == "authentication" || self.key_usage == "both"
    }

    pub fn allows_signing(&self) -> bool {
        self.key_usage == "signing" || self.key_usage == "both"
    }

    pub fn usage_label(&self) -> &'static str {
        match self.key_usage.as_str() {
            "signing" => "Signing",
            "both" => "Authentication & Signing",
            _ => "Authentication",
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct Collaborator {
    pub repo_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ActivityEvent {
    pub id: i64,
    pub actor_id: Option<Uuid>,
    pub repo_id: Option<Uuid>,
    pub kind: String,
    pub summary: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Issue {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub number: i32,
    pub author_id: Uuid,
    pub title: String,
    pub body: String,
    pub state: String,
    pub milestone_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PullRequest {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub number: i32,
    pub author_id: Uuid,
    pub title: String,
    pub body: String,
    pub state: String,
    pub source_branch: String,
    pub target_branch: String,
    pub merge_commit: Option<String>,
    pub source_repo_id: Option<Uuid>,
    pub milestone_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub merged_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Label {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub name: String,
    pub color: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl Label {
    pub fn bg_color(&self) -> String {
        format!("#{}", self.color.trim_start_matches('#'))
    }

    pub fn text_color(&self) -> &'static str {
        let hex = self.color.trim_start_matches('#');
        if hex.len() != 6 {
            return "#ffffff";
        }
        let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0) as f32;
        let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0) as f32;
        let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0) as f32;
        let lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
        if lum > 0.55 {
            "#111111"
        } else {
            "#ffffff"
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct Milestone {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub title: String,
    pub description: String,
    pub due_on: Option<NaiveDate>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Comment {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub author_id: Uuid,
    pub issue_id: Option<Uuid>,
    pub pull_id: Option<Uuid>,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Release {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub author_id: Uuid,
    pub tag_name: String,
    pub title: String,
    pub body: String,
    pub is_prerelease: bool,
    pub is_draft: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ReleaseAsset {
    pub id: Uuid,
    pub release_id: Uuid,
    pub filename: String,
    pub stored_path: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CommitDay {
    pub day: NaiveDate,
    pub count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    None,
    Read,
    Write,
    Admin,
    Owner,
}

impl Access {
    pub fn can_read(self) -> bool {
        !matches!(self, Access::None)
    }
    pub fn can_write(self) -> bool {
        matches!(self, Access::Write | Access::Admin | Access::Owner)
    }
    pub fn can_admin(self) -> bool {
        matches!(self, Access::Admin | Access::Owner)
    }
    pub fn can_owner(self) -> bool {
        matches!(self, Access::Owner)
    }
}
