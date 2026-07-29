use crate::og::SocialMeta;
use crate::db::models::{
    Access, BranchRule, CommitDay, GpgKey, Issue, Label, Milestone, Notification, PullRequest,
    Release, RepoMirror, Repository, SshKey, User, UserEmail,
};
use crate::db::DeployKey;
use askama::Template;
use askama_web::WebTemplate;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ΓöÇΓöÇ view models ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

pub struct ActivityRow {
    pub kind: String,
    /// Text before an optional issue/PR reference (e.g. `"commented on "`).
    pub summary: String,
    /// Linked phrase such as `"issue #1"` / `"pull #2"`.
    pub ref_label: Option<String>,
    pub ref_href: Option<String>,
    pub actor_username: Option<String>,
    pub actor_avatar: Option<String>,
    pub repo_owner: Option<String>,
    pub repo_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct ReactionView {
    pub emoji: String,
    pub label: String,
    pub count: i64,
    pub mine: bool,
}

pub struct CommentView {
    pub id: Uuid,
    pub author: User,
    pub avatar_url: String,
    pub body_html: String,
    pub created_at: DateTime<Utc>,
    pub reactions: Vec<ReactionView>,
}

pub struct DiffFileView {
    pub path: String,
    pub anchor: String,
    pub additions: u32,
    pub deletions: u32,
    pub html: String,
    pub truncated: bool,
    pub total_lines: usize,
    pub binary: bool,
}

pub struct TreeEntryView {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub mode: String,
}

pub struct CommitView {
    pub id: String,
    pub short_id: String,
    pub message: String,
    pub author: String,
    pub email: String,
    pub time: i64,
    pub verified: bool,
    pub verify_kind: String,
    pub verify_fingerprint: String,
    pub verify_fingerprint_label: String,
    pub verified_at: String,
}

pub struct CollaboratorView {
    pub user: User,
    pub role: String,
    pub avatar_url: String,
}

pub struct WebhookView {
    pub id: Uuid,
    pub url: String,
    pub has_secret: bool,
    pub events_label: String,
    pub active: bool,
    pub created_at: String,
}

pub struct WebhookDeliveryView {
    pub event: String,
    pub action: String,
    pub success: bool,
    pub status_label: String,
    pub webhook_url: String,
    pub created_at: String,
}

pub struct LabelOption {
    pub label: Label,
    pub selected: bool,
}

pub struct MilestoneOption {
    pub milestone: Milestone,
    pub selected: bool,
}

pub struct IssueListItem {
    pub issue: Issue,
    pub labels: Vec<Label>,
    pub milestone: Option<Milestone>,
}

pub struct PullListItem {
    pub pull: PullRequest,
    pub labels: Vec<Label>,
    pub milestone: Option<Milestone>,
}

pub struct LanguageStatView {
    pub name: String,
    pub percent: f64,
    pub color: String,
}

pub struct BranchRow {
    pub name: String,
    pub is_default: bool,
    pub updated: String,
    pub ahead: usize,
    pub behind: usize,
    pub pull_number: Option<i32>,
}

pub struct TagRow {
    pub name: String,
    pub short_id: String,
    pub target: String,
    pub message: String,
    pub updated: String,
    pub has_release: bool,
}

pub struct ReleaseAssetView {
    pub id: Uuid,
    pub filename: String,
    pub size_label: String,
    pub content_type: String,
}

// ΓöÇΓöÇ page templates ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

#[derive(Template, WebTemplate)]
#[template(path = "home.html")]
pub struct HomeTemplate {
    pub viewer: Option<User>,
    pub motd: String,
    pub my_repos: Vec<Repository>,
    pub activities: Vec<ActivityRow>,
    pub social: SocialMeta,
}

pub struct ExploreRepo {
    pub owner: String,
    pub repo: Repository,
}

pub struct ExploreIssueHit {
    pub owner: String,
    pub repo_name: String,
    pub number: i32,
    pub title: String,
    pub state: String,
    pub visibility: String,
    pub updated_at: DateTime<Utc>,
}

pub struct ExplorePullHit {
    pub owner: String,
    pub repo_name: String,
    pub number: i32,
    pub title: String,
    pub state: String,
    pub visibility: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Template, WebTemplate)]
#[template(path = "explore.html")]
pub struct ExploreTemplate {
    pub viewer: Option<User>,
    pub query: String,
    pub search_type: String,
    pub repos: Vec<ExploreRepo>,
    pub users: Vec<User>,
    pub issues: Vec<ExploreIssueHit>,
    pub pulls: Vec<ExplorePullHit>,
    pub social: SocialMeta,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub viewer: Option<User>,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "signup.html")]
pub struct SignupTemplate {
    pub viewer: Option<User>,
    pub error: Option<String>,
    pub signups_enabled: bool,
    pub signup_disabled_message: String,
    pub invite: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub viewer: Option<User>,
    pub status: u16,
    pub message: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "new_repo.html")]
pub struct NewRepoTemplate {
    pub viewer: Option<User>,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "profile_settings.html")]
pub struct ProfileSettingsTemplate {
    pub viewer: Option<User>,
    pub user: User,
    pub avatar_url: String,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "account_settings.html")]
pub struct AccountSettingsTemplate {
    pub viewer: Option<User>,
    pub user: User,
    pub emails: Vec<UserEmail>,
    pub sessions: Vec<SessionView>,
    pub current_session_id: Option<Uuid>,
    pub audit_entries: Vec<AuditEntryView>,
    pub error: Option<String>,
    pub message: Option<String>,
}

pub struct AuditEntryView {
    pub action: String,
    pub action_label: String,
    pub ip: String,
    pub user_agent: String,
    pub metadata: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Template, WebTemplate)]
#[template(path = "mfa_challenge.html")]
pub struct MfaChallengeTemplate {
    pub viewer: Option<User>,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "mfa_settings.html")]
pub struct MfaSettingsTemplate {
    pub viewer: Option<User>,
    pub user: User,
    pub enabled: bool,
    pub pending: bool,
    pub secret: Option<String>,
    pub qr_data_uri: Option<String>,
    pub recovery_codes: Option<Vec<String>>,
    pub recovery_remaining: usize,
    pub error: Option<String>,
    pub message: Option<String>,
}

pub struct SessionView {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub is_current: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "keys_settings.html")]
pub struct KeysSettingsTemplate {
    pub viewer: Option<User>,
    pub keys: Vec<SshKey>,
    pub gpg_keys: Vec<GpgKey>,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "profile.html")]
pub struct ProfileTemplate {
    pub viewer: Option<User>,
    pub profile: User,
    pub avatar_url: String,
    pub repos: Vec<Repository>,
    pub starred: Vec<ExploreRepo>,
    pub watched_activity: Vec<ActivityRow>,
    pub graph: Vec<CommitDay>,
    pub has_activity: bool,
    pub is_self: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_home.html")]
pub struct RepoHomeTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub owner_avatar: String,
    pub clone_http: String,
    pub clone_ssh: String,
    pub branches: Vec<String>,
    pub current_branch: String,
    pub entries: Vec<TreeEntryView>,
    pub readme_html: Option<String>,
    pub languages: Vec<LanguageStatView>,
    pub empty: bool,
    pub latest_commit: Option<CommitView>,
    pub starred: bool,
    pub watching: bool,
    pub forked_from: Option<(String, String)>,
    pub social: SocialMeta,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_tree.html")]
pub struct RepoTreeTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub branch: String,
    pub path: String,
    pub breadcrumbs: Vec<(String, String)>,
    pub entries: Vec<TreeEntryView>,
    pub readme_html: Option<String>,
    pub latest_commit: Option<CommitView>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_blob.html")]
pub struct RepoBlobTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub branch: String,
    pub path: String,
    pub breadcrumbs: Vec<(String, String)>,
    pub binary: bool,
    pub size: usize,
    pub content_html: Option<String>,
    pub is_markdown: bool,
    pub clone_http: String,
    pub clone_ssh: String,
}

pub struct BlameLineView {
    pub line_no: usize,
    pub content: String,
    pub commit_id: String,
    pub short_id: String,
    pub author: String,
    pub time_display: String,
    pub summary: String,
    pub hunk_start: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_blame.html")]
pub struct RepoBlameTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub branch: String,
    pub path: String,
    pub breadcrumbs: Vec<(String, String)>,
    pub lines: Vec<BlameLineView>,
    pub binary: bool,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_history.html")]
pub struct RepoHistoryTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub branch: String,
    pub path: String,
    pub breadcrumbs: Vec<(String, String)>,
    pub commits: Vec<CommitView>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_commits.html")]
pub struct RepoCommitsTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub branch: String,
    pub commits: Vec<CommitView>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_commit.html")]
pub struct RepoCommitTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub commit: CommitView,
    pub message_html: String,
    pub diff_html: String,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_diff.html")]
pub struct RepoDiffTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub commit: CommitView,
    pub diff_html: String,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_branches.html")]
pub struct RepoBranchesTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<BranchRow>,
    pub tags: Vec<TagRow>,
    pub clone_http: String,
    pub clone_ssh: String,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "issues_list.html")]
pub struct IssuesListTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub issues: Vec<IssueListItem>,
    pub labels: Vec<Label>,
    pub milestones: Vec<Milestone>,
    pub state_filter: String,
    pub label_filter: Option<Uuid>,
    pub milestone_filter: Option<Uuid>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "issue_new.html")]
pub struct IssueNewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub labels: Vec<Label>,
    pub milestones: Vec<Milestone>,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "issue_view.html")]
pub struct IssueViewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub issue: Issue,
    pub author: User,
    pub author_avatar: String,
    pub body_html: String,
    pub comments: Vec<CommentView>,
    pub labels: Vec<Label>,
    pub label_options: Vec<LabelOption>,
    pub milestone: Option<Milestone>,
    pub milestone_options: Vec<MilestoneOption>,
    pub can_triage: bool,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "pulls_list.html")]
pub struct PullsListTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub pulls: Vec<PullListItem>,
    pub labels: Vec<Label>,
    pub milestones: Vec<Milestone>,
    pub state_filter: String,
    pub label_filter: Option<Uuid>,
    pub milestone_filter: Option<Uuid>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "pull_new.html")]
pub struct PullNewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub branches: Vec<String>,
    pub labels: Vec<Label>,
    pub milestones: Vec<Milestone>,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
    pub upstream: Option<(String, String)>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pull_view.html")]
pub struct PullViewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub pull: PullRequest,
    pub author: User,
    pub author_avatar: String,
    pub body_html: String,
    pub comments: Vec<CommentView>,
    pub commits: Vec<CommitView>,
    pub diff_files: Vec<DiffFileView>,
    pub tab: String,
    pub conversation_count: usize,
    pub can_merge: bool,
    pub merge_styles: Vec<String>,
    pub labels: Vec<Label>,
    pub label_options: Vec<LabelOption>,
    pub milestone: Option<Milestone>,
    pub milestone_options: Vec<MilestoneOption>,
    pub can_triage: bool,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "labels_list.html")]
pub struct LabelsListTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub labels: Vec<Label>,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "milestones_list.html")]
pub struct MilestonesListTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub milestones: Vec<Milestone>,
    pub state_filter: String,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "releases_list.html")]
pub struct ReleasesListTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub releases: Vec<Release>,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "release_new.html")]
pub struct ReleaseNewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
    pub tag_name: String,
    pub title: String,
    pub body: String,
    pub target: String,
    pub is_prerelease: bool,
    pub is_draft: bool,
    pub branches: Vec<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "release_edit.html")]
pub struct ReleaseEditTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub release: Release,
    pub error: Option<String>,
    pub clone_http: String,
    pub clone_ssh: String,
    pub target: String,
    pub branches: Vec<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "release_view.html")]
pub struct ReleaseViewTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub release: Release,
    pub author: User,
    pub author_avatar: String,
    pub body_html: String,
    pub assets: Vec<ReleaseAssetView>,
    pub tag_short: String,
    pub tag_target: String,
    pub clone_http: String,
    pub clone_ssh: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_settings.html")]
pub struct RepoSettingsTemplate {
    pub viewer: Option<User>,
    pub owner: User,
    pub repo: Repository,
    pub access: Access,
    pub collaborators: Vec<CollaboratorView>,
    pub branches: Vec<String>,
    pub branch_rules: Vec<BranchRule>,
    pub mirror: Option<RepoMirror>,
    pub deploy_keys: Vec<DeployKey>,
    pub webhooks: Vec<WebhookView>,
    pub webhook_deliveries: Vec<WebhookDeliveryView>,
    pub clone_http: String,
    pub clone_ssh: String,
    pub is_site_admin: bool,
    pub error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin.html")]
pub struct AdminTemplate {
    pub viewer: Option<User>,
    pub users: Vec<User>,
    pub user_query: String,
    pub user_page: i64,
    pub user_pages: i64,
    pub user_total: i64,
    pub motd: String,
    pub announcement: String,
    pub signups_enabled: bool,
    pub signup_disabled_message: String,
    pub invites: Vec<AdminInviteView>,
    pub repos: Vec<AdminRepoView>,
    pub repo_query: String,
    pub repo_page: i64,
    pub repo_pages: i64,
    pub repo_total: i64,
    pub stats: AdminStatsView,
    pub flash: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_user_audit.html")]
pub struct AdminUserAuditTemplate {
    pub viewer: Option<User>,
    pub user: User,
    pub audit_entries: Vec<AuditEntryView>,
}

pub struct AdminInviteView {
    pub id: Uuid,
    pub code: String,
    pub created_at: DateTime<Utc>,
}

pub struct AdminRepoView {
    pub id: Uuid,
    pub owner: String,
    pub name: String,
    pub visibility: String,
    pub archived: bool,
    pub updated_at: DateTime<Utc>,
}

pub struct AdminStatsView {
    pub user_count: i64,
    pub repo_count: i64,
    pub public_repo_count: i64,
    pub recent_signups: i64,
    pub active_invites: i64,
    pub disk_label: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "notifications.html")]
pub struct NotificationsTemplate {
    pub viewer: Option<User>,
    pub notifications: Vec<Notification>,
    pub unread_count: i64,
}
