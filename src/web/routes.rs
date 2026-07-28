use crate::auth::{
    self, clear_mfa_pending_cookie, clear_session_cookie, current_user, mfa_pending_cookie_header,
    mfa_pending_from_headers, session_cookie_header, AuthState, LoginOutcome,
};
use crate::db::models::{Access, Comment, Repository, User};
use crate::db::queries;
use crate::git;
use crate::git::ssh::fingerprint_ssh_pubkey;
use crate::highlight::highlight;
use crate::markdown::{MarkdownRepoBase, parent_dir, render_markdown, render_markdown_in_repo};
use crate::og;
use crate::state::AppState;
use crate::web::templates::*;
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::body::Body;
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

// â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub type AppResult<T> = Result<T, AppError>;

pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "login required")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("internal: {err:#}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
    pub fn with_message(mut self, msg: String) -> Self {
        self.message = msg;
        self
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(e)
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ErrorTemplate {
            viewer: None,
            status: self.status.as_u16(),
            message: self.message,
        };
        (self.status, body).into_response()
    }
}

fn redirect(to: &str) -> Response {
    Redirect::to(to).into_response()
}

pub fn redirect_see_other(to: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, to.to_string())]).into_response()
}

fn redirect_with_cookie(to: &str, cookie: HeaderValue) -> Response {
    let location = HeaderValue::from_str(to).unwrap_or_else(|_| HeaderValue::from_static("/"));
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, location), (SET_COOKIE, cookie)],
    )
        .into_response()
}

fn redirect_with_cookies(to: &str, cookies: Vec<HeaderValue>) -> Response {
    let location = HeaderValue::from_str(to).unwrap_or_else(|_| HeaderValue::from_static("/"));
    let mut res = (StatusCode::SEE_OTHER, [(LOCATION, location)]).into_response();
    for c in cookies {
        res.headers_mut().append(SET_COOKIE, c);
    }
    res
}

pub fn avatar_url_for(user: &User) -> String {
    let bust = user.updated_at.timestamp();
    // Always go through our avatar endpoint when a local file exists.
    if user.avatar_path.is_some() {
        return format!("/avatars/{}?v={}", user.id, bust);
    }
    // External OIDC pictures are fine in <img src>, but never use our own
    // /avatars/{id} URL as avatar_url â€” that creates a redirect loop.
    if let Some(ref url) = user.avatar_url {
        if !url.is_empty() && !is_self_avatar_url(url, user.id) {
            return url.clone();
        }
    }
    format!("/avatars/{}?v={}", user.id, bust)
}

fn is_self_avatar_url(url: &str, user_id: Uuid) -> bool {
    let id = user_id.to_string();
    if url == format!("/avatars/{id}") || url.starts_with(&format!("/avatars/{id}?")) {
        return true;
    }
    // Absolute URLs that point back at this app's avatar route.
    if let Ok(u) = url::Url::parse(url) {
        let path = u.path().trim_end_matches('/');
        if path == format!("/avatars/{id}") {
            return true;
        }
    }
    false
}

fn sniff_image_ext(data: &[u8], declared_ct: &str) -> Option<&'static str> {
    if data.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n']) {
        return Some("png");
    }
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return Some("jpg");
    }
    if data.len() >= 6 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Some("gif");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some("webp");
    }
    match declared_ct {
        "image/png" => Some("png"),
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        _ if declared_ct.starts_with("image/") => Some("bin"),
        _ => None,
    }
}

fn initials_avatar_svg(user: &User) -> Vec<u8> {
    let label = if !user.display_name.trim().is_empty() {
        user.display_name.as_str()
    } else {
        user.username.as_str()
    };
    let mut initials = String::new();
    for part in label.split(|c: char| c.is_whitespace() || c == '-' || c == '_') {
        if let Some(ch) = part.chars().find(|c| c.is_alphanumeric()) {
            initials.push(ch.to_ascii_uppercase());
            if initials.chars().count() == 2 {
                break;
            }
        }
    }
    if initials.is_empty() {
        initials.push('?');
    }
    // Deterministic muted tone from user id.
    let bytes = user.id.as_bytes();
    let h = bytes.iter().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(*b as u32));
    let r = 40 + (h % 80) as u8;
    let g = 40 + ((h >> 8) % 80) as u8;
    let b = 40 + ((h >> 16) % 80) as u8;
    let bg = format!("#{r:02x}{g:02x}{b:02x}");
    let safe: String = initials
        .chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            _ => c.to_string(),
        })
        .collect();
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
<rect width="64" height="64" fill="{bg}"/>
<text x="32" y="34" text-anchor="middle" dominant-baseline="middle"
 font-family="JetBrains Mono, ui-monospace, monospace" font-size="22" font-weight="700" fill="#f4f1ea">{safe}</text>
</svg>"##
    )
    .into_bytes()
}

const DIFF_RENDER_MAX_LINES: usize = 50;

fn language_stat_views(stats: serde_json::Value) -> Vec<LanguageStatView> {
    let enriched = git::languages::enrich_language_colors(stats);
    let Some(obj) = enriched.as_object() else {
        return Vec::new();
    };
    let mut out: Vec<LanguageStatView> = obj
        .iter()
        .map(|(name, meta)| LanguageStatView {
            name: name.clone(),
            percent: meta
                .get("percent")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
            color: meta
                .get("color")
                .and_then(|v| v.as_str())
                .unwrap_or("#858585")
                .to_string(),
        })
        .collect();
    out.sort_by(|a, b| {
        b.percent
            .partial_cmp(&a.percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn reaction_label(emoji: &str) -> String {
    match emoji {
        "+1" => "ðŸ‘".into(),
        "-1" => "ðŸ‘Ž".into(),
        "heart" => "â¤ï¸".into(),
        "laugh" => "ðŸ˜„".into(),
        "rocket" => "ðŸš€".into(),
        "eyes" => "ðŸ‘€".into(),
        other => other.to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            _ => c.to_string(),
        })
        .collect()
}

fn readme_to_html(
    name: &str,
    src: &str,
    owner: &str,
    repo: &str,
    git_ref: &str,
    dir: &str,
    grepo: &git2::Repository,
) -> String {
    if name.ends_with(".md") || name.ends_with(".MD") {
        let base = MarkdownRepoBase {
            owner,
            repo,
            git_ref,
            dir,
        };
        render_markdown_in_repo(src, &base, |path| git::path_is_dir(grepo, git_ref, path))
    } else {
        format!("<pre>{}</pre>", html_escape(src))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitRefKind {
    /// Explicit pull-request wording (`pull request #N`, `Merge pull request #N`).
    Pull,
    /// Explicit issue wording (`issue #N`).
    Issue,
    /// Closing keywords (`fixes #N`, `closes #N`, …): prefer issue if it exists, else pull.
    Closing,
    /// Bare `#N` — default to issues.
    Bare,
}

fn classify_commit_ref(before: &str) -> CommitRefKind {
    let lower: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphabetic() || c.is_whitespace())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .to_ascii_lowercase();
    let trimmed = lower.trim_end();
    if trimmed.ends_with("pull request") || trimmed.ends_with("pull requests") {
        return CommitRefKind::Pull;
    }
    // "pull #N" but not as part of another word
    if trimmed == "pull" || trimmed.ends_with(" pull") {
        return CommitRefKind::Pull;
    }
    if trimmed.ends_with("issue") || trimmed.ends_with("issues") {
        return CommitRefKind::Issue;
    }
    for kw in [
        "fix", "fixes", "fixed", "fixing", "close", "closes", "closed", "closing", "resolve",
        "resolves", "resolved", "resolving",
    ] {
        if trimmed == kw || trimmed.ends_with(&format!(" {kw}")) {
            return CommitRefKind::Closing;
        }
    }
    CommitRefKind::Bare
}

fn parse_hash_number(s: &str) -> Option<(usize, i32)> {
    // `s` starts at '#'
    if !s.starts_with('#') {
        return None;
    }
    let digits: String = s[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let n: i32 = digits.parse().ok()?;
    if n <= 0 {
        return None;
    }
    Some((1 + digits.len(), n))
}

/// Escape a commit message and turn GitHub-style `#N` refs into issue/PR links.
async fn linkify_commit_message(
    pool: &sqlx::PgPool,
    repo_id: Uuid,
    owner: &str,
    repo: &str,
    message: &str,
) -> String {
    let mut out = String::with_capacity(message.len() + 32);
    let mut i = 0;
    let bytes = message.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'#' {
            if let Some((len, number)) = parse_hash_number(&message[i..]) {
                // Avoid matching mid-word like `C#1` or `foo#1` — require start or non-alnum before.
                let ok_boundary = i == 0
                    || !message[..i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric());
                if ok_boundary {
                    let kind = classify_commit_ref(&message[..i]);
                    let href = match kind {
                        CommitRefKind::Pull => format!("/{owner}/{repo}/pulls/{number}"),
                        CommitRefKind::Issue | CommitRefKind::Bare => {
                            format!("/{owner}/{repo}/issues/{number}")
                        }
                        CommitRefKind::Closing => {
                            if queries::get_issue(pool, repo_id, number)
                                .await
                                .ok()
                                .flatten()
                                .is_some()
                            {
                                format!("/{owner}/{repo}/issues/{number}")
                            } else if queries::get_pull(pool, repo_id, number)
                                .await
                                .ok()
                                .flatten()
                                .is_some()
                            {
                                format!("/{owner}/{repo}/pulls/{number}")
                            } else {
                                format!("/{owner}/{repo}/issues/{number}")
                            }
                        }
                    };
                    let label = html_escape(&message[i..i + len]);
                    out.push_str(&format!(r#"<a href="{href}">{label}</a>"#));
                    i += len;
                    continue;
                }
            }
        }
        // Copy one char, escaping as needed.
        let ch = message[i..].chars().next().unwrap();
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod commit_ref_tests {
    use super::{classify_commit_ref, parse_hash_number, CommitRefKind};

    #[test]
    fn parse_hash_number_basic() {
        assert_eq!(parse_hash_number("#12 from"), Some((3, 12)));
        assert_eq!(parse_hash_number("#0"), None);
        assert_eq!(parse_hash_number("#"), None);
        assert_eq!(parse_hash_number("12"), None);
    }

    #[test]
    fn classify_merge_pull_request() {
        assert_eq!(
            classify_commit_ref("Merge pull request "),
            CommitRefKind::Pull
        );
        assert_eq!(classify_commit_ref("fixes "), CommitRefKind::Closing);
        assert_eq!(classify_commit_ref("closes "), CommitRefKind::Closing);
        assert_eq!(classify_commit_ref("issue "), CommitRefKind::Issue);
        assert_eq!(classify_commit_ref("hello "), CommitRefKind::Bare);
    }
}

fn diff_line_class(line: &str) -> &'static str {
    if line.starts_with("+++") || line.starts_with("---") {
        "kg-diff__meta"
    } else if line.starts_with('+') {
        "kg-diff__add"
    } else if line.starts_with('-') {
        "kg-diff__del"
    } else if line.starts_with("@@") {
        "kg-diff__hunk"
    } else if line.starts_with('\\') {
        // Unified-diff meta, e.g. `\ No newline at end of file`
        "kg-diff__meta"
    } else if line.starts_with("diff ")
        || line.starts_with("index ")
        || line.starts_with("similarity ")
        || line.starts_with("rename ")
        || line.starts_with("new file ")
        || line.starts_with("deleted file ")
        || line.starts_with("old mode ")
        || line.starts_with("new mode ")
    {
        "kg-diff__meta"
    } else {
        ""
    }
}

fn append_diff_line(out: &mut String, line: &str) {
    let class = diff_line_class(line);
    if class.is_empty() {
        out.push_str(&html_escape(line));
    } else {
        out.push_str(&format!(
            "<span class=\"{class}\">{}</span>",
            html_escape(line)
        ));
    }
    out.push('\n');
}

fn render_diff_html(diff: &str) -> String {
    let lines: Vec<&str> = diff.lines().collect();
    let (html, truncated, total) = render_diff_lines(&lines, Some(DIFF_RENDER_MAX_LINES));
    if truncated {
        format!(
            "{html}<p class=\"kg-diff__truncated\">Large diffs are not rendered by default. Showing the first {DIFF_RENDER_MAX_LINES} of {total} lines.</p>"
        )
    } else {
        html
    }
}

/// Render unified-diff lines. When `max_lines` is set, stop after that many
/// lines (GitHub-style truncation for oversized patches).
fn render_diff_lines(lines: &[&str], max_lines: Option<usize>) -> (String, bool, usize) {
    let total = lines.len();
    let limit = max_lines.unwrap_or(total);
    let truncated = total > limit;
    let mut out = String::from("<pre class=\"kg-diff\">");
    for line in lines.iter().take(limit) {
        append_diff_line(&mut out, line);
    }
    out.push_str("</pre>");
    (out, truncated, total)
}

fn diff_file_path(header: &str) -> String {
    // `diff --git a/path b/path` (paths may contain spaces rarely; take b/ side)
    if let Some(rest) = header.strip_prefix("diff --git ") {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            let b = parts[1];
            return b.strip_prefix("b/").unwrap_or(b).to_string();
        }
        if let Some(a) = parts.first() {
            return a.strip_prefix("a/").unwrap_or(a).to_string();
        }
    }
    "unknown".into()
}

fn anchor_for_path(path: &str, idx: usize) -> String {
    let safe: String = path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("diff-{idx}-{safe}")
}

fn parse_diff_files(diff: &str) -> Vec<DiffFileView> {
    let mut files = Vec::new();
    if diff.trim().is_empty() {
        return files;
    }
    let mut current: Option<(String, Vec<String>)> = None;

    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            if let Some((path, lines)) = current.take() {
                files.push(build_diff_file(files.len(), path, &lines));
            }
            current = Some((diff_file_path(line), vec![line.to_string()]));
        } else if let Some((_, ref mut lines)) = current {
            lines.push(line.to_string());
        } else {
            // Preamble without a file header â€” treat as one blob.
            current = Some(("diff".into(), vec![line.to_string()]));
        }
    }
    if let Some((path, lines)) = current {
        files.push(build_diff_file(files.len(), path, &lines));
    }
    files
}

fn build_diff_file(idx: usize, path: String, lines: &[String]) -> DiffFileView {
    let mut additions = 0u32;
    let mut deletions = 0u32;
    let mut binary = false;
    for line in lines {
        if line.starts_with("Binary files ") || line.contains("GIT binary patch") {
            binary = true;
        }
        if line.starts_with('+') && !line.starts_with("+++") {
            additions += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            deletions += 1;
        }
    }
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let (html, truncated, total_lines) = if binary {
        (
            String::from(
                "<pre class=\"kg-diff\"><span class=\"kg-diff__meta\">Binary file not shown.</span></pre>",
            ),
            false,
            refs.len(),
        )
    } else {
        render_diff_lines(&refs, Some(DIFF_RENDER_MAX_LINES))
    };
    DiffFileView {
        anchor: anchor_for_path(&path, idx),
        path,
        additions,
        deletions,
        html,
        truncated,
        total_lines,
        binary,
    }
}

fn prepare_latest_commit(
    grepo: &git2::Repository,
    branch: &str,
) -> Option<(git::CommitInfo, Option<(String, Vec<u8>)>)> {
    let c = git::list_commits(grepo, branch, 1)
        .ok()
        .and_then(|mut v| v.drain(..).next())?;
    let extracted = git::extract_commit_signature(grepo, &c.id);
    Some((c, extracted))
}

async fn latest_commit_view(
    state: &AppState,
    prepared: Option<(git::CommitInfo, Option<(String, Vec<u8>)>)>,
) -> Option<CommitView> {
    let (c, extracted) = prepared?;
    Some(commit_view(state, c, extracted).await)
}

fn clone_urls(state: &AppState, owner: &str, repo: &str) -> (String, String) {
    let base = state.config.public_url.trim_end_matches('/');
    // Always advertise the classic `.git` HTTP URL (middleware strips it).
    let http = format!("{base}/{owner}/{repo}.git");
    let host = url::Url::parse(&state.config.public_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "localhost".into());
    let port = state.config.ssh_advertise_port();
    // Port 22: GitHub-style `git@host:owner/repo.git` (default SSH port).
    // Other ports: ssh:// form — `git@host:2222/path` is parsed as path `2222/path` on port 22.
    let ssh = if port == 22 {
        format!("git@{host}:{owner}/{repo}.git")
    } else {
        format!("ssh://git@{host}:{port}/{owner}/{repo}.git")
    };
    (http, ssh)
}

fn valid_repo_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 100 {
        return false;
    }
    if name == "." || name == ".." || name.starts_with('.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub async fn require_login(auth: &AuthState, headers: &HeaderMap) -> AppResult<User> {
    current_user(auth, headers)
        .await?
        .ok_or_else(AppError::unauthorized)
}

pub async fn load_repo_context(
    state: &AppState,
    owner: &str,
    repo: &str,
    headers: &HeaderMap,
) -> AppResult<(Repository, User, Option<User>, Access)> {
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let (repository, owner_user) = queries::get_repo(&state.pool, owner, repo)
        .await?
        .ok_or_else(AppError::not_found)?;
    let viewer = current_user(&state.auth, headers).await?;
    let access = queries::repo_access(&state.pool, &repository, viewer.as_ref().map(|u| u.id)).await?;
    if !access.can_read() {
        return Err(AppError::not_found());
    }
    Ok((repository, owner_user, viewer, access))
}

fn split_ref_path(grepo: &git2::Repository, rest: &str) -> (String, String) {
    let rest = rest.trim_matches('/');
    if rest.is_empty() {
        return ("HEAD".into(), String::new());
    }
    if git::resolve_ref(grepo, rest).is_ok() {
        return (rest.to_string(), String::new());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    for i in (1..parts.len()).rev() {
        let reference = parts[..i].join("/");
        if git::resolve_ref(grepo, &reference).is_ok() {
            return (reference, parts[i..].join("/"));
        }
    }
    (
        parts[0].to_string(),
        if parts.len() > 1 {
            parts[1..].join("/")
        } else {
            String::new()
        },
    )
}

fn breadcrumbs(path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if path.is_empty() {
        return out;
    }
    let mut acc = String::new();
    for part in path.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        out.push((part.to_string(), acc.clone()));
    }
    out
}

async fn comment_views(
    pool: &sqlx::PgPool,
    comments: Vec<Comment>,
    viewer_id: Option<uuid::Uuid>,
) -> AppResult<Vec<CommentView>> {
    let mut out = Vec::with_capacity(comments.len());
    for c in comments {
        let author = queries::get_user_by_id(pool, c.author_id)
            .await?
            .ok_or_else(AppError::not_found)?;
        let avatar = avatar_url_for(&author);
        let reactions = queries::list_reaction_counts(pool, c.id, viewer_id)
            .await?
            .into_iter()
            .map(|(emoji, count, mine)| ReactionView {
                label: reaction_label(&emoji),
                emoji,
                count,
                mine,
            })
            .collect();
        out.push(CommentView {
            id: c.id,
            author,
            avatar_url: avatar,
            body_html: render_markdown(&c.body),
            created_at: c.created_at,
            reactions,
        });
    }
    Ok(out)
}

fn checkbox(v: &Option<String>) -> bool {
    matches!(v.as_deref(), Some("on") | Some("true") | Some("1") | Some("yes"))
}

/// Split an activity summary into prefix text plus an optional issue/PR link.
/// Uses `payload.number` with owner/repo from the hydrated event (not regex on display).
fn activity_summary_parts(
    kind: &str,
    summary: &str,
    payload: &serde_json::Value,
    owner: Option<&str>,
    repo: Option<&str>,
) -> (String, Option<String>, Option<String>) {
    let Some(number) = payload.get("number").and_then(|v| v.as_i64()) else {
        return (summary.to_string(), None, None);
    };
    let number = number as i32;
    let (Some(owner), Some(repo)) = (owner, repo) else {
        return (summary.to_string(), None, None);
    };

    let (label_candidates, href) = match kind {
        "issue.open" | "issue.comment" => (
            vec![format!("issue #{number}")],
            format!("/{owner}/{repo}/issues/{number}"),
        ),
        "pull.open" | "pull.comment" | "pull.merge" => (
            vec![
                format!("pull #{number}"),
                format!("pull request #{number}"),
            ],
            format!("/{owner}/{repo}/pulls/{number}"),
        ),
        _ => return (summary.to_string(), None, None),
    };

    for label in label_candidates {
        if let Some(prefix) = summary.strip_suffix(&label) {
            return (prefix.to_string(), Some(label), Some(href));
        }
    }

    (summary.to_string(), None, None)
}

fn map_activity_rows(
    raw: Vec<(
        crate::db::models::ActivityEvent,
        Option<crate::db::models::User>,
        Option<crate::db::models::Repository>,
        Option<String>,
    )>,
) -> Vec<ActivityRow> {
    let mut activities = Vec::with_capacity(raw.len());
    for (event, actor, repo, owner_name) in raw {
        let actor_username = actor.as_ref().map(|u| u.username.clone());
        let actor_avatar = actor.as_ref().map(avatar_url_for);
        let repo_name = repo.as_ref().map(|r| r.name.clone());
        let (summary, ref_label, ref_href) = activity_summary_parts(
            &event.kind,
            &event.summary,
            &event.payload,
            owner_name.as_deref(),
            repo_name.as_deref(),
        );
        activities.push(ActivityRow {
            kind: event.kind,
            summary,
            ref_label,
            ref_href,
            actor_username,
            actor_avatar,
            repo_owner: owner_name,
            repo_name,
            created_at: event.created_at,
        });
    }
    activities
}

// â”€â”€ home / auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn home(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let viewer = current_user(&state.auth, &headers).await?;
    let motd = queries::get_setting(&state.pool, "motd").await.unwrap_or_default();

    // Logged-out: branded landing only (no activity / repos).
    let Some(user) = viewer else {
        return Ok(HomeTemplate {
            viewer: None,
            motd,
            my_repos: Vec::new(),
            activities: Vec::new(),
            social: og::site_social_meta(
                &state.config.public_url,
                "/",
                "kitgit - self-hosted git forge",
                og::SITE_TAGLINE,
            ),
        });
    };

    let my_repos = queries::list_user_repos(&state.pool, user.id, Some(user.id))
        .await
        .unwrap_or_default();
    let raw = queries::latest_activity_for_user(&state.pool, user.id, 40).await?;
    let activities = map_activity_rows(raw);
    Ok(HomeTemplate {
        viewer: Some(user),
        motd,
        my_repos,
        activities,
        social: og::site_social_meta(
            &state.config.public_url,
            "/",
            "kitgit - self-hosted git forge",
            og::SITE_TAGLINE,
        ),
    })
}

#[derive(Deserialize)]
pub struct ExploreQuery {
    pub q: Option<String>,
}

pub async fn explore(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExploreQuery>,
) -> AppResult<impl IntoResponse> {
    let viewer = current_user(&state.auth, &headers).await?;
    let query = q.q.unwrap_or_default();
    let rows = queries::list_public_repos(
        &state.pool,
        if query.trim().is_empty() {
            None
        } else {
            Some(query.as_str())
        },
        50,
    )
    .await?;
    let repos = rows
        .into_iter()
        .map(|(repo, owner)| ExploreRepo { owner, repo })
        .collect();
    let social = if query.trim().is_empty() {
        og::site_social_meta(
            &state.config.public_url,
            "/explore",
            "explore repositories - kitgit",
            "Browse public repositories on kitgit.",
        )
    } else {
        let title = format!("search '{query}' - kitgit");
        let desc = format!("Public repositories matching '{query}' on kitgit.");
        og::site_social_meta(&state.config.public_url, "/explore", &title, &desc)
    };
    Ok(ExploreTemplate {
        viewer,
        repos,
        query,
        social,
    })
}

pub async fn auth_login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    if current_user(&state.auth, &headers).await?.is_some() {
        return Ok(redirect("/").into_response());
    }
    Ok(LoginTemplate {
        viewer: None,
        error: None,
    }
    .into_response())
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn auth_login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> AppResult<Response> {
    match auth::login_with_password(&state.auth, &form.username, &form.password).await {
        Ok(LoginOutcome::Complete { token, .. }) => Ok(redirect_with_cookies(
            "/",
            vec![
                session_cookie_header(&token, 14 * 24 * 3600),
                clear_mfa_pending_cookie(),
            ],
        )),
        Ok(LoginOutcome::MfaRequired { pending_token }) => Ok(redirect_with_cookie(
            "/auth/mfa",
            mfa_pending_cookie_header(&pending_token, 10 * 60),
        )),
        Err(e) => {
            tracing::warn!("login failed: {e:#}");
            Ok(LoginTemplate {
                viewer: None,
                error: Some(crate::mfa::sanitize_user_error(&e.to_string())),
            }
            .into_response())
        }
    }
}

pub async fn auth_mfa_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if current_user(&state.auth, &headers).await?.is_some() {
        return Ok(redirect("/").into_response());
    }
    if mfa_pending_from_headers(&headers).is_none() {
        return Ok(redirect("/auth/login").into_response());
    }
    Ok(MfaChallengeTemplate {
        viewer: None,
        error: None,
    }
    .into_response())
}

#[derive(Deserialize)]
pub struct MfaChallengeForm {
    pub code: String,
}

pub async fn auth_mfa_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> AppResult<Response> {
    let Some(pending) = mfa_pending_from_headers(&headers) else {
        return Ok(redirect("/auth/login"));
    };
    match auth::complete_mfa_login(&state.auth, &pending, &form.code).await {
        Ok((_user, token)) => Ok(redirect_with_cookies(
            "/",
            vec![
                session_cookie_header(&token, 14 * 24 * 3600),
                clear_mfa_pending_cookie(),
            ],
        )),
        Err(e) => {
            tracing::warn!("mfa challenge failed: {e:#}");
            let msg = crate::mfa::sanitize_user_error(&e.to_string());
            if msg.contains("expired") {
                return Ok(redirect_with_cookie("/auth/login", clear_mfa_pending_cookie()));
            }
            Ok(MfaChallengeTemplate {
                viewer: None,
                error: Some(msg),
            }
            .into_response())
        }
    }
}

/// Legacy OIDC browser start — disabled so users never leave kitgit UI.
pub async fn auth_oidc_start() -> AppResult<Response> {
    Ok(redirect("/auth/login"))
}

#[derive(Deserialize)]
pub struct SignupQuery {
    pub invite: Option<String>,
}

pub async fn auth_signup_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SignupQuery>,
) -> AppResult<impl IntoResponse> {
    if current_user(&state.auth, &headers).await?.is_some() {
        return Ok(redirect("/").into_response());
    }
    let signups_enabled = queries::signups_enabled(&state.pool).await;
    let signup_disabled_message = queries::signup_disabled_message(&state.pool).await;
    let mut invite = q.invite.unwrap_or_default().trim().to_string();
    let mut error = None;
    if !signups_enabled && !invite.is_empty() {
        if queries::get_valid_invite(&state.pool, &invite)
            .await?
            .is_none()
        {
            error = Some("invalid or already used invite code".into());
            invite.clear();
        }
    }
    Ok(SignupTemplate {
        viewer: None,
        error,
        signups_enabled,
        signup_disabled_message,
        invite,
    }
    .into_response())
}

#[derive(Deserialize)]
pub struct SignupForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    pub invite: Option<String>,
}

pub async fn auth_signup_submit(
    State(state): State<AppState>,
    Form(form): Form<SignupForm>,
) -> AppResult<Response> {
    let signups_enabled = queries::signups_enabled(&state.pool).await;
    let signup_disabled_message = queries::signup_disabled_message(&state.pool).await;
    let invite_code = form.invite.clone().unwrap_or_default();
    let invite_row = if !signups_enabled {
        match queries::get_valid_invite(&state.pool, &invite_code).await? {
            Some(inv) => Some(inv),
            None => {
                return Ok(SignupTemplate {
                    viewer: None,
                    error: Some("a valid invite code is required".into()),
                    signups_enabled: false,
                    signup_disabled_message,
                    invite: invite_code,
                }
                .into_response());
            }
        }
    } else {
        None
    };

    match auth::signup_with_password(
        &state.auth,
        &form.username,
        &form.email,
        &form.password,
        form.display_name.as_deref().unwrap_or(""),
    )
    .await
    {
        Ok(outcome) => {
            if let Some(inv) = invite_row {
                if let LoginOutcome::Complete { user, .. } = &outcome {
                    let _ = queries::consume_invite(&state.pool, inv.id, user.id).await;
                } else if let Some(u) = queries::get_user_by_username(
                    &state.pool,
                    &form.username.trim().to_ascii_lowercase(),
                )
                .await?
                {
                    let _ = queries::consume_invite(&state.pool, inv.id, u.id).await;
                }
            }
            match outcome {
                LoginOutcome::Complete { token, .. } => Ok(redirect_with_cookies(
                    "/",
                    vec![
                        session_cookie_header(&token, 14 * 24 * 3600),
                        clear_mfa_pending_cookie(),
                    ],
                )),
                LoginOutcome::MfaRequired { pending_token } => Ok(redirect_with_cookie(
                    "/auth/mfa",
                    mfa_pending_cookie_header(&pending_token, 10 * 60),
                )),
            }
        }
        Err(e) => {
            tracing::warn!("signup failed: {e:#}");
            Ok(SignupTemplate {
                viewer: None,
                error: Some(crate::mfa::sanitize_user_error(&e.to_string())),
                signups_enabled,
                signup_disabled_message,
                invite: invite_code,
            }
            .into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn auth_callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> AppResult<Response> {
    if let Some(err) = q.error {
        return Err(AppError::bad(format!("oidc error: {err}")));
    }
    let code = q.code.ok_or_else(|| AppError::bad("missing code"))?;
    let st = q.state.ok_or_else(|| AppError::bad("missing state"))?;
    let (_user, token) = auth::finish_login(&state.auth, &code, &st).await?;
    let cookie = session_cookie_header(&token, 14 * 24 * 3600);
    Ok(redirect_with_cookie("/", cookie))
}

pub async fn auth_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    auth::logout(&state.auth, &headers).await?;
    Ok(redirect_with_cookie("/", clear_session_cookie()))
}

// â”€â”€ site admin panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async fn require_site_admin(auth: &AuthState, headers: &HeaderMap) -> AppResult<User> {
    let user = require_login(auth, headers).await?;
    if !user.is_site_admin {
        return Err(AppError::forbidden());
    }
    Ok(user)
}

fn format_bytes(n: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n.max(0) as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n, UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path());
        }
    }
    total
}

#[derive(Deserialize)]
pub struct AdminQuery {
    pub q: Option<String>,
    pub page: Option<i64>,
    pub repo_q: Option<String>,
    pub repo_page: Option<i64>,
    pub flash: Option<String>,
}

const ADMIN_PAGE_SIZE: i64 = 20;

pub async fn admin_panel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminQuery>,
) -> AppResult<impl IntoResponse> {
    let viewer = require_site_admin(&state.auth, &headers).await?;
    let user_query = q.q.unwrap_or_default();
    let user_page = q.page.unwrap_or(1).max(1);
    let repo_query = q.repo_q.unwrap_or_default();
    let repo_page = q.repo_page.unwrap_or(1).max(1);

    let (users, user_total) = queries::search_users(
        &state.pool,
        if user_query.is_empty() {
            None
        } else {
            Some(user_query.as_str())
        },
        ADMIN_PAGE_SIZE,
        (user_page - 1) * ADMIN_PAGE_SIZE,
    )
    .await?;
    let user_pages = ((user_total + ADMIN_PAGE_SIZE - 1) / ADMIN_PAGE_SIZE).max(1);

    let (repo_rows, repo_total) = queries::list_repos_admin(
        &state.pool,
        if repo_query.is_empty() {
            None
        } else {
            Some(repo_query.as_str())
        },
        ADMIN_PAGE_SIZE,
        (repo_page - 1) * ADMIN_PAGE_SIZE,
    )
    .await?;
    let repo_pages = ((repo_total + ADMIN_PAGE_SIZE - 1) / ADMIN_PAGE_SIZE).max(1);
    let repos = repo_rows
        .into_iter()
        .map(|(r, owner)| AdminRepoView {
            id: r.id,
            owner,
            name: r.name,
            visibility: r.visibility,
            archived: r.archived,
            updated_at: r.updated_at,
        })
        .collect();

    let motd = queries::get_setting(&state.pool, "motd")
        .await
        .unwrap_or_default();
    let announcement = queries::site_announcement(&state.pool).await;
    let signups_enabled = queries::signups_enabled(&state.pool).await;
    let signup_disabled_message = queries::signup_disabled_message(&state.pool).await;
    let invites = queries::list_active_invites(&state.pool, 50)
        .await?
        .into_iter()
        .map(|i| AdminInviteView {
            id: i.id,
            code: i.code,
            created_at: i.created_at,
        })
        .collect();

    let mut stats = queries::admin_stats(&state.pool).await?;
    let repos_dir = state.config.repos_dir();
    stats.disk_bytes = match tokio::task::spawn_blocking(move || dir_size(&repos_dir)).await {
        Ok(n) => n,
        Err(_) => 0,
    };

    Ok(AdminTemplate {
        viewer: Some(viewer),
        users,
        user_query,
        user_page,
        user_pages,
        user_total,
        motd,
        announcement,
        signups_enabled,
        signup_disabled_message,
        invites,
        repos,
        repo_query,
        repo_page,
        repo_pages,
        repo_total,
        stats: AdminStatsView {
            user_count: stats.user_count,
            repo_count: stats.repo_count,
            public_repo_count: stats.public_repo_count,
            recent_signups: stats.recent_signups,
            active_invites: stats.active_invites,
            disk_label: format_bytes(stats.disk_bytes as i64),
        },
        flash: q.flash.filter(|s| !s.is_empty()),
    })
}

#[derive(Deserialize)]
pub struct AdminToggleForm {
    pub user_id: Uuid,
    pub is_site_admin: Option<String>,
}

pub async fn admin_set_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminToggleForm>,
) -> AppResult<Response> {
    let viewer = require_site_admin(&state.auth, &headers).await?;
    let make_admin = matches!(
        form.is_site_admin.as_deref(),
        Some("on") | Some("true") | Some("1") | Some("yes")
    );
    // Prevent removing your own admin bit if you're the last admin.
    if form.user_id == viewer.id && !make_admin {
        let count = queries::site_admin_count(&state.pool).await?;
        if count <= 1 {
            return Err(AppError::bad("cannot remove the last site admin"));
        }
    }
    queries::set_site_admin(&state.pool, form.user_id, make_admin).await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminSuspendForm {
    pub user_id: Uuid,
    pub is_suspended: Option<String>,
}

pub async fn admin_set_suspended(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminSuspendForm>,
) -> AppResult<Response> {
    let viewer = require_site_admin(&state.auth, &headers).await?;
    let suspend = checkbox(&form.is_suspended);
    if form.user_id == viewer.id && suspend {
        return Err(AppError::bad("cannot suspend yourself"));
    }
    let target = queries::get_user_by_id(&state.pool, form.user_id)
        .await?
        .ok_or_else(|| AppError::bad("user not found"))?;
    if target.is_site_admin && suspend {
        let count = queries::site_admin_count(&state.pool).await?;
        if count <= 1 {
            return Err(AppError::bad("cannot suspend the last site admin"));
        }
    }
    queries::set_user_suspended(&state.pool, form.user_id, suspend).await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminMotdForm {
    pub motd: Option<String>,
}

pub async fn admin_save_motd(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminMotdForm>,
) -> AppResult<Response> {
    let _viewer = require_site_admin(&state.auth, &headers).await?;
    queries::set_setting(&state.pool, "motd", form.motd.unwrap_or_default().trim()).await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminAnnouncementForm {
    pub announcement: Option<String>,
}

pub async fn admin_save_announcement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminAnnouncementForm>,
) -> AppResult<Response> {
    let _viewer = require_site_admin(&state.auth, &headers).await?;
    queries::set_setting(
        &state.pool,
        "announcement",
        form.announcement.unwrap_or_default().trim(),
    )
    .await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminSignupsForm {
    pub signups_enabled: Option<String>,
    pub signup_disabled_message: Option<String>,
}

pub async fn admin_save_signups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminSignupsForm>,
) -> AppResult<Response> {
    let _viewer = require_site_admin(&state.auth, &headers).await?;
    let enabled = checkbox(&form.signups_enabled);
    queries::set_setting(
        &state.pool,
        "signups_enabled",
        if enabled { "true" } else { "false" },
    )
    .await?;
    let raw = form.signup_disabled_message.unwrap_or_default();
    let trimmed = raw.trim();
    let message = if trimmed.is_empty() {
        queries::DEFAULT_SIGNUP_DISABLED_MESSAGE
    } else {
        trimmed
    };
    queries::set_setting(&state.pool, "signup_disabled_message", message).await?;
    Ok(redirect_see_other("/admin"))
}

pub async fn admin_create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let viewer = require_site_admin(&state.auth, &headers).await?;
    let inv = queries::create_invite(&state.pool, viewer.id).await?;
    let flash_raw = format!("invite created: {}", inv.code);
    let flash = urlencoding::encode(&flash_raw);
    Ok(redirect_see_other(&format!("/admin?flash={flash}")))
}

pub async fn admin_revoke_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let _viewer = require_site_admin(&state.auth, &headers).await?;
    queries::revoke_invite(&state.pool, id).await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminVisibilityForm {
    pub visibility: String,
}

pub async fn admin_repo_visibility(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AdminVisibilityForm>,
) -> AppResult<Response> {
    let _viewer = require_site_admin(&state.auth, &headers).await?;
    let visibility = match form.visibility.as_str() {
        "public" => "public",
        _ => "private",
    };
    queries::set_repo_visibility(&state.pool, id, visibility).await?;
    Ok(redirect_see_other("/admin"))
}

#[derive(Deserialize)]
pub struct AdminDeleteRepoForm {
    pub confirm: Option<String>,
}

pub async fn admin_repo_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<AdminDeleteRepoForm>,
) -> AppResult<Response> {
    let viewer = require_site_admin(&state.auth, &headers).await?;
    let (repo, owner) = queries::get_repo_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::bad("repository not found"))?;
    let confirm = form.confirm.unwrap_or_default();
    if confirm != repo.name && confirm != format!("{owner}/{}", repo.name) {
        return Err(AppError::bad("type the repository name to confirm delete"));
    }
    queries::delete_repo(&state.pool, repo.id).await?;
    let _ = git::remove_bare(&state.config.repos_dir(), &owner, &repo.name);
    queries::record_activity(
        &state.pool,
        Some(viewer.id),
        None,
        "repo.delete",
        "deleted repository",
        serde_json::json!({ "owner": owner, "name": repo.name, "admin": true }),
    )
    .await?;
    Ok(redirect_see_other("/admin"))
}

pub async fn site_banner_json(State(state): State<AppState>) -> impl IntoResponse {
    let message = queries::site_announcement(&state.pool).await;
    axum::Json(serde_json::json!({ "message": message }))
}

// â”€â”€ new repo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn new_repo_form(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let viewer = require_login(&state.auth, &headers).await?;
    Ok(NewRepoTemplate {
        viewer: Some(viewer),
        error: None,
    })
}

#[derive(Deserialize)]
pub struct NewRepoForm {
    pub name: String,
    pub description: Option<String>,
    pub visibility: Option<String>,
}

pub async fn new_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewRepoForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let name = form.name.trim().to_string();
    let description = form.description.unwrap_or_default();
    let visibility = match form.visibility.as_deref() {
        Some("private") => "private",
        _ => "public",
    };

    if !valid_repo_name(&name) {
        return Ok(NewRepoTemplate {
            viewer: Some(user),
            error: Some("invalid repository name".into()),
        }
        .into_response());
    }

    if queries::get_repo(&state.pool, &user.username, &name)
        .await?
        .is_some()
    {
        return Ok(NewRepoTemplate {
            viewer: Some(user),
            error: Some("repository already exists".into()),
        }
        .into_response());
    }

    let repo = queries::create_repo(&state.pool, user.id, &name, &description, visibility).await?;
    git::init_bare(
        &state.config.repos_dir(),
        &user.username,
        &name,
        &repo.default_branch,
    )?;
    let author_name = if user.display_name.is_empty() {
        user.username.as_str()
    } else {
        user.display_name.as_str()
    };
    let author_email = if user.email.is_empty() {
        format!("{}@users.kitgit", user.username)
    } else {
        user.email.clone()
    };
    let _ = git::seed_initial_commit(
        &state.config.repos_dir(),
        &user.username,
        &name,
        &repo.default_branch,
        author_name,
        &author_email,
    );
    let _ = queries::ensure_primary_email(&state.pool, user.id, &user.email).await;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repo.id),
        "repo.create",
        "created repository",
        serde_json::json!({}),
    )
    .await?;

    Ok(redirect_see_other(&format!("/{}/{}", user.username, name)))
}

// â”€â”€ profile settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn profile_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let avatar_url = avatar_url_for(&user);
    Ok(ProfileSettingsTemplate {
        viewer: Some(user.clone()),
        user,
        avatar_url,
        error: None,
    })
}

pub async fn profile_settings_save(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let mut display_name = user.display_name.clone();
    let mut bio = user.bio.clone();
    let mut avatar_path: Option<String> = None;
    let mut avatar_error: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        // Surface limit/parse failures as a page error instead of a dropped connection.
        AppError::bad(format!("could not read upload: {e}"))
    })? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "display_name" => {
                display_name = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
            }
            "bio" => {
                bio = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
            }
            "avatar" => {
                let filename = field.file_name().unwrap_or("").to_string();
                if filename.is_empty() {
                    let _ = field.bytes().await;
                    continue;
                }
                let ct = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let data = match field.bytes().await {
                    Ok(d) => d,
                    Err(e) => {
                        avatar_error = Some(format!("could not read avatar: {e}"));
                        continue;
                    }
                };
                if data.is_empty() {
                    continue;
                }
                // 5MB soft cap after raising the HTTP body limit.
                if data.len() > 5 * 1024 * 1024 {
                    avatar_error = Some("avatar too large (max 5MB)".into());
                    continue;
                }
                let Some(ext) = sniff_image_ext(&data, &ct) else {
                    avatar_error = Some(
                        "avatar must be png, jpeg, gif, or webp (heic not supported)".into(),
                    );
                    continue;
                };
                if let Err(e) = std::fs::create_dir_all(state.config.avatars_dir()) {
                    return Err(AppError::internal(format!("avatars dir: {e}")));
                }
                let rel = format!("{}.{}", user.id, ext);
                let path = state.config.avatars_dir().join(&rel);
                if let Err(e) = std::fs::write(&path, &data) {
                    return Err(AppError::internal(format!("could not save avatar: {e}")));
                }
                avatar_path = Some(rel);
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let updated = queries::update_user_profile(
        &state.pool,
        user.id,
        display_name.trim(),
        bio.trim(),
        avatar_path.as_deref(),
    )
    .await?;

    if let Some(err) = avatar_error {
        let avatar_url = avatar_url_for(&updated);
        return Ok(ProfileSettingsTemplate {
            viewer: Some(updated.clone()),
            user: updated,
            avatar_url,
            error: Some(err),
        }
        .into_response());
    }

    Ok(redirect_see_other("/settings/profile"))
}

// â”€â”€ SSH keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn keys_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let keys = queries::list_ssh_keys(&state.pool, user.id).await?;
    let gpg_keys = queries::list_gpg_keys(&state.pool, user.id).await?;
    Ok(KeysSettingsTemplate {
        viewer: Some(user),
        keys,
        gpg_keys,
        error: None,
    })
}

#[derive(Deserialize)]
pub struct AddKeyForm {
    pub name: String,
    pub public_key: String,
    pub key_usage: Option<String>,
}

pub async fn keys_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddKeyForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let name = form.name.trim();
    let public_key = form.public_key.trim();
    let key_usage = form.key_usage.as_deref().unwrap_or("authentication");
    if name.is_empty() || public_key.is_empty() {
        let keys = queries::list_ssh_keys(&state.pool, user.id).await?;
        let gpg_keys = queries::list_gpg_keys(&state.pool, user.id).await?;
        return Ok(KeysSettingsTemplate {
            viewer: Some(user),
            keys,
            gpg_keys,
            error: Some("name and public key required".into()),
        }
        .into_response());
    }
    let fp = fingerprint_ssh_pubkey(public_key).map_err(|e| AppError::bad(e.to_string()))?;
    queries::add_ssh_key(&state.pool, user.id, name, public_key, &fp, key_usage)
        .await
        .map_err(|e| AppError::bad(format!("could not add key: {e}")))?;
    Ok(redirect_see_other("/settings/keys"))
}

#[derive(Deserialize)]
pub struct KeyUsageForm {
    pub key_usage: String,
}

pub async fn keys_update_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<KeyUsageForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::update_ssh_key_usage(&state.pool, user.id, id, &form.key_usage).await?;
    Ok(redirect_see_other("/settings/keys"))
}

pub async fn keys_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::delete_ssh_key(&state.pool, user.id, id).await?;
    Ok(redirect_see_other("/settings/keys"))
}

// â”€â”€ avatar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn avatar(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Response> {
    let user = queries::get_user_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(AppError::not_found)?;

    if let Some(ref rel) = user.avatar_path {
        // Only allow basename under avatars_dir (no path traversal).
        let base = std::path::Path::new(rel)
            .file_name()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(rel));
        let path = state.config.avatars_dir().join(base);
        if path.is_file() {
            let data = std::fs::read(&path)?;
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .essence_str()
                .to_string();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, mime)
                // Cache-bust via ?v= on URLs; avoid year-long immutable (stale avatars).
                .header(
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=3600, must-revalidate",
                )
                .body(Body::from(data))
                .unwrap());
        }
    }

    // Never HTTP-redirect from /avatars/{id}. Self-referential avatar_url values
    // (e.g. "/avatars/{id}") make the browser loop forever on <img>.
    let svg = initials_avatar_svg(&user);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/svg+xml; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=60")
        .body(Body::from(svg))
        .unwrap())
}

// â”€â”€ profile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> AppResult<impl IntoResponse> {
    let viewer = current_user(&state.auth, &headers).await?;
    let profile = queries::get_user_by_username(&state.pool, &username)
        .await?
        .ok_or_else(AppError::not_found)?;
    let viewer_id = viewer.as_ref().map(|u| u.id);
    let repos = queries::list_user_repos(&state.pool, profile.id, viewer_id).await?;
    let starred_raw =
        queries::list_public_starred_repos(&state.pool, profile.id, 30).await?;
    let starred = starred_raw
        .into_iter()
        .map(|(repo, owner)| ExploreRepo { owner, repo })
        .collect();
    let watched_raw =
        queries::latest_activity_for_watched_repos(&state.pool, profile.id, 30).await?;
    let watched_activity = map_activity_rows(watched_raw);
    let graph = queries::commit_graph(&state.pool, profile.id, 365).await?;
    let is_self = viewer
        .as_ref()
        .map(|v| v.id == profile.id)
        .unwrap_or(false);
    let avatar_url = avatar_url_for(&profile);
    let has_activity = graph.iter().any(|d| d.count > 0);
    Ok(ProfileTemplate {
        viewer,
        profile,
        avatar_url,
        repos,
        starred,
        watched_activity,
        graph,
        has_activity,
        is_self,
    })
}

// â”€â”€ repository browse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn repo_home(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let owner_avatar = avatar_url_for(&owner_user);

    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo).ok();
    let current_branch = repository.default_branch.clone();
    let mut branches = Vec::new();
    let mut entries = Vec::new();
    let mut readme_html = None;
    let mut empty = true;
    let mut languages = queries::get_language_stats(&state.pool, repository.id).await?;

    if let Some(ref g) = grepo {
        branches = git::list_branches(g).unwrap_or_default();
        if git::resolve_ref(g, &current_branch).is_ok() {
            empty = false;
            entries = git::list_tree(g, &current_branch, "")
                .unwrap_or_default()
                .into_iter()
                .map(|e| TreeEntryView {
                    name: e.name,
                    path: e.path,
                    is_dir: e.is_dir,
                    mode: e.mode,
                })
                .collect();
            if let Ok(Some((name, src))) = git::find_readme(g, &current_branch, "") {
                readme_html = Some(readme_to_html(
                    &name,
                    &src,
                    &owner,
                    &repo,
                    &current_branch,
                    "",
                    g,
                ));
            }
            if languages.as_object().map(|o| o.is_empty()).unwrap_or(true) {
                if let Ok(files) = git::walk_files(g, &current_branch) {
                    let stats = git::languages::detect_languages(&files);
                    let _ = queries::set_language_stats(&state.pool, repository.id, stats.clone())
                        .await;
                    languages = stats;
                }
            }
        }
    }

    let latest_commit = match grepo.as_ref() {
        Some(g) => {
            let prepared = prepare_latest_commit(g, &current_branch);
            latest_commit_view(&state, prepared).await
        }
        None => None,
    };
    let languages = language_stat_views(languages);

    let forked_from = if let Some(fid) = repository.fork_of_id {
        match queries::get_repo_by_id(&state.pool, fid).await? {
            Some((parent, parent_owner)) => Some((parent_owner, parent.name)),
            None => None,
        }
    } else {
        None
    };
    let (starred, watching) = if let Some(ref u) = viewer {
        (
            queries::is_starred(&state.pool, repository.id, u.id).await?,
            queries::is_watching(&state.pool, repository.id, u.id).await?,
        )
    } else {
        (false, false)
    };

    let social = og::repo_social_meta(&state.config.public_url, &owner, &repository);
    Ok(RepoHomeTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        owner_avatar,
        clone_http,
        clone_ssh,
        branches,
        current_branch,
        entries,
        readme_html,
        languages,
        empty,
        latest_commit,
        forked_from,
        starred,
        watching,
        social,
    })
}

pub async fn repo_og_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<Response> {
    let (repository, owner_user, _viewer, _access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let png = og::render_repo_card(&owner_user.username, &repository);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/png")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(png))
        .unwrap())
}

pub async fn site_og_image() -> Response {
    let png = og::render_site_card();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/png")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=86400")
        .body(Body::from(png))
        .unwrap()
}

pub async fn repo_tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let (branch, path) = split_ref_path(&grepo, &rest);
    let entries = git::list_tree(&grepo, &branch, &path)
        .map_err(|e| AppError::not_found().with_message(e.to_string()))?
        .into_iter()
        .map(|e| TreeEntryView {
            name: e.name,
            path: e.path,
            is_dir: e.is_dir,
            mode: e.mode,
        })
        .collect();
    let readme_html = match git::find_readme(&grepo, &branch, &path) {
        Ok(Some((name, src))) => Some(readme_to_html(
            &name,
            &src,
            &owner,
            &repo,
            &branch,
            &path,
            &grepo,
        )),
        _ => None,
    };
    let branches = git::list_branches(&grepo).unwrap_or_default();
    let prepared = prepare_latest_commit(&grepo, &branch);
    let latest_commit = latest_commit_view(&state, prepared).await;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(RepoTreeTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        branches,
        branch,
        path: path.clone(),
        breadcrumbs: breadcrumbs(&path),
        entries,
        readme_html,
        latest_commit,
        clone_http,
        clone_ssh,
    })
}

pub async fn repo_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let (branch, path) = split_ref_path(&grepo, &rest);
    if path.is_empty() {
        return Err(AppError::bad("missing file path"));
    }
    let (data, binary) = git::read_blob(&grepo, &branch, &path)
        .map_err(|_| AppError::not_found())?;
    let size = data.len();
    let (content_html, is_markdown) = if binary {
        (None, false)
    } else {
        let text = String::from_utf8_lossy(&data);
        if path.ends_with(".md") || path.ends_with(".MD") {
            let base = MarkdownRepoBase {
                owner: &owner,
                repo: &repo,
                git_ref: &branch,
                dir: parent_dir(&path),
            };
            let html = render_markdown_in_repo(&text, &base, |p| {
                git::path_is_dir(&grepo, &branch, p)
            });
            (Some(html), true)
        } else {
            (Some(highlight(&path, &text)), false)
        }
    };
    let branches = git::list_branches(&grepo).unwrap_or_default();
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(RepoBlobTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        branches,
        branch,
        path: path.clone(),
        breadcrumbs: breadcrumbs(&path),
        binary,
        size,
        content_html,
        is_markdown,
        clone_http,
        clone_ssh,
    })
}

#[derive(Deserialize)]
pub struct BranchQuery {
    pub branch: Option<String>,
}

pub async fn repo_commits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchQuery>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let branch = q
        .branch
        .unwrap_or_else(|| repository.default_branch.clone());
    let raw_commits = git::list_commits(&grepo, &branch, 100).unwrap_or_default();
    let prepared: Vec<_> = raw_commits
        .into_iter()
        .map(|c| {
            let extracted = git::extract_commit_signature(&grepo, &c.id);
            (c, extracted)
        })
        .collect();
    let commits = commit_views(&state, prepared).await;
    let branches = git::list_branches(&grepo).unwrap_or_default();
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(RepoCommitsTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        branches,
        branch,
        commits,
        clone_http,
        clone_ssh,
    })
}

pub async fn repo_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let commit = git::get_commit(&grepo, &id).map_err(|_| AppError::not_found())?;
    let extracted = git::extract_commit_signature(&grepo, &commit.id);
    let diff = git::commit_diff(&grepo, &id).unwrap_or_default();
    let diff_html = render_diff_html(&diff);
    let message_html = linkify_commit_message(
        &state.pool,
        repository.id,
        &owner,
        &repo,
        &commit.message,
    )
    .await;
    Ok(RepoCommitTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        commit: commit_view(&state, commit, extracted).await,
        message_html,
        diff_html,
        clone_http: clone_urls(&state, &owner, &repo).0,
        clone_ssh: clone_urls(&state, &owner, &repo).1,
    })
}

pub async fn repo_diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let commit = git::get_commit(&grepo, &id).map_err(|_| AppError::not_found())?;
    let extracted = git::extract_commit_signature(&grepo, &commit.id);
    let diff = git::commit_diff(&grepo, &id).unwrap_or_default();
    let diff_html = render_diff_html(&diff);
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(RepoDiffTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        commit: commit_view(&state, commit, extracted).await,
        diff_html,
        clone_http,
        clone_ssh,
    })
}

#[derive(Deserialize)]
pub struct ArchiveQuery {
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
    /// Optional subtree path (directory or file) within the ref.
    pub path: Option<String>,
}

pub async fn repo_archive_zip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<ArchiveQuery>,
) -> AppResult<Response> {
    let (repository, _owner_user, _viewer, _access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let reference = q
        .ref_name
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| repository.default_branch.clone());
    let path = q
        .path
        .as_deref()
        .map(|s| s.trim_matches('/'))
        .filter(|s| !s.is_empty());
    let bytes = git::archive_zip(
        &state.config.repos_dir(),
        &owner,
        &repo,
        &reference,
        path,
    )
    .map_err(|e| AppError::bad(e.to_string()))?;
    let ref_slug = reference.replace('/', "-");
    let filename = match path {
        Some(p) => {
            let base = p.rsplit('/').next().unwrap_or(p);
            format!("{repo}-{ref_slug}-{base}.zip")
        }
        None => format!("{repo}-{ref_slug}.zip"),
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .unwrap())
}

pub async fn repo_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (repository, _owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let mut branch = repository.default_branch.clone();
    let mut dir = String::new();
    let mut message = String::from("Upload file");
    let mut file_name = String::new();
    let mut file_bytes: Option<bytes::Bytes> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "branch" => {
                branch = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
            }
            "path" => {
                dir = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?
                    .trim_matches('/')
                    .to_string();
            }
            "message" => {
                let m = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
                if !m.trim().is_empty() {
                    message = m;
                }
            }
            "file" => {
                file_name = field.file_name().unwrap_or("").to_string();
                if file_name.is_empty() {
                    let _ = field.bytes().await;
                    continue;
                }
                // sanitize filename
                file_name = file_name
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&file_name)
                    .to_string();
                if file_name.contains("..") || file_name.is_empty() {
                    return Err(AppError::bad("invalid filename"));
                }
                file_bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::bad(e.to_string()))?,
                );
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let data = file_bytes.ok_or_else(|| AppError::bad("file required"))?;
    if data.len() > 50 * 1024 * 1024 {
        return Err(AppError::bad("file too large (max 50MB)"));
    }
    let dest = if dir.is_empty() {
        file_name.clone()
    } else {
        format!("{dir}/{file_name}")
    };
    let author = if user.display_name.is_empty() {
        user.username.clone()
    } else {
        user.display_name.clone()
    };
    git::commit_file(
        &state.config.repos_dir(),
        &owner,
        &repo,
        &branch,
        &dest,
        &data,
        &author,
        &user.email,
        &message,
    )
    .map_err(|e| AppError::bad(e.to_string()))?;

    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "push",
        "uploaded file",
        serde_json::json!({ "path": dest }),
    )
    .await?;

    let redirect_path = if dir.is_empty() {
        format!("/{owner}/{repo}/tree/{branch}")
    } else {
        format!("/{owner}/{repo}/tree/{branch}/{dir}")
    };
    Ok(redirect_see_other(&redirect_path))
}

pub async fn repo_branches(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    let names = git::list_branches(&grepo).unwrap_or_default();
    let default_branch = repository.default_branch.clone();
    let open_pulls = queries::list_pulls(&state.pool, repository.id, Some("open"))
        .await
        .unwrap_or_default();
    let branches: Vec<BranchRow> = names
        .into_iter()
        .map(|name| {
            let is_default = name == default_branch;
            let (ahead, behind) = if is_default {
                (0usize, 0usize)
            } else {
                git::ahead_behind(&grepo, &name, &default_branch).unwrap_or((0, 0))
            };
            let pull_number = open_pulls
                .iter()
                .find(|p| p.source_branch == name)
                .map(|p| p.number);
            let updated = git::list_commits(&grepo, &name, 1)
                .ok()
                .and_then(|mut v| v.pop())
                .map(|c| c.time.to_string())
                .unwrap_or_default();
            BranchRow {
                name,
                is_default,
                updated,
                ahead,
                behind,
                pull_number,
            }
        })
        .collect();
    let release_tags: std::collections::HashSet<String> =
        queries::list_releases(&state.pool, repository.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.tag_name)
            .collect();
    let tags: Vec<TagRow> = git::list_tags(&grepo)
        .unwrap_or_default()
        .into_iter()
        .map(|t| TagRow {
            has_release: release_tags.contains(&t.name),
            name: t.name,
            short_id: t.short_id,
            target: t.target,
            message: t.message,
            updated: t.time.to_string(),
        })
        .collect();
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(RepoBranchesTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        branches,
        tags,
        clone_http,
        clone_ssh,
        error: None,
    })
}

async fn commit_view(
    state: &AppState,
    c: git::CommitInfo,
    extracted: Option<(String, Vec<u8>)>,
) -> CommitView {
    let verification = match extracted {
        Some((sig, payload)) => {
            git::verify_commit_signature(
                &state.pool,
                &sig,
                &payload,
                &c.email,
                c.time,
            )
            .await
        }
        None => None,
    };
    let (verified, verify_kind, verify_fingerprint, verify_fingerprint_label, verified_at) =
        match verification {
            Some(v) => {
                let label = v.fingerprint_label().to_string();
                (
                    true,
                    v.kind.clone(),
                    v.fingerprint,
                    label,
                    v.verified_at,
                )
            }
            None => (false, String::new(), String::new(), String::new(), String::new()),
        };
    CommitView {
        id: c.id,
        short_id: c.short_id,
        message: c.message,
        author: c.author,
        email: c.email,
        time: c.time,
        verified,
        verify_kind,
        verify_fingerprint,
        verify_fingerprint_label,
        verified_at,
    }
}

async fn commit_views(
    state: &AppState,
    commits: Vec<(git::CommitInfo, Option<(String, Vec<u8>)>)>,
) -> Vec<CommitView> {
    let mut out = Vec::with_capacity(commits.len());
    for (c, extracted) in commits {
        out.push(commit_view(state, c, extracted).await);
    }
    out
}

// â”€â”€ issues â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Deserialize)]
pub struct StateFilter {
    pub state: Option<String>,
}

pub async fn issues_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<StateFilter>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.issues_enabled {
        return Err(AppError::not_found());
    }
    // Default to open-only (GitHub-style) when no state query param is set.
    let filter = match q.state.as_deref() {
        Some("closed") => "closed",
        _ => "open",
    };
    let issues = queries::list_issues(&state.pool, repository.id, Some(filter)).await?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(IssuesListTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        issues,
        state_filter: filter.to_string(),
        clone_http,
        clone_ssh,
    })
}

pub async fn issue_new(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.issues_enabled {
        return Err(AppError::not_found());
    }
    let _ = viewer.as_ref().ok_or_else(AppError::unauthorized)?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(IssueNewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        error: None,
        clone_http,
        clone_ssh,
    })
}

#[derive(Deserialize)]
pub struct IssueCreateForm {
    pub title: String,
    pub body: Option<String>,
}

pub async fn issue_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<IssueCreateForm>,
) -> AppResult<Response> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.issues_enabled {
        return Err(AppError::not_found());
    }
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let title = form.title.trim();
    if title.is_empty() {
        let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
        return Ok(IssueNewTemplate {
            viewer: Some(user),
            owner: owner_user,
            repo: repository,
            access,
            error: Some("title required".into()),
            clone_http,
            clone_ssh,
        }
        .into_response());
    }
    let body = form.body.unwrap_or_default();
    let number = queries::next_issue_number(&state.pool, repository.id).await?;
    let issue =
        queries::create_issue(&state.pool, repository.id, user.id, number, title, &body).await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "issue.open",
        &format!("opened issue #{number}"),
        serde_json::json!({ "number": number }),
    )
    .await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/issues/{}",
        issue.number
    )))
}

pub async fn issue_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.issues_enabled {
        return Err(AppError::not_found());
    }
    let issue = queries::get_issue(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    let author = queries::get_user_by_id(&state.pool, issue.author_id)
        .await?
        .ok_or_else(AppError::not_found)?;
    let comments = comment_views(
        &state.pool,
        queries::list_issue_comments(&state.pool, issue.id).await?,
        viewer.as_ref().map(|u| u.id),
    )
    .await?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(IssueViewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        author_avatar: avatar_url_for(&author),
        body_html: render_markdown(&issue.body),
        issue,
        author,
        comments,
        clone_http,
        clone_ssh,
    })
}

#[derive(Deserialize)]
pub struct CommentForm {
    pub body: String,
}

pub async fn issue_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    Form(form): Form<CommentForm>,
) -> AppResult<Response> {
    let (repository, _owner_user, viewer, _access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let issue = queries::get_issue(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::bad("empty comment"));
    }
    queries::add_comment(
        &state.pool,
        repository.id,
        user.id,
        Some(issue.id),
        None,
        body,
    )
    .await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "issue.comment",
        &format!("commented on issue #{number}"),
        serde_json::json!({ "number": number }),
    )
    .await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/issues/{number}"
    )))
}

pub async fn issue_close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let issue = queries::get_issue(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    if !(access.can_write() || issue.author_id == user.id) {
        return Err(AppError::forbidden());
    }
    queries::set_issue_state(&state.pool, issue.id, "closed").await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/issues/{number}"
    )))
}

pub async fn issue_reopen(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let issue = queries::get_issue(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    if !(access.can_write() || issue.author_id == user.id) {
        return Err(AppError::forbidden());
    }
    queries::set_issue_state(&state.pool, issue.id, "open").await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/issues/{number}"
    )))
}

// â”€â”€ pull requests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn pulls_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<StateFilter>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.pulls_enabled {
        return Err(AppError::not_found());
    }
    let filter = q
        .state
        .as_deref()
        .filter(|s| *s == "open" || *s == "closed" || *s == "merged");
    let pulls = queries::list_pulls(&state.pool, repository.id, filter).await?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(PullsListTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        pulls,
        state_filter: filter.unwrap_or("open").to_string(),
        clone_http,
        clone_ssh,
    })
}

pub async fn pull_new(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.pulls_enabled {
        return Err(AppError::not_found());
    }
    let _ = viewer.as_ref().ok_or_else(AppError::unauthorized)?;
    let branches = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .ok()
        .and_then(|g| git::list_branches(&g).ok())
        .unwrap_or_default();
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(PullNewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        branches,
        error: None,
        clone_http,
        clone_ssh,
        upstream: None,
    })
}

#[derive(Deserialize)]
pub struct PullCreateForm {
    pub title: String,
    pub body: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
}

pub async fn pull_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<PullCreateForm>,
) -> AppResult<Response> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.pulls_enabled {
        return Err(AppError::not_found());
    }
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let title = form.title.trim();
    let source = form.source_branch.trim();
    let target = form.target_branch.trim();
    if title.is_empty() || source.is_empty() || target.is_empty() {
        let branches = git::open_bare(&state.config.repos_dir(), &owner, &repo)
            .ok()
            .and_then(|g| git::list_branches(&g).ok())
            .unwrap_or_default();
        let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
        return Ok(PullNewTemplate {
            viewer: Some(user),
            owner: owner_user,
            repo: repository,
            access,
            branches,
            error: Some("title, source, and target required".into()),
            clone_http,
            clone_ssh,
            upstream: None,
        }
        .into_response());
    }
    if source == target {
        return Err(AppError::bad("source and target must differ"));
    }
    let body = form.body.unwrap_or_default();
    let number = queries::next_pull_number(&state.pool, repository.id).await?;
    let pull = queries::create_pull(
        &state.pool,
        repository.id,
        user.id,
        number,
        title,
        &body,
        source,
        target,
    )
    .await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "pull.open",
        &format!("opened pull #{number}"),
        serde_json::json!({ "number": number }),
    )
    .await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/pulls/{}",
        pull.number
    )))
}

#[derive(Deserialize)]
pub struct PullTabQuery {
    pub tab: Option<String>,
}

pub async fn pull_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    Query(q): Query<PullTabQuery>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.pulls_enabled {
        return Err(AppError::not_found());
    }
    let pull = queries::get_pull(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    let author = queries::get_user_by_id(&state.pool, pull.author_id)
        .await?
        .ok_or_else(AppError::not_found)?;
    let comments = comment_views(
        &state.pool,
        queries::list_pull_comments(&state.pool, pull.id).await?,
        viewer.as_ref().map(|u| u.id),
    )
    .await?;

    let tab = match q.tab.as_deref() {
        Some("commits") => "commits",
        Some("files") => "files",
        _ => "conversation",
    }
    .to_string();

    let mut commits = Vec::new();
    let mut diff_files = Vec::new();
    if let Ok(g) = git::open_bare(&state.config.repos_dir(), &owner, &repo) {
        let prepared: Vec<_> = git::commits_between(&g, &pull.source_branch, &pull.target_branch, 100)
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let extracted = git::extract_commit_signature(&g, &c.id);
                (c, extracted)
            })
            .collect();
        commits = commit_views(&state, prepared).await;
        let diff =
            git::branch_diff(&g, &pull.source_branch, &pull.target_branch).unwrap_or_default();
        diff_files = parse_diff_files(&diff);
    }

    let can_merge = access.can_write() && pull.state == "open";
    let mut merge_styles = Vec::new();
    if repository.allow_merge {
        merge_styles.push("merge".to_string());
    }
    if repository.allow_squash {
        merge_styles.push("squash".to_string());
    }
    if repository.allow_rebase {
        merge_styles.push("rebase".to_string());
    }

    let conversation_count = comments.len() + 1;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(PullViewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        author_avatar: avatar_url_for(&author),
        body_html: render_markdown(&pull.body),
        pull,
        author,
        comments,
        commits,
        conversation_count,
        diff_files,
        tab,
        can_merge,
        merge_styles,
        clone_http,
        clone_ssh,
    })
}

pub async fn pull_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    Form(form): Form<CommentForm>,
) -> AppResult<Response> {
    let (repository, _o, viewer, _a) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let pull = queries::get_pull(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::bad("empty comment"));
    }
    queries::add_comment(
        &state.pool,
        repository.id,
        user.id,
        None,
        Some(pull.id),
        body,
    )
    .await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "pull.comment",
        &format!("commented on pull #{number}"),
        serde_json::json!({ "number": number }),
    )
    .await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/pulls/{number}")))
}

#[derive(Deserialize)]
pub struct MergeForm {
    pub style: Option<String>,
}

pub async fn pull_merge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    Form(form): Form<MergeForm>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    if repository.archived {
        return Err(AppError::forbidden());
    }
    let pull = queries::get_pull(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    if pull.state != "open" {
        return Err(AppError::bad("pull is not open"));
    }

    let style = form
        .style
        .as_deref()
        .unwrap_or(repository.default_merge_style.as_str());
    let allowed = match style {
        "squash" => repository.allow_squash,
        "rebase" => repository.allow_rebase,
        _ => repository.allow_merge,
    };
    if !allowed {
        return Err(AppError::bad("merge style not allowed"));
    }

    let message = format!("Merge pull request #{number} from {}", pull.source_branch);
    let author = if user.display_name.is_empty() {
        user.username.as_str()
    } else {
        user.display_name.as_str()
    };
    let merge_commit = git::merge_branches(
        &state.config.repos_dir(),
        &owner,
        &repo,
        &pull.source_branch,
        &pull.target_branch,
        style,
        &message,
        author,
        &user.email,
    )
    .map_err(|e| AppError::bad(format!("merge failed: {e}")))?;

    queries::set_pull_state(&state.pool, pull.id, "merged", Some(&merge_commit)).await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "pull.merge",
        &format!("merged pull #{number}"),
        serde_json::json!({ "number": number, "commit": merge_commit }),
    )
    .await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/pulls/{number}")))
}

pub async fn pull_close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i32)>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let pull = queries::get_pull(&state.pool, repository.id, number)
        .await?
        .ok_or_else(AppError::not_found)?;
    if !(access.can_write() || pull.author_id == user.id) {
        return Err(AppError::forbidden());
    }
    if pull.state != "open" {
        return Err(AppError::bad("pull is not open"));
    }
    queries::set_pull_state(&state.pool, pull.id, "closed", None).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/pulls/{number}")))
}

// â”€â”€ releases â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


fn asset_views(assets: Vec<crate::db::models::ReleaseAsset>) -> Vec<ReleaseAssetView> {
    assets
        .into_iter()
        .map(|a| ReleaseAssetView {
            id: a.id,
            filename: a.filename,
            size_label: format_bytes(a.size_bytes),
            content_type: a.content_type,
        })
        .collect()
}

fn release_branch_choices(state: &AppState, owner: &str, repo: &str, default: &str) -> Vec<String> {
    let mut branches = git::open_bare(&state.config.repos_dir(), owner, repo)
        .ok()
        .and_then(|g| git::list_branches(&g).ok())
        .unwrap_or_default();
    if branches.is_empty() {
        branches.push(default.to_string());
    }
    branches
}

pub async fn releases_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    let mut releases = queries::list_releases(&state.pool, repository.id).await?;
    if !access.can_write() {
        releases.retain(|r| !r.is_draft);
    }
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(ReleasesListTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        releases,
        clone_http,
        clone_ssh,
    })
}

pub async fn release_new(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let target = repository.default_branch.clone();
    let branches = release_branch_choices(&state, &owner, &repo, &target);
    Ok(ReleaseNewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        error: None,
        clone_http,
        clone_ssh,
        tag_name: String::new(),
        title: String::new(),
        body: String::new(),
        target,
        is_prerelease: false,
        is_draft: false,
        branches,
    })
}

#[derive(Deserialize)]
pub struct ReleaseCreateForm {
    pub tag_name: String,
    pub title: String,
    pub body: Option<String>,
    pub target: Option<String>,
    pub is_prerelease: Option<String>,
    pub is_draft: Option<String>,
}

pub async fn release_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ReleaseCreateForm>,
) -> AppResult<Response> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let tag = form.tag_name.trim().to_string();
    let title = form.title.trim().to_string();
    let body = form.body.clone().unwrap_or_default();
    let target = form
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(repository.default_branch.as_str())
        .to_string();
    let is_prerelease = checkbox(&form.is_prerelease);
    let is_draft = checkbox(&form.is_draft);
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let branches = release_branch_choices(&state, &owner, &repo, &repository.default_branch);

    let redisplay = |err: String| {
        ReleaseNewTemplate {
            viewer: Some(user.clone()),
            owner: owner_user.clone(),
            repo: repository.clone(),
            access,
            error: Some(err),
            clone_http: clone_http.clone(),
            clone_ssh: clone_ssh.clone(),
            tag_name: tag.clone(),
            title: title.clone(),
            body: body.clone(),
            target: target.clone(),
            is_prerelease,
            is_draft,
            branches: branches.clone(),
        }
        .into_response()
    };

    if tag.is_empty() || title.is_empty() {
        return Ok(redisplay("tag and title required".into()));
    }
    if queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .is_some()
    {
        return Ok(redisplay("a release already exists for this tag".into()));
    }

    let bare = git::bare_path(&state.config.repos_dir(), &owner, &repo);
    if let Ok(grepo) = git::open_bare(&state.config.repos_dir(), &owner, &repo) {
        if !git::tag_exists(&grepo, &tag) {
            if let Err(e) = git::create_tag_at(&bare, &tag, &target, &title) {
                return Ok(redisplay(format!("could not create tag: {e}")));
            }
        }
    } else if let Err(e) = git::create_tag_at(&bare, &tag, &target, &title) {
        return Ok(redisplay(format!("could not create tag: {e}")));
    }

    let release = queries::create_release(
        &state.pool,
        repository.id,
        user.id,
        &tag,
        &title,
        &body,
        is_prerelease,
        is_draft,
    )
    .await?;
    let action = if is_draft { "drafted" } else { "published" };
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "release.create",
        &format!("{action} release {tag}"),
        serde_json::json!({ "tag": tag }),
    )
    .await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/releases/{}",
        release.tag_name
    )))
}

pub async fn release_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;
    if release.is_draft && !access.can_write() {
        return Err(AppError::not_found());
    }
    let assets = asset_views(queries::list_release_assets(&state.pool, release.id).await?);
    let author = queries::get_user_by_id(&state.pool, release.author_id)
        .await?
        .ok_or_else(AppError::not_found)?;
    let (tag_short, tag_target) = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .ok()
        .and_then(|g| {
            git::list_tags(&g)
                .ok()?
                .into_iter()
                .find(|t| t.name == tag)
                .map(|t| (t.short_id, t.target))
        })
        .unwrap_or_else(|| (tag.clone(), String::new()));
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    Ok(ReleaseViewTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        author_avatar: avatar_url_for(&author),
        body_html: render_markdown(&release.body),
        release,
        author,
        assets,
        tag_short,
        tag_target,
        clone_http,
        clone_ssh,
    })
}

pub async fn release_edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let _ = viewer.as_ref().ok_or_else(AppError::unauthorized)?;
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let target = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .ok()
        .and_then(|g| {
            git::list_tags(&g)
                .ok()?
                .into_iter()
                .find(|t| t.name == tag)
                .map(|t| t.target)
        })
        .unwrap_or_else(|| repository.default_branch.clone());
    let branches = release_branch_choices(&state, &owner, &repo, &repository.default_branch);
    Ok(ReleaseEditTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        release,
        error: None,
        clone_http,
        clone_ssh,
        target,
        branches,
    })
}

#[derive(Deserialize)]
pub struct ReleaseUpdateForm {
    pub tag_name: String,
    pub title: String,
    pub body: Option<String>,
    pub target: Option<String>,
    pub is_prerelease: Option<String>,
    pub is_draft: Option<String>,
}

pub async fn release_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    Form(form): Form<ReleaseUpdateForm>,
) -> AppResult<Response> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;

    let new_tag = form.tag_name.trim().to_string();
    let title = form.title.trim().to_string();
    let body = form.body.clone().unwrap_or_default();
    let is_prerelease = checkbox(&form.is_prerelease);
    let is_draft = checkbox(&form.is_draft);
    let target = form
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let branches = release_branch_choices(&state, &owner, &repo, &repository.default_branch);

    if new_tag.is_empty() || title.is_empty() {
        let mut release = release;
        release.tag_name = new_tag;
        release.title = title;
        release.body = body;
        release.is_prerelease = is_prerelease;
        release.is_draft = is_draft;
        return Ok(ReleaseEditTemplate {
            viewer: Some(user),
            owner: owner_user,
            repo: repository,
            access,
            release,
            error: Some("tag and title required".into()),
            clone_http,
            clone_ssh,
            target: target.unwrap_or_default(),
            branches,
        }
        .into_response());
    }

    if new_tag != tag {
        if queries::get_release(&state.pool, repository.id, &new_tag)
            .await?
            .is_some()
        {
            return Err(AppError::bad("a release already exists for that tag"));
        }
        if let Ok(grepo) = git::open_bare(&state.config.repos_dir(), &owner, &repo) {
            if git::tag_exists(&grepo, &tag) {
                git::rename_tag(&grepo, &tag, &new_tag)
                    .map_err(|e| AppError::bad(format!("rename tag failed: {e}")))?;
            }
        }
        // Move on-disk assets directory if present
        let old_dir = state
            .config
            .releases_dir()
            .join(repository.id.to_string())
            .join(&tag);
        let new_dir = state
            .config
            .releases_dir()
            .join(repository.id.to_string())
            .join(&new_tag);
        if old_dir.is_dir() && !new_dir.exists() {
            let _ = std::fs::rename(&old_dir, &new_dir);
        }
        let old_prefix = format!("{}/{}/", repository.id, tag);
        let new_prefix = format!("{}/{}/", repository.id, new_tag);
        queries::rewrite_asset_paths_for_tag(&state.pool, release.id, &old_prefix, &new_prefix)
            .await?;
    }

    if let Some(ref tgt) = target {
        let bare = git::bare_path(&state.config.repos_dir(), &owner, &repo);
        let _ = git::retarget_tag(&bare, &new_tag, tgt, &title);
    }

    let updated = queries::update_release(
        &state.pool,
        release.id,
        &new_tag,
        &title,
        &body,
        is_prerelease,
        is_draft,
    )
    .await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "release.update",
        &format!("updated release {}", updated.tag_name),
        serde_json::json!({ "tag": updated.tag_name }),
    )
    .await?;
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/releases/{}",
        updated.tag_name
    )))
}

pub async fn release_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !repository.releases_enabled {
        return Err(AppError::not_found());
    }
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;
    let assets = queries::list_release_assets(&state.pool, release.id).await?;
    for a in &assets {
        let path = state.config.releases_dir().join(&a.stored_path);
        let _ = std::fs::remove_file(path);
    }
    let dir = state
        .config
        .releases_dir()
        .join(repository.id.to_string())
        .join(&tag);
    let _ = std::fs::remove_dir_all(dir);
    queries::delete_release(&state.pool, release.id).await?;
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repository.id),
        "release.delete",
        &format!("deleted release {tag}"),
        serde_json::json!({ "tag": tag }),
    )
    .await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/releases")))
}

pub async fn release_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;

    let dir = state
        .config
        .releases_dir()
        .join(repository.id.to_string())
        .join(&tag);
    std::fs::create_dir_all(&dir)?;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "asset" && name != "file" {
            let _ = field.bytes().await;
            continue;
        }
        let filename = field
            .file_name()
            .unwrap_or("asset.bin")
            .replace(['/', '\\'], "_");
        if filename.is_empty() {
            continue;
        }
        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::bad(e.to_string()))?;
        let stored_name = format!("{}-{}", Uuid::new_v4(), filename);
        let path = dir.join(&stored_name);
        std::fs::write(&path, &data)?;
        let rel = format!("{}/{}/{}", repository.id, tag, stored_name);
        queries::add_release_asset(
            &state.pool,
            release.id,
            &filename,
            &rel,
            data.len() as i64,
            &content_type,
        )
        .await?;
    }

    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/releases/{tag}"
    )))
}

pub async fn asset_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, id)): Path<(String, String, Uuid)>,
) -> AppResult<Response> {
    let (_repository, _o, _viewer, _access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let asset = queries::get_asset(&state.pool, id)
        .await?
        .ok_or_else(AppError::not_found)?;
    let path = state.config.releases_dir().join(&asset.stored_path);
    if !path.is_file() {
        // also try absolute stored path
        let alt = PathBuf::from(&asset.stored_path);
        if alt.is_file() {
            return serve_file(&alt, &asset.filename, &asset.content_type);
        }
        return Err(AppError::not_found());
    }
    serve_file(&path, &asset.filename, &asset.content_type)
}

pub async fn asset_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag, id)): Path<(String, String, String, Uuid)>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let release = queries::get_release(&state.pool, repository.id, &tag)
        .await?
        .ok_or_else(AppError::not_found)?;
    let asset = queries::delete_release_asset(&state.pool, id)
        .await?
        .ok_or_else(AppError::not_found)?;
    if asset.release_id != release.id {
        return Err(AppError::not_found());
    }
    let path = state.config.releases_dir().join(&asset.stored_path);
    let _ = std::fs::remove_file(path);
    Ok(redirect_see_other(&format!(
        "/{owner}/{repo}/releases/{tag}"
    )))
}

fn serve_file(path: &std::path::Path, filename: &str, content_type: &str) -> AppResult<Response> {
    let data = std::fs::read(path)?;
    let disp = format!("attachment; filename=\"{}\"", filename.replace('"', ""));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_DISPOSITION, disp)
        .body(Body::from(data))
        .unwrap())
}

// â”€â”€ repo settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn repo_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let (repository, owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_admin() {
        return Err(AppError::forbidden());
    }
    let collaborators = queries::list_collaborators(&state.pool, repository.id).await?;
    let collab_views: Vec<CollaboratorView> = collaborators
        .into_iter()
        .map(|(c, u)| {
            let avatar_url = avatar_url_for(&u);
            CollaboratorView {
                user: u,
                role: c.role,
                avatar_url,
            }
        })
        .collect();
    let mut branches = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .ok()
        .and_then(|g| git::list_branches(&g).ok())
        .unwrap_or_default();
    if !branches.is_empty() && !branches.iter().any(|b| b == &repository.default_branch) {
        branches.insert(0, repository.default_branch.clone());
    }
    let (clone_http, clone_ssh) = clone_urls(&state, &owner, &repo);
    let branch_rules = queries::list_branch_rules(&state.pool, repository.id).await?;
    let is_site_admin = viewer.as_ref().map(|u| u.is_site_admin).unwrap_or(false);
    Ok(RepoSettingsTemplate {
        viewer,
        owner: owner_user,
        repo: repository,
        access,
        collaborators: collab_views,
        branches,
        clone_http,
        clone_ssh,
        branch_rules,
        is_site_admin,
        error: None,
    })
}

#[derive(Deserialize)]
pub struct RepoSettingsForm {
    pub description: Option<String>,
    pub visibility: Option<String>,
    pub default_branch: Option<String>,
    pub issues_enabled: Option<String>,
    pub pulls_enabled: Option<String>,
    pub releases_enabled: Option<String>,
    pub allow_merge: Option<String>,
    pub allow_squash: Option<String>,
    pub allow_rebase: Option<String>,
    pub default_merge_style: Option<String>,
    pub protect_default_branch: Option<String>,
    pub protect_block_force_push: Option<String>,
}

pub async fn repo_settings_save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<RepoSettingsForm>,
) -> AppResult<Response> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_admin() {
        return Err(AppError::forbidden());
    }
    let visibility = match form.visibility.as_deref() {
        Some("private") => "private",
        _ => "public",
    };
    let merge_style = match form.default_merge_style.as_deref() {
        Some("squash") => "squash",
        Some("rebase") => "rebase",
        _ => "merge",
    };
    let default_branch = form
        .default_branch
        .as_deref()
        .unwrap_or(&repository.default_branch)
        .trim()
        .to_string();
    if default_branch.is_empty() {
        return Err(AppError::bad("default branch required"));
    }
    queries::update_repo_settings(
        &state.pool,
        repository.id,
        form.description.as_deref().unwrap_or(""),
        visibility,
        &default_branch,
        checkbox(&form.issues_enabled),
        checkbox(&form.pulls_enabled),
        checkbox(&form.releases_enabled),
        checkbox(&form.allow_merge),
        checkbox(&form.allow_squash),
        checkbox(&form.allow_rebase),
        merge_style,
        checkbox(&form.protect_default_branch),
        checkbox(&form.protect_block_force_push),
    )
    .await?;
    let bare = git::bare_path(&state.config.repos_dir(), &owner, &repo);
    if let Ok(g) = git::open_bare(&state.config.repos_dir(), &owner, &repo) {
        if git::resolve_ref(&g, &default_branch).is_ok() {
            let _ = git::set_head_branch(&g, &default_branch);
        }
    }
    git::sync_branch_protection(
        &bare,
        &default_branch,
        checkbox(&form.protect_default_branch),
        checkbox(&form.protect_block_force_push),
    )?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

#[derive(Deserialize)]
pub struct CollabAddForm {
    pub username: String,
    pub role: Option<String>,
}

pub async fn collab_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CollabAddForm>,
) -> AppResult<Response> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_admin() {
        return Err(AppError::forbidden());
    }
    let username = form.username.trim();
    let role = match form.role.as_deref() {
        Some("admin") => "admin",
        Some("read") => "read",
        _ => "write",
    };
    let target = queries::get_user_by_username(&state.pool, username)
        .await?
        .ok_or_else(|| AppError::bad("user not found"))?;
    if target.id == repository.owner_id {
        return Err(AppError::bad("owner is already the owner"));
    }
    queries::add_collaborator(&state.pool, repository.id, target.id, role).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

pub async fn collab_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, user_id)): Path<(String, String, Uuid)>,
) -> AppResult<Response> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_admin() {
        return Err(AppError::forbidden());
    }
    queries::remove_collaborator(&state.pool, repository.id, user_id).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

#[derive(Deserialize)]
pub struct ArchiveForm {
    pub archived: Option<String>,
}

pub async fn repo_archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ArchiveForm>,
) -> AppResult<Response> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_owner() {
        return Err(AppError::forbidden());
    }
    let archived = match form.archived.as_deref() {
        Some("false") | Some("0") | Some("unarchive") => false,
        _ => !repository.archived,
    };
    queries::set_archived(&state.pool, repository.id, archived).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub confirm: Option<String>,
}

pub async fn repo_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> AppResult<Response> {
    let (repository, _owner_user, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let user = viewer.ok_or_else(AppError::unauthorized)?;
    let is_admin = user.is_site_admin;
    if !access.can_owner() && !is_admin {
        return Err(AppError::forbidden());
    }
    let confirm = form.confirm.unwrap_or_default();
    if confirm != repository.name && confirm != format!("{owner}/{repo}") {
        return Err(AppError::bad("type the repository name to confirm delete"));
    }
    queries::delete_repo(&state.pool, repository.id).await?;
    let _ = git::remove_bare(&state.config.repos_dir(), &owner, &repo);
    queries::record_activity(
        &state.pool,
        Some(user.id),
        None,
        "repo.delete",
        "deleted repository",
        serde_json::json!({}),
    )
    .await?;
    Ok(redirect_see_other(&format!("/{}", user.username)))
}

#[derive(Deserialize)]
pub struct TransferForm {
    pub new_owner: String,
}

pub async fn repo_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<TransferForm>,
) -> AppResult<Response> {
    let (repository, _o, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _user = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_owner() {
        return Err(AppError::forbidden());
    }
    let new_name = form.new_owner.trim();
    let new_owner = queries::get_user_by_username(&state.pool, new_name)
        .await?
        .ok_or_else(|| AppError::bad("user not found"))?;
    if new_owner.id == repository.owner_id {
        return Err(AppError::bad("already owned by that user"));
    }
    if queries::get_repo(&state.pool, &new_owner.username, &repo)
        .await?
        .is_some()
    {
        return Err(AppError::bad("target already has a repo with that name"));
    }

    let old_path = git::bare_path(&state.config.repos_dir(), &owner, &repo);
    let new_path = git::bare_path(&state.config.repos_dir(), &new_owner.username, &repo);
    if old_path.exists() {
        if let Some(parent) = new_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&old_path, &new_path).map_err(|e| {
            AppError::internal(format!("failed to move repository on disk: {e}"))
        })?;
    }

    queries::transfer_repo(&state.pool, repository.id, new_owner.id).await?;
    Ok(redirect_see_other(&format!(
        "/{}/{repo}",
        new_owner.username
    )))
}

