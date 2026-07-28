//! Social, account, branch, raw, and admin helpers.

use super::routes::{
    avatar_url_for, load_repo_context, redirect_see_other, require_login, AppError, AppResult,
};
use crate::auth::{self, clear_session_cookie, hash_token, token_from_headers};
use crate::db::queries;
use crate::git;
use crate::state::AppState;
use crate::web::templates::*;
use axum::extract::{Form, Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::body::Body;
use serde::Deserialize;
use uuid::Uuid;

fn checkbox(v: &Option<String>) -> bool {
    matches!(
        v.as_deref(),
        Some("on") | Some("true") | Some("1") | Some("yes")
    )
}

pub async fn repo_raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let (_repository, _owner_user, _viewer, _access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)
        .map_err(|_| AppError::not_found())?;
    // reuse split via rest: branch/path
    let rest = rest.trim_matches('/');
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() < 2 {
        return Err(AppError::bad("missing path"));
    }
    // Prefer longest matching ref prefix
    let (branch, path) = {
        let mut found = None;
        for i in (1..parts.len()).rev() {
            let reference = parts[..i].join("/");
            if git::resolve_ref(&grepo, &reference).is_ok() {
                found = Some((reference, parts[i..].join("/")));
                break;
            }
        }
        found.unwrap_or_else(|| (parts[0].to_string(), parts[1..].join("/")))
    };
    if path.is_empty() {
        return Err(AppError::bad("missing file path"));
    }
    let (data, _binary) = git::read_blob(&grepo, &branch, &path).map_err(|_| AppError::not_found())?;
    let filename = path.rsplit('/').next().unwrap_or("file");
    let ct = mime_guess::from_path(filename)
        .first_or_octet_stream()
        .to_string();
    let disp = format!("attachment; filename=\"{filename}\"");
    Ok((
        [
            (CONTENT_TYPE, HeaderValue::from_str(&ct).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))),
            (
                CONTENT_DISPOSITION,
                HeaderValue::from_str(&disp).unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            ),
        ],
        Body::from(data),
    )
        .into_response())
}

pub async fn repo_star(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let (repository, _, _, _) = load_repo_context(&state, &owner, &repo, &headers).await?;
    queries::toggle_star(&state.pool, repository.id, user.id).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}")))
}

pub async fn repo_watch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let (repository, _, _, _) = load_repo_context(&state, &owner, &repo, &headers).await?;
    queries::toggle_watch(&state.pool, repository.id, user.id).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}")))
}

pub async fn repo_fork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let (repository, owner_user, _, _) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if owner_user.id == user.id {
        return Err(AppError::bad("cannot fork your own repository"));
    }
    if let Some(existing) =
        queries::get_fork_of_user(&state.pool, repository.id, user.id).await?
    {
        return Ok(redirect_see_other(&format!(
            "/{}/{}",
            user.username, existing.name
        )));
    }
    let name = repository.name.clone();
    if queries::get_repo(&state.pool, &user.username, &name)
        .await?
        .is_some()
    {
        return Err(AppError::bad(
            "you already have a repository with this name",
        ));
    }
    let src = git::bare_path(&state.config.repos_dir(), &owner, &repo);
    let dest = git::bare_path(&state.config.repos_dir(), &user.username, &name);
    git::clone_bare(&src, &dest)?;
    let forked = queries::create_fork(
        &state.pool,
        user.id,
        &name,
        &repository.description,
        &repository.visibility,
        repository.id,
    )
    .await?;
    let _ = forked;
    Ok(redirect_see_other(&format!("/{}/{}", user.username, name)))
}

#[derive(Deserialize)]
pub struct ReactForm {
    pub emoji: String,
}

pub async fn comment_react(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, comment_id)): Path<(String, String, Uuid)>,
    Form(form): Form<ReactForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let (_repository, _, _, access) = load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_read() {
        return Err(AppError::forbidden());
    }
    let allowed = [
        "+1", "-1", "laugh", "hooray", "confused", "heart", "rocket", "eyes",
    ];
    if !allowed.contains(&form.emoji.as_str()) {
        return Err(AppError::bad("invalid reaction"));
    }
    queries::toggle_reaction(&state.pool, comment_id, user.id, &form.emoji).await?;
    let referer = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    // Prefer relative path
    let path = if let Ok(u) = url::Url::parse(referer) {
        u.path().to_string()
    } else if referer.starts_with('/') {
        referer.to_string()
    } else {
        format!("/{owner}/{repo}")
    };
    Ok(redirect_see_other(&path))
}

#[derive(Deserialize)]
pub struct BranchRuleForm {
    pub pattern: String,
    pub require_pr: Option<String>,
    pub block_force_push: Option<String>,
    pub allow_deletions: Option<String>,
}

pub async fn branch_rule_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<BranchRuleForm>,
) -> AppResult<Response> {
    let (_u, repository, access) = {
        let (repository, _, viewer, access) =
            load_repo_context(&state, &owner, &repo, &headers).await?;
        let _ = viewer.ok_or_else(AppError::unauthorized)?;
        if !access.can_admin() {
            return Err(AppError::forbidden());
        }
        ((), repository, access)
    };
    let _ = access;
    let pattern = form.pattern.trim();
    if pattern.is_empty() {
        return Err(AppError::bad("pattern required"));
    }
    queries::add_branch_rule(
        &state.pool,
        repository.id,
        pattern,
        checkbox(&form.require_pr),
        checkbox(&form.block_force_push),
        checkbox(&form.allow_deletions),
    )
    .await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

pub async fn branch_rule_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, id)): Path<(String, String, Uuid)>,
) -> AppResult<Response> {
    let (repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_admin() {
        return Err(AppError::forbidden());
    }
    queries::delete_branch_rule(&state.pool, id, repository.id).await?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/settings")))
}

#[derive(Deserialize)]
pub struct RenameBranchForm {
    pub new_name: String,
}

pub async fn branch_rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, branch)): Path<(String, String, String)>,
    Form(form): Form<RenameBranchForm>,
) -> AppResult<Response> {
    let (repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    if branch == repository.default_branch {
        return Err(AppError::bad("cannot rename default branch here"));
    }
    let new_name = form.new_name.trim();
    if new_name.is_empty() || new_name.contains('/') {
        return Err(AppError::bad("invalid branch name"));
    }
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)?;
    git::rename_branch(&grepo, &branch, new_name)?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/branches")))
}

pub async fn branch_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let (repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    if branch == repository.default_branch {
        return Err(AppError::bad("cannot delete default branch"));
    }
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)?;
    git::delete_branch(&grepo, &branch)?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/branches")))
}

#[derive(Deserialize)]
pub struct CreateTagForm {
    pub name: String,
    pub target: Option<String>,
    pub message: Option<String>,
}

pub async fn tag_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CreateTagForm>,
) -> AppResult<Response> {
    let (repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let name = form.name.trim();
    if name.is_empty() || name.contains("..") {
        return Err(AppError::bad("invalid tag name"));
    }
    let target = form
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(repository.default_branch.as_str());
    let message = form.message.unwrap_or_default();
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)?;
    if git::tag_exists(&grepo, name) {
        return Err(AppError::bad("tag already exists"));
    }
    let bare = git::bare_path(&state.config.repos_dir(), &owner, &repo);
    git::create_tag_at(&bare, name, target, &message)
        .map_err(|e| AppError::bad(format!("create tag failed: {e}")))?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/branches")))
}

#[derive(Deserialize)]
pub struct RenameTagForm {
    pub new_name: String,
}

pub async fn tag_rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    Form(form): Form<RenameTagForm>,
) -> AppResult<Response> {
    let (repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let new_name = form.new_name.trim();
    if new_name.is_empty() || new_name.contains("..") {
        return Err(AppError::bad("invalid tag name"));
    }
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)?;
    git::rename_tag(&grepo, &tag, new_name)
        .map_err(|e| AppError::bad(format!("rename tag failed: {e}")))?;
    if let Some(release) =
        queries::rename_release_tag(&state.pool, repository.id, &tag, new_name).await?
    {
        let old_dir = state
            .config
            .releases_dir()
            .join(repository.id.to_string())
            .join(&tag);
        let new_dir = state
            .config
            .releases_dir()
            .join(repository.id.to_string())
            .join(new_name);
        if old_dir.is_dir() && !new_dir.exists() {
            let _ = std::fs::rename(&old_dir, &new_dir);
        }
        let old_prefix = format!("{}/{}/", repository.id, tag);
        let new_prefix = format!("{}/{}/", repository.id, new_name);
        queries::rewrite_asset_paths_for_tag(&state.pool, release.id, &old_prefix, &new_prefix)
            .await?;
    }
    Ok(redirect_see_other(&format!("/{owner}/{repo}/branches")))
}

pub async fn tag_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let (_repository, _, viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let _ = viewer.ok_or_else(AppError::unauthorized)?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    let grepo = git::open_bare(&state.config.repos_dir(), &owner, &repo)?;
    git::delete_tag(&grepo, &tag).map_err(|e| AppError::bad(format!("delete tag failed: {e}")))?;
    Ok(redirect_see_other(&format!("/{owner}/{repo}/branches")))
}

// ── account settings ─────────────────────────────────────────────────────────

pub async fn account_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let emails = queries::list_user_emails(&state.pool, user.id).await?;
    let sessions_raw = queries::list_sessions(&state.pool, user.id).await?;
    let current_hash = token_from_headers(&headers).map(|t| hash_token(&t));
    let mut current_session_id = None;
    let sessions = sessions_raw
        .into_iter()
        .map(|s| {
            let is_current = current_hash
                .as_ref()
                .map(|h| h == &s.token_hash)
                .unwrap_or(false);
            if is_current {
                current_session_id = Some(s.id);
            }
            SessionView {
                id: s.id,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                is_current,
            }
        })
        .collect();
    Ok(AccountSettingsTemplate {
        viewer: Some(user.clone()),
        user,
        emails,
        sessions,
        current_session_id,
        error: None,
        message: None,
    })
}

fn mfa_page(
    user: crate::db::models::User,
    mfa: Option<crate::db::models::UserMfa>,
    recovery_codes: Option<Vec<String>>,
    error: Option<String>,
    message: Option<String>,
) -> AppResult<MfaSettingsTemplate> {
    let enabled = mfa.as_ref().is_some_and(|m| m.enabled);
    let pending_secret = mfa
        .as_ref()
        .and_then(|m| m.pending_secret.clone())
        .filter(|s| !s.is_empty());
    let pending = !enabled && pending_secret.is_some();
    let (secret, qr_data_uri) = if let Some(ref sec) = pending_secret {
        let uri = crate::mfa::otpauth_uri(&user.username, sec, "kitgit");
        let qr = crate::mfa::qr_svg_data_uri(&uri).ok();
        (Some(sec.clone()), qr)
    } else {
        (None, None)
    };
    let recovery_remaining = mfa
        .as_ref()
        .map(|m| m.recovery_code_hashes.len())
        .unwrap_or(0);
    Ok(MfaSettingsTemplate {
        viewer: Some(user.clone()),
        user,
        enabled,
        pending,
        secret,
        qr_data_uri,
        recovery_codes,
        recovery_remaining,
        error,
        message,
    })
}

pub async fn mfa_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let mfa = queries::get_user_mfa(&state.pool, user.id).await?;
    Ok(mfa_page(user, mfa, None, None, None)?)
}

pub async fn mfa_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    if queries::mfa_is_enabled(&state.pool, user.id).await? {
        return Ok(redirect_see_other("/settings/mfa"));
    }
    let secret = crate::mfa::generate_totp_secret();
    queries::mfa_start_enroll(&state.pool, user.id, &secret).await?;
    Ok(redirect_see_other("/settings/mfa"))
}

#[derive(Deserialize)]
pub struct MfaCodeForm {
    pub code: String,
}

pub async fn mfa_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaCodeForm>,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let mfa = queries::get_user_mfa(&state.pool, user.id)
        .await?
        .ok_or_else(|| AppError::bad("start enrollment first"))?;
    let pending = mfa
        .pending_secret
        .as_deref()
        .ok_or_else(|| AppError::bad("start enrollment first"))?;
    if !crate::mfa::verify_totp(pending, &form.code) {
        return Ok(mfa_page(
            user,
            Some(mfa),
            None,
            Some("invalid confirmation code".into()),
            None,
        )?
        .into_response());
    }
    let codes = crate::mfa::generate_recovery_codes();
    let hashes: Vec<String> = codes.iter().map(|c| crate::mfa::hash_recovery_code(c)).collect();
    let secret = pending.to_string();
    queries::mfa_confirm_enroll(&state.pool, user.id, &secret, &hashes).await?;
    let mfa = queries::get_user_mfa(&state.pool, user.id).await?;
    Ok(mfa_page(
        user,
        mfa,
        Some(codes),
        None,
        Some("two-factor authentication enabled".into()),
    )?
    .into_response())
}

pub async fn mfa_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MfaCodeForm>,
) -> AppResult<impl IntoResponse> {
    let user = require_login(&state.auth, &headers).await?;
    let mfa = queries::get_user_mfa(&state.pool, user.id)
        .await?
        .ok_or_else(|| AppError::bad("MFA is not enabled"))?;
    if !mfa.enabled {
        return Ok(redirect_see_other("/settings/mfa").into_response());
    }
    let secret = mfa
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::bad("MFA is not enabled"))?;
    let ok = if crate::mfa::verify_totp(secret, &form.code) {
        true
    } else if let Some(idx) = crate::mfa::verify_recovery_code(&mfa.recovery_code_hashes, &form.code)
    {
        let mut hashes = mfa.recovery_code_hashes.clone();
        hashes.remove(idx);
        queries::mfa_set_recovery_hashes(&state.pool, user.id, &hashes).await?;
        true
    } else {
        false
    };
    if !ok {
        return Ok(mfa_page(
            user,
            Some(mfa),
            None,
            Some("invalid authentication code".into()),
            None,
        )?
        .into_response());
    }
    queries::mfa_disable(&state.pool, user.id).await?;
    Ok(redirect_see_other("/settings/mfa").into_response())
}

#[derive(Deserialize)]
pub struct UsernameForm {
    pub username: String,
}

pub async fn account_change_username(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UsernameForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let username = form.username.trim().to_lowercase();
    if !username
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false)
        || username.len() > 39
        || !username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(AppError::bad("invalid username"));
    }
    if username != user.username {
        if queries::get_user_by_username(&state.pool, &username)
            .await?
            .is_some()
        {
            return Err(AppError::bad("username taken"));
        }
        // rename repos on disk
        let old_root = state.config.repos_dir().join(&user.username);
        let new_root = state.config.repos_dir().join(&username);
        if old_root.exists() {
            if new_root.exists() {
                return Err(AppError::bad("cannot rename: target path exists"));
            }
            std::fs::rename(&old_root, &new_root)?;
        }
        queries::update_username(&state.pool, user.id, &username).await?;
    }
    Ok(redirect_see_other("/settings/account"))
}

#[derive(Deserialize)]
pub struct PasswordForm {
    pub current_password: String,
    pub new_password: String,
}

pub async fn account_change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    if form.new_password.len() < 8 {
        return Err(AppError::bad("password must be at least 8 characters"));
    }
    // Verify current password via Authentik (no session / MFA side effects).
    auth::verify_password(&state.auth, &user.username, &form.current_password)
        .await
        .map_err(|_| AppError::bad("current password incorrect"))?;
    let pk = auth::authentik_user_pk(&state.auth, &user.username)
        .await
        .map_err(|e| AppError::bad(crate::mfa::sanitize_user_error(&e.to_string())))?;
    auth::authentik_set_password(&state.auth, pk, &form.new_password)
        .await
        .map_err(|e| AppError::bad(crate::mfa::sanitize_user_error(&e.to_string())))?;
    Ok(redirect_see_other("/settings/account"))
}

#[derive(Deserialize)]
pub struct PrivacyForm {
    pub show_email: Option<String>,
    pub vigilant_mode: Option<String>,
}

pub async fn account_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PrivacyForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::update_privacy(
        &state.pool,
        user.id,
        checkbox(&form.show_email),
        checkbox(&form.vigilant_mode),
    )
    .await?;
    Ok(redirect_see_other("/settings/account"))
}

#[derive(Deserialize)]
pub struct ThemeForm {
    pub theme: String,
}

pub async fn account_theme(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ThemeForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let theme = match form.theme.trim() {
        "light" | "dark" | "system" => form.theme.trim(),
        _ => return Err(AppError::bad("theme must be light, dark, or system")),
    };
    queries::update_user_theme(&state.pool, user.id, theme).await?;
    Ok(redirect_see_other("/settings/account"))
}

#[derive(Deserialize)]
pub struct EmailForm {
    pub email: String,
}

pub async fn account_add_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let email = form.email.trim();
    if !email.contains('@') {
        return Err(AppError::bad("invalid email"));
    }
    queries::add_user_email(&state.pool, user.id, email).await?;
    Ok(redirect_see_other("/settings/account"))
}

pub async fn account_delete_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::delete_user_email(&state.pool, id, user.id).await?;
    Ok(redirect_see_other("/settings/account"))
}

pub async fn account_revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::delete_session_by_id(&state.pool, id, user.id).await?;
    Ok(redirect_see_other("/settings/account"))
}

pub async fn account_revoke_others(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let Some(token) = token_from_headers(&headers) else {
        return Err(AppError::unauthorized());
    };
    queries::delete_other_sessions(&state.pool, user.id, &hash_token(&token)).await?;
    Ok(redirect_see_other("/settings/account"))
}

pub async fn account_export(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let data = queries::export_user_data(&state.pool, user.id).await?;
    let body = serde_json::to_vec_pretty(&data).map_err(|e| AppError::internal(e))?;
    Ok((
        [
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"kitgit-export.json\""),
            ),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DeleteAccountForm {
    pub confirm: String,
}

pub async fn account_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteAccountForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    if form.confirm != user.username {
        return Err(AppError::bad("type your username to confirm"));
    }
    // Remove repos on disk
    let root = state.config.repos_dir().join(&user.username);
    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }
    queries::delete_user(&state.pool, user.id).await?;
    Ok((
        StatusCode::SEE_OTHER,
        [
            (
                axum::http::header::LOCATION,
                HeaderValue::from_static("/"),
            ),
            (SET_COOKIE, clear_session_cookie()),
        ],
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct GpgForm {
    pub name: String,
    pub public_key: String,
}

pub async fn gpg_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GpgForm>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    let key = form.public_key.trim();
    if !key.contains("BEGIN PGP PUBLIC KEY") {
        return Err(AppError::bad("expected a PGP public key block"));
    }
    let fp = crate::git::verify::gpg_fingerprint_from_armor(key)
        .unwrap_or_else(|_| crate::git::verify::gpg_fingerprint_fallback(key));
    queries::add_gpg_key(&state.pool, user.id, form.name.trim(), key, &fp).await?;
    Ok(redirect_see_other("/settings/keys"))
}

pub async fn gpg_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Response> {
    let user = require_login(&state.auth, &headers).await?;
    queries::delete_gpg_key(&state.pool, id, user.id).await?;
    Ok(redirect_see_other("/settings/keys"))
}

// silence unused import warning for avatar_url_for if not used
#[allow(dead_code)]
fn _use_avatar(u: &crate::db::models::User) -> String {
    avatar_url_for(u)
}
