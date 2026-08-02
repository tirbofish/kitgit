pub mod routes;
pub mod routes_extra;
pub mod templates;

use crate::git;
use crate::state::AppState;
use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::time::{Duration, Instant};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;

const RENDER_MS_MARKER: &[u8] = b"<!--kg-render-ms-->";

fn format_render_duration(elapsed: Duration) -> String {
    let ms = elapsed.as_secs_f64() * 1000.0;
    if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{:.0}ms", ms.round())
    }
}

fn inject_render_marker(html: &[u8], label: &str) -> Option<Vec<u8>> {
    let pos = html
        .windows(RENDER_MS_MARKER.len())
        .position(|window| window == RENDER_MS_MARKER)?;
    let mut out = Vec::with_capacity(html.len() - RENDER_MS_MARKER.len() + label.len());
    out.extend_from_slice(&html[..pos]);
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(&html[pos + RENDER_MS_MARKER.len()..]);
    Some(out)
}

/// Measure HTML page handler time and fill the layout footer timing marker.
async fn inject_render_timing(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let res = next.run(req).await;
    let elapsed = start.elapsed();

    let is_html = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));
    if !is_html {
        return res;
    }

    let (mut parts, body) = res.into_parts();
    let Ok(bytes) = to_bytes(body, 16 * 1024 * 1024).await else {
        return Response::from_parts(parts, Body::empty());
    };

    let label = format_render_duration(elapsed);
    let body = match inject_render_marker(&bytes, &label) {
        Some(updated) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            if let Ok(len) = HeaderValue::from_str(&updated.len().to_string()) {
                parts.headers.insert(header::CONTENT_LENGTH, len);
            }
            Body::from(updated)
        }
        None => Body::from(bytes),
    };
    Response::from_parts(parts, body)
}

/// Rewrite `/owner/repo.git` ├óΓÇáΓÇÖ `/owner/repo` and drop a trailing slash so
/// browser pages and git smart-HTTP both work with classic forge URLs.
fn normalize_repo_path(path: &str) -> String {
    let mut path = path.to_string();
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    if let Some(idx) = path.find(".git/") {
        path = format!("{}{}", &path[..idx], &path[idx + 4..]);
    } else if path.ends_with(".git") {
        path.truncate(path.len() - 4);
    }
    if path.is_empty() {
        "/".into()
    } else {
        path
    }
}

async fn normalize_git_url(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let normalized = normalize_repo_path(path);
    if normalized != path {
        // 308 keeps method/body (needed for git-receive-pack POST).
        let dest = match req.uri().query() {
            Some(q) => format!("{normalized}?{q}"),
            None => normalized,
        };
        return (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, dest)]).into_response();
    }
    next.run(req).await
}

pub fn app_router(state: AppState) -> Router {
    let static_dir = state.config.static_dir.clone();
    Router::new()
        .route("/", get(routes::home))
        .route("/og.png", get(routes::site_og_image))
        .route("/explore", get(routes::explore))
        .route("/search", get(routes::explore))
        .route(
            "/auth/login",
            get(routes::auth_login_page).post(routes::auth_login_submit),
        )
        .route(
            "/auth/mfa",
            get(routes::auth_mfa_page).post(routes::auth_mfa_submit),
        )
        .route(
            "/auth/signup",
            get(routes::auth_signup_page).post(routes::auth_signup_submit),
        )
        .route("/auth/oidc", get(routes::auth_oidc_start))
        .route("/auth/callback", get(routes::auth_callback))
        .route("/auth/logout", get(routes::auth_logout))
        .route("/admin", get(routes::admin_panel))
        .route(
            "/admin/users/{username}/audit",
            get(routes::admin_user_audit),
        )
        .route("/admin/users", post(routes::admin_set_user))
        .route("/admin/users/suspend", post(routes::admin_set_suspended))
        .route("/admin/motd", post(routes::admin_save_motd))
        .route("/admin/announcement", post(routes::admin_save_announcement))
        .route("/admin/signups", post(routes::admin_save_signups))
        .route("/admin/invites", post(routes::admin_create_invite))
        .route(
            "/admin/invites/{id}/revoke",
            post(routes::admin_revoke_invite),
        )
        .route(
            "/admin/repos/{id}/visibility",
            post(routes::admin_repo_visibility),
        )
        .route("/admin/repos/{id}/delete", post(routes::admin_repo_delete))
        .route("/site-banner.json", get(routes::site_banner_json))
        .route("/notifications", get(routes::notifications_list))
        .route(
            "/notifications/unread.json",
            get(routes::notifications_unread_json),
        )
        .route(
            "/notifications/read-all",
            post(routes::notifications_mark_all_read),
        )
        .route(
            "/notifications/{id}/read",
            post(routes::notifications_mark_read),
        )
        .route(
            "/organizations/new",
            get(routes::organization_new_form).post(routes::organization_new),
        )
        .route(
            "/organizations/{organization}/settings",
            get(routes::organization_settings).post(routes::organization_settings_save),
        )
        .route(
            "/organizations/{organization}/delete",
            post(routes::organization_delete),
        )
        .route(
            "/organizations/{organization}/people/invite",
            post(routes::organization_invite),
        )
        .route(
            "/organizations/{organization}/people/{user_id}/role",
            post(routes::organization_member_role),
        )
        .route(
            "/organizations/{organization}/people/{user_id}/remove",
            post(routes::organization_member_remove),
        )
        .route(
            "/organizations/{organization}/people/{user_id}/visibility",
            post(routes::organization_membership_visibility),
        )
        .route(
            "/organizations/{organization}/leave",
            post(routes::organization_leave),
        )
        .route(
            "/organizations/{organization}/invitations/{id}/cancel",
            post(routes::organization_invitation_cancel),
        )
        .route(
            "/organizations/invitations/{id}",
            get(routes::organization_invitation_page).post(routes::organization_invitation_respond),
        )
        .route("/new", get(routes::new_repo_form).post(routes::new_repo))
        .route(
            "/settings/profile",
            get(routes::profile_settings).post(routes::profile_settings_save),
        )
        .route("/settings/account", get(routes_extra::account_settings))
        .route("/settings/mfa", get(routes_extra::mfa_settings))
        .route("/settings/mfa/enroll", post(routes_extra::mfa_enroll))
        .route("/settings/mfa/confirm", post(routes_extra::mfa_confirm))
        .route("/settings/mfa/disable", post(routes_extra::mfa_disable))
        .route(
            "/settings/account/username",
            post(routes_extra::account_change_username),
        )
        .route(
            "/settings/account/password",
            post(routes_extra::account_change_password),
        )
        .route(
            "/settings/account/privacy",
            post(routes_extra::account_privacy),
        )
        .route("/settings/account/theme", post(routes_extra::account_theme))
        .route(
            "/settings/account/emails",
            post(routes_extra::account_add_email),
        )
        .route(
            "/settings/account/emails/{id}/delete",
            post(routes_extra::account_delete_email),
        )
        .route(
            "/settings/account/emails/{id}/primary",
            post(routes_extra::account_set_primary_email),
        )
        .route(
            "/settings/account/sessions/{id}/revoke",
            post(routes_extra::account_revoke_session),
        )
        .route(
            "/settings/account/sessions/revoke-others",
            post(routes_extra::account_revoke_others),
        )
        .route(
            "/settings/account/export",
            get(routes_extra::account_export),
        )
        .route(
            "/settings/account/delete",
            post(routes_extra::account_delete),
        )
        .route(
            "/settings/keys",
            get(routes::keys_settings).post(routes::keys_add),
        )
        .route("/settings/keys/{id}/delete", post(routes::keys_delete))
        .route("/settings/keys/{id}/usage", post(routes::keys_update_usage))
        .route("/settings/gpg", post(routes_extra::gpg_add))
        .route("/settings/gpg/{id}/delete", post(routes_extra::gpg_delete))
        .route("/avatars/{user_id}", get(routes::avatar))
        .route("/{owner}/{repo}/info/refs", get(git::http::info_refs))
        .route(
            "/{owner}/{repo}/git-upload-pack",
            post(git::http::upload_pack),
        )
        .route(
            "/{owner}/{repo}/git-receive-pack",
            post(git::http::receive_pack),
        )
        .route(
            "/{owner}/{repo}/info/lfs/objects/batch",
            post(git::lfs::lfs_batch),
        )
        .route(
            "/{owner}/{repo}/info/lfs/objects/{oid}/{size}",
            get(git::lfs::lfs_download).put(git::lfs::lfs_upload),
        )
        .route("/{owner}/{repo}", get(routes::repo_home))
        .route("/{owner}/{repo}/og.png", get(routes::repo_og_image))
        .route("/{owner}/{repo}/tree/{*rest}", get(routes::repo_tree))
        .route("/{owner}/{repo}/blob/{*rest}", get(routes::repo_blob))
        .route("/{owner}/{repo}/blame/{*rest}", get(routes::repo_blame))
        .route("/{owner}/{repo}/history/{*rest}", get(routes::repo_history))
        .route("/{owner}/{repo}/raw/{*rest}", get(routes_extra::repo_raw))
        .route("/{owner}/{repo}/star", post(routes_extra::repo_star))
        .route("/{owner}/{repo}/watch", post(routes_extra::repo_watch))
        .route("/{owner}/{repo}/fork", post(routes_extra::repo_fork))
        .route(
            "/{owner}/{repo}/comments/{comment_id}/react",
            post(routes_extra::comment_react),
        )
        .route("/{owner}/{repo}/commits", get(routes::repo_commits))
        .route("/{owner}/{repo}/commit/{id}", get(routes::repo_commit))
        .route("/{owner}/{repo}/diff/{id}", get(routes::repo_diff))
        .route("/{owner}/{repo}/archive.zip", get(routes::repo_archive_zip))
        .route("/{owner}/{repo}/upload", post(routes::repo_upload))
        .route("/{owner}/{repo}/branches", get(routes::repo_branches))
        .route(
            "/{owner}/{repo}/branches/rename",
            post(routes_extra::branch_rename),
        )
        .route(
            "/{owner}/{repo}/branches/delete",
            post(routes_extra::branch_delete),
        )
        .route("/{owner}/{repo}/tags", post(routes_extra::tag_create))
        .route(
            "/{owner}/{repo}/tags/rename",
            post(routes_extra::tag_rename),
        )
        .route(
            "/{owner}/{repo}/tags/delete",
            post(routes_extra::tag_delete),
        )
        .route(
            "/{owner}/{repo}/issues",
            get(routes::issues_list).post(routes::issue_create),
        )
        .route("/{owner}/{repo}/issues/new", get(routes::issue_new))
        .route(
            "/{owner}/{repo}/issues/{number}",
            get(routes::issue_view).post(routes::issue_comment),
        )
        .route(
            "/{owner}/{repo}/issues/{number}/close",
            post(routes::issue_close),
        )
        .route(
            "/{owner}/{repo}/issues/{number}/reopen",
            post(routes::issue_reopen),
        )
        .route(
            "/{owner}/{repo}/issues/{number}/labels",
            post(routes::issue_labels_save),
        )
        .route(
            "/{owner}/{repo}/issues/{number}/milestone",
            post(routes::issue_milestone_save),
        )
        .route(
            "/{owner}/{repo}/pulls",
            get(routes::pulls_list).post(routes::pull_create),
        )
        .route("/{owner}/{repo}/pulls/new", get(routes::pull_new))
        .route(
            "/{owner}/{repo}/pulls/{number}",
            get(routes::pull_view).post(routes::pull_comment),
        )
        .route(
            "/{owner}/{repo}/pulls/{number}/merge",
            post(routes::pull_merge),
        )
        .route(
            "/{owner}/{repo}/pulls/{number}/close",
            post(routes::pull_close),
        )
        .route(
            "/{owner}/{repo}/pulls/{number}/labels",
            post(routes::pull_labels_save),
        )
        .route(
            "/{owner}/{repo}/pulls/{number}/milestone",
            post(routes::pull_milestone_save),
        )
        .route(
            "/{owner}/{repo}/pulls/{number}/review",
            post(routes::pull_review),
        )
        .route(
            "/{owner}/{repo}/labels",
            get(routes_extra::labels_list).post(routes_extra::label_create),
        )
        .route(
            "/{owner}/{repo}/labels/{id}/update",
            post(routes_extra::label_update),
        )
        .route(
            "/{owner}/{repo}/labels/{id}/delete",
            post(routes_extra::label_delete),
        )
        .route(
            "/{owner}/{repo}/milestones",
            get(routes_extra::milestones_list).post(routes_extra::milestone_create),
        )
        .route(
            "/{owner}/{repo}/milestones/{id}/update",
            post(routes_extra::milestone_update),
        )
        .route(
            "/{owner}/{repo}/milestones/{id}/close",
            post(routes_extra::milestone_close),
        )
        .route(
            "/{owner}/{repo}/milestones/{id}/reopen",
            post(routes_extra::milestone_reopen),
        )
        .route(
            "/{owner}/{repo}/milestones/{id}/delete",
            post(routes_extra::milestone_delete),
        )
        .route(
            "/{owner}/{repo}/releases",
            get(routes::releases_list).post(routes::release_create),
        )
        .route("/{owner}/{repo}/releases/new", get(routes::release_new))
        .route("/{owner}/{repo}/releases/{tag}", get(routes::release_view))
        .route(
            "/{owner}/{repo}/releases/{tag}/edit",
            get(routes::release_edit).post(routes::release_update),
        )
        .route(
            "/{owner}/{repo}/releases/{tag}/delete",
            post(routes::release_delete),
        )
        .route(
            "/{owner}/{repo}/releases/{tag}/upload",
            post(routes::release_upload),
        )
        .route(
            "/{owner}/{repo}/releases/{tag}/assets/{id}/delete",
            post(routes::asset_delete),
        )
        .route("/{owner}/{repo}/assets/{id}", get(routes::asset_download))
        .route(
            "/{owner}/{repo}/settings",
            get(routes::repo_settings).post(routes::repo_settings_save),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators",
            post(routes::collab_add),
        )
        .route(
            "/{owner}/{repo}/settings/collaborators/{user_id}/remove",
            post(routes::collab_remove),
        )
        .route(
            "/{owner}/{repo}/settings/deploy-keys",
            post(routes::deploy_key_add),
        )
        .route(
            "/{owner}/{repo}/settings/deploy-keys/{id}/delete",
            post(routes::deploy_key_delete),
        )
        .route(
            "/{owner}/{repo}/settings/webhooks",
            post(routes::webhook_add),
        )
        .route(
            "/{owner}/{repo}/settings/webhooks/{id}/delete",
            post(routes::webhook_delete),
        )
        .route(
            "/{owner}/{repo}/settings/webhooks/{id}/toggle",
            post(routes::webhook_toggle),
        )
        .route(
            "/{owner}/{repo}/settings/branch-rules",
            post(routes_extra::branch_rule_add),
        )
        .route(
            "/{owner}/{repo}/settings/branch-rules/{id}/delete",
            post(routes_extra::branch_rule_delete),
        )
        .route(
            "/{owner}/{repo}/settings/mirror",
            post(routes_extra::mirror_save),
        )
        .route(
            "/{owner}/{repo}/settings/mirror/sync",
            post(routes_extra::mirror_sync),
        )
        .route(
            "/{owner}/{repo}/settings/mirror/delete",
            post(routes_extra::mirror_delete),
        )
        .route(
            "/{owner}/{repo}/settings/danger/archive",
            post(routes::repo_archive),
        )
        .route(
            "/{owner}/{repo}/settings/danger/delete",
            post(routes::repo_delete),
        )
        .route(
            "/{owner}/{repo}/settings/danger/transfer",
            post(routes::repo_transfer),
        )
        .route("/{username}", get(routes::profile))
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(from_fn(inject_render_timing))
        .layer(from_fn(normalize_git_url))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod path_tests {
    use super::{format_render_duration, inject_render_marker, normalize_repo_path};
    use std::time::Duration;

    #[test]
    fn strips_git_suffix_and_slash() {
        assert_eq!(normalize_repo_path("/o/r.git"), "/o/r");
        assert_eq!(normalize_repo_path("/o/r.git/"), "/o/r");
        assert_eq!(normalize_repo_path("/o/r.git/info/refs"), "/o/r/info/refs");
        assert_eq!(normalize_repo_path("/o/r/"), "/o/r");
        assert_eq!(normalize_repo_path("/"), "/");
    }

    #[test]
    fn injects_render_timing_marker() {
        let html = b"<footer>rendered in <!--kg-render-ms--></footer>";
        let out = inject_render_marker(html, "4.2ms").unwrap();
        assert_eq!(out, b"<footer>rendered in 4.2ms</footer>");
        assert!(inject_render_marker(b"<footer>kitgit</footer>", "1ms").is_none());
    }

    #[test]
    fn formats_render_duration() {
        assert_eq!(format_render_duration(Duration::from_micros(4200)), "4.2ms");
        assert_eq!(format_render_duration(Duration::from_millis(42)), "42ms");
    }
}
