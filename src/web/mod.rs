pub mod routes;
pub mod routes_extra;
pub mod templates;

use crate::git;
use crate::state::AppState;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;

/// Rewrite `/owner/repo.git` â†’ `/owner/repo` and drop a trailing slash so
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
        return (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, dest)],
        )
            .into_response();
    }
    next.run(req).await
}

pub fn app_router(state: AppState) -> Router {
    let static_dir = state.config.static_dir.clone();
    Router::new()
        .route("/", get(routes::home))
        .route("/og.png", get(routes::site_og_image))
        .route("/explore", get(routes::explore))
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
        .route("/admin/users/{username}/audit", get(routes::admin_user_audit))
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
        .route(
            "/settings/account/emails",
            post(routes_extra::account_add_email),
        )
        .route(
            "/settings/account/emails/{id}/delete",
            post(routes_extra::account_delete_email),
        )
        .route(
            "/settings/account/sessions/{id}/revoke",
            post(routes_extra::account_revoke_session),
        )
        .route(
            "/settings/account/sessions/revoke-others",
            post(routes_extra::account_revoke_others),
        )
        .route("/settings/account/export", get(routes_extra::account_export))
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
            "/{owner}/{repo}/branches/{branch}/rename",
            post(routes_extra::branch_rename),
        )
        .route(
            "/{owner}/{repo}/branches/{branch}/delete",
            post(routes_extra::branch_delete),
        )
        .route("/{owner}/{repo}/tags", post(routes_extra::tag_create))
        .route(
            "/{owner}/{repo}/tags/{tag}/rename",
            post(routes_extra::tag_rename),
        )
        .route(
            "/{owner}/{repo}/tags/{tag}/delete",
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
            "/{owner}/{repo}/settings/branch-rules",
            post(routes_extra::branch_rule_add),
        )
        .route(
            "/{owner}/{repo}/settings/branch-rules/{id}/delete",
            post(routes_extra::branch_rule_delete),
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
        .layer(from_fn(normalize_git_url))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod path_tests {
    use super::normalize_repo_path;

    #[test]
    fn strips_git_suffix_and_slash() {
        assert_eq!(normalize_repo_path("/o/r.git"), "/o/r");
        assert_eq!(normalize_repo_path("/o/r.git/"), "/o/r");
        assert_eq!(normalize_repo_path("/o/r.git/info/refs"), "/o/r/info/refs");
        assert_eq!(normalize_repo_path("/o/r/"), "/o/r");
        assert_eq!(normalize_repo_path("/"), "/");
    }
}

