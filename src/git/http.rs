use crate::db::models::{Access, Repository, User};
use crate::db::queries;
use crate::git::repo::bare_path;
use crate::state::AppState;
use anyhow::Result;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Request, Response, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use futures::StreamExt;
use serde::Deserialize;
use sqlx::PgPool;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_util::io::ReaderStream;

#[derive(Deserialize)]
pub struct ServiceQuery {
    pub service: Option<String>,
}

pub async fn info_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<ServiceQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let repo_name = strip_git_suffix(&repo);
    match authorize_git(&state, &owner, repo_name, &headers).await {
        Ok((access, user, _repo)) => {
            if !access.can_read() {
                return if user.is_none() {
                    unauthorized()
                } else {
                    forbidden()
                };
            }
            let service = match q.service.as_deref() {
                Some("git-upload-pack") => "git-upload-pack",
                Some("git-receive-pack") => {
                    // Unauthenticated → 401 so git prompts for credentials.
                    // Authenticated but no write → 403.
                    if !access.can_write() {
                        return if user.is_none() {
                            unauthorized()
                        } else {
                            forbidden()
                        };
                    }
                    "git-receive-pack"
                }
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "missing or unsupported service",
                    )
                        .into_response();
                }
            };
            let path = bare_path(&state.config.repos_dir(), &owner, repo_name);
            match advertise_refs(&path, service).await {
                Ok(body) => Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        header::CONTENT_TYPE,
                        format!("application/x-{service}-advertisement"),
                    )
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(body))
                    .unwrap()
                    .into_response(),
                Err(e) => {
                    tracing::error!("info/refs: {e:#}");
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        }
        Err(_) => unauthorized(),
    }
}

pub async fn upload_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    req: Request<Body>,
) -> impl IntoResponse {
    let repo_name = strip_git_suffix(&repo);
    match authorize_git(&state, &owner, repo_name, &headers).await {
        Ok((access, user, _)) if access.can_read() => {
            let path = bare_path(&state.config.repos_dir(), &owner, repo_name);
            rpc_service(&path, "git-upload-pack", req).await
        }
        Ok((_, user, _)) => {
            if user.is_none() {
                unauthorized()
            } else {
                forbidden()
            }
        }
        Err(_) => unauthorized(),
    }
}

pub async fn receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    req: Request<Body>,
) -> impl IntoResponse {
    let repo_name = strip_git_suffix(&repo);
    match authorize_git(&state, &owner, repo_name, &headers).await {
        Ok((access, user, repository)) if access.can_write() => {
            if repository.archived {
                return (
                    StatusCode::FORBIDDEN,
                    "repository is archived",
                )
                    .into_response();
            }
            let path = bare_path(&state.config.repos_dir(), &owner, repo_name);
            let resp = rpc_service(&path, "git-receive-pack", req).await;
            if let Some(u) = user {
                let _ = post_push_hooks(&state, &u, &repository, &owner).await;
            }
            resp
        }
        Ok((_, user, _)) => {
            if user.is_none() {
                unauthorized()
            } else {
                forbidden()
            }
        }
        Err(_) => unauthorized(),
    }
}

async fn post_push_hooks(
    state: &AppState,
    user: &User,
    repo: &Repository,
    owner: &str,
) -> Result<()> {
    queries::record_activity(
        &state.pool,
        Some(user.id),
        Some(repo.id),
        "push",
        "pushed",
        serde_json::json!({}),
    )
    .await?;
    queries::bump_commit_activity(&state.pool, user.id, chrono::Utc::now().date_naive(), 1).await?;

    if let Ok(g) = crate::git::open_bare(&state.config.repos_dir(), owner, &repo.name) {
        let branch = repo.default_branch.clone();
        if let Ok(files) = crate::git::walk_files(&g, &branch) {
            let stats = crate::git::languages::detect_languages(&files);
            queries::set_language_stats(&state.pool, repo.id, stats).await?;
        }
    }
    let _ = sqlx::query("UPDATE repositories SET updated_at = now() WHERE id = $1")
        .bind(repo.id)
        .execute(&state.pool)
        .await;
    Ok(())
}

async fn advertise_refs(path: &std::path::Path, service: &str) -> Result<Vec<u8>> {
    let output = Command::new(service)
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(path)
        .output()
        .await?;
    if !output.status.success() {
        anyhow::bail!(
            "{} failed: {}",
            service,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut body = Vec::new();
    let header = format!("# service={service}\n");
    body.extend_from_slice(pkt_line(&header).as_slice());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&output.stdout);
    Ok(body)
}

fn pkt_line(s: &str) -> Vec<u8> {
    let len = s.len() + 4;
    format!("{len:04x}{s}").into_bytes()
}

async fn rpc_service(path: &std::path::Path, service: &str, req: Request<Body>) -> Response<Body> {
    let mut child = match Command::new(service)
        .arg("--stateless-rpc")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("spawn {service}: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut body = req.into_body().into_data_stream();

    tokio::spawn(async move {
        while let Some(Ok(chunk)) = body.next().await {
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = stdin.shutdown().await;
    });

    let stream = ReaderStream::new(stdout);
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            format!("application/x-{service}-result"),
        )
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn authorize_git(
    state: &AppState,
    owner: &str,
    name: &str,
    headers: &HeaderMap,
) -> Result<(Access, Option<User>, Repository)> {
    let (repo, owner_user) = queries::get_repo(&state.pool, owner, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("not found"))?;

    let mut user = crate::auth::current_user(&state.auth, headers).await?;
    if user.is_none() {
        user = basic_auth_user(&state.pool, headers).await?;
    }
    let access = queries::repo_access(&state.pool, &repo, user.as_ref().map(|u| u.id)).await?;
    let _ = owner_user;
    Ok((access, user, repo))
}

async fn basic_auth_user(pool: &PgPool, headers: &HeaderMap) -> Result<Option<User>> {
    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let Ok(s) = auth.to_str() else {
        return Ok(None);
    };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return Ok(None);
    };
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let pair = String::from_utf8(decoded)?;
    let (username, _password) = pair.split_once(':').unwrap_or((pair.as_str(), ""));
    // For HTTP git with Authentik, prefer session cookie. Basic auth accepts username
    // with any password matching an existing user (dev-friendly). Production should
    // use deploy tokens later; for now OIDC session or SSH is preferred.
    Ok(queries::get_user_by_username(pool, username)
        .await?
        .filter(|u| !u.is_suspended))
}

fn strip_git_suffix(name: &str) -> &str {
    name.strip_suffix(".git").unwrap_or(name)
}

fn unauthorized() -> axum::response::Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"kitgit\"")
        .body(Body::from("unauthorized"))
        .unwrap()
}

fn forbidden() -> axum::response::Response {
    (StatusCode::FORBIDDEN, "forbidden").into_response()
}
