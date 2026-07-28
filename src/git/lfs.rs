//! Minimal Git LFS batch + basic transfer API.

use crate::db::queries;
use crate::state::AppState;
use crate::web::routes::{load_repo_context, AppError, AppResult};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

fn lfs_root(state: &AppState) -> PathBuf {
    state.config.data_dir.join("lfs")
}

fn oid_path(state: &AppState, oid: &str) -> PathBuf {
    let prefix = if oid.len() >= 2 { &oid[..2] } else { "xx" };
    lfs_root(state).join(prefix).join(oid)
}

#[derive(Deserialize)]
pub struct LfsBatchRequest {
    pub operation: String,
    #[serde(default)]
    pub transfers: Vec<String>,
    pub objects: Vec<LfsObjectSpec>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct LfsObjectSpec {
    pub oid: String,
    pub size: i64,
}

#[derive(Serialize)]
pub struct LfsBatchResponse {
    pub transfer: String,
    pub objects: Vec<LfsObjectResult>,
}

#[derive(Serialize)]
pub struct LfsObjectResult {
    pub oid: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<LfsActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LfsError>,
}

#[derive(Serialize)]
pub struct LfsActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<LfsAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<LfsAction>,
}

#[derive(Serialize)]
pub struct LfsAction {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<std::collections::HashMap<String, String>>,
    pub expires_in: u64,
}

#[derive(Serialize)]
pub struct LfsError {
    pub code: u16,
    pub message: String,
}

pub async fn lfs_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<LfsBatchRequest>,
) -> AppResult<impl IntoResponse> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    let need_write = req.operation == "upload";
    if need_write && !access.can_write() {
        return Err(AppError::forbidden());
    }
    if !access.can_read() {
        return Err(AppError::forbidden());
    }

    let base = state.config.public_url.trim_end_matches('/');
    let mut objects = Vec::new();
    for obj in req.objects {
        if !obj.oid.chars().all(|c| c.is_ascii_hexdigit()) || obj.oid.len() != 64 {
            objects.push(LfsObjectResult {
                oid: obj.oid,
                size: obj.size,
                actions: None,
                error: Some(LfsError {
                    code: 422,
                    message: "invalid oid".into(),
                }),
            });
            continue;
        }
        let path = oid_path(&state, &obj.oid);
        let exists = path.exists();
        let href = format!("{base}/{owner}/{repo}/info/lfs/objects/{}/{}", obj.oid, obj.size);
        let mut actions = LfsActions {
            download: None,
            upload: None,
        };
        if req.operation == "download" {
            if exists {
                actions.download = Some(LfsAction {
                    href: href.clone(),
                    header: None,
                    expires_in: 3600,
                });
            } else {
                objects.push(LfsObjectResult {
                    oid: obj.oid,
                    size: obj.size,
                    actions: None,
                    error: Some(LfsError {
                        code: 404,
                        message: "object not found".into(),
                    }),
                });
                continue;
            }
        } else if req.operation == "upload" {
            if !exists {
                actions.upload = Some(LfsAction {
                    href: href.clone(),
                    header: None,
                    expires_in: 3600,
                });
            }
            // verify/download optional after upload
            actions.download = Some(LfsAction {
                href,
                header: None,
                expires_in: 3600,
            });
            let _ = queries::register_lfs_object(&state.pool, repository.id, &obj.oid, obj.size).await;
        }
        objects.push(LfsObjectResult {
            oid: obj.oid,
            size: obj.size,
            actions: Some(actions),
            error: None,
        });
    }

    Ok((
        [(header::CONTENT_TYPE, "application/vnd.git-lfs+json")],
        Json(LfsBatchResponse {
            transfer: "basic".into(),
            objects,
        }),
    ))
}

pub async fn lfs_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, oid, size)): Path<(String, String, String, i64)>,
    body: Body,
) -> AppResult<Response> {
    let (repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_write() {
        return Err(AppError::forbidden());
    }
    if oid.len() != 64 || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::bad("invalid oid"));
    }

    let path = oid_path(&state, &oid);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let bytes = axum::body::to_bytes(body, 1024 * 1024 * 1024)
        .await
        .map_err(|e| AppError::bad(e.to_string()))?;
    if size >= 0 && bytes.len() as i64 != size {
        return Err(AppError::bad("size mismatch"));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let dig = hex::encode(hasher.finalize());
    if dig != oid {
        return Err(AppError::bad("oid mismatch"));
    }

    let mut file = fs::File::create(&path).await?;
    file.write_all(&bytes).await?;
    file.flush().await?;
    queries::register_lfs_object(&state.pool, repository.id, &oid, bytes.len() as i64).await?;
    Ok(StatusCode::OK.into_response())
}

pub async fn lfs_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, oid, _size)): Path<(String, String, String, i64)>,
) -> AppResult<Response> {
    let (_repository, _o, _viewer, access) =
        load_repo_context(&state, &owner, &repo, &headers).await?;
    if !access.can_read() {
        return Err(AppError::forbidden());
    }
    let path = oid_path(&state, &oid);
    if !path.exists() {
        return Err(AppError::not_found());
    }
    let data = fs::read(&path).await?;
    let len = data.len().to_string();
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_LENGTH, len.as_str()),
        ],
        data,
    )
        .into_response())
}
