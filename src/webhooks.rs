//! Repository webhook delivery (JSON POST + optional HMAC-SHA256).

use crate::db::models::{Repository, User, Webhook};
use crate::db::queries;
use anyhow::Result;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use std::time::Instant;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const EVENT_PUSH: &str = "push";
pub const EVENT_ISSUES: &str = "issues";
pub const EVENT_PULL_REQUEST: &str = "pull_request";
pub const EVENT_RELEASE: &str = "release";

pub const ALL_EVENTS: &[&str] = &[EVENT_PUSH, EVENT_ISSUES, EVENT_PULL_REQUEST, EVENT_RELEASE];

pub fn normalize_events(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for e in raw {
        let e = e.trim();
        if ALL_EVENTS.contains(&e) && !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    out
}

fn sign_body(secret: &str, body: &[u8]) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body);
    Some(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

fn build_envelope(
    event: &str,
    action: &str,
    delivery_id: Uuid,
    repo: &Repository,
    owner: &str,
    sender: Option<&User>,
    payload: Value,
) -> Value {
    json!({
        "event": event,
        "action": action,
        "delivery_id": delivery_id.to_string(),
        "repository": {
            "id": repo.id,
            "name": repo.name,
            "owner": owner,
            "full_name": format!("{owner}/{}", repo.name),
            "default_branch": repo.default_branch,
            "visibility": repo.visibility,
            "private": repo.visibility == "private",
        },
        "sender": sender.map(|u| json!({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
        })),
        "payload": payload,
    })
}

/// Fire matching active webhooks for a repo. Failures are logged; callers should ignore errors.
pub async fn dispatch(
    pool: &PgPool,
    event: &str,
    action: &str,
    repo: &Repository,
    owner: &str,
    sender: Option<&User>,
    payload: Value,
) -> Result<()> {
    let hooks = queries::list_active_webhooks_for_event(pool, repo.id, event).await?;
    if hooks.is_empty() {
        return Ok(());
    }
    let delivery_id = Uuid::new_v4();
    let body_val = build_envelope(event, action, delivery_id, repo, owner, sender, payload);
    let body = serde_json::to_vec(&body_val)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("kitgit-webhooks/0.1")
        .build()?;

    for hook in hooks {
        deliver_one(pool, &client, &hook, event, action, delivery_id, &body).await;
    }
    Ok(())
}

/// Spawn a background dispatch so request handlers stay fast.
pub fn spawn_dispatch(
    pool: PgPool,
    event: &'static str,
    action: String,
    repo: Repository,
    owner: String,
    sender: Option<User>,
    payload: Value,
) {
    tokio::spawn(async move {
        if let Err(e) = dispatch(
            &pool,
            event,
            &action,
            &repo,
            &owner,
            sender.as_ref(),
            payload,
        )
        .await
        {
            tracing::warn!("webhook dispatch failed: {e:#}");
        }
    });
}

async fn deliver_one(
    pool: &PgPool,
    client: &reqwest::Client,
    hook: &Webhook,
    event: &str,
    action: &str,
    delivery_id: Uuid,
    body: &[u8],
) {
    let started = Instant::now();
    let mut req = client
        .post(&hook.url)
        .header("Content-Type", "application/json")
        .header("X-Kitgit-Event", event)
        .header("X-Kitgit-Delivery", delivery_id.to_string())
        .header("X-Kitgit-Action", action)
        .body(body.to_vec());

    if let Some(sig) = sign_body(&hook.secret, body) {
        req = req.header("X-Hub-Signature-256", sig);
    }

    let (success, status_code, error) = match req.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16() as i32;
            let ok = resp.status().is_success();
            let err = if ok {
                None
            } else {
                let text = resp.text().await.unwrap_or_default();
                let truncated: String = text.chars().take(500).collect();
                Some(if truncated.is_empty() {
                    format!("HTTP {code}")
                } else {
                    format!("HTTP {code}: {truncated}")
                })
            };
            (ok, Some(code), err)
        }
        Err(e) => (false, None, Some(e.to_string())),
    };

    let duration_ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
    if let Err(e) = queries::record_webhook_delivery(
        pool,
        hook.id,
        event,
        action,
        success,
        status_code,
        error.as_deref(),
        duration_ms,
    )
    .await
    {
        tracing::warn!("failed to record webhook delivery: {e:#}");
    }
}