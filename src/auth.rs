use crate::config::Config;
use crate::db::models::User;
use crate::db::queries;
use anyhow::{anyhow, Context, Result};
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use url::Url;

pub const SESSION_COOKIE: &str = "kitgit_session";
pub const MFA_PENDING_COOKIE: &str = "kitgit_mfa_pending";

/// Result of password login after Authentik accepts credentials.
pub enum LoginOutcome {
    /// Full kitgit session cookie value.
    Complete { user: User, token: String },
    /// Password ok; TOTP/recovery still required. Cookie value for pending MFA.
    MfaRequired { pending_token: String },
}

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct AuthState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub http: reqwest::Client,
    pub oidc_enabled: bool,
}

impl AuthState {
    pub async fn new(pool: PgPool, config: Arc<Config>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()?;
        let oidc_enabled = !config.oidc_issuer.is_empty() && !config.oidc_client_secret.is_empty();
        let authentik_ready = !config.authentik_base().is_empty();
        if !oidc_enabled && !authentik_ready {
            tracing::error!("Auth not configured — set Authentik / OIDC env vars");
        } else if oidc_enabled {
            if let Err(e) = discover_client(&config, &http).await {
                tracing::warn!("OIDC discovery failed at startup: {e:#}; will retry on demand");
            }
        }
        Ok(Self {
            pool,
            config,
            http,
            oidc_enabled,
        })
    }
}

async fn discover_client(config: &Config, http: &reqwest::Client) -> Result<OidcClient> {
    let discovery = config.discovery_issuer();
    let issuer = IssuerUrl::new(discovery.to_string())?;
    let meta = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .context("OIDC discovery")?;
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(config.oidc_client_id.clone()),
        Some(ClientSecret::new(config.oidc_client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(config.oidc_redirect_url.clone())?);
    Ok(client)
}

/// Rewrite URL host from internal discovery host to public issuer host (browser-facing).
fn rewrite_public_url(raw: &str, config: &Config) -> Result<String> {
    let public = Url::parse(&config.oidc_issuer).context("parse public issuer")?;
    let discovery = Url::parse(config.discovery_issuer()).context("parse discovery issuer")?;
    let mut u = Url::parse(raw).context("parse auth url")?;
    if u.host_str() == discovery.host_str() && discovery.host_str() != public.host_str() {
        let _ = u.set_scheme(public.scheme());
        let _ = u.set_host(public.host_str());
        let _ = u.set_port(public.port());
    }
    Ok(u.to_string())
}

pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn new_session_token() -> String {
    use rand::RngExt;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    hex::encode(buf)
}

pub fn session_cookie_header(token: &str, max_age_secs: i64) -> HeaderValue {
    let v = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    );
    HeaderValue::from_str(&v).expect("cookie")
}

pub fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static("kitgit_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

pub fn mfa_pending_cookie_header(token: &str, max_age_secs: i64) -> HeaderValue {
    let v = format!(
        "{MFA_PENDING_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    );
    HeaderValue::from_str(&v).expect("cookie")
}

pub fn clear_mfa_pending_cookie() -> HeaderValue {
    HeaderValue::from_static("kitgit_mfa_pending=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

pub fn mfa_pending_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{MFA_PENDING_COOKIE}=")) {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

pub async fn current_user(auth: &AuthState, headers: &HeaderMap) -> Result<Option<User>> {
    if let Some(token) = token_from_headers(headers) {
        let hash = hash_token(&token);
        if let Some(u) = queries::user_from_session(&auth.pool, &hash).await? {
            return Ok(Some(u));
        }
    }
    Ok(None)
}

pub async fn begin_login(auth: &AuthState) -> Result<(String, HeaderMap)> {
    if !auth.oidc_enabled {
        return Err(anyhow!("OIDC not configured"));
    }
    let client = discover_client(&auth.config, &auth.http).await?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    queries::store_oidc_pending(
        &auth.pool,
        csrf.secret(),
        pkce_verifier.secret(),
        nonce.secret(),
    )
    .await?;

    let public_url = rewrite_public_url(auth_url.as_str(), &auth.config)?;
    Ok((public_url, HeaderMap::new()))
}

pub async fn finish_login(auth: &AuthState, code: &str, state: &str) -> Result<(User, String)> {
    if !auth.oidc_enabled {
        return Err(anyhow!("OIDC not configured"));
    }
    let client = discover_client(&auth.config, &auth.http).await?;
    let (verifier, nonce) = queries::take_oidc_pending(&auth.pool, state)
        .await?
        .ok_or_else(|| anyhow!("unknown OIDC state"))?;

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&auth.http)
        .await
        .context("token exchange")?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("no id_token"))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce))
        .context("verify id_token")?;

    let sub = claims.subject().to_string();
    let email = claims
        .email()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .unwrap_or_else(|| email.clone());
    let preferred = claims
        .preferred_username()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| email.split('@').next().map(|s| s.to_lowercase()))
        .unwrap_or_else(|| format!("user{}", &sub[..8.min(sub.len())]));

    let username = sanitize_username(&preferred);
    let picture = claims
        .picture()
        .and_then(|p| p.get(None))
        .map(|u| u.to_string());

    let mut user = queries::upsert_user_from_oidc(
        &auth.pool,
        &sub,
        &username,
        &name,
        &email,
        picture.as_deref(),
    )
    .await?;

    // First user to ever log in becomes site admin.
    if queries::site_admin_count(&auth.pool).await? == 0 {
        user = queries::set_site_admin(&auth.pool, user.id, true).await?;
        tracing::info!("bootstrap site admin: {}", user.username);
    }

    let token = new_session_token();
    queries::create_session(&auth.pool, user.id, &hash_token(&token), 14).await?;
    Ok((user, token))
}

pub async fn logout(auth: &AuthState, headers: &HeaderMap) -> Result<()> {
    if let Some(token) = token_from_headers(headers) {
        queries::delete_session(&auth.pool, &hash_token(&token)).await?;
    }
    Ok(())
}

fn sanitize_username(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.starts_with('-') {
        s.remove(0);
    }
    if s.is_empty() {
        s = "user".into();
    }
    s.truncate(39);
    s
}

// ── Authentik API (kitgit-hosted login & signup) ─────────────────────────────

#[derive(Debug, Deserialize)]
struct FlowChallenge {
    component: String,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    response_errors: Option<serde_json::Value>,
    #[serde(default)]
    password_fields: Option<bool>,
    /// Present on identification challenges (null when captcha disabled).
    #[serde(default)]
    captcha_stage: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AuthentikMe {
    #[serde(default)]
    pk: i64,
    username: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    uid: String,
}

/// Authentik `/api/v3/core/users/me/` returns `{ "user": { ... } }` (SessionUserSerializer).
#[derive(Debug, Deserialize)]
struct AuthentikMeEnvelope {
    user: AuthentikMe,
}

#[derive(Debug, Deserialize)]
struct TokenResponseJson {
    access_token: Option<String>,
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserinfoJson {
    sub: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
    email: Option<String>,
}

fn new_http_client() -> Result<::reqwest::Client> {
    Ok(::reqwest::Client::builder()
        .cookie_store(true)
        .redirect(::reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?)
}

fn truncate(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(n).collect::<String>())
    }
}

/// Rewrite Authentik redirect targets onto the internal base (Docker DNS).
fn rewrite_internal(internal_base: &str, location: &str) -> String {
    let base = Url::parse(internal_base).ok();
    if location.starts_with("http://") || location.starts_with("https://") {
        if let (Ok(mut loc), Some(b)) = (Url::parse(location), base) {
            let _ = loc.set_scheme(b.scheme());
            let _ = loc.set_host(b.host_str());
            let _ = loc.set_port(b.port());
            return loc.to_string();
        }
        return location.to_string();
    }
    if let Some(b) = base {
        if let Ok(joined) = b.join(location) {
            return joined.to_string();
        }
    }
    format!(
        "{}{}",
        internal_base.trim_end_matches('/'),
        if location.starts_with('/') {
            location.to_string()
        } else {
            format!("/{location}")
        }
    )
}

fn capture_csrf(resp: &::reqwest::Response, csrf: &mut Option<String>) {
    for val in resp.headers().get_all(::reqwest::header::SET_COOKIE) {
        let Ok(s) = val.to_str() else { continue };
        let name_val = s.split(';').next().unwrap_or("").trim();
        if let Some(v) = name_val
            .strip_prefix("authentik_csrf=")
            .or_else(|| name_val.strip_prefix("csrftoken="))
        {
            if !v.is_empty() {
                *csrf = Some(v.to_string());
            }
        }
    }
}

fn json_headers(csrf: &Option<String>, referer: Option<&str>) -> ::reqwest::header::HeaderMap {
    let mut headers = ::reqwest::header::HeaderMap::new();
    headers.insert(
        ::reqwest::header::CONTENT_TYPE,
        ::reqwest::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        ::reqwest::header::ACCEPT,
        ::reqwest::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        ::reqwest::header::USER_AGENT,
        ::reqwest::header::HeaderValue::from_static("kitgit/0.1"),
    );
    // Tip Authentik toward JSON challenge responses (not HTML/302 UI redirects).
    headers.insert(
        ::reqwest::header::HeaderName::from_static("x-requested-with"),
        ::reqwest::header::HeaderValue::from_static("XMLHttpRequest"),
    );
    if let Some(r) = referer {
        if let Ok(v) = ::reqwest::header::HeaderValue::from_str(r) {
            headers.insert(::reqwest::header::REFERER, v);
        }
    }
    if let Some(csrf) = csrf {
        if let Ok(v) = ::reqwest::header::HeaderValue::from_str(csrf) {
            headers.insert("X-authentik-CSRF", v.clone());
            headers.insert("X-CSRFToken", v);
        }
    }
    headers
}

fn bearer_headers(token: &str) -> ::reqwest::header::HeaderMap {
    let mut headers = ::reqwest::header::HeaderMap::new();
    headers.insert(
        ::reqwest::header::ACCEPT,
        ::reqwest::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        ::reqwest::header::CONTENT_TYPE,
        ::reqwest::header::HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = ::reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
        headers.insert(::reqwest::header::AUTHORIZATION, v);
    }
    headers
}

async fn read_challenge(
    resp: ::reqwest::Response,
    csrf: &mut Option<String>,
    internal_base: &str,
    executor_url: &str,
    client: &::reqwest::Client,
    depth: u8,
) -> Result<FlowChallenge> {
    capture_csrf(&resp, csrf);
    let status = resp.status();

    // Authentik often answers stage POSTs with 302. Prefer staying on the JSON
    // executor API — Location may point at the HTML /if/flow UI.
    if status.is_redirection() {
        let loc = resp
            .headers()
            .get(::reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        tracing::debug!("authentik {status} Location={loc}");
        if depth >= 10 {
            anyhow::bail!("authentik redirect loop");
        }
        let next = if loc.contains("/api/v3/flows/executor/") {
            rewrite_internal(internal_base, &loc)
        } else {
            // Browser UI or empty Location → re-GET the API executor with cookies.
            executor_url.to_string()
        };
        let follow = client
            .get(&next)
            .headers(json_headers(csrf, Some(&next)))
            .send()
            .await
            .context("authentik follow redirect")?;
        return Box::pin(read_challenge(
            follow,
            csrf,
            internal_base,
            executor_url,
            client,
            depth + 1,
        ))
        .await;
    }

    let text = resp.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        // Empty non-redirect — try executor GET once (session may already have advanced).
        if depth < 10 {
            tracing::debug!("authentik empty body ({status}); re-GET executor");
            let follow = client
                .get(executor_url)
                .headers(json_headers(csrf, Some(executor_url)))
                .send()
                .await
                .context("authentik empty-body recovery GET")?;
            return Box::pin(read_challenge(
                follow,
                csrf,
                internal_base,
                executor_url,
                client,
                depth + 1,
            ))
            .await;
        }
        anyhow::bail!("authentik returned empty body ({status})");
    }
    if !status.is_success() && status.as_u16() != 400 {
        tracing::warn!("authentik HTTP {status}: {}", truncate(&text, 400));
        anyhow::bail!("authentik error ({status}): {}", truncate(&text, 200));
    }
    let challenge: FlowChallenge = serde_json::from_str(&text).map_err(|e| {
        tracing::warn!(
            "authentik JSON parse fail ({status}): {}",
            truncate(&text, 400)
        );
        anyhow!("could not parse authentik response ({status}): {e}")
    })?;
    if challenge.component == "ak-stage-access-denied" {
        anyhow::bail!("invalid username or password");
    }
    if let Some(errs) = challenge.response_errors.as_ref().and_then(|e| e.as_object()) {
        if !errs.is_empty() {
            tracing::warn!("authentik stage errors: {errs:?}");
            // Surface captcha misconfig clearly; otherwise treat as bad credentials.
            if errs.contains_key("captcha_stage") || errs.contains_key("captcha_token") {
                anyhow::bail!("login misconfigured: captcha required by Authentik (disable captcha on identification stage)");
            }
            if errs.contains_key("uid_field")
                || errs.values().any(|v| {
                    v.to_string().to_lowercase().contains("invalid_identifier")
                        || v.to_string().to_lowercase().contains("failed to authenticate")
                })
            {
                anyhow::bail!("invalid username or password");
            }
            anyhow::bail!("invalid username or password");
        }
    }
    Ok(challenge)
}

async fn flow_get(
    client: &::reqwest::Client,
    url: &str,
    csrf: &mut Option<String>,
    internal_base: &str,
) -> Result<FlowChallenge> {
    let resp = client
        .get(url)
        .headers(json_headers(csrf, Some(url)))
        .send()
        .await
        .context("authentik flow GET")?;
    read_challenge(resp, csrf, internal_base, url, client, 0).await
}

async fn flow_post(
    client: &::reqwest::Client,
    url: &str,
    csrf: &mut Option<String>,
    internal_base: &str,
    body: serde_json::Value,
) -> Result<FlowChallenge> {
    tracing::debug!("authentik POST {url} body={}", truncate(&body.to_string(), 200));
    let resp = client
        .post(url)
        .headers(json_headers(csrf, Some(url)))
        .json(&body)
        .send()
        .await
        .context("authentik flow POST")?;
    read_challenge(resp, csrf, internal_base, url, client, 0).await
}

async fn run_password_flow(
    client: &::reqwest::Client,
    base: &str,
    flow_slug: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let url = format!("{base}/api/v3/flows/executor/{flow_slug}/");
    let mut csrf = None;
    let mut challenge = flow_get(client, &url, &mut csrf, base).await?;
    let mut password_sent = false;
    let mut identification_sent = false;

    for _ in 0..12 {
        match challenge.component.as_str() {
            "xak-flow-redirect" => {
                // Login finished — session cookie is set. Optionally hit `to`.
                if let Some(to) = challenge.to.as_deref() {
                    let next = rewrite_internal(base, to);
                    if next.contains("/api/") {
                        let _ = client
                            .get(&next)
                            .headers(json_headers(&csrf, Some(&next)))
                            .send()
                            .await;
                    }
                }
                return Ok(());
            }
            "ak-stage-access-denied" => anyhow::bail!("invalid username or password"),
            "ak-stage-identification" => {
                if identification_sent {
                    anyhow::bail!("invalid username or password");
                }
                identification_sent = true;
                if challenge.captcha_stage.as_ref().is_some_and(|v| !v.is_null()) {
                    anyhow::bail!(
                        "login misconfigured: Authentik identification stage has captcha enabled; disable it for kitgit"
                    );
                }
                let with_password = challenge.password_fields == Some(true);
                // captcha_stage/captcha_token must be present as empty strings (not JSON null)
                // on Authentik builds that validate those keys.
                challenge = flow_post(
                    client,
                    &url,
                    &mut csrf,
                    base,
                    serde_json::json!({
                        "component": "ak-stage-identification",
                        "uid_field": username,
                        "password": if with_password { password } else { "" },
                        "captcha_token": "",
                        "captcha_stage": "",
                    }),
                )
                .await?;
            }
            "ak-stage-password" => {
                if password_sent {
                    anyhow::bail!("invalid username or password");
                }
                password_sent = true;
                challenge = flow_post(
                    client,
                    &url,
                    &mut csrf,
                    base,
                    serde_json::json!({
                        "component": "ak-stage-password",
                        "password": password,
                    }),
                )
                .await?;
            }
            "ak-stage-user-login" => {
                challenge = flow_post(
                    client,
                    &url,
                    &mut csrf,
                    base,
                    serde_json::json!({ "component": "ak-stage-user-login" }),
                )
                .await?;
            }
            "ak-stage-captcha" => {
                anyhow::bail!(
                    "login misconfigured: Authentik captcha stage is enabled; disable captcha for kitgit"
                );
            }
            "ak-stage-authenticator-validate" => {
                // Never send the browser to Authentik MFA; kitgit uses app-local MFA.
                anyhow::bail!("invalid username or password");
            }
            other => {
                tracing::debug!("authentik stage {other}, acknowledging");
                challenge = flow_post(
                    client,
                    &url,
                    &mut csrf,
                    base,
                    serde_json::json!({ "component": other }),
                )
                .await
                .with_context(|| format!("unexpected authentik stage: {other}"))?;
            }
        }
    }
    anyhow::bail!("authentik login flow did not complete")
}

async fn try_password_grant(
    auth: &AuthState,
    username: &str,
    password: &str,
) -> Result<AuthentikMe> {
    let base = auth.config.authentik_base();
    let client = new_http_client()?;
    let token_url = format!("{base}/application/o/token/");
    let resp = client
        .post(&token_url)
        .header(::reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("client_id", auth.config.oidc_client_id.as_str()),
            ("client_secret", auth.config.oidc_client_secret.as_str()),
            ("scope", "openid profile email"),
        ])
        .send()
        .await
        .context("password grant")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let parsed: TokenResponseJson = serde_json::from_str(&text).unwrap_or(TokenResponseJson {
        access_token: None,
        id_token: None,
        error: Some(format!("http_{status}")),
        error_description: Some(truncate(&text, 200)),
    });
    if let Some(err) = parsed.error {
        anyhow::bail!(
            "password grant unavailable ({err}): {}",
            parsed.error_description.unwrap_or_default()
        );
    }
    let access = parsed
        .access_token
        .ok_or_else(|| anyhow!("password grant: no access_token ({status}) {}", truncate(&text, 200)))?;

    let ui = client
        .get(format!("{base}/application/o/userinfo/"))
        .header(::reqwest::header::AUTHORIZATION, format!("Bearer {access}"))
        .header(::reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("userinfo")?;
    let ui_status = ui.status();
    let ui_text = ui.text().await.unwrap_or_default();
    if !ui_status.is_success() {
        anyhow::bail!("userinfo {ui_status}: {}", truncate(&ui_text, 200));
    }
    let info: UserinfoJson = serde_json::from_str(&ui_text).context("parse userinfo")?;
    let username = info
        .preferred_username
        .filter(|s| !s.is_empty())
        .or_else(|| info.email.as_ref().and_then(|e| e.split('@').next().map(|s| s.to_string())))
        .unwrap_or_else(|| username.to_string());
    Ok(AuthentikMe {
        pk: 0,
        username,
        name: info.name.unwrap_or_default(),
        email: info.email.unwrap_or_default(),
        uid: info.sub.unwrap_or_default(),
    })
}

async fn authentik_me(client: &::reqwest::Client, base: &str) -> Result<AuthentikMe> {
    let resp = client
        .get(format!("{base}/api/v3/core/users/me/"))
        .header(::reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("authentik users/me")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        tracing::warn!("users/me {status}: {}", truncate(&text, 300));
        anyhow::bail!("session not established ({status})");
    }
    // Nested `{ "user": {...} }` is the normal Authentik session shape; also accept flat.
    if let Ok(env) = serde_json::from_str::<AuthentikMeEnvelope>(&text) {
        return Ok(env.user);
    }
    serde_json::from_str(&text).with_context(|| {
        format!("parse users/me: {}", truncate(&text, 200))
    })
}

async fn user_from_authentik_me(auth: &AuthState, me: &AuthentikMe) -> Result<User> {
    let sub = if !me.uid.is_empty() {
        me.uid.clone()
    } else if me.pk != 0 {
        format!("ak:{}", me.pk)
    } else {
        format!("ak:{}", me.username)
    };
    let username = sanitize_username(&me.username);
    let name = if me.name.is_empty() {
        username.clone()
    } else {
        me.name.clone()
    };
    let mut user = queries::upsert_user_from_oidc(
        &auth.pool,
        &sub,
        &username,
        &name,
        &me.email,
        None,
    )
    .await?;
    if queries::site_admin_count(&auth.pool).await? == 0 {
        user = queries::set_site_admin(&auth.pool, user.id, true).await?;
        tracing::info!("bootstrap site admin: {}", user.username);
    }
    Ok(user)
}

async fn create_kitgit_session(auth: &AuthState, user: &User) -> Result<(User, String)> {
    let token = new_session_token();
    queries::create_session(&auth.pool, user.id, &hash_token(&token), 14).await?;
    Ok((user.clone(), token))
}

/// Verify username/password against Authentik only (no kitgit session, no MFA gate).
pub async fn verify_password(
    auth: &AuthState,
    username: &str,
    password: &str,
) -> Result<User> {
    let base = auth.config.authentik_base();
    if base.is_empty() {
        return Err(anyhow!("identity provider not configured"));
    }
    let username = username.trim();
    if username.is_empty() || password.is_empty() {
        anyhow::bail!("username and password required");
    }

    match try_password_grant(auth, username, password).await {
        Ok(me) => {
            tracing::info!("password verified via grant: {}", me.username);
            return user_from_authentik_me(auth, &me).await;
        }
        Err(e) => {
            tracing::debug!("password grant unavailable, trying flow: {e:#}");
        }
    }

    let client = new_http_client()?;
    run_password_flow(
        &client,
        &base,
        &auth.config.authentik_auth_flow,
        username,
        password,
    )
    .await
    .map_err(|e| {
        let msg = e.to_string();
        tracing::warn!("authentik flow login failed: {e:#}");
        if msg.contains("misconfigured") || msg.contains("captcha") {
            e
        } else {
            anyhow!("invalid username or password")
        }
    })?;
    let me = authentik_me(&client, &base)
        .await
        .context("password accepted but user could not be read")?;
    user_from_authentik_me(auth, &me).await
}

/// Authenticate with Authentik, then enforce app-local MFA when enabled.
pub async fn login_with_password(
    auth: &AuthState,
    username: &str,
    password: &str,
) -> Result<LoginOutcome> {
    let user = verify_password(auth, username, password).await?;
    if queries::mfa_is_enabled(&auth.pool, user.id).await? {
        let pending = new_session_token();
        queries::delete_mfa_pending_for_user(&auth.pool, user.id).await?;
        queries::create_mfa_pending_login(&auth.pool, user.id, &hash_token(&pending), 10).await?;
        return Ok(LoginOutcome::MfaRequired {
            pending_token: pending,
        });
    }
    let (user, token) = create_kitgit_session(auth, &user).await?;
    Ok(LoginOutcome::Complete { user, token })
}

/// Complete login after TOTP / recovery code for a pending MFA cookie.
pub async fn complete_mfa_login(
    auth: &AuthState,
    pending_token: &str,
    code: &str,
) -> Result<(User, String)> {
    let user_id = queries::take_mfa_pending_login(&auth.pool, &hash_token(pending_token))
        .await?
        .ok_or_else(|| anyhow!("verification expired; log in again"))?;
    let mfa = queries::get_user_mfa(&auth.pool, user_id)
        .await?
        .ok_or_else(|| anyhow!("two-factor authentication is not set up"))?;
    if !mfa.enabled {
        anyhow::bail!("two-factor authentication is not set up");
    }
    let secret = mfa
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow!("two-factor authentication is not set up"))?;

    let code = code.trim();
    let ok = if crate::mfa::verify_totp(secret, code) {
        true
    } else if let Some(idx) = crate::mfa::verify_recovery_code(&mfa.recovery_code_hashes, code) {
        let mut hashes = mfa.recovery_code_hashes;
        hashes.remove(idx);
        queries::mfa_set_recovery_hashes(&auth.pool, user_id, &hashes).await?;
        true
    } else {
        false
    };
    if !ok {
        // Re-store pending so the user can retry within the window.
        queries::create_mfa_pending_login(&auth.pool, user_id, &hash_token(pending_token), 10)
            .await?;
        anyhow::bail!("invalid authentication code");
    }

    let user = queries::get_user_by_id(&auth.pool, user_id)
        .await?
        .ok_or_else(|| anyhow!("user not found"))?;
    create_kitgit_session(auth, &user).await
}

/// Create user via Authentik API token, then log them into kitgit.
pub async fn signup_with_password(
    auth: &AuthState,
    username: &str,
    email: &str,
    password: &str,
    display_name: &str,
) -> Result<LoginOutcome> {
    let username = sanitize_username(username);
    if username.len() < 2 {
        anyhow::bail!("username too short");
    }
    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters");
    }
    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        anyhow::bail!("valid email required");
    }
    let base = auth.config.authentik_base();
    if base.is_empty() {
        return Err(anyhow!("identity provider not configured"));
    }
    let api_token = auth.config.authentik_token();
    if api_token.is_empty() {
        anyhow::bail!("signup unavailable");
    }

    let client = new_http_client()?;
    let name = if display_name.trim().is_empty() {
        username.clone()
    } else {
        display_name.trim().to_string()
    };

    let create_resp = client
        .post(format!("{base}/api/v3/core/users/"))
        .headers(bearer_headers(&api_token))
        .json(&serde_json::json!({
            "username": username,
            "name": name,
            "email": email,
            "path": "users",
            "is_active": true,
            "type": "internal",
            "attributes": {},
            "groups": [],
        }))
        .send()
        .await
        .context("create authentik user")?;
    let create_status = create_resp.status();
    let create_body = create_resp.text().await.unwrap_or_default();
    if !create_status.is_success() {
        tracing::warn!("create user {create_status}: {}", truncate(&create_body, 400));
        let lower = create_body.to_lowercase();
        if lower.contains("unique") || lower.contains("already") || create_status.as_u16() == 400 {
            anyhow::bail!("username or email already taken");
        }
        if create_status.as_u16() == 401 || create_status.as_u16() == 403 {
            anyhow::bail!("signup unavailable");
        }
        anyhow::bail!("could not create account");
    }
    let created: serde_json::Value =
        serde_json::from_str(&create_body).context("parse created user")?;
    let pk = created
        .get("pk")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("no pk in created user"))?;

    let pw_resp = client
        .post(format!("{base}/api/v3/core/users/{pk}/set_password/"))
        .headers(bearer_headers(&api_token))
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .context("set authentik password")?;
    if !pw_resp.status().is_success() {
        let t = pw_resp.text().await.unwrap_or_default();
        tracing::warn!("set_password failed: {}", truncate(&t, 300));
        anyhow::bail!("could not set password");
    }

    login_with_password(auth, &username, password).await
}

/// Look up Authentik user pk by username (admin API).
pub async fn authentik_user_pk(auth: &AuthState, username: &str) -> Result<i64> {
    let base = auth.config.authentik_base();
    let token = auth.config.authentik_token();
    if token.is_empty() {
        anyhow::bail!("account API unavailable");
    }
    let client = new_http_client()?;
    let list = client
        .get(format!(
            "{base}/api/v3/core/users/?username={}",
            urlencoding::encode(username)
        ))
        .bearer_auth(&token)
        .send()
        .await
        .context("list users")?;
    let body: serde_json::Value = list.json().await.context("parse users")?;
    body.pointer("/results/0/pk")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("account not found"))
}

pub async fn authentik_set_password(auth: &AuthState, pk: i64, password: &str) -> Result<()> {
    let base = auth.config.authentik_base();
    let token = auth.config.authentik_token();
    if token.is_empty() {
        anyhow::bail!("account API unavailable");
    }
    let client = new_http_client()?;
    let resp = client
        .post(format!("{base}/api/v3/core/users/{pk}/set_password/"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .context("set password")?;
    if !resp.status().is_success() {
        anyhow::bail!("could not change password");
    }
    Ok(())
}

