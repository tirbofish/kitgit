//! App-local TOTP MFA (enforced in kitgit after Authentik password succeeds).

use anyhow::{anyhow, Result};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use qrcode::render::svg;
use qrcode::QrCode;
use rand::RngExt;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

const TOTP_DIGITS: u32 = 6;
const TOTP_STEP: u64 = 30;
const TOTP_WINDOW: i64 = 1;
const RECOVERY_CODE_COUNT: usize = 8;

pub fn generate_totp_secret() -> String {
    let mut buf = [0u8; 20];
    rand::rng().fill(&mut buf);
    BASE32_NOPAD.encode(&buf)
}

pub fn otpauth_uri(username: &str, secret_base32: &str, issuer: &str) -> String {
    let label_raw = format!("{issuer}:{username}");
    let label = urlencoding::encode(&label_raw);
    let issuer_q = urlencoding::encode(issuer);
    format!(
        "otpauth://totp/{label}?secret={secret_base32}&issuer={issuer_q}&digits={TOTP_DIGITS}&period={TOTP_STEP}"
    )
}

pub fn qr_svg_data_uri(otpauth: &str) -> Result<String> {
    let code = QrCode::new(otpauth.as_bytes()).map_err(|e| anyhow!("qr encode: {e}"))?;
    let svg = code
        .render::<svg::Color>()
        .min_dimensions(180, 180)
        .dark_color(svg::Color("#111111"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())
    ))
}

fn hotp(secret: &[u8], counter: u64) -> Result<u32> {
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|_| anyhow!("invalid hmac key"))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);
    Ok(code % 10u32.pow(TOTP_DIGITS))
}

fn decode_secret(secret_base32: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret_base32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| anyhow!("invalid authenticator secret"))
}

fn time_counter(now: u64) -> u64 {
    now / TOTP_STEP
}

pub fn verify_totp(secret_base32: &str, code: &str) -> bool {
    let code = code.trim().replace(' ', "");
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(expected) = code.parse::<u32>() else {
        return false;
    };
    let Ok(secret) = decode_secret(secret_base32) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let counter = time_counter(now) as i64;
    for skew in -TOTP_WINDOW..=TOTP_WINDOW {
        let c = (counter + skew) as u64;
        if let Ok(n) = hotp(&secret, c) {
            if n == expected {
                return true;
            }
        }
    }
    false
}

pub fn generate_recovery_codes() -> Vec<String> {
    let mut out = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut rng = rand::rng();
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut buf = [0u8; 5];
        rng.fill(&mut buf);
        let hex = hex::encode(buf);
        out.push(format!("{}-{}", &hex[..5], &hex[5..]));
    }
    out
}

pub fn hash_recovery_code(code: &str) -> String {
    let normalized = code.trim().to_lowercase().replace([' ', '-'], "");
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())
}

pub fn verify_recovery_code(hashes: &[String], code: &str) -> Option<usize> {
    let want = hash_recovery_code(code);
    hashes.iter().position(|h| h == &want)
}

/// Normalize user-facing auth errors so "Authentik" never appears in the browser.
pub fn sanitize_user_error(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("invalid username or password") {
        return "invalid username or password".into();
    }
    if lower.contains("mfa") || lower.contains("authenticator") {
        return "additional verification required".into();
    }
    if lower.contains("misconfigured") || lower.contains("captcha") {
        return "login is temporarily unavailable".into();
    }
    if lower.contains("already taken") {
        return "username or email already taken".into();
    }
    if lower.contains("too short") || lower.contains("at least") {
        return msg.to_string();
    }
    if lower.contains("email") && lower.contains("required") {
        return msg.to_string();
    }
    if lower.contains("signup unavailable") || lower.contains("api token") {
        return "signup is temporarily unavailable".into();
    }
    if lower.contains("authentik") || lower.contains("oidc") {
        return "authentication failed".into();
    }
    // Keep short, safe messages; hide internal detail.
    if msg.len() < 80 && !lower.contains("http") && !lower.contains("api/") {
        return msg.to_string();
    }
    "authentication failed".into()
}
