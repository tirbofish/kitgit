//! Commit signature verification (SSH + GPG).

use crate::db::queries;
use anyhow::Result;
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use git2::{Oid, Repository as G2Repo};
use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};
use pgp::types::PublicKeyTrait;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use ssh_key::{HashAlg, PublicKey, SshSig};

const GIT_SSH_NAMESPACE: &str = "git";

#[derive(Debug, Clone)]
pub struct CommitVerification {
    /// `"ssh"` or `"gpg"`.
    pub kind: String,
    /// Fingerprint shown in the badge popover (no `SHA256:` prefix for SSH).
    pub fingerprint: String,
    /// Human-readable "Verified on …" timestamp from the commit.
    pub verified_at: String,
}

impl CommitVerification {
    pub fn fingerprint_label(&self) -> &'static str {
        match self.kind.as_str() {
            "gpg" => "GPG Key Fingerprint",
            _ => "SSH Key Fingerprint",
        }
    }
}

/// Sync extract only — keep `git2::Repository` off async boundaries (`!Send`).
pub fn extract_commit_signature(repo: &G2Repo, commit_id: &str) -> Option<(String, Vec<u8>)> {
    let oid = Oid::from_str(commit_id).ok()?;
    let (sig_buf, data_buf) = repo.extract_signature(&oid, None).ok()?;
    let sig = std::str::from_utf8(&sig_buf).ok()?.trim().to_string();
    let payload = data_buf.to_vec();
    if sig.contains("BEGIN SSH SIGNATURE") || sig.contains("BEGIN PGP SIGNATURE") {
        Some((sig, payload))
    } else {
        None
    }
}

/// Verify a previously extracted signature against registered signing keys.
pub async fn verify_commit_signature(
    pool: &PgPool,
    sig: &str,
    payload: &[u8],
    author_email: &str,
    commit_time: i64,
) -> Option<CommitVerification> {
    let verified_at = format_verified_at(commit_time);
    if sig.contains("BEGIN SSH SIGNATURE") {
        return verify_ssh(pool, sig, payload, author_email, verified_at).await;
    }
    if sig.contains("BEGIN PGP SIGNATURE") {
        return verify_gpg(pool, sig, payload, author_email, verified_at).await;
    }
    None
}

/// Extract + verify a commit signature. Does all git2 work before any `.await`.
pub async fn verify_commit(
    pool: &PgPool,
    repo: &G2Repo,
    commit_id: &str,
    author_email: &str,
    commit_time: i64,
) -> Option<CommitVerification> {
    let (sig, payload) = extract_commit_signature(repo, commit_id)?;
    verify_commit_signature(pool, &sig, &payload, author_email, commit_time).await
}

async fn verify_ssh(
    pool: &PgPool,
    sig_pem: &str,
    payload: &[u8],
    author_email: &str,
    verified_at: String,
) -> Option<CommitVerification> {
    let sshsig = SshSig::from_pem(sig_pem.as_bytes()).ok()?;
    let embedded = PublicKey::new(sshsig.public_key().clone(), "");
    let fp = embedded.fingerprint(HashAlg::Sha256).to_string();

    let key = queries::signing_ssh_key_by_fingerprint(pool, &fp)
        .await
        .ok()
        .flatten()?;

    if !email_matches_user(pool, key.user_id, author_email).await {
        return None;
    }

    let stored: PublicKey = key.public_key.trim().parse().ok()?;
    stored.verify(GIT_SSH_NAMESPACE, payload, &sshsig).ok()?;

    Some(CommitVerification {
        kind: "ssh".into(),
        fingerprint: display_ssh_fingerprint(&fp),
        verified_at,
    })
}

async fn verify_gpg(
    pool: &PgPool,
    sig_armor: &str,
    payload: &[u8],
    author_email: &str,
    verified_at: String,
) -> Option<CommitVerification> {
    let (signature, _) = StandaloneSignature::from_string(sig_armor).ok()?;
    let keys = queries::list_all_gpg_keys(pool).await.ok()?;

    for key in keys {
        if !email_matches_user(pool, key.user_id, author_email).await {
            continue;
        }
        let Ok((pubkey, _)) = SignedPublicKey::from_string(&key.public_key) else {
            continue;
        };
        let mut ok = signature.verify(&pubkey, payload).is_ok();
        if !ok {
            for sub in &pubkey.public_subkeys {
                if signature.verify(sub, payload).is_ok() {
                    ok = true;
                    break;
                }
            }
        }
        if ok {
            return Some(CommitVerification {
                kind: "gpg".into(),
                fingerprint: display_gpg_fingerprint(&key.fingerprint),
                verified_at,
            });
        }
    }
    None
}

async fn email_matches_user(pool: &PgPool, user_id: uuid::Uuid, email: &str) -> bool {
    let email = email.trim();
    if email.is_empty() {
        return false;
    }
    queries::user_owns_email(pool, user_id, email)
        .await
        .unwrap_or(false)
}

/// Compute a real OpenPGP fingerprint (uppercase hex) from armored public key.
pub fn gpg_fingerprint_from_armor(armor: &str) -> Result<String> {
    let (pubkey, _) = SignedPublicKey::from_string(armor)?;
    Ok(hex::encode_upper(pubkey.fingerprint().as_bytes()))
}

/// Legacy fallback used when OpenPGP parse fails — keep old keys loadable.
pub fn gpg_fingerprint_fallback(armor: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(armor.as_bytes());
    hex::encode(hasher.finalize())
}

fn display_ssh_fingerprint(fp: &str) -> String {
    fp.strip_prefix("SHA256:")
        .unwrap_or(fp)
        .trim_end_matches('=')
        .to_string()
}

fn display_gpg_fingerprint(fp: &str) -> String {
    let clean: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() == 40 {
        clean
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
            .to_uppercase()
    } else {
        fp.to_string()
    }
}

fn format_verified_at(secs: i64) -> String {
    let dt: DateTime<Utc> = DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now);
    let local = dt.with_timezone(&Local);
    let (is_pm, hour12) = local.hour12();
    let ampm = if is_pm { "PM" } else { "AM" };
    let month = match local.month() {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    };
    format!(
        "{month} {}, {}, {}:{:02} {ampm}",
        local.day(),
        local.year(),
        hour12,
        local.minute()
    )
}
