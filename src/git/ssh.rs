use crate::db::queries;
use crate::git::repo::bare_path;
use crate::state::AppState;
use anyhow::{Context, Result};
use base64::Engine;
use russh::keys::{decode_secret_key, encode_pkcs8_pem, PublicKeyBase64};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

fn publickey_methods() -> MethodSet {
    let mut m = MethodSet::empty();
    m.push(MethodKind::PublicKey);
    m
}

fn auth_reject() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(publickey_methods()),
        partial_success: false,
    }
}

pub async fn run_ssh(state: AppState) -> Result<()> {
    std::fs::create_dir_all(&state.config.data_dir)?;
    let key_path = state.config.ssh_host_key_path();
    let key = load_or_create_host_key(&key_path)?;

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        keys: vec![key],
        methods: publickey_methods(),
        // Default Preferred leads with mlkem768x25519-sha256 (PQ hybrid KEX).
        preferred: russh::Preferred::DEFAULT,
        ..Default::default()
    };
    let bind = state.config.ssh_bind;
    let config = Arc::new(config);
    let mut server = SshServer { state };
    tracing::info!("ssh listening on {bind}");
    server.run_on_address(config, bind).await?;
    Ok(())
}

fn load_or_create_host_key(path: &PathBuf) -> Result<russh::keys::PrivateKey> {
    if path.exists() {
        let data = std::fs::read_to_string(path)?;
        return decode_secret_key(&data, None).context("decode host key");
    }
    let key = russh::keys::PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Ed25519,
    )?;
    let mut pem = Vec::new();
    encode_pkcs8_pem(&key, &mut pem)?;
    std::fs::write(path, pem)?;
    Ok(key)
}

pub fn fingerprint_ssh_pubkey(line: &str) -> Result<String> {
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid public key");
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(parts[1])?;
    Ok(ssh_fingerprint_sha256(&raw))
}

fn fingerprint_public_key(key: &russh::keys::PublicKey) -> String {
    // Must match the authorized_keys blob (type || key material), same as
    // OpenSSH `ssh-keygen -lf` SHA256 fingerprints (base64, no padding).
    let blob = key.public_key_bytes();
    ssh_fingerprint_sha256(&blob)
}

fn ssh_fingerprint_sha256(blob: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(h.finalize())
    )
}

struct SshServer {
    state: AppState,
}

impl Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        SshHandler {
            state: self.state.clone(),
            user_id: None,
            username: None,
            stdin: None,
            receive_meta: None,
        }
    }
}

struct SshHandler {
    state: AppState,
    user_id: Option<Uuid>,
    username: Option<String>,
    stdin: Option<Arc<Mutex<tokio::process::ChildStdin>>>,
    receive_meta: Option<(String, String)>,
}

impl SshHandler {
    /// Print `static/text.txt` (with `{user}` substituted) and close — no shell access.
    async fn greet_and_quit(
        &self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), anyhow::Error> {
        let username = self.username.as_deref().unwrap_or("git");
        let path = self.state.config.static_dir.join("text.txt");
        let mut msg = tokio::fs::read_to_string(&path).await.unwrap_or_else(|_| {
            format!(
                "Hi {username}! You've successfully authenticated, but kitgit does not provide shell access.\n"
            )
        });
        msg = msg.replace("{user}", username);
        if !msg.ends_with('\n') {
            msg.push('\n');
        }
        session.channel_success(channel)?;
        session.data(channel, msg.into_bytes())?;
        // Match GitHub: non-zero exit so clients don't treat this as a shell login.
        session.exit_status_request(channel, 1)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fp = fingerprint_public_key(public_key);
        if let Some(user) = queries::user_by_ssh_fingerprint(&self.state.pool, &fp).await? {
            if user.is_suspended {
                tracing::info!("ssh rejected suspended user {}", user.username);
                return Ok(auth_reject());
            }
            self.user_id = Some(user.id);
            self.username = Some(user.username);
            return Ok(Auth::Accept);
        }
        tracing::debug!("ssh publickey rejected fp={fp}");
        Ok(auth_reject())
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<Auth, Self::Error> {
        // Password auth is not supported — keys only.
        Ok(auth_reject())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Accept PTY so interactive `ssh git@host` can proceed to shell_request.
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.user_id.is_none() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.greet_and_quit(channel, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        let Some(user_id) = self.user_id else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let (service, repo_path) = match parse_git_command(&cmd) {
            Ok(v) => v,
            Err(_) => {
                // Non-git exec (e.g. `ssh host exit`) — same greeting as a bare SSH.
                return self.greet_and_quit(channel, session).await;
            }
        };
        let (owner, name) = split_repo_path(&repo_path)?;
        let Some((repo, _)) = queries::get_repo(&self.state.pool, &owner, &name).await? else {
            session.data(channel, b"repository not found\n".as_slice())?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        };
        let access = queries::repo_access(&self.state.pool, &repo, Some(user_id)).await?;
        let allowed = match service {
            "git-upload-pack" => access.can_read(),
            "git-receive-pack" => access.can_write() && !repo.archived,
            _ => false,
        };
        if !allowed {
            session.data(channel, b"access denied\n".as_slice())?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        let bare = bare_path(&self.state.config.repos_dir(), &owner, &name);
        let mut child = tokio::process::Command::new(service)
            .arg(bare.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        self.stdin = Some(Arc::new(Mutex::new(stdin)));
        if service == "git-receive-pack" {
            self.receive_meta = Some((owner.clone(), name.clone()));
        }

        let handle = session.handle();
        tokio::spawn(async move {
            let mut buf = [0u8; 16384];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = handle.data(channel, buf[..n].to_vec()).await;
                    }
                    Err(_) => break,
                }
            }
            let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(1) as u32;
            let _ = handle.eof(channel).await;
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.close(channel).await;
        });

        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = &self.stdin {
            let mut g = stdin.lock().await;
            g.write_all(data).await?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = self.stdin.take() {
            let mut g = stdin.lock().await;
            let _ = g.shutdown().await;
        }
        if let (Some(uid), Some((owner, name))) = (self.user_id, self.receive_meta.take()) {
            if let Ok(Some((repo, _))) = queries::get_repo(&self.state.pool, &owner, &name).await {
                if let Ok(Some(user)) = queries::get_user_by_id(&self.state.pool, uid).await {
                    let _ = queries::record_activity(
                        &self.state.pool,
                        Some(user.id),
                        Some(repo.id),
                        "push",
                        "pushed",
                        serde_json::json!({}),
                    )
                    .await;
                    let _ = queries::bump_commit_activity(
                        &self.state.pool,
                        user.id,
                        chrono::Utc::now().date_naive(),
                        1,
                    )
                    .await;
                    if let Ok(g) = crate::git::open_bare(&self.state.config.repos_dir(), &owner, &name)
                    {
                        if let Ok(files) = crate::git::walk_files(&g, &repo.default_branch) {
                            let stats = crate::git::languages::detect_languages(&files);
                            let _ = queries::set_language_stats(&self.state.pool, repo.id, stats).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_git_command(cmd: &str) -> Result<(&'static str, String)> {
    let cmd = cmd.trim();
    if cmd.contains("git-upload-pack") {
        return Ok(("git-upload-pack", extract_quoted_path(cmd)?));
    }
    if cmd.contains("git-receive-pack") {
        return Ok(("git-receive-pack", extract_quoted_path(cmd)?));
    }
    anyhow::bail!("unsupported command")
}

fn extract_quoted_path(cmd: &str) -> Result<String> {
    if let Some(start) = cmd.find('\'') {
        let rest = &cmd[start + 1..];
        if let Some(end) = rest.find('\'') {
            return Ok(rest[..end].to_string());
        }
    }
    let parts: Vec<_> = cmd.split_whitespace().collect();
    Ok(parts
        .last()
        .context("no path")?
        .trim_matches('"')
        .to_string())
}

fn split_repo_path(path: &str) -> Result<(String, String)> {
    let path = path.trim_start_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next().context("owner")?.to_string();
    let name = parts.next().context("name")?.to_string();
    Ok((owner, name))
}
