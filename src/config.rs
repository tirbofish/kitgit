use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Clone, Parser)]
#[command(name = "kitgit", about = "self-hosted git. templates, not a product page.")]
pub struct Config {
    #[arg(long, env = "KITGIT_DATABASE_URL", default_value = "postgres://kitgit:kitgit@127.0.0.1:5432/kitgit")]
    pub database_url: String,

    #[arg(long, env = "KITGIT_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    #[arg(long, env = "KITGIT_STATIC_DIR", default_value = "./static")]
    pub static_dir: PathBuf,

    #[arg(long, env = "KITGIT_HTTP_BIND", default_value = "0.0.0.0:8080")]
    pub http_bind: SocketAddr,

    #[arg(long, env = "KITGIT_SSH_BIND", default_value = "0.0.0.0:2222")]
    pub ssh_bind: SocketAddr,

    /// Port advertised in clone URLs / `ssh git@host`. Defaults to the
    /// `KITGIT_SSH_BIND` port. Set to `22` in production when published as `22:2222`.
    #[arg(long, env = "KITGIT_SSH_PUBLIC_PORT", default_value_t = 0)]
    pub ssh_public_port: u16,

    #[arg(long, env = "KITGIT_PUBLIC_URL", default_value = "http://localhost:8080")]
    pub public_url: String,

    #[arg(long, env = "KITGIT_SESSION_SECRET", default_value = "change-me-kitgit-session-secret")]
    pub session_secret: String,

    /// Public OIDC issuer (browser-facing), e.g. http://localhost:9000/application/o/kitgit/
    #[arg(long, env = "KITGIT_OIDC_ISSUER", default_value = "")]
    pub oidc_issuer: String,

    /// Optional internal discovery base (container DNS). Falls back to oidc_issuer.
    /// Example: http://authentik-server:9000/application/o/kitgit/
    #[arg(long, env = "KITGIT_OIDC_DISCOVERY_URL", default_value = "")]
    pub oidc_discovery_url: String,

    #[arg(long, env = "KITGIT_OIDC_CLIENT_ID", default_value = "kitgit")]
    pub oidc_client_id: String,

    #[arg(long, env = "KITGIT_OIDC_CLIENT_SECRET", default_value = "")]
    pub oidc_client_secret: String,

    #[arg(long, env = "KITGIT_OIDC_REDIRECT_URL", default_value = "http://localhost:8080/auth/callback")]
    pub oidc_redirect_url: String,

    /// Authentik base URL for flow/API calls (internal Docker DNS preferred).
    /// Example: http://authentik-server:9000
    #[arg(long, env = "KITGIT_AUTHENTIK_URL", default_value = "")]
    pub authentik_url: String,

    /// API token (intent=api) for creating users on signup. Also accepted as AUTHENTIK_TOKEN.
    #[arg(long, env = "KITGIT_AUTHENTIK_API_TOKEN", default_value = "")]
    pub authentik_api_token: String,

    #[arg(long, env = "KITGIT_AUTHENTIK_AUTH_FLOW", default_value = "default-authentication-flow")]
    pub authentik_auth_flow: String,

    #[arg(long, env = "KITGIT_CONFIG", default_value = "")]
    pub config_file: String,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    database_url: Option<String>,
    data_dir: Option<PathBuf>,
    public_url: Option<String>,
    session_secret: Option<String>,
    oidc_issuer: Option<String>,
    oidc_discovery_url: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_redirect_url: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut cfg = Config::parse();
        if !cfg.config_file.is_empty() {
            let text = std::fs::read_to_string(&cfg.config_file)
                .with_context(|| format!("read config {}", cfg.config_file))?;
            let file: FileConfig = toml::from_str(&text)?;
            if let Some(v) = file.database_url {
                cfg.database_url = v;
            }
            if let Some(v) = file.data_dir {
                cfg.data_dir = v;
            }
            if let Some(v) = file.public_url {
                cfg.public_url = v;
            }
            if let Some(v) = file.session_secret {
                cfg.session_secret = v;
            }
            if let Some(v) = file.oidc_issuer {
                cfg.oidc_issuer = v;
            }
            if let Some(v) = file.oidc_discovery_url {
                cfg.oidc_discovery_url = v;
            }
            if let Some(v) = file.oidc_client_id {
                cfg.oidc_client_id = v;
            }
            if let Some(v) = file.oidc_client_secret {
                cfg.oidc_client_secret = v;
            }
            if let Some(v) = file.oidc_redirect_url {
                cfg.oidc_redirect_url = v;
            }
        }
        Ok(cfg)
    }

    pub fn discovery_issuer(&self) -> &str {
        if self.oidc_discovery_url.is_empty() {
            &self.oidc_issuer
        } else {
            &self.oidc_discovery_url
        }
    }

    /// Base URL for Authentik API / flow executor (no trailing slash).
    pub fn authentik_base(&self) -> String {
        if !self.authentik_url.is_empty() {
            return self.authentik_url.trim_end_matches('/').to_string();
        }
        Url::parse(self.discovery_issuer())
            .ok()
            .map(|u| {
                let mut origin = format!("{}://{}", u.scheme(), u.host_str().unwrap_or("localhost"));
                if let Some(port) = u.port() {
                    origin.push(':');
                    origin.push_str(&port.to_string());
                }
                origin
            })
            .unwrap_or_default()
    }

    /// Service API token for Authentik admin API (signup).
    pub fn authentik_token(&self) -> String {
        if !self.authentik_api_token.is_empty() {
            return self.authentik_api_token.clone();
        }
        std::env::var("AUTHENTIK_TOKEN").unwrap_or_default()
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }

    pub fn avatars_dir(&self) -> PathBuf {
        self.data_dir.join("avatars")
    }

    pub fn releases_dir(&self) -> PathBuf {
        self.data_dir.join("releases")
    }

    pub fn ssh_host_key_path(&self) -> PathBuf {
        self.data_dir.join("ssh_host_ed25519_key")
    }

    /// External SSH port for clone URLs. Falls back to the bind port when unset (0).
    pub fn ssh_advertise_port(&self) -> u16 {
        if self.ssh_public_port == 0 {
            self.ssh_bind.port()
        } else {
            self.ssh_public_port
        }
    }
}
