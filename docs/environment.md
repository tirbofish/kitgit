# Environment

| Variable | Purpose |
|----------|---------|
| `KITGIT_DATABASE_URL` | Postgres |
| `KITGIT_DATA_DIR` | Repos, avatars, SSH host key, releases |
| `KITGIT_HTTP_BIND` / `KITGIT_SSH_BIND` | Listen addresses (container-internal) |
| `KITGIT_SSH_PUBLIC_PORT` | Port in clone URLs / `ssh git@host` (default: bind port; use `22` when published as `22:2222`) |
| `KITGIT_PUBLIC_URL` | Public base URL for clone links |
| `KITGIT_SESSION_SECRET` | Session cookie secret |
| `KITGIT_OIDC_ISSUER` | Public issuer (browser), e.g. `http://localhost:9000/application/o/kitgit/` |
| `KITGIT_OIDC_DISCOVERY_URL` | Discovery URL (defaults to issuer) |
| `KITGIT_OIDC_CLIENT_ID` / `SECRET` / `REDIRECT_URL` | OIDC client |
