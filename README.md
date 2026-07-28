# kitgit

Self-hosted git. Templates, not a product page.

Authentication is **Authentik OIDC only** — there is no local/dev password bypass.

## Docker Compose

```bash
cd deploy
cp .env.example .env
# edit secrets if you want
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| kitgit | http://localhost:8080 |
| kitgit SSH | localhost:2222 |
| Authentik | http://localhost:9000 |

### Authentik bootstrap

Compose sets:

- user: `akadmin`
- password: value of `AUTHENTIK_BOOTSTRAP_PASSWORD` (default `kitgit-admin-change-me`)

A blueprint at `deploy/authentik/blueprints/kitgit-oidc.yaml` creates the **kitgit** OAuth2 application (client id `kitgit`, redirect `http://localhost:8080/auth/callback`).

After Authentik is up, apply/confirm the blueprint if needed:

```bash
docker compose exec authentik-worker ak apply_blueprint /blueprints/custom/kitgit-oidc.yaml
```

Then open http://localhost:8080/auth/login → Authentik → kitgit.

### Site admins

- The **first** successful OIDC login becomes a site admin automatically.
- Site admins open **/admin** and can grant/revoke admin for any user.

## Environment

| Variable | Purpose |
|----------|---------|
| `KITGIT_DATABASE_URL` | Postgres |
| `KITGIT_DATA_DIR` | Repos, avatars, SSH host key, releases |
| `KITGIT_HTTP_BIND` / `KITGIT_SSH_BIND` | Listen addresses |
| `KITGIT_PUBLIC_URL` | Public base URL for clone links |
| `KITGIT_SESSION_SECRET` | Session cookie secret |
| `KITGIT_OIDC_ISSUER` | Public issuer (browser), e.g. `http://localhost:9000/application/o/kitgit/` |
| `KITGIT_OIDC_DISCOVERY_URL` | Discovery URL (defaults to issuer) |
| `KITGIT_OIDC_CLIENT_ID` / `SECRET` / `REDIRECT_URL` | OIDC client |

## Build

```bash
cargo build --release
```

## Backup

- Postgres: `pg_dump` the `kitgit` database.
- Data dir: bare repos, avatars, releases, SSH host key.

## DigitalOcean (production)

Minimal single-Droplet deploy under the **personal** project:

| Resource | Value |
|----------|-------|
| Droplet | `kitgit` · `s-2vcpu-4gb` · `syd1` · Docker 1-Click |
| Sites | https://git.tirbo.fish · https://auth.tirbo.fish |
| Git SSH | `git.tirbo.fish:2222` |
| Cost | ~$24/mo (droplet only; no managed DB/LB/registry) |

On the droplet, the stack lives in `/opt/kitgit` and is started with:

```bash
cd /opt/kitgit/deploy
docker compose up -d --build
```

Prod files: `deploy/docker-compose.prod.yml`, `deploy/Caddyfile`, `deploy/.env.prod.example`, `deploy/authentik/blueprints-prod/`.

## Brand

See `brand/index.html`. Mark glyph is **狐**.
