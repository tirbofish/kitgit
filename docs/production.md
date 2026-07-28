# Production (DigitalOcean)

Minimal single-Droplet deploy under the **personal** project:

| Resource | Value |
|----------|-------|
| Droplet | `kitgit` · `s-2vcpu-4gb` · `syd1` · Docker 1-Click |
| Sites | https://git.tirbo.fish · https://auth.tirbo.fish |
| Git SSH | `git@git.tirbo.fish` (host port 22 → kitgit) |
| Admin SSH | droplet port **2222** (system `sshd`; not Git) |
| Cost | ~$24/mo (droplet only; no managed DB/LB/registry) |

On the droplet, the stack lives in `/opt/kitgit` and is started with:

```bash
cd /opt/kitgit/deploy
docker compose up -d --build
```

Prod files: `deploy/docker-compose.prod.yml`, `deploy/Caddyfile`, `deploy/.env.prod.example`, `deploy/authentik/blueprints-prod/`.

**SSH layout:** Git uses host port **22** (`ssh git@git.tirbo.fish`). Droplet admin `sshd` is on **2222** (`ssh -p 2222 root@…`).
