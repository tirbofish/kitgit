# Production (DigitalOcean)

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
