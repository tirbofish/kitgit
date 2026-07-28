# Authentik

Compose sets:

- user: `akadmin`
- password: value of `AUTHENTIK_BOOTSTRAP_PASSWORD` (default `kitgit-admin-change-me`)

A blueprint at `deploy/authentik/blueprints/kitgit-oidc.yaml` creates the **kitgit** OAuth2 application (client id `kitgit`, redirect `http://localhost:8080/auth/callback`).

After Authentik is up, apply/confirm the blueprint if needed:

```bash
docker compose exec authentik-worker ak apply_blueprint /blueprints/custom/kitgit-oidc.yaml
```

Then open http://localhost:8080/auth/login → Authentik → kitgit.

## Site admins

- The **first** successful OIDC login becomes a site admin automatically.
- Site admins open **/admin** and can grant/revoke admin for any user.
