# kitgit

a minimalistic git frontend built in Rust and pure HTML templates.

## Deployment

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

## Build

```bash
cargo build --release
```

## Docs

check out the documentation in the [docs](docs) folder.