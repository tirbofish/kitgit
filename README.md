# kitgit

a minimalistic git frontend built in Rust and pure HTML templates.

> [!WARNING]
> This project is pure slop. I used to use this myself, but found it easier to just host it on GitHub or some other platform.
>
> If you wish to run it, I'm not maintaining it, so deploy at your own discretion. 

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

## License
kitgit uses the MIT License, however realistically I could not care less what you do with this project
