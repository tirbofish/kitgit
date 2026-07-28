# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY templates ./templates
COPY static ./static
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git git-lfs \
    && git lfs install --system \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/kitgit /usr/local/bin/kitgit
COPY static /app/static
COPY migrations /app/migrations
ENV KITGIT_STATIC_DIR=/app/static
ENV KITGIT_DATA_DIR=/data
EXPOSE 8080 2222
VOLUME ["/data"]
ENTRYPOINT ["kitgit"]
