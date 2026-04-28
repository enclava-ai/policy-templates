# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /workspace

COPY signing-service/Cargo.toml signing-service/Cargo.lock ./signing-service/
COPY signing-service/src ./signing-service/src
WORKDIR /workspace/signing-service
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked

WORKDIR /workspace
COPY signing-service ./signing-service
COPY templates ./templates
WORKDIR /workspace/signing-service
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/signing-service/target \
    cargo build --release --locked && \
    cp target/release/enclava-policy-signing-service /usr/local/bin/enclava-policy-signing-service

FROM debian:bookworm-slim AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 65532 signing-service; \
    useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin signing-service; \
    mkdir -p /data; \
    chown 65532:65532 /data

COPY --from=builder /usr/local/bin/enclava-policy-signing-service /usr/local/bin/enclava-policy-signing-service

USER 65532:65532
ENV BIND_ADDR=0.0.0.0:8080 \
    OWNER_DB_PATH=/data/owner-state.sqlite3 \
    GENPOLICY_BIN=/usr/local/bin/genpolicy
EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/enclava-policy-signing-service"]
