FROM rust:1.83-alpine3.20 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY engine/Cargo.toml ./Cargo.toml
COPY engine/rules ./rules
COPY engine/src ./src

RUN cargo build --release --locked || cargo build --release

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl jq bash

COPY --from=builder /build/target/release/sovereigngate /usr/local/bin/sovereigngate
COPY ci/github-action/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/sovereigngate /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]