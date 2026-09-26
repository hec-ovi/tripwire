# Toolchain lives here, not on the host. See scripts/dev.sh.
FROM rust:1-alpine AS dev
RUN apk add --no-cache musl-dev \
 && rustup component add clippy rustfmt \
 && mkdir -p /usr/local/cargo/registry /target \
 && chmod 1777 /usr/local/cargo/registry /target
ENV CARGO_TARGET_DIR=/target HOME=/tmp
WORKDIR /src

FROM dev AS build
COPY . .
RUN cargo build --release --locked

# docker build --target export --output dist .
FROM scratch AS export
COPY --from=build /target/release/tripwire /tripwire
