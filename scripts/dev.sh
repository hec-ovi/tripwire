#!/bin/sh
# Run a command inside the Rust dev container. Nothing is installed on the host;
# the cargo registry and build cache live in Docker volumes.
#   scripts/dev.sh cargo test
set -eu
cd "$(dirname "$0")/.."
docker build -q --target dev -t tripwire-dev . >/dev/null
exec docker run --rm -i \
  -u "$(id -u):$(id -g)" \
  -v "$PWD:/src" \
  -v tripwire-registry:/usr/local/cargo/registry \
  -v tripwire-target:/target \
  tripwire-dev "$@"
