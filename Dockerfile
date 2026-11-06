# syntax=docker/dockerfile:1
#
# The Synapse daemon and its clients, built from this workspace.
#
# Binaries: `synapsed` (the daemon), `synapse` (the CLI, from the `synapsectl` crate) and
# `synapse-claude-channel` (the Claude Code adapter). The build is `--locked`: dependencies are the
# committed Cargo.lock's, so an image is reproducible from its commit.
#
# NOTE: `synapsed` listens on loopback only (it refuses any other address), so a container running it
# is reachable only from inside that container. The image is for running `synapse` or the adapter
# against a daemon in the same container, not for publishing a port.

FROM rust:1.98-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    cmake \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/synapse
COPY . .
RUN cargo build --locked --release -p synapsed -p synapsectl -p synapse-claude-channel

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/synapse/target/release/synapsed /usr/local/bin/synapsed
COPY --from=builder /usr/src/synapse/target/release/synapse /usr/local/bin/synapse
COPY --from=builder /usr/src/synapse/target/release/synapse-claude-channel /usr/local/bin/synapse-claude-channel

RUN useradd --create-home --uid 10001 synapse && \
    mkdir -p /home/synapse/.local/share/synapse && \
    chown -R synapse:synapse /home/synapse
USER synapse
WORKDIR /home/synapse

# The store, keys and announce file live here; mount a volume to keep them.
ENV SYNAPSE_HOME=/home/synapse/.local/share/synapse
VOLUME ["/home/synapse/.local/share/synapse"]

CMD ["synapsed"]
