FROM rust:1-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends linux-perf elfutils libdw-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install inferno --locked

WORKDIR /work
