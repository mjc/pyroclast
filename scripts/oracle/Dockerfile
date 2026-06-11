# Ubuntu so the oracle perf is modern (>= 6.16 demangles Rust v0 symbols the
# same way pyroclast does); Debian trixie's perf 6.12 leaves _R symbols raw.
FROM ubuntu:25.10

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl elfutils linux-perf \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH

RUN cargo install inferno --locked

WORKDIR /work
