ARG PLAYWRIGHT_VERSION=1.58.2

FROM rust:1.93-bookworm AS rp
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests/interop/rp.rs ./tests/interop/rp.rs
RUN cargo build --locked --features hyper --example interop_rp
CMD ["/workspace/target/debug/examples/interop_rp"]

FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble AS browser
ARG PLAYWRIGHT_VERSION
WORKDIR /test
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --no-audit --no-fund --no-package-lock "playwright@${PLAYWRIGHT_VERSION}"
COPY tests/interop/login.mjs ./login.mjs
CMD ["node", "login.mjs"]