FROM rust:1.99.1 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ make pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# The formal model build uses the same reviewed CargoFork pin as CI, while
# rustc stays on the 1.99.1 toolchain from this pinned image. The helper reuses
# a valid cache entry and records the full revision and binary SHA-256.
COPY scripts/install_ci_cargo_fork.sh /usr/local/bin/install_ci_cargo_fork.sh
RUN chmod 0755 /usr/local/bin/install_ci_cargo_fork.sh \
    && /usr/local/bin/install_ci_cargo_fork.sh install \
         --cache-dir /opt/rootyard-cargo-fork \
         --require-os linux \
         --record /build/ci-cargo-fork.json
ENV PATH="/opt/rootyard-cargo-fork/bin:${PATH}" \
    CARGO_FORK_AUTO_UPDATE=0
RUN /usr/local/bin/install_ci_cargo_fork.sh verify \
      --cache-dir /opt/rootyard-cargo-fork \
      --require-os linux \
      --require-path \
      --record /build/ci-cargo-fork.json
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY src ./src
COPY migrations ./migrations
COPY schema ./schema
RUN cargo -vV \
    && cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 rootyard \
    && useradd --uid 10001 --gid rootyard --no-create-home rootyard \
    && mkdir -p /var/lib/rootyard && chown rootyard:rootyard /var/lib/rootyard
COPY --from=build /build/target/release/rootyard /usr/local/bin/rootyard
ENV ROOTYARD_DATA_DIR=/var/lib/rootyard ROOTYARD_BIND=0.0.0.0:8080
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["rootyard"]
CMD ["serve"]
