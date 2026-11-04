FROM rust:1-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ make pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY schema ./schema
RUN cargo build --release --locked

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
