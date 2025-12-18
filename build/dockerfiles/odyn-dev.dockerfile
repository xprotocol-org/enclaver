ARG TARGETARCH

FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:latest AS builder
ARG TARGETARCH
ARG BUILDPLATFORM

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
        amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    rustup target add $RUST_TARGET

WORKDIR /build
COPY . .

RUN case "$TARGETARCH" in \
        amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
    esac && \
    cargo zigbuild --release --target $RUST_TARGET --features run_enclave,odyn && \
    cp target/$RUST_TARGET/release/odyn /odyn

FROM scratch
COPY --from=builder /odyn /usr/local/bin/odyn
ENTRYPOINT ["/usr/local/bin/odyn"]
