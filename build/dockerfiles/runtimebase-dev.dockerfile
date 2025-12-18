ARG NITRO_CLI_IMAGE=public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
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
    cp target/$RUST_TARGET/release/enclaver-run /enclaver-run

###############################

FROM ${NITRO_CLI_IMAGE} AS nitro_cli
RUN touch /tmp/dummy

###############################

FROM scratch AS build-amd64
COPY --from=nitro_cli /lib64/ld-linux-x86-64.so.2 /lib64/

###############################

FROM scratch AS build-arm64
COPY --from=nitro_cli /lib/ld-linux-aarch64.so.1 /lib/

###############################

FROM build-${TARGETARCH} AS build

ARG TARGETARCH

COPY --from=nitro_cli /lib64/libssl.so.3 /lib64/libcrypto.so.3 /lib64/libgcc_s.so.1 /lib64/libm.so.6 /lib64/libc.so.6 /lib64/libz.so.1 /lib64/
COPY --from=nitro_cli /usr/bin/nitro-cli /bin/nitro-cli

COPY --from=nitro_cli /tmp/dummy /var/log/nitro_enclaves/
COPY --from=nitro_cli /tmp/dummy /run/nitro_enclaves/

COPY --from=builder /enclaver-run /usr/local/bin/enclaver-run

ENTRYPOINT ["/usr/local/bin/enclaver-run"]
