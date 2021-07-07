FROM rust:1.53.0 as builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev

WORKDIR /usr/src/app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

# Copy the compiled binary from the builder container
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/oktaws /oktaws

# Pass all arguments etc to binary
ENTRYPOINT [ "/oktaws" ]
