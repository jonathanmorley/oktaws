FROM clux/muslrust:1.53.0 as cargo-build

RUN apt-get -y update && apt-get -y install libdbus-1-dev

WORKDIR /usr/src/app
COPY Cargo.lock .
COPY Cargo.toml .
#RUN mkdir .cargo src
#RUN touch ./src/main.rs
#RUN --mount=type=cache,target=vendor  \
#  cargo vendor > .cargo/config

COPY ./src src
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=target/release/build \
    --mount=type=cache,target=target/release/deps \
  cargo build --release
#RUN cargo install --path . --verbose
#RUN --mount=type=cache,target=/root/.cargo/registry \
#    --mount=type=cache,target=target/release/build \
#    --mount=type=cache,target=target/release/deps \
#  cargo run --release -- --version
#RUN target/x86_64-unknown-linux-musl/release/oktaws --version

FROM alpine
# Copy the compiled binary from the builder container
COPY --from=cargo-build /root/.cargo/bin/oktaws /oktaws
# Pass all arguments etc to binary
ENTRYPOINT [ "/oktaws" ]
