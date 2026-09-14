# RoleDiff for Rust

Native Rust library and CLI for the [RoleDiff authorization test suite](../README.md). This implementation uses reqwest with rustls for HTTP/TLS, serde for configuration and reports, and exact decimal comparison for JSON values. It does not require a Go runtime or binary.

```sh
cargo build --release --locked
cargo test --locked
./target/release/rolediff -h
```

The toolchain file selects Rust 1.85.1 without changing your global default. Cargo.lock is committed. From another Cargo project you can use a local `path` dependency pointing at this directory, or a Git dependency on this repository; the crate is not published to crates.io.

See the [main README](../README.md) for the shared suite schema, demonstration, flags, report format and operational scope. The Python parity tests compare this executable with the independent Go implementation.
