# Contributing

Keep the suite schema and JSON reports consistent between Go and Rust. Add unit tests and, for observable behavior, a shared case in `scripts/test_parity.py`. Include a similar case that should not fail. Use fictional identities and credentials throughout.

Preserve fixed error codes and avoid including response content, URLs or credentials in errors and reports. Explain any change to network behavior or request limits. Go should remain standard-library-only; Rust dependency changes must update Cargo.lock.

Run Go tests with the race detector, `go vet`, Rust tests, Clippy and the parity suite. Format Go with gofmt and Rust with cargo fmt.
