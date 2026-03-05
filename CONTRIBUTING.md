# Contributing

Thank you for your interest in hexvault.

## Building

```sh
cargo build
```

## Running Tests

```sh
cargo test --verbose
```

## Code Style

This project enforces formatting and lint rules via CI:

- **Formatting**: `cargo fmt --all -- --check`
- **Linting**: `cargo clippy -- -D warnings`

Please run both before submitting a PR.

## Documentation

All public items must have `///` doc comments. Doc comments are verified during CI with `cargo doc --no-deps`.

## Security Issues

If you discover a security vulnerability, please report it privately. See [SECURITY.md](SECURITY.MD) for details.
