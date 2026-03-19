# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-20

### Added
- **Partition Tier**: Introduced a `Partition` layer between `Vault` and `Cell` for robust blast-radius containment, separating encryption domains physically by partition.
- **Audit Log Tamper Evidence**: Implemented a cryptographic hash chain within the `AuditLog` so missing or tampered records break the cryptographic chain guarantee.
- **Trust Boundary Policy Enforcement**: Replaced ambient `LayerContext` properties with an enforced `TokenResolver` boundary, securing context creation safely.

## [1.0.0] — 2026-03-05

### Added

- Core architecture: `Cell`, `Stack`, `Edge`, `Vault` API.
- AES-256-GCM authenticated encryption via `ring`.
- HKDF-SHA256 key derivation with cell-scoped, layer-scoped, context-scoped info strings.
- Three-layer encryption stack: At-rest (Layer 0), Access-gated (Layer 1), Session-bound (Layer 2).
- Edge traversal with bounded plaintext lifetime and automatic audit logging.
- Append-only `AuditLog` with pluggable `AuditSink` trait.
- Built-in `FileAuditSink` for JSON-lines persistence.
- Benchmarks: traversal latency and KMS comparison.
- Example: `multi_tenant_demo` demonstrating cell isolation and audit logging.
- CI: `cargo fmt`, `cargo clippy`, `cargo doc`, `cargo test`.
- Documentation: `SECURITY.md`, `architecture.md`, `design-decisions.md`, `when-to-use-hexvault.md`, `key-rotation.md`.
