# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-04-11

### Security

- **CRITICAL — AAD binding**: `encrypt` / `decrypt` now bind Additional Authenticated Data (cell ID + layer tag) to every ciphertext via the GCM authentication tag. Prevents cross-cell and cross-layer ciphertext replay attacks.
- **CRITICAL — Compiler-proof zeroisation**: Replaced manual `Drop` implementations on `MasterKey`, `PartitionKey`, and `DerivedKey` with `zeroize::ZeroizeOnDrop`. Volatile writes ensure the compiler cannot optimise away key clearing.
- **HIGH — Plaintext zeroisation**: Edge traversal (`traverse()`) now explicitly zeroises the intermediate plaintext via `zeroize` before returning — regardless of seal success or failure.
- **HIGH — HKDF info string encoding**: Switched from colon-delimited to length-prefixed info segments in HKDF derivation. Prevents delimiter collisions where a cell ID containing `:` could produce the same derived key as a different (cell_id, layer) pair.
- **HIGH — Input validation**: `cell_id`, `partition_id`, `access_policy_id`, and `session_id` are now validated to be non-empty. Empty identifiers previously collapsed key isolation silently.

### Changed

- `LayerContext::new()` now returns `Result<Self, HexvaultError>` instead of `Self`. Empty `Some("")` values are rejected.
- `crypto::encrypt()` and `crypto::decrypt()` now accept an `aad_bytes: &[u8]` parameter (crate-internal API).
- Pinned `ring` dependency to exact version `=0.17.14` to prevent silent patch pulls.
- Added `zeroize` dependency (`v1`, `derive` feature) for key material handling.

### Added

- `AuditLog::verify_chain()` — public method to verify the integrity of the cryptographic hash chain. Returns `false` if any record has been tampered with.
- `HexvaultError::InvalidCellId` — returned when an empty cell ID is provided.
- `HexvaultError::InvalidPartitionId` — returned when an empty partition ID is provided.
- New integration test suite: `tests/security_hardening.rs` covering AAD replay, empty ID rejection, layer-skip attacks, audit tamper detection, and cross-partition isolation.
- Expanded `SECURITY.md` with nonce domain documentation, `SystemRandom` failure behaviour, master key entropy warnings, AAD and HKDF encoding details, and input validation table.

### Fixed

- `AuditLog::add_forward_sink()` no longer uses `unwrap()` internally.
- `AuditRecord::Display` no longer panics when `entry_hash` is shorter than 8 characters.

## [1.1.1] - 2026-03-20

### Fixed
- Updated `README.md` to include professional ecosystem badges indicating CI and Docs status.
- Added `homepage` and `readme` metadata mapping to `Cargo.toml` for improved `crates.io` rendering.

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
