# HexVault

[<img alt="github" src="https://img.shields.io/badge/github-Z3DDIEZ/HexVault-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/Z3DDIEZ/HexVault)
[<img alt="crates.io" src="https://img.shields.io/crates/v/hexvault.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/hexvault)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-hexvault-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/hexvault)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/Z3DDIEZ/HexVault/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/Z3DDIEZ/HexVault/actions?query=branch%3Amain)

Cascading cell-partitioned encryption architecture in Rust.

Layered key isolation, auditable boundary traversal, and threat-model-driven testing.

---

## What This Is

hexvault is not a cipher. It is a structural pattern for how encryption contexts are organised, partitioned, and traversed.

Data is structurally divided into logical **Partitions**, which then host isolated **Cells** — each an independent encryption domain with its own derived keys. Within each cell, encryption is applied in cascading layers, where each layer corresponds to a distinct trust boundary. Movement of data between cells is controlled exclusively by edge handlers: re-encryption gateways that never expose plaintext to the caller, and log every traversal.

The result is an encryption architecture where blast radius is contained by structure, access is gated by layer, and every boundary crossing is auditable.

---

## Architecture

```text
        ┌────────────────────────────────────────────────────────────┐
        │                        Partition                           │
        │   ┌───────────────┐   edge    ┌───────────────┐            │
        │   │    Cell A     │◄─────────►│    Cell B     │            │
        │   │               │           │               │            │
        │   │  ┌──────────┐ │           │  ┌──────────┐ │            │
        │   │  │ Layer 2  │ │           │  │ Layer 2  │ │            │
        │   │  │ session  │ │           │  │ session  │ │            │
        │   │  ├──────────┤ │           │  ├──────────┤ │            │
        │   │  │ Layer 1  │ │           │  │ Layer 1  │ │            │
        │   │  │ access   │ │           │  │ access   │ │            │
        │   │  ├──────────┤ │           │  ├──────────┤ │            │
        │   │  │ Layer 0  │ │           │  │ Layer 0  │ │            │
        │   │  │ at-rest  │ │           │  │ at-rest  │ │            │
        │   │  └──────────┘ │           │  └──────────┘ │            │
        │   └───────────────┘           └───────────────┘            │
        └────────────────────────────────────────────────────────────┘
```

**Partitions** structure encryption into independent sub-trees derived directly from the Master Key.
**Cells** partition data horizontally within a partition. Each cell owns its keys. No cell can decrypt another cell's data — there is no API path that permits it.

**Stacks** layer encryption vertically within a cell. Layer 0 is base at-rest encryption. Layer 1 gates access behind a policy context. Layer 2 binds encryption to a session. Decryption peels top-down: you cannot reach Layer 0 without first peeling Layer 2 and Layer 1. Note: All policy contexts are verified opaquely bounded by a trusted `TokenResolver`.

**Edges** are the only mechanism for moving data between cells (even across partitions). They decrypt under the source cell's key, re-encrypt under the destination cell's key, and append a tamper-evident hash-chained audit record. Plaintext exists in memory only for the duration of that re-encryption — it is never returned to the caller.

---

## Cryptographic Primitives

| Primitive            | Implementation             | Role                                                      |
| -------------------- | -------------------------- | --------------------------------------------------------- |
| Symmetric encryption | AES-256-GCM                | Authenticated encryption for all payloads                 |
| Key derivation       | HKDF-SHA256                | Derives per-cell, per-layer keys from a single master key |
| Randomness           | `ring::rand::SystemRandom` | 96-bit nonce generation per encryption operation          |

All cryptographic operations are backed by the [`ring`](https://github.com/briansmith/ring) crate — AWS-backed, FIPS-compatible, actively audited.

---

## Quick Start

```rust
use hexvault::{Vault, generate_master_key};
use hexvault::stack::{Layer, LayerContext, TokenResolver};
use hexvault::error::HexvaultError;
use std::sync::Arc;

struct DummyResolver;
impl TokenResolver for DummyResolver {
    fn resolve(&self, _token: &str) -> Result<LayerContext, HexvaultError> {
        Ok(LayerContext::empty())
    }
}

// Master key is caller-provided. In production, source this from a KMS.
let master_key = generate_master_key().unwrap();

// Create the vault, attach a resolver, and register a partition & cells.
let mut vault = Vault::new(master_key, Arc::new(DummyResolver));
let partition = vault.get_partition("dept-eng").unwrap();
let mut cell_a = partition.create_cell("cell-a".to_string());
let mut cell_b = partition.create_cell("cell-b".to_string());

let token = "";

// Encrypt a payload into Cell A at the base layer.
partition.seal(&mut cell_a, "sensitive payload", b"data", Layer::AtRest, token).unwrap();

// Traverse from Cell A to Cell B. Plaintext never leaves the edge.
vault.traverse(&partition, &cell_a, &partition, &mut cell_b, "sensitive payload", Layer::AtRest, token, token).unwrap();

// Audit log is populated automatically and records are cryptographically hash-chained.
let log = vault.audit_log();
assert_eq!(log.len(), 1);
```

---

## Running Tests and Examples

```sh
cargo test
cargo run --example multi_tenant_demo
cargo run --example layered_access_demo         # All three stack layers demonstrated
cargo bench --bench kms_comparison_benchmark     # HexVault vs. KMS-style (simulated latency)
```

The test suite is organised into five modules, each targeting a specific security property. See `tests/` for full coverage. The threat model and what each test module validates is documented in [SECURITY.md](SECURITY.MD).

---

## Project Documentation

| Document                                                     | What It Covers                                                                      |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| [SECURITY.md](SECURITY.MD)                                   | Threat model, what each architectural layer defends against, responsible disclosure |
| [docs/architecture.md](docs/architecture.md)                 | Full design detail: cells, stacks, edges, key derivation, data flow                 |
| [docs/design-decisions.md](docs/design-decisions.md)         | ADR-style log of why things were built the way they were                            |
| [docs/when-to-use-hexvault.md](docs/when-to-use-hexvault.md) | When to choose HexVault vs. KMS + IAM — decision guide for architects               |
| [docs/key-rotation.md](docs/key-rotation.md)                 | Key rotation design (dual-key period, lazy re-encryption)                           |
| [CONTRIBUTING.md](CONTRIBUTING.md)                           | How to build, test, and contribute                                                  |
| [CHANGELOG.md](CHANGELOG.md)                                 | Release history                                                                     |

---

## Why Rust

Rust's ownership model is not incidental to this project — it is load-bearing. Each cell owns its key material exclusively. Keys cannot be copied implicitly; passing a key into an operation moves it. Key material is zeroed on scope exit via the `Drop` trait. Any point where these rules must be broken is marked `unsafe` and is auditable. The compiler enforces the isolation properties that the architecture requires.

See [docs/design-decisions.md](docs/design-decisions.md) for the full rationale.



### Performance

Benchmarks run on an AMD Ryzen 9 5950X (or equivalent high-end desktop):
| Payload Size | Time (µs) | Throughput |
|---|---|---|
| 100 B | ~5.6 µs | 17 MB/s |
| 1 KB | ~6.3 µs | 155 MB/s |
| 10 KB | ~13.2 µs | 739 MB/s |

_Note: The non-linear throughput scaling confirms the fixed overhead of key derivation (HKDF) and audit logging dominates small payloads, while AES-GCM encryption speed dominates larger payloads._

**vs. KMS:** HexVault traversal is ~1000× faster than cloud KMS for local operations (KMS ~15–30ms per call due to network RTT). Run `cargo bench --bench kms_comparison_benchmark` for the comparative benchmark.

---

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
