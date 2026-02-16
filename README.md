# hexvault

Cascading cell-partitioned encryption architecture in Rust.

Layered key isolation, auditable boundary traversal, and threat-model-driven testing.

---

## What This Is

hexvault is not a cipher. It is a structural pattern for how encryption contexts are organised, partitioned, and traversed.

Data is divided into isolated cells — each an independent encryption domain with its own derived keys. Within each cell, encryption is applied in cascading layers, where each layer corresponds to a distinct trust boundary. Movement of data between cells is controlled exclusively by edge handlers: re-encryption gateways that never expose plaintext to the caller, and log every traversal.

The result is an encryption architecture where blast radius is contained by structure, access is gated by layer, and every boundary crossing is auditable.

---

## Architecture

```
        ┌───────────────┐   edge    ┌───────────────┐   edge    ┌───────────────┐
        │    Cell A      │◄─────────►│    Cell B      │◄─────────►│    Cell C      │
        │                │           │                │           │                │
        │  ┌──────────┐  │           │  ┌──────────┐  │           │  ┌──────────┐  │
        │  │ Layer 2  │  │           │  │ Layer 2  │  │           │  │ Layer 2  │  │
        │  │ session  │  │           │  │ session  │  │           │  │ session  │  │
        │  ├──────────┤  │           │  ├──────────┤  │           │  ├──────────┤  │
        │  │ Layer 1  │  │           │  │ Layer 1  │  │           │  │ Layer 1  │  │
        │  │ access   │  │           │  │ access   │  │           │  │ access   │  │
        │  ├──────────┤  │           │  ├──────────┤  │           │  ├──────────┤  │
        │  │ Layer 0  │  │           │  │ Layer 0  │  │           │  │ Layer 0  │  │
        │  │ at-rest  │  │           │  │ at-rest  │  │           │  │ at-rest  │  │
        │  └──────────┘  │           │  └──────────┘  │           │  └──────────┘  │
        └───────────────┘           └───────────────┘           └───────────────┘
```

**Cells** partition data horizontally. Each cell owns its keys. No cell can decrypt another cell's data — there is no API path that permits it.

**Stacks** layer encryption vertically within a cell. Layer 0 is base at-rest encryption. Layer 1 gates access behind a policy context. Layer 2 binds encryption to a session. Decryption peels top-down: you cannot reach Layer 0 without first peeling Layer 2 and Layer 1.

**Edges** are the only mechanism for moving data between cells. They decrypt under the source cell's key, re-encrypt under the destination cell's key, and append an audit record. Plaintext exists in memory only for the duration of that re-encryption — it is never returned to the caller.

---

## Cryptographic Primitives

| Primitive | Implementation | Role |
|---|---|---|
| Symmetric encryption | AES-256-GCM | Authenticated encryption for all payloads |
| Key derivation | HKDF-SHA256 | Derives per-cell, per-layer keys from a single master key |
| Randomness | `ring::rand::SystemRandom` | 96-bit nonce generation per encryption operation |

All cryptographic operations are backed by the [`ring`](https://github.com/briansmith/ring) crate — AWS-backed, FIPS-compatible, actively audited.

---

## Quick Start

```rust
use hexvault::{Vault, CellId, LayerContext};

// Master key is caller-provided. In production, source this from a KMS.
let master_key = hexvault::generate_master_key().unwrap();

// Create the vault and register cells.
let mut vault = Vault::new(master_key);
let mut cell_a = vault.create_cell("cell-a".to_string());
let mut cell_b = vault.create_cell("cell-b".to_string());

// Encrypt a payload into Cell A through all three stack layers.
let context = LayerContext {
    access_policy_id: Some("policy-001".into()),
    session_id: Some("session-abc".into()),
};
vault.seal(&mut cell_a, "sensitive payload", b"data", Layer::AtRest, &context).unwrap();

// Traverse from Cell A to Cell B. Plaintext never leaves the edge.
// Note: We use the same context for source and destination here for simplicity.
vault.traverse(&cell_a, &mut cell_b, "sensitive payload", Layer::AtRest, &context, &context).unwrap();

// Audit log is populated automatically.
let log = vault.audit_log();
assert_eq!(log.len(), 1);
```

---

## Running Tests and Examples

```sh
cargo test
cargo run --example multi_tenant_demo
cargo bench --bench kms_comparison_benchmark   # HexVault vs. KMS-style (simulated latency)
```

The test suite is organised into five modules, each targeting a specific security property. See `tests/` for full coverage. The threat model and what each test module validates is documented in [SECURITY.md](SECURITY.md).

---

## Project Documentation

| Document | What It Covers |
|---|---|
| [SECURITY.md](SECURITY.md) | Threat model, what each architectural layer defends against, responsible disclosure |
| [docs/architecture.md](docs/architecture.md) | Full design detail: cells, stacks, edges, key derivation, data flow |
| [docs/design-decisions.md](docs/design-decisions.md) | ADR-style log of why things were built the way they were |
| [docs/when-to-use-hexvault.md](docs/when-to-use-hexvault.md) | When to choose HexVault vs. KMS + IAM — decision guide for architects |
| [docs/key-rotation.md](docs/key-rotation.md) | Key rotation design (dual-key period, lazy re-encryption) |

---

## Why Rust

Rust's ownership model is not incidental to this project — it is load-bearing. Each cell owns its key material exclusively. Keys cannot be copied implicitly; passing a key into an operation moves it. Key material is zeroed on scope exit via the `Drop` trait. Any point where these rules must be broken is marked `unsafe` and is auditable. The compiler enforces the isolation properties that the architecture requires.

See [docs/design-decisions.md](docs/design-decisions.md) for the full rationale.

---

## Project Roadmap & Status

This project was built following a strict "Levels of Completion" strategy to ensure a shippable artifact at every stage.

### Level 1: PoC Complete (Minimum Viable) ✅
- **Goal**: Core architecture implemented, verifying the `Cell` -> `Stack` -> `Edge` pattern.
- **Status**: Complete. All 8 source modules compile, unit tests pass, and the public API is stable.

### Level 2: Portfolio-Ready (Current State) ✅
- **Goal**: Documentation, security verification, and clean presentation.
- **Deliverables**:
    - `SECURITY.md` ensuring threat model coverage.
    - Integration test suite (`tests/`) verifying isolation and audit logging.
    - CI/CD workflow (`.github/workflows/ci.yml`) for automated testing.
    - Comprehensive `Planning-Log` documenting the build process.

### Level 3: Production-Grade (Current State) ✅
- **Goal**: Optimize for real-world usage constraints.
- **Deliverables**:
    - Benchmarks (`criterion`) measuring traversal latency (~13µs for 10KB).
    - Full `crates.io` metadata and semantic versioning compliance.
    - *Note: Third-party security audit is explicitly out of scope for this release.*

---


### Performance

Benchmarks run on an AMD Ryzen 9 5950X (or equivalent high-end desktop):
| Payload Size | Time (µs) | Throughput |
|---|---|---|
| 100 B | ~5.6 µs | 17 MB/s |
| 1 KB | ~6.3 µs | 155 MB/s |
| 10 KB | ~13.2 µs | 739 MB/s |

*Note: The non-linear throughput scaling confirms the fixed overhead of key derivation (HKDF) and audit logging dominates small payloads, while AES-GCM encryption speed dominates larger payloads.*

**vs. KMS:** HexVault traversal is ~1000× faster than cloud KMS for local operations (KMS ~15–30ms per call due to network RTT). Run `cargo bench --bench kms_comparison_benchmark` for the comparative benchmark.

---

## License

MIT