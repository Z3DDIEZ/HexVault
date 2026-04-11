# Security

## Threat Model

hexvault is designed around five threat categories. Each is defended by a specific architectural layer, enforced by a specific mechanism, and validated by a specific test module.

| # | Threat | Architectural Layer | Enforcement Mechanism | Test Module |
|---|---|---|---|---|
| 1 | Data at rest exposure | Cell (horizontal isolation) + Stack (vertical depth) | Per-cell derived keys; multi-layer authenticated wrapping; AAD binds ciphertext to cell + layer | `isolation.rs`, `stack_ordering.rs`, `security_hardening.rs` |
| 2 | Data in transit interception | Edge (controlled traversal) | Plaintext exists only within the edge handler scope; explicitly zeroised before return; re-encrypted before the operation completes; never returned to the caller | `edge_traversal.rs` |
| 3 | Unauthorised access | Stack (layer gating) | Layers 1 and 2 require an explicit context object (access policy ID, session ID) to peel; missing, invalid, or empty context is rejected at construction time | `stack_ordering.rs`, `threat_model.rs`, `security_hardening.rs` |
| 4 | Blast radius from key compromise | Cell (horizontal isolation) | Each cell's keys are derived independently using HKDF with length-prefixed, cell-scoped info strings; compromising one cell's derived keys does not propagate to peers | `isolation.rs`, `threat_model.rs`, `security_hardening.rs` |
| 5 | Insider threat / privilege escalation | Edge (audit trail) + Stack (explicit peeling) | Every edge traversal appends an immutable, hash-chained audit record (source, destination, layer, timestamp); every layer peel is an explicit operation requiring a context — there is no bulk-decrypt path; chain integrity is verifiable via `AuditLog::verify_chain()` | `edge_traversal.rs`, `threat_model.rs`, `security_hardening.rs` |

---

## What Is Not in Scope

hexvault operates at the application and data layer. The following are outside its boundary and must be handled by the surrounding system:

- **Transport security.** TLS (or equivalent) is required to protect data in transit over a network. hexvault's edge handlers protect data semantically during re-encryption; they do not replace channel-level transport encryption.
- **Key storage.** The master key is caller-provided. In a production deployment, the master key should be sourced from a dedicated key management service (AWS KMS, Azure Key Vault, Google Cloud KMS, or equivalent). hexvault does not generate, store, or manage the master key.
- **Persistent storage.** Cells and their payloads exist in memory for the duration of the PoC. Persistence (to disk, a database, or object storage) is an infrastructure concern that sits beneath this library.
- **Authentication and authorisation.** hexvault enforces encryption boundaries. It does not authenticate users or authorise actions. Access policy IDs and session IDs are opaque strings — the library does not validate their meaning. That validation is the caller's responsibility.

---

## Master Key Entropy — Caller Responsibility

**hexvault does not manage master keys.** The caller is fully responsible for sourcing master key bytes with sufficient entropy.

- **DO**: Source master keys from a hardware-backed KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS) or from a CSPRNG with at least 256 bits of entropy.
- **DO**: Rotate master keys via a documented key-rotation protocol (see `docs/key-rotation.md`).
- **DO NOT**: Derive master keys from passwords, user input, timestamps, or any low-entropy source.
- **DO NOT**: Hardcode master keys in source code, configuration files, or environment variables.

If the master key is weak, **all** derived keys are weak and the entire encryption stack is compromised. `hexvault::generate_master_key()` uses `ring::rand::SystemRandom` for local key generation, but in production, prefer a KMS-managed key.

---

## Key Lifecycle

Key material in hexvault is handled with the following guarantees:

- **No implicit copying.** Rust's move semantics prevent keys from being duplicated without explicit action. The library does not expose `Clone` or `Debug` on key types — there is no way to print or copy key material through the public API.
- **Volatile zeroisation on drop.** When a key goes out of scope, its memory is overwritten using the `zeroize` crate (`ZeroizeOnDrop` derive). This uses volatile writes that the compiler **cannot** optimise away. All three key types (`MasterKey`, `PartitionKey`, `DerivedKey`) are covered.
- **Plaintext zeroisation in edge traversal.** During `traverse()`, the decrypted plaintext is explicitly zeroised via `zeroize` before the function returns — regardless of whether re-encryption succeeds or fails.
- **Derivation, not storage.** Per-cell and per-layer keys are derived on demand from the master key using HKDF-SHA256. The library does not persist derived keys — they are recreated from the master key and the derivation context each time they are needed.

---

## Nonce Domain & Uniqueness Guarantees

- **Nonce size:** 96 bits (12 bytes), as recommended by NIST SP 800-38D for AES-GCM.
- **Nonce generation:** Every encryption call generates a fresh nonce via `ring::rand::SystemRandom`. There is no counter-based, timestamp-based, or incremental nonce generation.
- **Uniqueness guarantee:** Nonces are drawn from a 2⁹⁶ space. The birthday-bound probability of collision is negligible for practical workloads (< 2⁻³² at 2³² encryptions per key).
- **No nonce caching or reuse paths.** The `generate_nonce()` function is called exactly once per `encrypt()` invocation. There is no retry path that reuses a nonce.
- **`SystemRandom` failure behaviour:** If the operating system's CSPRNG fails (e.g. insufficient entropy at boot), `encrypt()` and `generate_master_key()` return `HexvaultError::RandomnessFailure`. **There is no fallback.** The library will not silently degrade to a weaker nonce source.

---

## Additional Authenticated Data (AAD)

Every `encrypt()` / `decrypt()` call binds Additional Authenticated Data (AAD) to the ciphertext via the GCM authentication tag:

```text
AAD = "hexvault:{cell_id}:{layer_tag}"
```

This provides defence-in-depth:
- Even if a key reuse bug were introduced, ciphertext from Cell A could not be injected into Cell B — the AAD mismatch would cause the GCM tag check to fail.
- Cross-layer replay is similarly prevented.

---

## HKDF Info String Encoding

Key derivation uses length-prefixed info strings to prevent delimiter collisions:

```text
info = [4-byte len(seg1)][seg1][4-byte len(seg2)][seg2][4-byte len(seg3)][seg3]
```

This ensures that a cell ID containing `:` or other control characters cannot produce the same derived key as a different (cell_id, layer, context) combination.

---

## Input Validation

The following inputs are validated to prevent silent security degradation:

| Input | Validated At | Constraint | Error |
|-------|-------------|------------|-------|
| `cell_id` | `keys::derive_key()` | Must be non-empty | `InvalidCellId` |
| `partition_id` | `keys::derive_partition_key()` | Must be non-empty | `InvalidPartitionId` |
| `access_policy_id` | `LayerContext::new()` | If `Some`, must be non-empty | `MissingOrInvalidContext` |
| `session_id` | `LayerContext::new()` | If `Some`, must be non-empty | `MissingOrInvalidContext` |

---

## Cryptographic Choices

| Decision | Choice | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption. Provides confidentiality and integrity in a single operation. Tampering is detected at decryption time. NIST-recommended. |
| Key derivation | HKDF-SHA256 | One-way, deterministic derivation. Different info strings produce independent keys from the same master. No key material leaks between derivation contexts. |
| Cryptographic backend | `ring` (pinned to exact version) | Narrow API surface — fewer ways to misuse it. AWS-backed. FIPS-compatible. Actively audited. Does not expose raw key bytes. |
| Nonce size | 96 bits (12 bytes) | NIST-recommended nonce length for AES-GCM. Matches `ring`'s expected input. |
| Key zeroisation | `zeroize` crate (`ZeroizeOnDrop`) | Volatile memory overwrites that cannot be optimised away by the compiler. Maintained by the RustCrypto team. |

---

## Responsible Disclosure

If you identify a security issue in hexvault, please report it privately before public disclosure.

Open a GitHub issue titled `[SECURITY]` with a description of the vulnerability, the conditions required to trigger it, and any relevant reproduction steps. Do not include exploit code in a public issue.

Issues will be triaged and addressed as quickly as possible. A fix will be released before any public disclosure of the vulnerability details.