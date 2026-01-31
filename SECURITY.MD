# Security

## Threat Model

hexvault is designed around five threat categories. Each is defended by a specific architectural layer, enforced by a specific mechanism, and validated by a specific test module.

| # | Threat | Architectural Layer | Enforcement Mechanism | Test Module |
|---|---|---|---|---|
| 1 | Data at rest exposure | Cell (horizontal isolation) + Stack (vertical depth) | Per-cell derived keys; multi-layer authenticated wrapping | `isolation.rs`, `stack_ordering.rs` |
| 2 | Data in transit interception | Edge (controlled traversal) | Plaintext exists only within the edge handler scope; re-encrypted before the operation completes; never returned to the caller | `edge_traversal.rs` |
| 3 | Unauthorised access | Stack (layer gating) | Layers 1 and 2 require an explicit context object (access policy ID, session ID) to peel; missing or invalid context is rejected at the layer boundary | `stack_ordering.rs`, `threat_model.rs` |
| 4 | Blast radius from key compromise | Cell (horizontal isolation) | Each cell's keys are derived independently using HKDF with cell-scoped info strings; compromising one cell's derived keys does not propagate to peers | `isolation.rs`, `threat_model.rs` |
| 5 | Insider threat / privilege escalation | Edge (audit trail) + Stack (explicit peeling) | Every edge traversal appends an immutable audit record (source, destination, layer, timestamp); every layer peel is an explicit operation requiring a context — there is no bulk-decrypt path | `edge_traversal.rs`, `threat_model.rs` |

---

## What Is Not in Scope

hexvault operates at the application and data layer. The following are outside its boundary and must be handled by the surrounding system:

- **Transport security.** TLS (or equivalent) is required to protect data in transit over a network. hexvault's edge handlers protect data semantically during re-encryption; they do not replace channel-level transport encryption.
- **Key storage.** The master key is caller-provided. In a production deployment, the master key should be sourced from a dedicated key management service (AWS KMS, Azure Key Vault, Google Cloud KMS, or equivalent). hexvault does not generate, store, or manage the master key.
- **Persistent storage.** Cells and their payloads exist in memory for the duration of the PoC. Persistence (to disk, a database, or object storage) is an infrastructure concern that sits beneath this library.
- **Authentication and authorisation.** hexvault enforces encryption boundaries. It does not authenticate users or authorise actions. Access policy IDs and session IDs are opaque strings — the library does not validate their meaning. That validation is the caller's responsibility.

---

## Key Lifecycle

Key material in hexvault is handled with the following guarantees:

- **No implicit copying.** Rust's move semantics prevent keys from being duplicated without explicit action. The library does not expose `Clone` on key types.
- **Zeroisation on drop.** When a key goes out of scope, its memory is overwritten before deallocation. This is enforced via the `Drop` trait on all key-holding types.
- **Derivation, not storage.** Per-cell and per-layer keys are derived on demand from the master key using HKDF-SHA256. The library does not persist derived keys — they are recreated from the master key and the derivation context each time they are needed.
- **Nonce uniqueness.** A fresh 96-bit nonce is generated via `ring::rand::SystemRandom` for every encryption operation. Nonce reuse — the most common source of AES-GCM failure — is structurally prevented.

---

## Cryptographic Choices

| Decision | Choice | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption. Provides confidentiality and integrity in a single operation. Tampering is detected at decryption time. NIST-recommended. |
| Key derivation | HKDF-SHA256 | One-way, deterministic derivation. Different info strings produce independent keys from the same master. No key material leaks between derivation contexts. |
| Cryptographic backend | `ring` | Narrow API surface — fewer ways to misuse it. AWS-backed. FIPS-compatible. Actively audited. Does not expose raw key bytes. |
| Nonce size | 96 bits (12 bytes) | NIST-recommended nonce length for AES-GCM. Matches `ring`'s expected input. |

---

## Responsible Disclosure

If you identify a security issue in hexvault, please report it privately before public disclosure.

Open a GitHub issue titled `[SECURITY]` with a description of the vulnerability, the conditions required to trigger it, and any relevant reproduction steps. Do not include exploit code in a public issue.

Issues will be triaged and addressed as quickly as possible. A fix will be released before any public disclosure of the vulnerability details.