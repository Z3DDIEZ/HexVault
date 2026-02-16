# Design Decisions

This document records the significant architectural and technical decisions made during the design of hexvault. Each entry follows the ADR (Architecture Decision Record) format: context, decision, consequences.

Entries are numbered chronologically — the order in which the decisions were made.

---

## ADR-001 — Encryption Architecture Pattern, Not a Custom Cipher

**Context.** The original concept was a "cascading hexagonal encryption" system inspired by honeycomb structures. The first design question was whether hexvault should implement a novel encryption algorithm or use standard primitives organised into a novel structure.

**Decision.** hexvault uses standard, well-audited cryptographic primitives (AES-256-GCM, HKDF-SHA256) and provides value through the structural pattern in which they are organised — not through modifications to the primitives themselves.

**Consequences.** The security of individual encryption and key derivation operations rests on decades of cryptanalysis and formal verification. hexvault's contribution is the architecture: how keys are scoped, how layers are ordered, how boundaries are traversed. This is a defensible separation. Inventing a custom cipher would introduce unaudited cryptographic surface area with no corresponding benefit.

---

## ADR-002 — Rust as the Implementation Language

**Context.** The project needed a language that would enforce — not merely encourage — the security properties the architecture requires. Key isolation, no implicit key duplication, bounded plaintext lifetimes, and auditable unsafe operations were all design requirements, not implementation preferences.

**Decision.** Rust was chosen as the implementation language.

**Consequences.** Rust's ownership model maps directly onto the security properties of the architecture. Keys cannot be shared implicitly — ownership prevents it. Keys cannot be copied without explicit action — move semantics prevent it. Key material is zeroed on scope exit — the `Drop` trait enforces it. Any deviation from these rules requires an `unsafe` block, making the security-critical surface area visible and auditable. No other mainstream language provides these guarantees at compile time.

The tradeoff is learning curve. Rust is not already in the project author's primary stack. This is an intentional choice — the project exists partly to build depth in systems-level reasoning, and Rust forces engagement with the exact concerns (memory ownership, byte-level operations, lifetime management) that the portfolio gap analysis identified.

---

## ADR-003 — `ring` Over `rust-cryptography` as the Cryptographic Backend

**Context.** Two mature Rust crates provide AES-GCM and HKDF: `ring` and the `rust-cryptography` family (`aes-gcm`, `hkdf`). Both are production-quality.

**Decision.** `ring` was chosen as the single cryptographic backend.

**Consequences.** `ring` has a deliberately narrow API surface. It does not expose raw key bytes. It forces the caller to work within its abstractions (`SealingKey`, `OpeningKey`, `LessSafeKey`). This makes misuse harder by construction. It is also AWS-backed and FIPS-compatible, which matters if the pattern is ever extended toward compliance-relevant use cases.

The tradeoff is that `ring`'s API is less flexible than `rust-cryptography`. Operations that are trivial with raw key access require working within `ring`'s type system. This is the point — the friction is a feature, not a bug, in a security-focused project.

---

## ADR-004 — HKDF-SHA256 for Key Derivation, Not Per-Cell Random Keys

**Context.** Two approaches to per-cell key generation were considered. The first: generate a random key for each cell and store it alongside the cell data. The second: derive each cell's key deterministically from a single master key using HKDF, where the cell ID and layer tag are part of the derivation input.

**Decision.** HKDF-SHA256 derivation was chosen. No per-cell keys are stored.

**Consequences.** Derivation means the only secret that needs to be managed is the master key. Per-cell keys are recreated on demand from the master key and the derivation context. This eliminates a key storage surface entirely. Rotating the master key invalidates all derived keys simultaneously. Compromising a derived key reveals nothing about the master key or any other derived key — HKDF is one-way and the derivation inputs are independent per cell and per layer.

The tradeoff is that key derivation adds a small computational cost on every encrypt/decrypt operation. For a PoC operating on in-memory data, this cost is negligible.

---

## ADR-005 — Fixed Three-Layer Stack for the PoC

**Context.** The stack layer structure could be designed as fixed (a predetermined set of roles) or pluggable (caller-defined layers with arbitrary semantics). A pluggable stack would be more flexible but adds significant API complexity and makes the security properties harder to reason about.

**Decision.** The PoC uses a fixed three-layer stack: Layer 0 (at-rest), Layer 1 (access-gated), Layer 2 (session-bound).

**Consequences.** Fixed layers make the security model explicit and testable. Each layer has a defined role, a defined context requirement, and a defined test case. The threat model can be mapped one-to-one onto the layer structure. A pluggable stack would be the natural evolution for a production library, but it introduces the risk of callers constructing insecure layer configurations. For a PoC whose goal is to prove the pattern works correctly, fixed layers are the right choice.

---

## ADR-006 — Edge Traversal Does Not Return Plaintext to the Caller

**Context.** The edge handler re-encrypts data from one cell to another. A simpler API would expose the plaintext to the caller between the decrypt and re-encrypt steps, letting the caller decide what to do with it. The chosen design keeps the plaintext internal to the edge handler.

**Decision.** The edge handler owns the plaintext for the duration of the re-encryption. It is not returned to the caller, not logged, and not accessible outside the handler's scope.

**Consequences.** This is the strongest boundary enforcement in the library. The caller cannot intercept, log, or exfiltrate data during a traversal. The plaintext's lifetime is bounded by the edge handler's scope — Rust's ownership system enforces this at compile time. The tradeoff is reduced flexibility: the caller cannot perform arbitrary operations on the plaintext during traversal. For hexvault's threat model (insider threat / privilege escalation), this is the correct tradeoff.

---

## ADR-007 — Append-Only Audit Log, Not a Mutable Event Store

**Context.** Edge traversals produce audit records. The audit log could be implemented as a mutable collection (allowing records to be edited or deleted) or as an append-only structure (records can only be added, never modified or removed).

**Decision.** The audit log is append-only.

**Consequences.** An append-only log cannot be retroactively altered to hide a traversal. This is the foundation of the insider threat defence. A mutable event store would require a separate integrity mechanism (e.g., a Merkle chain over the records) to detect tampering — adding complexity without adding the guarantee that append-only semantics provide for free. The tradeoff is that the log grows without bound for the lifetime of the vault instance. For an in-memory PoC, this is not a concern. For a production system, the log would need to be flushed to a persistent, tamper-evident store at regular intervals.

---

## ADR-008 — Synchronous Operations Only

**Context.** Rust has a mature async ecosystem (`tokio`, `async-std`). The edge handler and stack operations could be modelled as async to allow concurrent traversals and non-blocking I/O.

**Decision.** All operations in the PoC are synchronous.

**Consequences.** Synchronous code is easier to reason about in the context of security-critical operations. The plaintext lifetime in the edge handler is a single, linear scope — there is no yield point where another task could observe it. Async would introduce potential for interleaving at yield points, which complicates the plaintext lifetime argument. For an in-memory PoC with no I/O, there is no performance case for async. If the library is extended to support persistent storage or network-based KMS, async would become the correct choice.

---

## ADR-009 — Pluggable Audit Sink for Persistence

**Context.** The audit log is in-memory. For production, records need to be persisted to a file, database, S3, or similar. The library could own every backend or allow callers to provide one.

**Decision.** Add an `AuditSink` trait and `add_forward_sink()` on `AuditLog`. The primary log remains in-memory for inspection; attached sinks receive a copy of every record. A built-in `FileAuditSink` writes JSON lines for common use cases.

**Consequences.** Callers can persist the audit trail without modifying core logic. The primary log stays in memory so `audit_log().iter()` continues to work. Forward sinks are optional — existing code is unchanged. The tradeoff is that sink failures (e.g., disk full) do not abort the traversal; the in-memory log still records it. Callers must ensure sink reliability for their compliance requirements.