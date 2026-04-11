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

**Context.** Two approaches to per-cell key generation were considered. The first: generate a random key for each cell and store it alongside the cell data. The second: derive each cell's key deterministically from a single master key using a two-tier hierarchy (Master -> Partition -> Cell).

**Decision.** HKDF-SHA256 derivation was chosen via a strict two-tier hierarchy. No per-cell keys are stored.

**Consequences.** Derivation means the only secret that needs to be managed is the master key. Per-cell keys are recreated on demand from the partition key and the derivation context. This eliminates a key storage surface entirely. Rotating the master key invalidates all derived keys simultaneously. Compromising a derived cell key reveals nothing about the partition key or any other derived key.

The tradeoff is that key derivation adds a small computational cost on every encrypt/decrypt operation. For a system operating predominantly in-memory without network calls, this cost is negligible.

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

## ADR-007 — Append-Only Cryptographic Hash Chain Audit Log

**Context.** Edge traversals produce audit records. The audit log could be implemented as a mutable collection or as an append-only structure. Furthermore, the persistence model needed tamper evidence.

**Decision.** The audit log is append-only and cryptographically hash-chained (SHA-256).

**Consequences.** An append-only log cannot be retroactively altered to hide a traversal. The inclusion of an `entry_hash` linking each record sequentially ensures mathematical tamper evidence. A malicious actor cannot delete or modify a single line without breaking the hash chain for all subsequent entries in the SIEM or file sink. 

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

---

## ADR-010 — Enforced Trust Boundaries via `TokenResolver`

**Context.** Initially, applications compiled `LayerContext` properties directly and passed them into the vault. This violated zero-trust because application code could construct any policy scope it wanted, bypassing actual authentication.

**Decision.** `LayerContext` creation is locked to the internal domain. Applications only pass opaque strings (`token`). A user-provided `TokenResolver` trait boundary translates those tokens into cryptographic contexts.

**Consequences.** A compromised API edge can no longer forge a layer context because it lacks the ability to instantiate the `TokenResolver`'s secure mapping logic. Access gating policy is completely decoupled from standard application flow.

---

## ADR-011 — Two-Tier Blast Radius via `Partition`

**Context.** Originally, the hierarchy was `Vault` -> `Cell`. If a single cell compromised a cryptographic weakness, the blast radius was theoretically bounded to that cell, but practically managed flatly.

**Decision.** Introduced a `Partition` tier. `Vault` hosts `Partitions`, which host `Cells`. Keys flow: Master -> Partition -> Cell.

**Consequences.** Partitions provide hard, secondary cryptographic separation, naturally aligning with enterprise SaaS architecture where Partition = Tenant and Cell = User. Even a catastrophic flaw in a Cell key derives strictly from a Partition, protecting adjacent Partitions cryptographically.

---

## ADR-012 — Compiler-Proof Key Zeroisation

**Context.** Original key structures (`MasterKey`, `PartitionKey`, `DerivedKey`) implemented manual `Drop` traits that explicitly overwrote memory with zeros to enforce bounded plaintext visibility and key lifecycle security.

**Decision.** Replaced manual `Drop` loops with the `zeroize` crate (`ZeroizeOnDrop`).

**Consequences.** Manual single-byte loops are highly susceptible to dead-store elimination by modern LLVM optimisers if the compiler determines the data isn't read post-write. `zeroize` forces volatile memory writes that the compiler is strictly forbidden from optimising away.

---

## ADR-013 — Length-Prefixed HKDF Info Strings

**Context.** Key derivation relied on concatenating strings to generate derivation constraints.

**Decision.** HKDF info strings now use length-prefixed encoding (e.g., `len(cell_id) || cell_id`).

**Consequences.** This eliminates delimiter collision vulnerabilities. Previously, a malicious actor might craft a `cell_id` containing the delimiter string to mimic a different derivation structure layer. Length-prefixing structurally prevents cross-layer derivation overlaps.

---

## ADR-014 — AAD Binding for Decryption Authenticity

**Context.** In the original design, AES-256-GCM authenticated the ciphertext intrinsically, but cross-cell replay wasn't structurally blocked via specific labels.

**Decision.** `cell_id` and `layer_tag` are now bound to every ciphertext via GCM's Additional Authenticated Data (AAD) block.

**Consequences.** Defence in depth. The GCM authentication check will now hard-fail immediately if ciphertext belonging to Cell A is submitted for decryption against Cell B—even if an implementation key-management bug theoretically leaked the wrong key.