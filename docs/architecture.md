# Architecture

## Overview

hexvault organises encryption as a three-dimensional structure. The horizontal axis partitions data into isolated cells. The vertical axis layers encryption within each cell according to trust boundaries. The connecting edges control how data moves between cells.

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

Each of these three components — cell, stack, edge — is described in full below.

---

## Cells

A cell is the fundamental unit of data isolation in hexvault. It is an independent encryption domain that owns its own keys and its own encrypted payloads. No cell can decrypt another cell's data, and no API path in the library permits cross-cell decryption outside of an edge traversal.

### What a Cell Contains

- A unique identifier (`CellId`) — an opaque string chosen by the caller.
- A set of derived keys, one per stack layer. These are not stored; they are derived on demand from the master key and the cell's identity.
- Zero or more encrypted payloads, each tagged with the layer at which they were sealed.

### Isolation Guarantee

Cell isolation is enforced structurally, not by access control checks at runtime. The key derivation function uses the cell ID as part of its input. Two cells with different IDs produce entirely different key streams from the same master key. A ciphertext produced under Cell A's keys is not decryptable under Cell B's keys — it will fail authentication verification and be rejected.

This means that even if an attacker gains access to Cell B's key material, they cannot use it to decrypt anything in Cell A. The blast radius of a single cell's compromise is bounded to that cell.

---

## Stacks

A stack is the set of encryption layers within a single cell. Layers are ordered and applied sequentially. Each layer corresponds to a distinct trust boundary and requires a distinct context to peel.

### Layer Definitions

| Layer | Name | Trust Boundary | Context Required to Peel |
|---|---|---|---|
| 0 | At-rest | Base data protection | None — this layer is always present and is the innermost encryption |
| 1 | Access-gated | Access policy enforcement | `access_policy_id` — an opaque string identifying a valid access policy |
| 2 | Session-bound | Session lifetime enforcement | `session_id` — an opaque string identifying an active session |

### Encryption Order (Seal)

Encryption is applied bottom-up. When a payload is sealed into a cell, the operations execute in this order:

```
plaintext
    │
    ▼  encrypt with Layer 0 key (at-rest)
ciphertext_0
    │
    ▼  encrypt with Layer 1 key (access-gated)
ciphertext_1
    │
    ▼  encrypt with Layer 2 key (session-bound)
ciphertext_2  ← stored
```

The stored value is `ciphertext_2`. It is opaque to anyone who does not hold the correct context for all three layers.

### Decryption Order (Peel)

Decryption is applied top-down. Each layer must be peeled in sequence, and each peel requires the correct context:

```
ciphertext_2  ← stored value
    │
    ▼  decrypt with Layer 2 key (requires session_id)
ciphertext_1
    │
    ▼  decrypt with Layer 1 key (requires access_policy_id)
ciphertext_0
    │
    ▼  decrypt with Layer 0 key
plaintext
```

Attempting to peel Layer 1 before Layer 2 is rejected. Attempting to peel any layer without the correct context is rejected. The stack enforces ordering at the type level — the API does not expose a path that skips or reorders layers.

---

## Edges

An edge is the only mechanism for moving encrypted data from one cell to another. It is an explicit, three-phase operation that re-encrypts the payload under the destination cell's keys without ever exposing the plaintext to the caller.

### Traversal Phases

```
┌─────────┐                              ┌─────────┐
│  Cell A  │                              │  Cell B  │
│          │                              │          │
│  sealed  │──► Phase 1: Peel ──►  plaintext  ──► Phase 2: Re-wrap ──►  sealed  │
│  payload │    (decrypt under A)   (in edge     (encrypt under B)      payload  │
│          │                         scope only)                        │          │
└─────────┘                              └─────────┘
                        │
                        ▼
               Phase 3: Audit
          (append traversal record)
```

**Phase 1 — Peel.** The edge handler decrypts the payload from the source cell, peeling through the stack layers in top-down order. The caller provides the layer context required for the source cell's stack.

**Phase 2 — Re-wrap.** The plaintext is immediately encrypted under the destination cell's keys. The caller provides the target layer context for the destination cell. The plaintext exists in memory only for the duration of this operation — it is not returned, stored, or logged.

**Phase 3 — Audit.** A traversal record is appended to the vault's audit log. The record contains the source cell ID, destination cell ID, the layer at which the traversal occurred, and a timestamp. The audit log is append-only.

### What the Caller Sees

The caller invokes a single `traverse` operation. They provide the source cell, destination cell, and the layer contexts for both. They do not receive the plaintext. They do not receive the intermediate ciphertext. They receive a confirmation that the traversal completed and can inspect the audit log to verify it.

---

## Key Derivation

All keys in hexvault are derived from a single master key using HKDF-SHA256. The master key is the only secret that must be managed by the caller. Everything else is derived deterministically.

### Derivation Inputs

Each derived key is produced from three inputs:

```
HKDF-SHA256(
    ikm   = master_key,
    salt  = None,
    info  = cell_id || ":" || layer_tag || ":" || context_id
)
```

| Input | Value | Purpose |
|---|---|---|
| `ikm` | The caller-provided master key | The single source of entropy |
| `info` | A structured string combining cell identity, layer tag, and context | Ensures every derived key is unique and scoped to exactly one cell + layer + context combination |

### Why This Works

HKDF is a one-way function. Knowing the output (a derived key) does not reveal the input (the master key). Two different `info` strings produce statistically independent outputs even from the same master key. This means:

- Compromising a derived key for Cell A, Layer 1 reveals nothing about Cell A's other layers or any other cell's keys.
- The master key can be rotated independently of the cells. Rotating the master key invalidates all derived keys simultaneously.

---

## Rust Ownership and the Security Model

The relationship between Rust's ownership system and hexvault's security properties is not coincidental. It is the reason Rust was chosen.

| Security Property | How Rust Enforces It |
|---|---|
| No two cells share key material | Ownership. Each cell owns its keys exclusively. There is no shared reference. |
| Keys cannot be accidentally duplicated | Move semantics. Passing a key into an operation transfers ownership. The original binding is invalidated by the compiler. |
| Key material does not linger in memory | `Drop` trait. Key-holding types implement `Drop` to overwrite their memory before deallocation. |
| Plaintext lifetime is bounded to the edge scope | Ownership. The plaintext value is created inside the edge handler and dropped when the handler returns. It cannot escape the scope. |
| Any violation of these rules is visible | `unsafe`. Any point where the pattern must break its own rules requires an explicit `unsafe` block. This makes the security-critical surface area auditable. |

---

## Module Responsibilities

| Module | Owns | Depends On |
|---|---|---|
| `cell.rs` | Cell identity, payload storage, isolation enforcement | `keys.rs`, `stack.rs` |
| `stack.rs` | Layer ordering, seal/peel sequencing, context validation | `crypto.rs`, `keys.rs` |
| `edge.rs` | Traversal logic, plaintext lifetime control, audit record creation | `cell.rs`, `stack.rs`, `audit.rs` |
| `keys.rs` | Key derivation (HKDF), key ownership, zeroisation | `crypto.rs` |
| `crypto.rs` | AES-256-GCM encrypt/decrypt, nonce generation | `ring` |
| `audit.rs` | Append-only traversal log, serialisation | `serde` |
| `error.rs` | All error types for the library | — |
| `lib.rs` | Public API surface. Re-exports only what callers need | All modules |