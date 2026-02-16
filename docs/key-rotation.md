# Key Rotation Design

This document outlines how master key rotation could work for HexVault. It is a design note — not yet implemented. The goal is to remove key rotation as an "unanswered question" for production evaluators.

---

## Problem

HexVault derives all per-cell, per-layer keys from a single master key using HKDF. The derivation info string is:

```
{cell_id}:{layer_tag}:{context_id}
```

There is no `key_version` in the derivation input. Rotating the master key would invalidate all derived keys immediately. All existing ciphertext would become undecryptable unless we re-encrypt everything under the new master.

---

## Requirements

1. **Zero downtime** — Rotation must not require taking the system offline.
2. **Gradual re-encryption** — We should not need to re-encrypt all cells in one shot.
3. **Auditability** — Key rotation events should be logged.
4. **Backward compatibility** — During the rotation window, both old and new keys must be usable.

---

## Proposed Approach: Dual-Key Period

### Phase 1: Introduce Key Version in Derivation

Extend the HKDF info string to include a version identifier:

```
{cell_id}:{layer_tag}:{context_id}:{key_version}
```

- `key_version` defaults to `0` for the current master key.
- A new master key is assigned `key_version = 1`.

### Phase 2: Rotation Procedure

1. **Generate new master key** — Caller obtains a new 256-bit master key (e.g., from KMS).
2. **Register both keys** — The vault holds `(old_master, version=0)` and `(new_master, version=1)`.
3. **Read path** — On decrypt, try `version=0` first (current ciphertext). If auth fails, try `version=1`. This supports ciphertext sealed under either key.
4. **Write path** — On encrypt, *always* use `version=1` (new master). New and updated data goes under the new key.
5. **Lazy re-encryption** — When data is read (decrypt) and then written (encrypt) — e.g., during traversal or migration — it is implicitly re-encrypted under the new key.
6. **Sweep (optional)** — Background job iterates over cells and re-seals payloads that are still under the old key. Traversal does this naturally; explicit sweep handles rarely-accessed data.
7. **Retire old key** — Once all ciphertext has been re-encrypted (or a deadline passes), remove the old master from the vault. Old ciphertext that wasn't re-encrypted is permanently lost — the sweep must complete first.

### Phase 3: Implementation Sketch

```rust
// Conceptual — not actual code
struct MasterKeySet {
    keys: HashMap<u32, MasterKey>,  // version -> key
    active_version: u32,             // version used for new encrypts
}

fn derive_key(master_set: &MasterKeySet, cell_id: &str, layer_tag: &str, 
              context_id: &str, version: u32) -> DerivedKey {
    let master = master_set.keys.get(&version).expect("version exists");
    let info = format!("{}:{}:{}:{}", cell_id, layer_tag, context_id, version);
    // ... HKDF as today
}
```

Ciphertext would need to store the `key_version` it was sealed under (e.g., prepended to the ciphertext or in metadata).

---

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| **Dual-key period (chosen)** | Gradual, no downtime, lazy re-encrypt | More complex, need to store version with ciphertext |
| **Full re-encryption in one shot** | Simple | Downtime or complex coordination; doesn't scale |
| **Envelope encryption with KMS** | KMS handles rotation | Requires KMS; different architecture |
| **Key version in context_id** | No schema change | Hacky; conflates context with key lifecycle |

---

## Migration Path for Existing Deployments

Existing HexVault ciphertext has no version field. For backward compatibility:

1. Treat ciphertext without a version as `version=0`.
2. When writing, prepend a version byte (or small header) to new ciphertext.
3. On read, if no version header, assume `version=0`.

This allows rotation to be added without breaking existing sealed data.

---

## Open Questions

1. **Sweep strategy** — How to iterate over all payloads? Cells are in-memory today; with persistence, we'd need a key iterator.
2. **Multiple old versions** — Can we support N concurrent old keys, or only 2 (current + previous)?
3. **Audit log** — Should rotation events (key added, key retired) be in the same audit stream as traversals?
4. **KMS integration** — If master comes from KMS, does KMS rotation trigger HexVault rotation, or are they independent?

---

## References

- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
- [NIST 800-57 Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) — key lifecycle recommendations
- [ADR-004](../docs/design-decisions.md) — Why HKDF derivation was chosen
