# When to Choose HexVault vs. KMS + IAM

A one-pager for architects and engineers evaluating HexVault. See also [AG-docs/hexvault_technical_assessment.md](../AG-docs/hexvault_technical_assessment.md) for a full assessment.

---

## TL;DR

| Use HexVault when… | Use KMS + IAM when… |
|--------------------|---------------------|
| You need cryptographic tenant isolation (not just RBAC) | Cloud KMS is available and acceptable |
| You deploy offline, on-prem, or at the edge | You're fully in AWS/Azure/GCP |
| Compliance requires proof of encryption-boundary separation | Standard IAM + encryption contexts suffice |
| You need deterministic key derivation from a master | Per-tenant KMS keys are fine |
| Latency must be sub-millisecond (local crypto) | Network RTT to KMS (~15–50ms) is acceptable |

---

## The Core Question

**"Do I need encryption boundaries, or just access control?"**

- **Access control** (RBAC, IAM): "Who can access this data?" — enforced at the policy layer.
- **Encryption boundaries** (HexVault): "Who can *decrypt* this data?" — enforced at the crypto layer.

If an attacker steals your database dump, RBAC doesn't help. Encryption boundaries do: tenant A's ciphertext cannot be decrypted with tenant B's keys, even if the attacker has both.

---

## Use HexVault If…

1. **Regulatory mandate for cryptographic tenant isolation**  
   HIPAA, PCI-DSS, or similar require that tenant data be provably isolated at the encryption layer, not just by access control.

2. **Offline, edge, or air-gapped deployment**  
   No cloud KMS. HexVault derives keys locally from a master key — no network calls for encrypt/decrypt.

3. **High-frequency local encryption**  
   HexVault: ~6–13µs for seal/traverse. KMS: ~15–50ms per call. If you're encrypting thousands of items per second locally, HexVault avoids KMS throttling and latency.

4. **Insider threat model with code access**  
   Developers can read production code but not deploy changes. HexVault's edge handler keeps plaintext scope-bounded — no `log(plaintext)` in the API.

5. **Deterministic key derivation**  
   Keys derived from master + context, no key storage. Rotate master → all derived keys invalid. Useful for key hierarchy auditing.

---

## Use KMS + IAM If…

1. **You're already in the cloud**  
   AWS KMS per-tenant keys + IAM policies give you tenant isolation. CloudTrail gives you audit. HexVault adds complexity without clear benefit.

2. **RBAC is sufficient**  
   Most SaaS apps don't need cryptographic tenant isolation. Database row-level security or application-layer checks are enough.

3. **You want managed key lifecycle**  
   KMS handles rotation, backup, HSM. HexVault expects *you* to manage the master key.

4. **Performance isn't critical**  
   A few hundred encrypt/decrypt operations per second can use KMS. Network latency dominates; local vs. remote crypto doesn't matter much.

---

## Decision Flow

```
Do you need cryptographic tenant isolation?
├─ No  → Use KMS + IAM (or just RBAC)
└─ Yes → Is cloud KMS available?
         ├─ Yes → Is sub-ms latency or offline operation required?
         │        ├─ Yes → Consider HexVault
         │        └─ No  → Use KMS per-tenant keys
         └─ No  → HexVault (or similar local derivation pattern)
```

---

## Summary

HexVault is for **multi-tenant systems with regulatory or architectural requirements for cryptographic isolation**, especially when cloud KMS is unavailable or too slow. For standard cloud deployments, KMS + IAM is usually simpler and sufficient.
