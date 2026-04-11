//! Security hardening tests — v1.1.2.
//!
//! These tests close the coverage gaps identified during the security audit.
//! Each test targets a specific finding from the audit.

use hexvault::audit::AuditLog;
use hexvault::stack::{self, Layer, LayerContext};
use hexvault::{generate_master_key, keys};

// ---------------------------------------------------------------------------
// F1: AAD — cross-cell ciphertext replay must fail
// ---------------------------------------------------------------------------

#[test]
fn test_cross_cell_replay_blocked_by_aad() {
    // Even though HKDF already derives different keys per cell, the AAD
    // provides defence-in-depth. This test seals in cell-a and attempts
    // to peel in cell-b — confirming the GCM tag rejects it.
    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let ctx = LayerContext::empty();

    let sealed_a = stack::seal(&partition, "cell-a", Layer::AtRest, &ctx, b"payload").unwrap();

    let result = stack::peel(&partition, "cell-b", Layer::AtRest, &ctx, &sealed_a);
    assert!(
        result.is_err(),
        "Cross-cell replay should be rejected by AAD + key mismatch"
    );
}

// ---------------------------------------------------------------------------
// F3: Empty session_id / access_policy_id must be rejected
// ---------------------------------------------------------------------------

#[test]
fn test_empty_session_id_rejected() {
    let result = LayerContext::new(Some("policy".into()), Some("".into()));
    assert!(
        result.is_err(),
        "Empty session_id should be rejected by LayerContext::new()"
    );
}

#[test]
fn test_empty_access_policy_id_rejected() {
    let result = LayerContext::new(Some("".into()), None);
    assert!(
        result.is_err(),
        "Empty access_policy_id should be rejected by LayerContext::new()"
    );
}

#[test]
fn test_none_context_ids_accepted() {
    // None is valid — it means "this layer is not in use".
    let result = LayerContext::new(None, None);
    assert!(
        result.is_ok(),
        "None values should be accepted by LayerContext::new()"
    );
}

// ---------------------------------------------------------------------------
// F4: Empty cell ID must be rejected at key derivation
// ---------------------------------------------------------------------------

#[test]
fn test_empty_cell_id_rejected() {
    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let ctx = LayerContext::empty();

    let result = stack::seal(&partition, "", Layer::AtRest, &ctx, b"data");
    assert!(
        result.is_err(),
        "Empty cell_id should be rejected during key derivation"
    );
}

// ---------------------------------------------------------------------------
// F11: Empty partition ID must be rejected
// ---------------------------------------------------------------------------

#[test]
fn test_empty_partition_id_rejected() {
    let master = generate_master_key().unwrap();
    let result = keys::derive_partition_key(&master, "");
    assert!(result.is_err(), "Empty partition_id should be rejected");
}

// ---------------------------------------------------------------------------
// Layer skip: attempting to skip Layer 1 and directly unwrap Layer 0
// ---------------------------------------------------------------------------

#[test]
fn test_skip_layer1_direct_layer0_unwrap() {
    // Seal at SessionBound (layers 0, 1, 2), then try peeling as if it
    // were only AtRest (layer 0). This must fail because the outermost
    // layer is SessionBound, not AtRest.
    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let ctx = LayerContext::new(Some("policy".into()), Some("session".into())).unwrap();

    let sealed = stack::seal(
        &partition,
        "cell-x",
        Layer::SessionBound,
        &ctx,
        b"deep secret",
    )
    .unwrap();

    // Try to peel as AtRest only — skipping layers 2 and 1.
    let result = stack::peel(&partition, "cell-x", Layer::AtRest, &ctx, &sealed);
    assert!(
        result.is_err(),
        "Peeling at AtRest should fail when data was sealed at SessionBound"
    );
}

// ---------------------------------------------------------------------------
// F9: Audit chain tamper detection
// ---------------------------------------------------------------------------

#[test]
fn test_audit_chain_tamper_detection() {
    use chrono::Utc;
    use hexvault::audit::AuditRecord;

    let mut log = AuditLog::new();

    log.append(AuditRecord {
        source_cell_id: "a".into(),
        dest_cell_id: "b".into(),
        layer: Layer::AtRest,
        timestamp: Utc::now(),
        entry_hash: String::new(),
    });
    log.append(AuditRecord {
        source_cell_id: "b".into(),
        dest_cell_id: "c".into(),
        layer: Layer::AccessGated,
        timestamp: Utc::now(),
        entry_hash: String::new(),
    });

    // 1. Valid chain
    assert!(log.verify_chain(), "Unmodified chain should verify");

    // 2. Tamper via serde roundtrip
    let json = serde_json::to_string(&log).unwrap();
    let tampered_json = json.replace("\"source_cell_id\":\"a\"", "\"source_cell_id\":\"z\"");
    let tampered: AuditLog = serde_json::from_str(&tampered_json).unwrap();

    assert!(
        !tampered.verify_chain(),
        "Tampered chain should fail verification"
    );
}

// ---------------------------------------------------------------------------
// Cross-partition isolation
// ---------------------------------------------------------------------------

#[test]
fn test_cross_partition_decryption_failure() {
    // Data sealed under partition "p1" must not be decryptable under partition "p2".
    let master = generate_master_key().unwrap();
    let p1 = keys::derive_partition_key(&master, "p1").unwrap();
    let p2 = keys::derive_partition_key(&master, "p2").unwrap();
    let ctx = LayerContext::empty();

    let sealed = stack::seal(&p1, "cell-a", Layer::AtRest, &ctx, b"isolated").unwrap();

    let result = stack::peel(&p2, "cell-a", Layer::AtRest, &ctx, &sealed);
    assert!(result.is_err(), "Cross-partition decryption should fail");
}
