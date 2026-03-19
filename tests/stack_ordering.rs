use hexvault::{generate_master_key, keys};
use hexvault::stack::{self, Layer, LayerContext};

#[test]
fn test_layer_peeling_order() {
    // Threat Model #1: Data at rest exposure (Depth).
    // Goal: Confirm that layers must be peeled in correct order (Top -> Down).

    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let cell_id = "test-cell";
    let plaintext = b"layered secret";

    let ctx = LayerContext::new(
        Some("policy".into()),
        Some("session".into()),
    );

    // 1. Seal to Layer 2 (SessionBound).
    // Stack: [AtRest] -> [AccessGated] -> [SessionBound]
    let sealed = stack::seal(&partition, cell_id, Layer::SessionBound, &ctx, plaintext).unwrap();

    // 2. Attempt to peel assuming it's only Layer 1 (AccessGated).
    // This effectively tries to decrypt the outer layer (SessionBound) using the AccessGated key.
    // This MUST fail.
    let result = stack::peel(&partition, cell_id, Layer::AccessGated, &ctx, &sealed);
    assert!(result.is_err(), "Managed to peel bypassing the top layer!");
}

#[test]
fn test_invalid_context_rejection() {
    // Threat Model #3: Unauthorised access.
    // Goal: Missing or wrong context ID rejects access.

    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let cell_id = "test-auth";
    let plaintext = b"guarded secret";

    let correct_ctx = LayerContext::new(
        Some("secret-policy".into()),
        None,
    );

    // 1. Seal to Layer 1 (AccessGated).
    let sealed = stack::seal(
        &partition,
        cell_id,
        Layer::AccessGated,
        &correct_ctx,
        plaintext,
    )
    .unwrap();

    // 2. Attempt to peel with WRONG policy ID.
    let wrong_ctx = LayerContext::new(Some("public-policy".into()), None);

    let result = stack::peel(&partition, cell_id, Layer::AccessGated, &wrong_ctx, &sealed);
    assert!(
        result.is_err(),
        "Peeling succeeded with wrong access policy ID!"
    );

    // 3. Attempt to peel with MISSING policy ID.
    let missing_ctx = LayerContext::new(None, None);

    let result_missing = stack::peel(&partition, cell_id, Layer::AccessGated, &missing_ctx, &sealed);
    assert!(
        result_missing.is_err(),
        "Peeling succeeded with missing access policy ID!"
    );
}
