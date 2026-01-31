use hexvault::stack::{self, Layer, LayerContext};
use hexvault::generate_master_key;

#[test]
fn test_layer_peeling_order() {
    // Threat Model #1: Data at rest exposure (Depth).
    // Goal: Confirm that layers must be peeled in correct order (Top -> Down).

    let master = generate_master_key().unwrap();
    let cell_id = "test-cell";
    let plaintext = b"layered secret";
    
    let ctx = LayerContext {
        access_policy_id: Some("policy".into()),
        session_id: Some("session".into()),
    };

    // 1. Seal to Layer 2 (SessionBound).
    // Stack: [AtRest] -> [AccessGated] -> [SessionBound]
    let sealed = stack::seal(&master, cell_id, Layer::SessionBound, &ctx, plaintext).unwrap();

    // 2. Attempt to peel assuming it's only Layer 1 (AccessGated).
    // This effectively tries to decrypt the outer layer (SessionBound) using the AccessGated key.
    // This MUST fail.
    let result = stack::peel(&master, cell_id, Layer::AccessGated, &ctx, &sealed);
    assert!(result.is_err(), "Managed to peel bypassing the top layer!");
}

#[test]
fn test_invalid_context_rejection() {
    // Threat Model #3: Unauthorised access.
    // Goal: Missing or wrong context ID rejects access.

    let master = generate_master_key().unwrap();
    let cell_id = "test-auth";
    let plaintext = b"guarded secret";
    
    let correct_ctx = LayerContext {
        access_policy_id: Some("secret-policy".into()),
        session_id: None, 
    };

    // 1. Seal to Layer 1 (AccessGated).
    let sealed = stack::seal(&master, cell_id, Layer::AccessGated, &correct_ctx, plaintext).unwrap();

    // 2. Attempt to peel with WRONG policy ID.
    let mut wrong_ctx = correct_ctx.clone();
    wrong_ctx.access_policy_id = Some("public-policy".into());

    let result = stack::peel(&master, cell_id, Layer::AccessGated, &wrong_ctx, &sealed);
    assert!(result.is_err(), "Peeling succeeded with wrong access policy ID!");

    // 3. Attempt to peel with MISSING policy ID.
    let mut missing_ctx = correct_ctx.clone();
    missing_ctx.access_policy_id = None;

    let result_missing = stack::peel(&master, cell_id, Layer::AccessGated, &missing_ctx, &sealed);
    assert!(result_missing.is_err(), "Peeling succeeded with missing access policy ID!");
}
