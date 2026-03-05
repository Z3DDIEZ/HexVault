//! Example: Using all three encryption layers with access and session gating.
//!
//! Demonstrates:
//! - Layer 0 (At-rest): base encryption, no context required.
//! - Layer 1 (Access-gated): requires an `access_policy_id` to decrypt.
//! - Layer 2 (Session-bound): requires both `access_policy_id` and `session_id`.
//!
//! Run with: `cargo run --example layered_access_demo`

use hexvault::stack::{Layer, LayerContext};
use hexvault::{generate_master_key, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = generate_master_key()?;
    let vault = Vault::new(master_key);

    let mut cell = vault.create_cell("user-data".into());

    // -----------------------------------------------------------------------
    // Layer 0 — At-rest: No context needed.
    // -----------------------------------------------------------------------
    let at_rest_ctx = LayerContext::default();

    vault.seal(
        &mut cell,
        "public_profile",
        b"display_name: Alice",
        Layer::AtRest,
        &at_rest_ctx,
    )?;

    let retrieved = vault.open(&cell, "public_profile", &at_rest_ctx)?;
    println!(
        "[Layer 0] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // -----------------------------------------------------------------------
    // Layer 1 — Access-gated: Requires access_policy_id.
    // -----------------------------------------------------------------------
    let access_ctx = LayerContext {
        access_policy_id: Some("policy-internal-hr".into()),
        session_id: None,
    };

    vault.seal(
        &mut cell,
        "salary_data",
        b"salary: $120,000",
        Layer::AccessGated,
        &access_ctx,
    )?;

    let retrieved = vault.open(&cell, "salary_data", &access_ctx)?;
    println!(
        "[Layer 1] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // Attempt with wrong policy — must fail.
    let wrong_ctx = LayerContext {
        access_policy_id: Some("policy-marketing".into()),
        session_id: None,
    };
    match vault.open(&cell, "salary_data", &wrong_ctx) {
        Ok(_) => println!("[Layer 1] ERROR: wrong policy succeeded!"),
        Err(e) => println!("[Layer 1] Correctly rejected wrong policy: {e}"),
    }

    // -----------------------------------------------------------------------
    // Layer 2 — Session-bound: Requires both access_policy_id AND session_id.
    // -----------------------------------------------------------------------
    let session_ctx = LayerContext {
        access_policy_id: Some("policy-internal-hr".into()),
        session_id: Some("session-abc-123".into()),
    };

    vault.seal(
        &mut cell,
        "ssn",
        b"SSN: 123-45-6789",
        Layer::SessionBound,
        &session_ctx,
    )?;

    let retrieved = vault.open(&cell, "ssn", &session_ctx)?;
    println!(
        "[Layer 2] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // Attempt with expired/wrong session — must fail.
    let expired_ctx = LayerContext {
        access_policy_id: Some("policy-internal-hr".into()),
        session_id: Some("session-expired".into()),
    };
    match vault.open(&cell, "ssn", &expired_ctx) {
        Ok(_) => println!("[Layer 2] ERROR: expired session succeeded!"),
        Err(e) => println!("[Layer 2] Correctly rejected expired session: {e}"),
    }

    println!("\nAll three layers demonstrated successfully.");
    Ok(())
}
