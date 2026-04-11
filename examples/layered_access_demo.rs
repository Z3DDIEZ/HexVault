//! Example: Using all three encryption layers with access and session gating.
//!
//! Demonstrates:
//! - Layer 0 (At-rest): base encryption, no context required.
//! - Layer 1 (Access-gated): requires an `access_policy_id` to decrypt.
//! - Layer 2 (Session-bound): requires both `access_policy_id` and `session_id`.
//!
//! Run with: `cargo run --example layered_access_demo`

use hexvault::error::HexvaultError;
use hexvault::stack::{Layer, LayerContext, TokenResolver};
use hexvault::{generate_master_key, Vault};

struct SimpleTokenResolver;

impl TokenResolver for SimpleTokenResolver {
    fn resolve(&self, token: &str) -> Result<LayerContext, HexvaultError> {
        if token.is_empty() {
            return Ok(LayerContext::empty());
        }

        let parts: Vec<&str> = token.split(':').collect();
        match parts.len() {
            1 => LayerContext::new(Some(parts[0].to_string()), None),
            2 => LayerContext::new(Some(parts[0].to_string()), Some(parts[1].to_string())),
            _ => Err(HexvaultError::MissingOrInvalidContext),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = generate_master_key()?;
    let vault = Vault::new(master_key, std::sync::Arc::new(SimpleTokenResolver));
    let partition = vault.get_partition("dept-engineering")?;

    let mut cell = partition.create_cell("user-data".into());

    // -----------------------------------------------------------------------
    // Layer 0 — At-rest: No context needed.
    // -----------------------------------------------------------------------
    let at_rest_token = "";

    partition.seal(
        &mut cell,
        "public_profile",
        b"display_name: Alice",
        Layer::AtRest,
        at_rest_token,
    )?;

    let retrieved = partition.open(&cell, "public_profile", at_rest_token)?;
    println!(
        "[Layer 0] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // -----------------------------------------------------------------------
    // Layer 1 — Access-gated: Requires access_policy_id.
    // -----------------------------------------------------------------------
    let access_token = "policy-internal-hr";

    partition.seal(
        &mut cell,
        "salary_data",
        b"salary: $120,000",
        Layer::AccessGated,
        access_token,
    )?;

    let retrieved = partition.open(&cell, "salary_data", access_token)?;
    println!(
        "[Layer 1] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // Attempt with wrong policy — must fail.
    let wrong_token = "policy-marketing";
    match partition.open(&cell, "salary_data", wrong_token) {
        Ok(_) => println!("[Layer 1] ERROR: wrong policy succeeded!"),
        Err(e) => println!("[Layer 1] Correctly rejected wrong policy: {e}"),
    }

    // -----------------------------------------------------------------------
    // Layer 2 — Session-bound: Requires both access_policy_id AND session_id.
    // -----------------------------------------------------------------------
    let session_token = "policy-internal-hr:session-abc-123";

    partition.seal(
        &mut cell,
        "ssn",
        b"SSN: 123-45-6789",
        Layer::SessionBound,
        session_token,
    )?;

    let retrieved = partition.open(&cell, "ssn", session_token)?;
    println!(
        "[Layer 2] Retrieved: {}",
        String::from_utf8_lossy(&retrieved)
    );

    // Attempt with expired/wrong session — must fail.
    let expired_token = "policy-internal-hr:session-expired";
    match partition.open(&cell, "ssn", expired_token) {
        Ok(_) => println!("[Layer 2] ERROR: expired session succeeded!"),
        Err(e) => println!("[Layer 2] Correctly rejected expired session: {e}"),
    }

    println!("\nAll three layers demonstrated successfully.");
    Ok(())
}
