//! Minimal example: HexVault in a multi-tenant scenario.
//!
//! Demonstrates cell isolation and audit logging with file persistence.
//! Run with: `cargo run --example multi_tenant_demo`
//!
//! This example serves as a dogfood/demo for the HexVault pattern:
//! - Tenant A and Tenant B have cryptographically isolated data
//! - Data movement between tenants is audited
//! - Audit log is persisted to a file for inspection

use hexvault::audit::FileAuditSink;
use hexvault::stack::{Layer, LayerContext};
use hexvault::{generate_master_key, Vault};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup
    let master_key = generate_master_key()?;
    let mut vault = Vault::new(master_key);

    // Optional: persist audit log to file
    let audit_path = PathBuf::from(std::env::temp_dir()).join("hexvault_audit.jsonl");
    vault.add_audit_sink(Box::new(FileAuditSink::new(&audit_path)?));

    // 2. Create cells (tenants)
    let mut tenant_a = vault.create_cell("tenant-a".into());
    let mut tenant_b = vault.create_cell("tenant-b".into());

    let ctx = LayerContext::default();

    // 3. Tenant A stores sensitive data
    vault.seal(
        &mut tenant_a,
        "customer_pii",
        b"Alice, alice@example.com, SSN-xxx",
        Layer::AtRest,
        &ctx,
    )?;

    println!("Stored data in tenant-a");

    // 4. Traverse from A to B (e.g., data migration, sharing with consent)
    vault.traverse(
        &tenant_a,
        &mut tenant_b,
        "customer_pii",
        Layer::AtRest,
        &ctx,
        &ctx,
    )?;

    println!("Traversed tenant-a -> tenant-b");

    // 5. Verify isolation: B can read, A still has its copy
    let in_b = vault.open(&tenant_b, "customer_pii", &ctx)?;
    assert_eq!(in_b, b"Alice, alice@example.com, SSN-xxx");

    // 6. Audit log
    let log = vault.audit_log();
    println!("Audit log: {} record(s)", log.len());
    for record in log.iter() {
        println!(
            "  {} -> {} @ {:?}",
            record.source_cell_id, record.dest_cell_id, record.timestamp
        );
    }
    println!("Full audit also written to: {}", audit_path.display());

    Ok(())
}
