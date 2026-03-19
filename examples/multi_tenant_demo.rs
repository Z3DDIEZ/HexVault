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
use hexvault::error::HexvaultError;
use hexvault::stack::{Layer, LayerContext, TokenResolver};
use hexvault::{generate_master_key, Vault};
use std::path::PathBuf;

struct DummyResolver;
impl TokenResolver for DummyResolver {
    fn resolve(&self, _token: &str) -> Result<LayerContext, HexvaultError> {
        Ok(LayerContext::empty())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup
    let master_key = generate_master_key()?;
    let mut vault = Vault::new(master_key, std::sync::Arc::new(DummyResolver));

    // Optional: persist audit log to file
    let audit_path = PathBuf::from(std::env::temp_dir()).join("hexvault_audit.jsonl");
    vault.add_audit_sink(Box::new(FileAuditSink::new(&audit_path)?));

    // 2. Create cells (tenants)
    let partition_a = vault.get_partition("tenant-a-part")?;
    let mut tenant_a = partition_a.create_cell("tenant-a".into());
    let partition_b = vault.get_partition("tenant-b-part")?;
    let mut tenant_b = partition_b.create_cell("tenant-b".into());

    let token = "";

    // 3. Tenant A stores sensitive data
    partition_a.seal(
        &mut tenant_a,
        "customer_pii",
        b"Alice, alice@example.com, SSN-xxx",
        Layer::AtRest,
        token,
    )?;

    println!("Stored data in tenant-a");

    // 4. Traverse from A to B (e.g., data migration, sharing with consent)
    vault.traverse(
        &partition_a,
        &tenant_a,
        &partition_b,
        &mut tenant_b,
        "customer_pii",
        Layer::AtRest,
        token,
        token,
    )?;

    println!("Traversed tenant-a -> tenant-b");

    // 5. Verify isolation: B can read, A still has its copy
    let in_b = partition_b.open(&tenant_b, "customer_pii", token)?;
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
