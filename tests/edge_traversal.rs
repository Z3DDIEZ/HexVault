use hexvault::{Vault, generate_master_key};
use hexvault::stack::{Layer, LayerContext};

#[test]
fn test_successful_traversal() {
    // Threat Model #2: Data in transit interception (Protected Traversal).
    
    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master);
    
    let mut cell_a = vault.create_cell("cell-a".into());
    let mut cell_b = vault.create_cell("cell-b".into());

    let ctx = LayerContext::default();
    let plaintext = b"moving target";

    // 1. Store in Source.
    vault.seal(&mut cell_a, "data", plaintext, Layer::AtRest, &ctx).unwrap();

    // 2. Traverse.
    vault.traverse(&cell_a, &mut cell_b, "data", Layer::AtRest, &ctx, &ctx).unwrap();

    // 3. Verify presence in Destination.
    let result = vault.open(&cell_b, "data", &ctx).unwrap();
    assert_eq!(result, plaintext);
}

#[test]
fn test_audit_logging() {
    // Threat Model #5: Insider threat (Audit Trail).
    
    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master);
    
    let mut cell_a = vault.create_cell("source".into());
    let mut cell_b = vault.create_cell("dest".into());
    let ctx = LayerContext::default();

    // 1. Perform traversal.
    vault.seal(&mut cell_a, "key", b"log me", Layer::AtRest, &ctx).unwrap();
    vault.traverse(&cell_a, &mut cell_b, "key", Layer::AtRest, &ctx, &ctx).unwrap();

    // 2. Verify Audit Log contains the record.
    let log = vault.audit_log();
    assert_eq!(log.len(), 1, "Audit log should have 1 record");
    
    let record = log.iter().next().unwrap();
    assert_eq!(record.source_cell_id, "source");
    assert_eq!(record.dest_cell_id, "dest");
    assert_eq!(record.layer, Layer::AtRest);
}
