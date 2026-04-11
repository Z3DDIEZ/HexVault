use hexvault::error::HexvaultError;
use hexvault::stack::{Layer, LayerContext, TokenResolver};
use hexvault::{generate_master_key, Vault};

struct DummyResolver;
impl TokenResolver for DummyResolver {
    fn resolve(&self, _token: &str) -> Result<LayerContext, HexvaultError> {
        Ok(LayerContext::empty())
    }
}

#[test]
fn test_successful_traversal() {
    // Threat Model #2: Data in transit interception (Protected Traversal).

    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master, std::sync::Arc::new(DummyResolver));

    let partition = vault.get_partition("test").unwrap();
    let mut cell_a = partition.create_cell("cell-a".into());
    let mut cell_b = partition.create_cell("cell-b".into());

    let token = "";
    let plaintext = b"moving target";

    // 1. Store in Source.
    partition
        .seal(&mut cell_a, "data", plaintext, Layer::AtRest, token)
        .unwrap();

    // 2. Traverse.
    vault
        .traverse(
            &partition,
            &cell_a,
            &partition,
            &mut cell_b,
            "data",
            Layer::AtRest,
            token,
            token,
        )
        .unwrap();

    // 3. Verify presence in Destination.
    let result = partition.open(&cell_b, "data", token).unwrap();
    assert_eq!(result, plaintext);
}

#[test]
fn test_audit_logging() {
    // Threat Model #5: Insider threat (Audit Trail).

    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master, std::sync::Arc::new(DummyResolver));

    let partition = vault.get_partition("test").unwrap();
    let mut cell_a = partition.create_cell("source".into());
    let mut cell_b = partition.create_cell("dest".into());
    let token = "";

    // 1. Perform traversal.
    partition
        .seal(&mut cell_a, "key", b"log me", Layer::AtRest, token)
        .unwrap();
    vault
        .traverse(
            &partition,
            &cell_a,
            &partition,
            &mut cell_b,
            "key",
            Layer::AtRest,
            token,
            token,
        )
        .unwrap();

    // 2. Verify Audit Log contains the record.
    let log = vault.audit_log();
    assert_eq!(log.len(), 1, "Audit log should have 1 record");

    let record = log.iter().next().unwrap();
    assert_eq!(record.source_cell_id, "source");
    assert_eq!(record.dest_cell_id, "dest");
    assert_eq!(record.layer, Layer::AtRest);

    // 3. Verify the audit chain is intact.
    assert!(log.verify_chain(), "Audit chain should be valid");
}
