//! Tests for the pluggable AuditSink / forward sink functionality.

use std::sync::{Arc, Mutex};

use hexvault::audit::{AuditRecord, AuditSink};
use hexvault::stack::{Layer, LayerContext, TokenResolver};
use hexvault::error::HexvaultError;
use hexvault::{generate_master_key, Vault};

struct DummyResolver;
impl TokenResolver for DummyResolver {
    fn resolve(&self, _token: &str) -> Result<LayerContext, HexvaultError> {
        Ok(LayerContext::empty())
    }
}

/// A test sink that collects records into a shared Vec.
struct SharedVecSink {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl SharedVecSink {
    fn new(records: Arc<Mutex<Vec<AuditRecord>>>) -> Self {
        Self { records }
    }
}

impl AuditSink for SharedVecSink {
    fn append(&mut self, record: AuditRecord) {
        self.records.lock().unwrap().push(record);
    }
}

#[test]
fn test_forward_sink_receives_records() {
    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master, std::sync::Arc::new(DummyResolver));

    let records = Arc::new(Mutex::new(Vec::new()));
    vault.add_audit_sink(Box::new(SharedVecSink::new(Arc::clone(&records))));

    let partition = vault.get_partition("test").unwrap();
    let mut cell_a = partition.create_cell("cell-x".into());
    let mut cell_b = partition.create_cell("cell-y".into());
    let token = "";

    partition
        .seal(&mut cell_a, "key", b"secret", Layer::AtRest, token)
        .unwrap();
    vault
        .traverse(&partition, &cell_a, &partition, &mut cell_b, "key", Layer::AtRest, token, token)
        .unwrap();

    // Primary log has the record
    assert_eq!(vault.audit_log().len(), 1);

    // Forward sink also received the record
    let collected = records.lock().unwrap();
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].source_cell_id, "cell-x");
    assert_eq!(collected[0].dest_cell_id, "cell-y");
}
