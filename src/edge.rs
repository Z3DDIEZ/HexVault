//! Edge traversal logic.
//!
//! Handles the secure movement of data between cells:
//! 1. Decrypt from source (Peel)
//! 2. Re-encrypt to destination (Seal)
//! 3. Append to audit log
//!
//! This is the ONLY way data moves between cells.

use chrono::Utc;

use crate::audit::{AuditLog, AuditRecord};
use crate::cell::Cell;
use crate::error::HexvaultError;
use crate::keys::MasterKey;
use crate::stack::{Layer, LayerContext};

/// Move a payload from one cell to another.
///
/// The payload is decrypted from the source cell using `source_ctx` and
/// immediately re-encrypted into the destination cell at `target_layer`
/// using `dest_ctx`.
///
/// The plaintext exists only within the scope of this function.
pub fn traverse(
    master: &MasterKey,
    source: &Cell,
    dest: &mut Cell,
    key: &str,
    target_layer: Layer,
    source_ctx: &LayerContext,
    dest_ctx: &LayerContext,
    audit: &mut AuditLog,
) -> Result<(), HexvaultError> {
    // Phase 1: Peel
    // We retrieve the plaintext from the source.
    // If the key doesn't exist or contexts are wrong, this fails early.
    let plaintext = source.retrieve(master, key, source_ctx)?;

    // Phase 2: Seal
    // We store the plaintext into the destination cell.
    // Note: We use the same key string for simplicity, but strictly speaking
    // the key in the new cell could be different. For this API, we keep it consistent.
    dest.store(master, key, &plaintext, target_layer, dest_ctx)?;

    // Phase 3: Audit
    // Log the successful traversal.
    let record = AuditRecord {
        source_cell_id: source.id().to_string(),
        dest_cell_id: dest.id().to_string(),
        layer: target_layer,
        timestamp: Utc::now(),
    };
    audit.append(record);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    #[test]
    fn test_traverse_audit() {
        let master = MasterKey::from_bytes([2u8; 32]);
        let mut cell_a = Cell::new("cell-a".to_string());
        let mut cell_b = Cell::new("cell-b".to_string());
        let mut audit = AuditLog::new();

        let ctx = LayerContext::default(); // Using AtRest (Layer 0) which needs empty context

        // Store in A
        cell_a
            .store(&master, "secret", b"move me", Layer::AtRest, &ctx)
            .unwrap();

        // Traverse to B
        traverse(
            &master,
            &cell_a,
            &mut cell_b,
            "secret",
            Layer::AtRest,
            &ctx,
            &ctx,
            &mut audit,
        )
        .unwrap();

        // 1. Verify B has the data
        let retrieved = cell_b.retrieve(&master, "secret", &ctx).unwrap();
        assert_eq!(retrieved, b"move me");

        // 2. Verify Audit Log
        assert_eq!(audit.len(), 1);
        let record = audit.iter().next().unwrap();
        assert_eq!(record.source_cell_id, "cell-a");
        assert_eq!(record.dest_cell_id, "cell-b");
    }
}
