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

/// Configuration arguments for a traversal operation.
///
/// Encapsulates the parameters required to move a payload between cells,
/// reducing the argument count for `traverse` and allowing for future extensibility.
pub struct TraversalRequest<'a> {
    pub source: &'a Cell,
    pub dest: &'a mut Cell,
    pub key: &'a str,
    pub target_layer: Layer,
    pub source_ctx: &'a LayerContext,
    pub dest_ctx: &'a LayerContext,
}

/// Move a payload from one cell to another.
///
/// The payload is decrypted from the source cell using `source_ctx` and
/// immediately re-encrypted into the destination cell at `target_layer`
/// using `dest_ctx`.
///
/// The plaintext exists only within the scope of this function.
pub fn traverse(
    master: &MasterKey,
    audit: &mut AuditLog,
    req: TraversalRequest,
) -> Result<(), HexvaultError> {
    // Phase 1: Peel
    // We retrieve the plaintext from the source.
    // If the key doesn't exist or contexts are wrong, this fails early.
    let plaintext = req.source.retrieve(master, req.key, req.source_ctx)?;

    // Phase 2: Seal
    // We store the plaintext into the destination cell.
    // Note: We use the same key string for simplicity, but strictly speaking
    // the key in the new cell could be different. For this API, we keep it consistent.
    req.dest
        .store(master, req.key, &plaintext, req.target_layer, req.dest_ctx)?;

    // Phase 3: Audit
    // Log the successful traversal.
    let record = AuditRecord {
        source_cell_id: req.source.id().to_string(),
        dest_cell_id: req.dest.id().to_string(),
        layer: req.target_layer,
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
            &mut audit,
            TraversalRequest {
                source: &cell_a,
                dest: &mut cell_b,
                key: "secret",
                target_layer: Layer::AtRest,
                source_ctx: &ctx,
                dest_ctx: &ctx,
            },
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
