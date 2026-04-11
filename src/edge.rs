//! Edge traversal logic.
//!
//! Handles the secure movement of data between cells:
//! 1. Decrypt from source (Peel)
//! 2. Re-encrypt to destination (Seal)
//! 3. Append to audit log
//!
//! This is the ONLY way data moves between cells.
//!
//! ## Plaintext lifetime guarantee
//!
//! The decrypted plaintext exists only within the scope of the `traverse`
//! function. It is explicitly zeroised (via `zeroize`) after re-encryption,
//! before the function returns — whether the operation succeeds or fails.

use chrono::Utc;
use zeroize::Zeroize;

use crate::audit::{AuditLog, AuditRecord};
use crate::cell::Cell;
use crate::error::HexvaultError;
use crate::keys::PartitionKey;
use crate::stack::{Layer, LayerContext};

/// Configuration arguments for a traversal operation.
///
/// Encapsulates the parameters required to move a payload between cells,
/// reducing the argument count for `traverse` and allowing for future extensibility.
pub struct TraversalRequest<'a> {
    pub source_partition_key: &'a PartitionKey,
    pub dest_partition_key: &'a PartitionKey,
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
/// The plaintext exists only within the scope of this function and is
/// explicitly zeroised before return.
pub fn traverse(audit: &mut AuditLog, req: TraversalRequest) -> Result<(), HexvaultError> {
    // Phase 1: Peel
    // We retrieve the plaintext from the source.
    // If the key doesn't exist or contexts are wrong, this fails early.
    let mut plaintext = req
        .source
        .retrieve(req.source_partition_key, req.key, req.source_ctx)?;

    // Phase 2: Seal
    // We store the plaintext into the destination cell.
    // Capture the result BEFORE zeroising plaintext so we can still report errors.
    let seal_result = req.dest.store(
        req.dest_partition_key,
        req.key,
        &plaintext,
        req.target_layer,
        req.dest_ctx,
    );

    // Zeroize plaintext IMMEDIATELY — regardless of seal success or failure.
    // This is the load-bearing security guarantee: plaintext never outlives
    // the re-encryption operation.
    plaintext.zeroize();

    // Now propagate any seal error.
    seal_result?;

    // Phase 3: Audit
    // Log the successful traversal.
    let record = AuditRecord {
        source_cell_id: req.source.id().to_string(),
        dest_cell_id: req.dest.id().to_string(),
        layer: req.target_layer,
        timestamp: Utc::now(),
        entry_hash: String::new(),
    };
    audit.append(record);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{self, MasterKey};

    #[test]
    fn test_traverse_audit() {
        let master = MasterKey::from_bytes([2u8; 32]);
        let partition = keys::derive_partition_key(&master, "p1").unwrap();
        let mut cell_a = Cell::new("cell-a".to_string());
        let mut cell_b = Cell::new("cell-b".to_string());
        let mut audit = AuditLog::new();

        let ctx = LayerContext::default(); // Using AtRest (Layer 0) which needs empty context

        // Store in A
        cell_a
            .store(&partition, "secret", b"move me", Layer::AtRest, &ctx)
            .unwrap();

        // Traverse to B
        traverse(
            &mut audit,
            TraversalRequest {
                source_partition_key: &partition,
                dest_partition_key: &partition,
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
        let retrieved = cell_b.retrieve(&partition, "secret", &ctx).unwrap();
        assert_eq!(retrieved, b"move me");

        // 2. Verify Audit Log
        assert_eq!(audit.len(), 1);
        let record = audit.iter().next().unwrap();
        assert_eq!(record.source_cell_id, "cell-a");
        assert_eq!(record.dest_cell_id, "cell-b");
    }
}
