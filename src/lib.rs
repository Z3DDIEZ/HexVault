//! # hexvault
//!
//! Cascading cell-partitioned encryption architecture.
//!
//! Data is partitioned into isolated cells, each with cascading layers of
//! encryption corresponding to different trust boundaries. Movement between
//! cells is controlled by auditable edge handlers that re-encrypt without
//! exposing plaintext.
//!
//! ## Public API
//!
//! The public surface of this crate is intentionally narrow. Only the types
//! and functions listed here are intended for use by callers. Everything else
//! is `pub(crate)` at most.

// Module declarations.
pub mod audit;
pub mod cell;
pub(crate) mod crypto;
pub mod edge;
pub mod error;
pub(crate) mod keys;
pub mod stack;

// ---------------------------------------------------------------------------
// Public API — Phase 2 surface
// ---------------------------------------------------------------------------

use keys::MasterKey;

/// Generate a cryptographically secure master key.
///
/// This is the only entry point for producing key material. The returned
/// `MasterKey` is the single secret from which all per-cell and per-layer
/// keys are derived. In production, callers should source master keys from
/// a dedicated KMS rather than generating them locally.
pub fn generate_master_key() -> Result<MasterKey, error::HexvaultError> {
    let bytes = crypto::generate_random_key()?;
    Ok(MasterKey::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Phase 4 API — Vault Wrapper
// ---------------------------------------------------------------------------

use audit::AuditLog;
use cell::{Cell, CellId};
use stack::{Layer, LayerContext};

/// The high-level entry point for managing cells and traversals.
///
/// Holds the master key and the central audit log.
pub struct Vault {
    master_key: MasterKey,
    audit_log: AuditLog,
}

impl Vault {
    /// Create a new Vault with the provided master key.
    pub fn new(master_key: MasterKey) -> Self {
        Self {
            master_key,
            audit_log: AuditLog::new(),
        }
    }

    /// Create a new isolated cell.
    pub fn create_cell(&self, id: CellId) -> Cell {
        Cell::new(id)
    }

    /// Seal a payload into a specific cell.
    pub fn seal(
        &self,
        cell: &mut Cell,
        key: &str,
        plaintext: &[u8],
        layer: Layer,
        context: &LayerContext,
    ) -> Result<(), error::HexvaultError> {
        cell.store(&self.master_key, key, plaintext, layer, context)
    }

    /// Retrieve a payload from a cell.
    pub fn open(
        &self,
        cell: &Cell,
        key: &str,
        context: &LayerContext,
    ) -> Result<Vec<u8>, error::HexvaultError> {
        cell.retrieve(&self.master_key, key, context)
    }

    /// Traverse data from one cell to another.
    pub fn traverse(
        &mut self,
        source: &Cell,
        dest: &mut Cell,
        key: &str,
        target_layer: Layer,
        source_ctx: &LayerContext,
        dest_ctx: &LayerContext,
    ) -> Result<(), error::HexvaultError> {
        edge::traverse(
            &self.master_key,
            source,
            dest,
            key,
            target_layer,
            source_ctx,
            dest_ctx,
            &mut self.audit_log,
        )
    }

    /// Inspect the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }
}
