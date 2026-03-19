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
pub mod keys;
pub mod partition;
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
#[must_use = "discarding a master key is likely a bug"]
pub fn generate_master_key() -> Result<MasterKey, error::HexvaultError> {
    let bytes = crypto::generate_random_key()?;
    Ok(MasterKey::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Phase 4 API — Vault Wrapper
// ---------------------------------------------------------------------------

use audit::AuditLog;
use cell::Cell;
use partition::Partition;
use stack::{Layer, TokenResolver};

use std::sync::Arc;

/// The high-level entry point for managing cells and traversals.
///
/// Holds the master key, the central audit log, and token resolver.
pub struct Vault {
    master_key: MasterKey,
    audit_log: AuditLog,
    token_resolver: Arc<dyn TokenResolver>,
}

impl Vault {
    /// Create a new Vault with the provided master key and token resolver.
    pub fn new(master_key: MasterKey, token_resolver: Arc<dyn TokenResolver>) -> Self {
        Self {
            master_key,
            audit_log: AuditLog::new(),
            token_resolver,
        }
    }

    /// Create or get a partition.
    pub fn get_partition(&self, id: &str) -> Result<Partition, error::HexvaultError> {
        let key = keys::derive_partition_key(&self.master_key, id)?;
        Ok(Partition::new(
            id.to_string(),
            key,
            Arc::clone(&self.token_resolver),
        ))
    }

    /// Traverse data from one cell to another.
    #[allow(clippy::too_many_arguments)]
    pub fn traverse(
        &mut self,
        source_partition: &Partition,
        source: &Cell,
        dest_partition: &Partition,
        dest: &mut Cell,
        key: &str,
        target_layer: Layer,
        source_token: &str,
        dest_token: &str,
    ) -> Result<(), error::HexvaultError> {
        let source_ctx = self.token_resolver.resolve(source_token)?;
        let dest_ctx = self.token_resolver.resolve(dest_token)?;

        edge::traverse(
            &mut self.audit_log,
            edge::TraversalRequest {
                source_partition_key: source_partition.key(),
                dest_partition_key: dest_partition.key(),
                source,
                dest,
                key,
                target_layer,
                source_ctx: &source_ctx,
                dest_ctx: &dest_ctx,
            },
        )
    }

    /// Inspect the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Add a sink to receive a copy of every traversal record.
    /// Use this to persist the audit log to a file, S3, or other store.
    pub fn add_audit_sink(&mut self, sink: Box<dyn audit::AuditSink>) {
        self.audit_log.add_forward_sink(sink);
    }

    /// Return the number of audit records logged so far.
    ///
    /// Convenience method equivalent to `vault.audit_log().len()`.
    pub fn audit_log_len(&self) -> usize {
        self.audit_log.len()
    }
}
