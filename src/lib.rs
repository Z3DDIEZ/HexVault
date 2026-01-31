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
pub(crate) mod crypto;
pub mod error;
pub(crate) mod keys;
pub mod cell;
pub mod stack;

// --- Phase 4 stubs (not yet implemented) ---
// pub(crate) mod audit;
// pub(crate) mod edge;

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