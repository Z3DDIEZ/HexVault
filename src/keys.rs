//! Key derivation and ownership.
//!
//! This module owns two responsibilities:
//! 1. Deriving per-cell, per-layer keys from a master key using HKDF-SHA256.
//! 2. Holding derived key material in types that are opaque, non-cloneable,
//!    and zeroised on drop.
//!
//! This is one of exactly two modules permitted to import `ring` directly
//! (the other is `crypto`). The HKDF derivation logic lives here because
//! it operates on the key material itself — not on ciphertexts.
//!
//! ## Derivation structure
//!
//! ```text
//! HKDF-SHA256(
//!     ikm  = master_key,
//!     salt = None,
//!     info = len(cell_id) || cell_id || len(layer_tag) || layer_tag || len(context_id) || context_id
//! )
//! ```
//!
//! Each unique combination of cell ID, layer tag, and context ID produces a
//! statistically independent key. The info string uses length-prefixed segments
//! to prevent delimiter collisions. Knowing one derived key reveals nothing
//! about the master key or any other derived key.

use ring::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::KEY_LEN;
use crate::error::HexvaultError;

// ---------------------------------------------------------------------------
// Master key
// ---------------------------------------------------------------------------

/// A master key. This is the single secret that must be managed by the caller.
/// All per-cell and per-layer keys are derived from it.
///
/// - Not `Clone`. Cannot be duplicated without explicit conversion.
/// - Zeroised on drop via the `zeroize` crate (`ZeroizeOnDrop`). Memory is
///   overwritten with a volatile write before deallocation — the compiler
///   cannot optimise this away.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl MasterKey {
    /// Construct a `MasterKey` from raw bytes.
    ///
    /// In production, the caller should source these bytes from a KMS.
    /// For the PoC, use `crate::generate_master_key()` which calls
    /// `crypto::generate_random_key()` internally.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw key bytes for use in HKDF derivation.
    ///
    /// This method is `pub(crate)` — raw bytes never leave the crate.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// Partition key
// ---------------------------------------------------------------------------

/// A partition key derived from the master key.
///
/// - Not `Clone`.
/// - Zeroised on drop via `ZeroizeOnDrop`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PartitionKey {
    bytes: [u8; KEY_LEN],
}

impl PartitionKey {
    /// Borrow the raw key bytes for use in HKDF derivation.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// Derived key
// ---------------------------------------------------------------------------

/// A key derived for a specific cell and layer.
///
/// - Not `Clone`. Each derived key is a single-use value scoped to one
///   cell + layer + context combination.
/// - Zeroised on drop via `ZeroizeOnDrop`.
/// - Raw bytes are never exposed outside this module. Other modules
///   access derived keys only through `as_bytes()`, which is `pub(crate)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    bytes: [u8; KEY_LEN],
}

impl DerivedKey {
    /// Borrow the raw key bytes for use in encrypt/decrypt operations.
    ///
    /// `pub(crate)` — raw bytes never leave the crate.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// Derivation helpers
// ---------------------------------------------------------------------------

/// The layer tags used in the HKDF info string.
/// These are the fixed identifiers that differentiate the three stack layers.
pub(crate) mod layer_tag {
    pub const AT_REST: &str = "rest";
    pub const ACCESS_GATED: &str = "access";
    pub const SESSION_BOUND: &str = "session";
}

/// Build a length-prefixed info byte string from variable-length segments.
///
/// Each segment is encoded as `[4-byte big-endian length][segment bytes]`.
/// This prevents delimiter-based collisions — e.g. a cell_id containing `:`
/// cannot produce the same info string as a different (cell_id, layer) pair.
fn build_info(segments: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    for seg in segments {
        buf.extend_from_slice(&(seg.len() as u32).to_be_bytes());
        buf.extend_from_slice(seg.as_bytes());
    }
    buf
}

// ---------------------------------------------------------------------------
// Derivation functions
// ---------------------------------------------------------------------------

/// Derive a key for a specific partition.
///
/// The info string is length-prefixed: `len("partition") || "partition" || len(partition_id) || partition_id`.
///
/// # Errors
///
/// Returns `HexvaultError::InvalidPartitionId` if `partition_id` is empty.
pub fn derive_partition_key(
    master: &MasterKey,
    partition_id: &str,
) -> Result<PartitionKey, HexvaultError> {
    if partition_id.is_empty() {
        return Err(HexvaultError::InvalidPartitionId);
    }

    let info = build_info(&["partition", partition_id]);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master.as_bytes());

    let info_slices = [info.as_slice()];
    let okm = prk
        .expand(&info_slices, hkdf::HKDF_SHA256)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    let mut derived = [0u8; KEY_LEN];
    okm.fill(&mut derived)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    Ok(PartitionKey { bytes: derived })
}

/// Derive a key for a specific cell, layer, and context.
///
/// The info string is length-prefixed:
/// ```text
/// len(cell_id) || cell_id || len(layer_tag) || layer_tag || len(context_id) || context_id
/// ```
///
/// `context_id` is empty for Layer 0 (at-rest), an access policy ID for
/// Layer 1, and a session ID for Layer 2.
///
/// # Security properties
/// - HKDF is one-way: the derived key reveals nothing about the master key.
/// - Length-prefixed info strings prevent delimiter collisions.
/// - Different info strings produce statistically independent outputs.
/// - The output length is fixed at 256 bits (32 bytes).
///
/// # Errors
///
/// Returns `HexvaultError::InvalidCellId` if `cell_id` is empty.
pub(crate) fn derive_key(
    partition_key: &PartitionKey,
    cell_id: &str,
    layer_tag: &str,
    context_id: &str,
) -> Result<DerivedKey, HexvaultError> {
    if cell_id.is_empty() {
        return Err(HexvaultError::InvalidCellId);
    }

    let info = build_info(&[cell_id, layer_tag, context_id]);

    // Extract phase: derive a pseudorandom key (PRK) from the partition key.
    // An empty salt is provided — HKDF internally treats this as a
    // zero-filled salt of the hash output length, which is standard.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(partition_key.as_bytes());

    // Expand phase: derive the final key from the PRK and the info string.
    // The info string encodes the cell, layer, and context — ensuring every
    // derived key is unique and scoped.
    let info_slices = [info.as_slice()];
    let okm = prk
        .expand(&info_slices, hkdf::HKDF_SHA256)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    let mut derived = [0u8; KEY_LEN];
    okm.fill(&mut derived)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    Ok(DerivedKey { bytes: derived })
}
