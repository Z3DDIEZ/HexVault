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
//!     info = "{cell_id}:{layer_tag}:{context_id}"
//! )
//! ```
//!
//! Each unique combination of cell ID, layer tag, and context ID produces a
//! statistically independent key. Knowing one derived key reveals nothing
//! about the master key or any other derived key.

use ring::hkdf;

use crate::crypto::KEY_LEN;
use crate::error::HexvaultError;

// ---------------------------------------------------------------------------
// Master key
// ---------------------------------------------------------------------------

/// A master key. This is the single secret that must be managed by the caller.
/// All per-cell and per-layer keys are derived from it.
///
/// - Not `Clone`. Cannot be duplicated without explicit conversion.
/// - Zeroised on drop. Memory is overwritten before deallocation.
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl MasterKey {
    /// Construct a `MasterKey` from raw bytes.
    ///
    /// In production, the caller should source these bytes from a KMS.
    /// For the PoC, use `crate::generate_master_key()` which calls
    /// `crypto::generate_random_key()` internally.
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

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Overwrite key material before the memory is deallocated.
        self.bytes = [0u8; KEY_LEN];
    }
}

// ---------------------------------------------------------------------------
// Derived key
// ---------------------------------------------------------------------------

/// A key derived for a specific cell and layer.
///
/// - Not `Clone`. Each derived key is a single-use value scoped to one
///   cell + layer + context combination.
/// - Zeroised on drop.
/// - Raw bytes are never exposed outside this module. Other modules
///   access derived keys only through `as_bytes()`, which is `pub(crate)`.
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

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.bytes = [0u8; KEY_LEN];
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// The layer tags used in the HKDF info string.
/// These are the fixed identifiers that differentiate the three stack layers.
pub(crate) mod layer_tag {
    pub const AT_REST: &str = "rest";
    pub const ACCESS_GATED: &str = "access";
    pub const SESSION_BOUND: &str = "session";
}

/// Derive a key for a specific cell, layer, and context.
///
/// The `info` string is constructed as:
/// ```text
/// {cell_id}:{layer_tag}:{context_id}
/// ```
///
/// `context_id` is empty for Layer 0 (at-rest), an access policy ID for
/// Layer 1, and a session ID for Layer 2.
///
/// # Security properties
/// - HKDF is one-way: the derived key reveals nothing about the master key.
/// - Different info strings produce statistically independent outputs.
/// - The output length is fixed at 256 bits (32 bytes).
pub(crate) fn derive_key(
    master: &MasterKey,
    cell_id: &str,
    layer_tag: &str,
    context_id: &str,
) -> Result<DerivedKey, HexvaultError> {
    let info = format!("{}:{}:{}", cell_id, layer_tag, context_id);

    // Extract phase: derive a pseudorandom key (PRK) from the master key.
    // An empty salt is provided — HKDF internally treats this as a
    // zero-filled salt of the hash output length, which is standard.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master.as_bytes());

    // Expand phase: derive the final key from the PRK and the info string.
    // The info string encodes the cell, layer, and context — ensuring every
    // derived key is unique and scoped.
    let info_bytes = info.as_bytes();
    let info_slices = [info_bytes];
    let okm = prk
        .expand(&info_slices, hkdf::HKDF_SHA256)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    let mut derived = [0u8; KEY_LEN];
    okm.fill(&mut derived)
        .map_err(|_| HexvaultError::KeyDerivationFailure)?;

    Ok(DerivedKey { bytes: derived })
}
