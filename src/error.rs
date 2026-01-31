//! Error types for hexvault.
//!
//! Every error variant is a distinct failure mode in the encryption
//! architecture. Error messages are intentionally minimal — they signal
//! *what* failed without revealing *why* in ways that could leak
//! cryptographic state.

use std::fmt;

/// The single error type for all hexvault operations.
#[derive(Debug)]
pub enum HexvaultError {
    /// A cryptographic key was invalid (wrong length, malformed, etc.).
    InvalidKey,

    /// Encryption failed. The underlying `ring` operation returned an error.
    EncryptionFailure,

    /// Decryption failed. This includes: wrong key, tampered ciphertext,
    /// or corrupted GCM authentication tag.
    DecryptionFailure,

    /// Key derivation (HKDF) failed.
    KeyDerivationFailure,

    /// The system's random number generator failed to produce bytes.
    RandomnessFailure,

    /// A cell with the given ID does not exist in the vault.
    CellNotFound(String),

    /// A cell with the given ID already exists in the vault.
    CellAlreadyExists(String),

    /// The requested stack layer does not exist or is out of range.
    InvalidLayer,

    /// A required layer context (access policy ID or session ID) was not
    /// provided, or the provided context does not match the expected value.
    MissingOrInvalidContext,

    /// An edge traversal was attempted but the source or destination cell
    /// is not valid for the operation.
    InvalidTraversal(String),
}

impl fmt::Display for HexvaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key"),
            Self::EncryptionFailure => write!(f, "encryption failed"),
            Self::DecryptionFailure => write!(f, "decryption failed"),
            Self::KeyDerivationFailure => write!(f, "key derivation failed"),
            Self::RandomnessFailure => write!(f, "randomness source failed"),
            Self::CellNotFound(id) => write!(f, "cell not found: {}", id),
            Self::CellAlreadyExists(id) => write!(f, "cell already exists: {}", id),
            Self::InvalidLayer => write!(f, "invalid layer"),
            Self::MissingOrInvalidContext => write!(f, "missing or invalid layer context"),
            Self::InvalidTraversal(reason) => write!(f, "invalid traversal: {}", reason),
        }
    }
}

impl std::error::Error for HexvaultError {}
