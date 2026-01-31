//! Low-level cryptographic operations.
//!
//! This module is one of exactly two places in the crate that import `ring`
//! directly (the other is `keys`). All other modules perform encryption and
//! decryption exclusively through the functions exposed here.
//!
//! Primitive choices:
//! - **Cipher**: AES-256-GCM (authenticated encryption)
//! - **Nonce**: 96-bit (12 bytes), generated fresh per operation via `SystemRandom`
//! - **Key size**: 256 bits (32 bytes)

use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::HexvaultError;

/// The AEAD algorithm used throughout hexvault.
const ALGORITHM: &aead::Algorithm = &AES_256_GCM;

/// Size of the nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Size of a master or derived key in bytes (256 bits).
pub const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/// Generate a cryptographically secure random nonce.
///
/// Uses `ring::rand::SystemRandom` — the only source of randomness in the crate.
/// A fresh nonce is generated for every encryption call. There is no nonce
/// caching or counter-based generation.
fn generate_nonce() -> Result<([u8; NONCE_LEN], Nonce), HexvaultError> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; NONCE_LEN];
    rng.fill(&mut buf).map_err(|_| HexvaultError::RandomnessFailure)?;
    Ok((buf, Nonce::assume_unique_for_key(buf)))
}

/// Encrypt a plaintext payload using AES-256-GCM.
///
/// Returns the nonce prepended to the ciphertext. The caller does not need to
/// manage the nonce separately — it is bundled with the output and extracted
/// automatically during decryption.
///
/// # Layout of returned bytes
/// ```text
/// [ nonce (12 bytes) ][ ciphertext + GCM tag ]
/// ```
pub fn encrypt(key_bytes: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, HexvaultError> {
    let unbound = UnboundKey::new(ALGORITHM, key_bytes)
        .map_err(|_| HexvaultError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);

    let (nonce_bytes, nonce) = generate_nonce()?;
    let aad = aead::Aad::empty();

    let mut buffer = plaintext.to_vec();

    // `seal_in_place_append_tag` encrypts `buffer` in place and
    // appends the GCM authentication tag.
    key.seal_in_place_append_tag(nonce, aad, &mut buffer)
        .map_err(|_| HexvaultError::EncryptionFailure)?;

    let mut output = Vec::with_capacity(NONCE_LEN + buffer.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&buffer);

    Ok(output)
}

/// Decrypt a ciphertext payload using AES-256-GCM.
///
/// Expects the input to be in the layout produced by `encrypt`:
/// nonce (12 bytes) followed by ciphertext and GCM tag.
///
/// If the key is wrong or the ciphertext has been tampered with, the GCM
/// authentication check fails and this function returns an error. The caller
/// receives no partial plaintext.
pub fn decrypt(key_bytes: &[u8; KEY_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, HexvaultError> {
    if ciphertext.len() < NONCE_LEN {
        return Err(HexvaultError::DecryptionFailure);
    }

    let nonce_bytes: [u8; NONCE_LEN] = ciphertext[..NONCE_LEN]
        .try_into()
        .map_err(|_| HexvaultError::DecryptionFailure)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound = UnboundKey::new(ALGORITHM, key_bytes)
        .map_err(|_| HexvaultError::InvalidKey)?;
    let key = LessSafeKey::new(unbound);

    let aad = aead::Aad::empty();
    let mut payload = ciphertext[NONCE_LEN..].to_vec();

    let plaintext = key
        .open_in_place(nonce, aad, &mut payload)
        .map_err(|_| HexvaultError::DecryptionFailure)?;

    Ok(plaintext.to_vec())
}

/// Generate a cryptographically secure random key.
///
/// This is the only function in the crate that produces raw key material from
/// scratch. It is used by `generate_master_key()` in the public API.
pub fn generate_random_key() -> Result<[u8; KEY_LEN], HexvaultError> {
    let rng = SystemRandom::new();
    let mut key = [0u8; KEY_LEN];
    rng.fill(&mut key).map_err(|_| HexvaultError::RandomnessFailure)?;
    Ok(key)
}