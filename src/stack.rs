//! Layered encryption sequencing.
//!
//! The stack defines how encryption is applied (bottom-up) and removed
//! (top-down). Each layer corresponds to a different trust boundary and
//! requires specific context to peel.

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::HexvaultError;
use crate::keys::{self, PartitionKey};

/// The three layers of the hexvault encryption stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Layer {
    /// Layer 0: Base data protection (at-rest).
    AtRest = 0,
    /// Layer 1: Access policy enforcement.
    AccessGated = 1,
    /// Layer 2: Session lifetime enforcement.
    SessionBound = 2,
}

impl Layer {
    /// Returns the tag used for key derivation for this layer.
    fn tag(&self) -> &'static str {
        match self {
            Self::AtRest => keys::layer_tag::AT_REST,
            Self::AccessGated => keys::layer_tag::ACCESS_GATED,
            Self::SessionBound => keys::layer_tag::SESSION_BOUND,
        }
    }
}

/// Context required to peel or seal specific layers.
///
/// Fields are validated on construction: `Some("")` (empty string) is rejected
/// to prevent silent key-derivation collisions.
///
/// Callers must use a `TokenResolver` to generate instances, or construct
/// via `LayerContext::new()` / `LayerContext::empty()`.
#[derive(Debug, Clone, Default)]
pub struct LayerContext {
    access_policy_id: Option<String>,
    session_id: Option<String>,
}

impl LayerContext {
    /// Create an empty context for Layer 0 (AtRest) operations.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a new `LayerContext`.
    ///
    /// # Errors
    ///
    /// Returns `HexvaultError::MissingOrInvalidContext` if either ID is
    /// `Some("")` (empty string). An empty string would derive the same
    /// Layer 2 key for all sessions or the same Layer 1 key for all
    /// access policies — collapsing the isolation guarantee.
    pub fn new(
        access_policy_id: Option<String>,
        session_id: Option<String>,
    ) -> Result<Self, HexvaultError> {
        if let Some(ref id) = access_policy_id {
            if id.is_empty() {
                return Err(HexvaultError::MissingOrInvalidContext);
            }
        }
        if let Some(ref id) = session_id {
            if id.is_empty() {
                return Err(HexvaultError::MissingOrInvalidContext);
            }
        }
        Ok(Self {
            access_policy_id,
            session_id,
        })
    }
}

/// Resolves opaque authentication/capability tokens into structured `LayerContext`s.
pub trait TokenResolver: Send + Sync {
    /// Exchange a token for a LayerContext representing the active security policies.
    fn resolve(&self, token: &str) -> Result<LayerContext, HexvaultError>;
}

impl LayerContext {
    /// Get the context ID string for a specific layer.
    fn get_id_for_layer(&self, layer: Layer) -> Result<String, HexvaultError> {
        match layer {
            Layer::AtRest => Ok(String::new()),
            Layer::AccessGated => self
                .access_policy_id
                .clone()
                .ok_or(HexvaultError::MissingOrInvalidContext),
            Layer::SessionBound => self
                .session_id
                .clone()
                .ok_or(HexvaultError::MissingOrInvalidContext),
        }
    }
}

/// Build the AAD (Additional Authenticated Data) for a specific cell and layer.
///
/// The AAD binds the ciphertext to its cell and layer, preventing cross-cell
/// and cross-layer replay attacks. Even if two cells share identical keys
/// (impossible under correct HKDF usage), the AAD check would still reject
/// replayed ciphertext.
fn build_aad(cell_id: &str, layer: Layer) -> Vec<u8> {
    format!("hexvault:{}:{}", cell_id, layer.tag()).into_bytes()
}

/// Seal a payload into the stack up to the target layer.
///
/// Encryption is applied bottom-up: Layer 0 -> Layer 1 -> ... -> target.
pub fn seal(
    partition_key: &PartitionKey,
    cell_id: &str,
    target: Layer,
    context: &LayerContext,
    plaintext: &[u8],
) -> Result<Vec<u8>, HexvaultError> {
    let mut current_data = plaintext.to_vec();

    // Iterate through layers from 0 up to and including the target layer.
    for i in 0..=(target as usize) {
        let layer = match i {
            0 => Layer::AtRest,
            1 => Layer::AccessGated,
            2 => Layer::SessionBound,
            _ => return Err(HexvaultError::InvalidLayer),
        };

        let context_id = context.get_id_for_layer(layer)?;
        let key = keys::derive_key(partition_key, cell_id, layer.tag(), &context_id)?;
        let aad = build_aad(cell_id, layer);

        current_data = crypto::encrypt(key.as_bytes(), &current_data, &aad)?;
    }

    Ok(current_data)
}

/// Peel a payload from its current top layer down to plaintext.
///
/// Decryption is applied top-down: current -> ... -> Layer 0.
pub fn peel(
    partition_key: &PartitionKey,
    cell_id: &str,
    current_top: Layer,
    context: &LayerContext,
    ciphertext: &[u8],
) -> Result<Vec<u8>, HexvaultError> {
    let mut current_data = ciphertext.to_vec();

    // Iterate through layers from the top layer down to 0.
    for i in (0..=(current_top as usize)).rev() {
        let layer = match i {
            0 => Layer::AtRest,
            1 => Layer::AccessGated,
            2 => Layer::SessionBound,
            _ => return Err(HexvaultError::InvalidLayer),
        };

        let context_id = context.get_id_for_layer(layer)?;
        let key = keys::derive_key(partition_key, cell_id, layer.tag(), &context_id)?;
        let aad = build_aad(cell_id, layer);

        current_data = crypto::decrypt(key.as_bytes(), &current_data, &aad)?;
    }

    Ok(current_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{self, MasterKey};

    #[test]
    fn test_seal_peel_roundtrip() {
        let master = MasterKey::from_bytes([0u8; 32]);
        let partition = keys::derive_partition_key(&master, "p1").unwrap();
        let cell_id = "test-cell";
        let plaintext = b"secret message";
        let context = LayerContext::new(
            Some("policy-123".to_string()),
            Some("session-456".to_string()),
        )
        .unwrap();

        // Test roundtrip for each layer depth.
        for layer in [Layer::AtRest, Layer::AccessGated, Layer::SessionBound] {
            let sealed = seal(&partition, cell_id, layer, &context, plaintext).unwrap();
            let peeled = peel(&partition, cell_id, layer, &context, &sealed).unwrap();
            assert_eq!(plaintext, &peeled[..]);
        }
    }

    #[test]
    fn test_peel_fails_with_wrong_context() {
        let master = MasterKey::from_bytes([0u8; 32]);
        let partition = keys::derive_partition_key(&master, "p1").unwrap();
        let cell_id = "test-cell";
        let plaintext = b"secret message";
        let context = LayerContext::new(
            Some("correct-policy".to_string()),
            Some("correct-session".to_string()),
        )
        .unwrap();

        let sealed = seal(
            &partition,
            cell_id,
            Layer::SessionBound,
            &context,
            plaintext,
        )
        .unwrap();

        // Wrong session ID
        let wrong_context = LayerContext::new(
            Some("correct-policy".to_string()),
            Some("wrong-session".to_string()),
        )
        .unwrap();
        assert!(peel(
            &partition,
            cell_id,
            Layer::SessionBound,
            &wrong_context,
            &sealed
        )
        .is_err());

        // Missing access policy
        let missing_context = LayerContext::new(None, None).unwrap();
        assert!(peel(
            &partition,
            cell_id,
            Layer::SessionBound,
            &missing_context,
            &sealed
        )
        .is_err());
    }
}
