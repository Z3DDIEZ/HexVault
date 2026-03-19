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
/// Fields are no longer public: callers must use a TokenResolver to generate instances.
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
    
    /// Create a new LayerContext. Intended to be called by `TokenResolver` implementations.
    pub fn new(access_policy_id: Option<String>, session_id: Option<String>) -> Self {
        Self { access_policy_id, session_id }
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

        current_data = crypto::encrypt(key.as_bytes(), &current_data)?;
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

        current_data = crypto::decrypt(key.as_bytes(), &current_data)?;
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
        let context = LayerContext {
            access_policy_id: Some("policy-123".to_string()),
            session_id: Some("session-456".to_string()),
        };

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
        let context = LayerContext {
            access_policy_id: Some("correct-policy".to_string()),
            session_id: Some("correct-session".to_string()),
        };

        let sealed = seal(&partition, cell_id, Layer::SessionBound, &context, plaintext).unwrap();

        // Wrong session ID
        let mut wrong_context = context.clone();
        wrong_context.session_id = Some("wrong-session".to_string());
        assert!(peel(
            &partition,
            cell_id,
            Layer::SessionBound,
            &wrong_context,
            &sealed
        )
        .is_err());

        // Missing access policy
        let mut missing_context = context.clone();
        missing_context.access_policy_id = None;
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
