//! Cell isolation and payload management.
//!
//! A cell is the fundamental unit of isolation. It owns a set of encrypted
//! payloads and ensures that they are only accessible through keys derived
//! using the cell's unique identity.

use std::collections::HashMap;

use crate::error::HexvaultError;
use crate::keys::MasterKey;
use crate::stack::{self, Layer, LayerContext};

/// A unique identifier for a cell.
pub type CellId = String;

/// A payload stored within a cell.
pub struct Payload {
    /// The encrypted bytes.
    pub data: Vec<u8>,
    /// The layer at which this payload was sealed.
    pub sealed_at: Layer,
}

/// An independent encryption domain.
pub struct Cell {
    id: CellId,
    payloads: HashMap<String, Payload>,
}

impl Cell {
    /// Create a new, empty cell.
    pub fn new(id: CellId) -> Self {
        Self {
            id,
            payloads: HashMap::new(),
        }
    }

    /// Return the cell's ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Seal a plaintext value into the cell.
    ///
    /// The value is encrypted up to the specified layer and stored under the given key.
    pub fn store(
        &mut self,
        master: &MasterKey,
        key: &str,
        text: &[u8],
        layer: Layer,
        context: &LayerContext,
    ) -> Result<(), HexvaultError> {
        let sealed = stack::seal(master, &self.id, layer, context, text)?;
        self.payloads.insert(
            key.to_string(),
            Payload {
                data: sealed,
                sealed_at: layer,
            },
        );
        Ok(())
    }

    /// Retrieve and peel a stored payload.
    ///
    /// Returns the original plaintext if the key exists and the correct context
    /// is provided for all layers.
    pub fn retrieve(
        &self,
        master: &MasterKey,
        key: &str,
        context: &LayerContext,
    ) -> Result<Vec<u8>, HexvaultError> {
        let payload = self
            .payloads
            .get(key)
            .ok_or_else(|| HexvaultError::CellNotFound(key.to_string()))?;

        stack::peel(master, &self.id, payload.sealed_at, context, &payload.data)
    }

    /// Remove a payload from the cell.
    pub fn remove(&mut self, key: &str) {
        self.payloads.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_isolation() {
        let master = MasterKey::from_bytes([1u8; 32]);
        let mut cell_a = Cell::new("cell-a".to_string());
        let mut cell_b = Cell::new("cell-b".to_string());
        let context = LayerContext::default();

        cell_a.store(&master, "secret", b"hello a", Layer::AtRest, &context).unwrap();
        cell_b.store(&master, "secret", b"hello b", Layer::AtRest, &context).unwrap();

        // Cell A should not be able to decrypt Cell B's payload data if it were somehow swapped.
        // But here we just verify they store different things.
        assert_eq!(cell_a.retrieve(&master, "secret", &context).unwrap(), b"hello a");
        assert_eq!(cell_b.retrieve(&master, "secret", &context).unwrap(), b"hello b");

        // Simulate swap/wrong ID by calling stack::peel directly with wrong ID
        let sealed_a = cell_a.payloads.get("secret").unwrap();
        assert!(stack::peel(&master, "cell-b", sealed_a.sealed_at, &context, &sealed_a.data).is_err());
    }
}
