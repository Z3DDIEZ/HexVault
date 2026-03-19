//! Partition management.
//!
//! A partition provides isolation between groups of cells. Keys for cells
//! are derived from the partition key, enabling a two-level blast-radius containment.

use crate::cell::{Cell, CellId};
use crate::error::HexvaultError;
use crate::keys::PartitionKey;
use crate::stack::{Layer, TokenResolver};

use std::sync::Arc;

/// A partition provides isolation between groups of cells.
pub struct Partition {
    id: String,
    key: PartitionKey,
    resolver: Arc<dyn TokenResolver>,
}

impl Partition {
    pub(crate) fn new(id: String, key: PartitionKey, resolver: Arc<dyn TokenResolver>) -> Self {
        Self { id, key, resolver }
    }

    /// Return the partition's ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrow the partition's key.
    pub(crate) fn key(&self) -> &PartitionKey {
        &self.key
    }

    /// Create a new isolated cell within this partition.
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
        token: &str,
    ) -> Result<(), HexvaultError> {
        let context = self.resolver.resolve(token)?;
        cell.store(&self.key, key, plaintext, layer, &context)
    }

    /// Retrieve a payload from a cell.
    pub fn open(&self, cell: &Cell, key: &str, token: &str) -> Result<Vec<u8>, HexvaultError> {
        let context = self.resolver.resolve(token)?;
        cell.retrieve(&self.key, key, &context)
    }
}
