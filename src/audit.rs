//! Immutable audit logging.
//!
//! records every edge traversal. The log is append-only.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::stack::Layer;

/// A permanent record of a data movement event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The cell the data moved FROM.
    pub source_cell_id: String,
    /// The cell the data moved TO.
    pub dest_cell_id: String,
    /// The encryption layer at which the payload was sealed in the destination.
    pub layer: Layer,
    /// When the traversal occurred.
    pub timestamp: DateTime<Utc>,
}

/// An append-only log of all traversals.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new record to the log.
    pub fn append(&mut self, record: AuditRecord) {
        self.records.push(record);
    }

    /// Return the number of records in the log.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over the records.
    pub fn iter(&self) -> std::slice::Iter<'_, AuditRecord> {
        self.records.iter()
    }
}
