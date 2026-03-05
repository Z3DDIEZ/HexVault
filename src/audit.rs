//! Immutable audit logging.
//!
//! Records every edge traversal. The log is append-only.
//! Supports pluggable sinks for forwarding records to files, S3, etc.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::stack::Layer;

/// A sink that receives audit records. Implement this to forward records
/// to a file, database, S3, or other persistent store.
pub trait AuditSink: Send {
    /// Append a record. Called for every edge traversal.
    fn append(&mut self, record: AuditRecord);
}

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

impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} → {} @ {:?} [{}]",
            self.source_cell_id, self.dest_cell_id, self.layer, self.timestamp
        )
    }
}

/// An append-only log of all traversals.
/// Can forward records to additional sinks via `add_forward_sink`.
#[derive(Default, Serialize, Deserialize)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
    #[serde(skip)]
    forward_sinks: Option<Vec<Box<dyn AuditSink>>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("records", &self.records)
            .field(
                "forward_sinks",
                &self.forward_sinks.as_ref().map(|s| s.len()),
            )
            .finish()
    }
}

impl Clone for AuditLog {
    fn clone(&self) -> Self {
        Self {
            records: self.records.clone(),
            forward_sinks: None, // Forward sinks are not cloned
        }
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            forward_sinks: None,
        }
    }

    /// Add a sink to receive a copy of every record. Useful for persisting
    /// to a file, S3, or other store without replacing the in-memory log.
    pub fn add_forward_sink(&mut self, sink: Box<dyn AuditSink>) {
        if self.forward_sinks.is_none() {
            self.forward_sinks = Some(Vec::new());
        }
        self.forward_sinks.as_mut().unwrap().push(sink);
    }

    /// Append a new record to the log and forward to any attached sinks.
    pub fn append(&mut self, record: AuditRecord) {
        if let Some(ref mut sinks) = self.forward_sinks {
            for sink in sinks.iter_mut() {
                sink.append(record.clone());
            }
        }
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

// ---------------------------------------------------------------------------
// Built-in sink: file
// ---------------------------------------------------------------------------

/// Writes audit records as JSON lines (one per record) to a file.
/// Creates the file if it doesn't exist; appends if it does.
pub struct FileAuditSink {
    file: std::fs::File,
}

impl FileAuditSink {
    /// Open or create a file for append-only audit logging.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }
}

impl AuditSink for FileAuditSink {
    fn append(&mut self, record: AuditRecord) {
        match serde_json::to_string(&record) {
            Ok(line) => {
                if let Err(e) = writeln!(self.file, "{line}") {
                    eprintln!("hexvault: FileAuditSink write error: {e}");
                }
                if let Err(e) = self.file.flush() {
                    eprintln!("hexvault: FileAuditSink flush error: {e}");
                }
            }
            Err(e) => {
                eprintln!("hexvault: FileAuditSink serialization error: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_audit_log_serde_roundtrip() {
        let mut log = AuditLog::new();

        log.append(AuditRecord {
            source_cell_id: "cell-a".into(),
            dest_cell_id: "cell-b".into(),
            layer: Layer::AtRest,
            timestamp: Utc::now(),
        });
        log.append(AuditRecord {
            source_cell_id: "cell-b".into(),
            dest_cell_id: "cell-c".into(),
            layer: Layer::SessionBound,
            timestamp: Utc::now(),
        });

        // Serialize
        let json = serde_json::to_string(&log).expect("serialize");

        // Deserialize
        let restored: AuditLog = serde_json::from_str(&json).expect("deserialize");

        // Records are preserved
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.iter().next().unwrap().source_cell_id, "cell-a");

        // Forward sinks are dropped (not serialised) — this is correct behaviour
        // The restored log should not have any sinks
    }

    #[test]
    fn test_audit_record_display() {
        let record = AuditRecord {
            source_cell_id: "cell-a".into(),
            dest_cell_id: "cell-b".into(),
            layer: Layer::AtRest,
            timestamp: Utc::now(),
        };

        let display = format!("{record}");
        assert!(display.contains("cell-a"));
        assert!(display.contains("cell-b"));
        assert!(display.contains("AtRest"));
    }
}
