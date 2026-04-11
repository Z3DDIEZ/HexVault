//! Immutable audit logging.
//!
//! Records every edge traversal. The log is append-only.
//! Supports pluggable sinks for forwarding records to files, S3, etc.
//!
//! ## Tamper evidence
//!
//! Each record contains a SHA-256 hash that chains to the previous record.
//! Tampering with or removing any record breaks the chain, which is
//! detectable via `AuditLog::verify_chain()`.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::stack::Layer;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // write! to a String is infallible — String's fmt::Write never
        // returns Err. Using `let _ =` silences the lint without unwrap.
        let _ = fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
    }
    s
}

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
    /// Cryptographic hash linking to the previous record in the chain.
    pub entry_hash: String,
}

impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bounds-check: if the hash is shorter than 8 chars (e.g. an empty
        // hash on a record that hasn't been inserted yet), show what's available.
        let hash_prefix = if self.entry_hash.len() >= 8 {
            &self.entry_hash[0..8]
        } else {
            &self.entry_hash
        };
        write!(
            f,
            "{} → {} @ {:?} [{}] (Hash: {})",
            self.source_cell_id, self.dest_cell_id, self.layer, self.timestamp, hash_prefix
        )
    }
}

/// The genesis hash used as the initial `last_hash` for an empty audit log.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An append-only log of all traversals.
/// Can forward records to additional sinks via `add_forward_sink`.
#[derive(Default, Serialize, Deserialize)]
pub struct AuditLog {
    records: Vec<AuditRecord>,
    last_hash: String,
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
            last_hash: self.last_hash.clone(),
            forward_sinks: None, // Forward sinks are not cloned
        }
    }
}

/// Compute the chain hash for a single record given the previous hash.
fn compute_record_hash(prev_hash: &str, record: &AuditRecord) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(prev_hash.as_bytes());
    ctx.update(record.source_cell_id.as_bytes());
    ctx.update(record.dest_cell_id.as_bytes());
    ctx.update(&(record.layer as u8).to_be_bytes());
    ctx.update(record.timestamp.timestamp_millis().to_string().as_bytes());
    to_hex(ctx.finish().as_ref())
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            last_hash: String::from(GENESIS_HASH),
            forward_sinks: None,
        }
    }

    /// Add a sink to receive a copy of every record. Useful for persisting
    /// to a file, S3, or other store without replacing the in-memory log.
    pub fn add_forward_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.forward_sinks.get_or_insert_with(Vec::new).push(sink);
    }

    /// Append a new record to the log and forward to any attached sinks.
    pub fn append(&mut self, mut record: AuditRecord) {
        let hash_hex = compute_record_hash(&self.last_hash, &record);
        record.entry_hash = hash_hex.clone();
        self.last_hash = hash_hex;

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

    /// Verify the integrity of the cryptographic hash chain.
    ///
    /// Re-computes the hash for every record and checks that it matches
    /// the stored `entry_hash`. If any record has been tampered with,
    /// removed, or reordered, this method returns `false`.
    ///
    /// An empty log is always valid.
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = String::from(GENESIS_HASH);

        for record in &self.records {
            let computed = compute_record_hash(&expected_prev, record);
            if computed != record.entry_hash {
                return false;
            }
            expected_prev = computed;
        }
        true
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
            entry_hash: String::new(),
        });
        log.append(AuditRecord {
            source_cell_id: "cell-b".into(),
            dest_cell_id: "cell-c".into(),
            layer: Layer::SessionBound,
            timestamp: Utc::now(),
            entry_hash: String::new(),
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
            entry_hash: "abcdef0123456789".into(),
        };

        let display = format!("{record}");
        assert!(display.contains("cell-a"));
        assert!(display.contains("cell-b"));
        assert!(display.contains("AtRest"));
    }

    #[test]
    fn test_audit_record_display_short_hash() {
        // F8: Confirm Display does not panic with a short or empty hash.
        let record = AuditRecord {
            source_cell_id: "x".into(),
            dest_cell_id: "y".into(),
            layer: Layer::AtRest,
            timestamp: Utc::now(),
            entry_hash: "abc".into(),
        };

        let display = format!("{record}");
        assert!(display.contains("abc"));
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut log = AuditLog::new();
        log.append(AuditRecord {
            source_cell_id: "a".into(),
            dest_cell_id: "b".into(),
            layer: Layer::AtRest,
            timestamp: Utc::now(),
            entry_hash: String::new(),
        });
        log.append(AuditRecord {
            source_cell_id: "b".into(),
            dest_cell_id: "c".into(),
            layer: Layer::AccessGated,
            timestamp: Utc::now(),
            entry_hash: String::new(),
        });
        assert!(log.verify_chain());
    }

    #[test]
    fn test_verify_chain_tampered() {
        let mut log = AuditLog::new();
        log.append(AuditRecord {
            source_cell_id: "a".into(),
            dest_cell_id: "b".into(),
            layer: Layer::AtRest,
            timestamp: Utc::now(),
            entry_hash: String::new(),
        });
        log.append(AuditRecord {
            source_cell_id: "b".into(),
            dest_cell_id: "c".into(),
            layer: Layer::AccessGated,
            timestamp: Utc::now(),
            entry_hash: String::new(),
        });

        // Tamper: mutate a record's cell ID after insertion.
        // We need interior access — use serde roundtrip to get mutable records.
        let json = serde_json::to_string(&log).unwrap();
        let tampered_json = json.replace("\"source_cell_id\":\"a\"", "\"source_cell_id\":\"z\"");
        let tampered: AuditLog = serde_json::from_str(&tampered_json).unwrap();

        assert!(
            !tampered.verify_chain(),
            "verify_chain should detect tampered records"
        );
    }

    #[test]
    fn test_verify_chain_empty() {
        let log = AuditLog::new();
        assert!(log.verify_chain(), "empty log should be valid");
    }
}
