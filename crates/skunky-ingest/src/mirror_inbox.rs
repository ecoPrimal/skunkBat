// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Mirror inbox — catches anonymous words left at the campfire (Wave 173).
//!
//! No IPs stored. No names. No sessions. No cookies.
//! Just words, a timestamp, and the shape they make.
//!
//! Replaces `mirror-receiver.py` (86 lines Python → typed Rust).
//!
//! # Integration
//!
//! Called from the skunky-ingest HTTP surface or standalone.
//! Messages stored as JSONL in the mirror messages file.
//! The campfire storyteller reads from the same file.

use std::io::Write;
use std::path::{Path, PathBuf};

use cellmembrane_types::campfire::MirrorMessage;
use serde::{Deserialize, Serialize};

/// Maximum message length in characters.
const MAX_MSG_LEN: usize = 2000;

/// Maximum file size before refusing new messages (10 MB).
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Incoming mirror message from a visitor.
#[derive(Debug, Deserialize)]
pub struct IncomingMessage {
    /// The words left in the mirror.
    pub words: String,
}

/// Response to a mirror message.
#[derive(Debug, Serialize)]
pub struct MirrorResponse {
    /// Whether the message was heard.
    pub heard: bool,
}

/// Mirror inbox — receives and stores anonymous messages.
pub struct MirrorInbox {
    /// Path to the JSONL message file.
    messages_path: PathBuf,
}

impl MirrorInbox {
    /// Create a new mirror inbox writing to the specified file.
    pub fn new(messages_path: impl Into<PathBuf>) -> Self {
        Self {
            messages_path: messages_path.into(),
        }
    }

    /// Receive a message from a visitor.
    ///
    /// Validates, truncates, timestamps, and appends to the JSONL file.
    /// Returns `Ok(MirrorResponse { heard: true })` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message is empty or too short (< 2 chars)
    /// - The file exceeds MAX_FILE_SIZE
    /// - The file cannot be written
    pub fn receive(&self, incoming: &IncomingMessage) -> Result<MirrorResponse, MirrorError> {
        let words = incoming.words.trim();

        if words.len() < 2 {
            return Err(MirrorError::TooShort);
        }

        // Truncate
        let words = if words.len() > MAX_MSG_LEN {
            &words[..MAX_MSG_LEN]
        } else {
            words
        };

        // Check file size
        if let Ok(meta) = std::fs::metadata(&self.messages_path) {
            if meta.len() > MAX_FILE_SIZE {
                return Err(MirrorError::Full);
            }
        }

        // Build the message
        let msg = MirrorMessage {
            ts: chrono_now_utc(),
            words: words.to_string(),
            word_count: words.split_whitespace().count(),
        };

        // Append to JSONL
        let json = serde_json::to_string(&msg)
            .map_err(|e| MirrorError::Io(e.to_string()))?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.messages_path)
            .map_err(|e| MirrorError::Io(e.to_string()))?;

        writeln!(file, "{json}")
            .map_err(|e| MirrorError::Io(e.to_string()))?;

        Ok(MirrorResponse { heard: true })
    }

    /// Read all messages from the JSONL file.
    pub fn read_all(&self) -> Vec<MirrorMessage> {
        let contents = match std::fs::read_to_string(&self.messages_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        contents.lines()
            .filter_map(|line| serde_json::from_str::<MirrorMessage>(line).ok())
            .filter(|m| !m.is_empty())
            .collect()
    }

    /// Path to the messages file.
    pub fn path(&self) -> &Path {
        &self.messages_path
    }
}

/// Errors from the mirror inbox.
#[derive(Debug)]
pub enum MirrorError {
    /// Message too short (< 2 chars).
    TooShort,
    /// Message file is full (> 10 MB).
    Full,
    /// I/O error writing the message.
    Io(String),
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message too short"),
            Self::Full => write!(f, "mirror is full"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

/// Public accessor for the timestamp function.
pub fn chrono_now_utc_pub() -> String {
    chrono_now_utc()
}

/// Get current UTC timestamp as ISO 8601 string.
/// Uses manual formatting to avoid chrono dependency.
fn chrono_now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();

    // Convert epoch seconds to UTC datetime
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified — good until 2100)
    let mut y = 1970u64;
    let mut remaining = days;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining < days_in_year { break; }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md { m = i; break; }
        remaining -= md;
    }
    let d = remaining + 1;

    format!("{y:04}-{:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z", m + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("mirror_test_{}.jsonl", std::process::id()));
        path
    }

    #[test]
    fn receive_and_read() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        let inbox = MirrorInbox::new(&path);
        let msg = IncomingMessage { words: "hello from the mirror".into() };
        let resp = inbox.receive(&msg).unwrap();
        assert!(resp.heard);

        let messages = inbox.read_all();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].words, "hello from the mirror");
        assert_eq!(messages[0].word_count, 4);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reject_too_short() {
        let path = temp_path();
        let inbox = MirrorInbox::new(&path);
        let msg = IncomingMessage { words: "x".into() };
        assert!(inbox.receive(&msg).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncate_long() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        let inbox = MirrorInbox::new(&path);
        let long = "a ".repeat(2000);
        let msg = IncomingMessage { words: long };
        inbox.receive(&msg).unwrap();

        let messages = inbox.read_all();
        assert!(messages[0].words.len() <= MAX_MSG_LEN);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timestamp_format() {
        let ts = chrono_now_utc();
        assert!(ts.starts_with("202"));
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn read_empty_file() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let inbox = MirrorInbox::new(&path);
        assert!(inbox.read_all().is_empty());
    }
}
