// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Shared campfire utilities — timestamps and JSON writing.
//!
//! Extracted from mirror_inbox (where `chrono_now_utc` lived)
//! and campfire_writer/storyteller (where `write_json` was inlined).

use std::path::Path;

use serde::Serialize;

/// Get current UTC timestamp as ISO 8601 string.
///
/// Uses manual formatting to avoid a chrono dependency.
/// Good until 2100 (leap year calculation is simplified).
pub fn utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();

    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

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

/// Write a serializable value as pretty JSON to a file.
///
/// # Errors
///
/// Returns an I/O error if serialization or file write fails.
pub fn write_json(value: &impl Serialize, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format() {
        let ts = utc_now();
        assert!(ts.starts_with("202"));
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20); // "YYYY-MM-DDTHH:MM:SSZ"
    }

    #[test]
    fn write_json_roundtrip() {
        let dir = std::env::temp_dir().join("campfire_util_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        #[derive(Serialize)]
        struct TestData { x: u32 }

        write_json(&TestData { x: 42 }, &path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("42"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
