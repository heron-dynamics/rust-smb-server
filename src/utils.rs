//! Small helpers shared across modules.

use std::time::{SystemTime, UNIX_EPOCH};

/// Number of 100-nanosecond intervals between 1601-01-01 (Windows FILETIME
/// epoch) and 1970-01-01 (UNIX epoch). 369 years.
const FILETIME_OFFSET: u64 = 116_444_736_000_000_000;

/// Convert a `SystemTime` to a Windows FILETIME (100ns ticks since 1601).
pub fn system_time_to_filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => FILETIME_OFFSET + (d.as_secs() * 10_000_000) + (d.subsec_nanos() as u64 / 100),
        // Pre-1970 — clamp to the FILETIME epoch.
        Err(_) => 0,
    }
}

/// Convert "now" to FILETIME.
pub fn now_filetime() -> u64 {
    system_time_to_filetime(SystemTime::now())
}

/// Encode a `&str` to little-endian UTF-16 bytes.
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode a UTF-16LE byte slice. Returns an empty string if the buffer is not
/// 2-byte aligned (caller decides what to do); replacement characters on
/// invalid surrogates.
pub fn utf16le_to_string(bytes: &[u8]) -> String {
    if !bytes.len().is_multiple_of(2) {
        return String::new();
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decode a UTF-16LE byte slice into a `Vec<u16>`, returning `None` on a
/// non-aligned buffer.
pub fn utf16le_to_units(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    )
}

/// Match an SMB directory entry name against the subset of DOS wildcard
/// syntax supported by v1. `?` matches one character, `*` matches any
/// sequence, and comparison is ASCII case-insensitive. Empty, `*`, and `*.*`
/// are the conventional match-all patterns used by SMB clients.
pub(crate) fn dos_pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
        return true;
    }

    // Walk both strings as char vectors so `?` matches a char rather than a
    // byte, without going through grapheme territory.
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    dos_pattern_matches_inner(&pattern, &name)
}

fn dos_pattern_matches_inner(pattern: &[char], name: &[char]) -> bool {
    let mut pattern_index = 0usize;
    let mut name_index = 0usize;
    let mut star: Option<(usize, usize)> = None;

    while name_index < name.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?'
                || pattern[pattern_index].eq_ignore_ascii_case(&name[name_index]))
        {
            pattern_index += 1;
            name_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star = Some((pattern_index + 1, name_index));
            pattern_index += 1;
        } else if let Some((after_star, star_name_index)) = star {
            pattern_index = after_star;
            name_index = star_name_index + 1;
            star = Some((after_star, star_name_index + 1));
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// Fill `out` with cryptographically-strong random bytes via `getrandom`.
/// Falls back to zeros if the OS RNG fails — the caller should treat this as
/// fatal, but we never panic.
pub fn fill_random(out: &mut [u8]) {
    if getrandom::fill(out).is_err() {
        for b in out.iter_mut() {
            *b = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_pattern_matching() {
        assert!(dos_pattern_matches("", "anything"));
        assert!(dos_pattern_matches("*", "anything"));
        assert!(dos_pattern_matches("*.*", "README"));
        assert!(dos_pattern_matches("*.txt", "foo.txt"));
        assert!(!dos_pattern_matches("*.txt", "foo.log"));
        assert!(dos_pattern_matches("a?c", "abc"));
        assert!(!dos_pattern_matches("a?c", "ac"));
        assert!(dos_pattern_matches("a*b*c", "axxxbxxxc"));
        assert!(dos_pattern_matches("FOO", "foo"));
        assert!(!dos_pattern_matches("new.txt", "pre_existing.txt"));
    }
}
