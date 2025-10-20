//! Parser for hashcat potfile content.
//!
//! Supported line formats:
//! - `hash:password` — only the first `:` splits the fields; the password may
//!   contain additional colons and is preserved as-is.
//! - `domain\\user:hash:password` — the username portion is ignored; the first
//!   `:` separates `domain\\user` from `hash`, and the next `:` separates `hash`
//!   from `password` (remaining colons belong to the password).
//!
//! Blank and malformed lines are ignored by bulk parsing.
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
/// Errors returned while parsing potfile lines.
pub enum PotError {
    #[error("malformed pot line: {0}")]
    MalformedLine(String),
}

/// Parse a single potfile line.
///
/// Accepted forms:
/// - `hash:password`
/// - `domain\\user:hash:password`
pub fn parse_pot_line(line: &str) -> Result<(String, String), PotError> {
    let s = line.trim();
    if let Some((left, rest)) = s.split_once(':') {
        if left.contains('\\') {
            // Expect rest to contain at least one ':' separating hash and password
            if let Some((hash, pass)) = rest.split_once(':') {
                return Ok((hash.trim().to_string(), pass.trim().to_string()));
            } else {
                return Err(PotError::MalformedLine(line.to_string()));
            }
        } else {
            // Standard hash:password; keep rest intact to preserve any additional colons in password
            return Ok((left.trim().to_string(), rest.trim().to_string()));
        }
    }
    Err(PotError::MalformedLine(line.to_string()))
}

/// Parse entire potfile contents into a hash->password map.
pub fn parse_pot_contents(contents: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok((h, p)) = parse_pot_line(line) {
            map.insert(h, p);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_password_with_colons() {
        let (h, p) = parse_pot_line("abcdef:pa:ss:wd").unwrap();
        assert_eq!(h, "abcdef");
        assert_eq!(p, "pa:ss:wd");
    }

    #[test]
    fn parses_user_prefixed_line_and_password_with_colons() {
        let (h, p) = parse_pot_line("dom.local\\alice:abcdef:pa:ss:wd").unwrap();
        assert_eq!(h, "abcdef");
        assert_eq!(p, "pa:ss:wd");
    }

    #[test]
    fn ignores_malformed_and_blank_lines() {
        let map = parse_pot_contents("\nno_colon\n123:abc\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("123").unwrap(), "abc");
    }
}
