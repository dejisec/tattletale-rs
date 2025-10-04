//! Parser for hashcat potfile content.
//!
//! Each line is `hash:password` where only the first `:` splits the fields; the
//! password may contain additional colons. Blank and malformed lines are
//! ignored by bulk parsing.
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
/// Errors returned while parsing potfile lines.
pub enum PotError {
    #[error("malformed pot line: {0}")]
    MalformedLine(String),
}

/// Parse a single `hash:password` potfile line. Only first `:` splits.
pub fn parse_pot_line(line: &str) -> Result<(String, String), PotError> {
    // hash:password, only first ':' splits; allow empty password
    if let Some((hash, rest)) = line.split_once(':') {
        Ok((hash.trim().to_string(), rest.trim().to_string()))
    } else {
        Err(PotError::MalformedLine(line.to_string()))
    }
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
    fn ignores_malformed_and_blank_lines() {
        let map = parse_pot_contents("\nno_colon\n123:abc\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("123").unwrap(), "abc");
    }
}
