use crate::credential::Credential;

#[derive(Debug, thiserror::Error)]
pub enum DitError {
    #[error("malformed line: {0}")]
    MalformedLine(String),
}

pub fn parse_dit_line(line: &str) -> Result<Credential, DitError> {
    // Expected: username:user_id:LM_hash:NT_hash; allow extra fields, ignore after 4
    let mut parts = line.split(':');
    let username = parts
        .next()
        .ok_or_else(|| DitError::MalformedLine(line.to_string()))?
        .trim();
    let _user_id = parts
        .next()
        .ok_or_else(|| DitError::MalformedLine(line.to_string()))?;
    let lm = parts
        .next()
        .ok_or_else(|| DitError::MalformedLine(line.to_string()))?
        .trim();
    let nt = parts
        .next()
        .ok_or_else(|| DitError::MalformedLine(line.to_string()))?
        .trim();

    let mut c = Credential::new();
    c.fill_from_dit(username, lm, nt);
    Ok(c)
}

pub fn parse_dit_contents(contents: &str) -> Vec<Credential> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match parse_dit_line(trimmed) {
                Ok(c) => Some(c),
                Err(_) => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_line() {
        let line =
            "DOMAIN\\User:1111:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c";
        let c = parse_dit_line(line).unwrap();
        assert_eq!(c.sam_account_name, "User");
        assert_eq!(c.domain, "DOMAIN");
        assert!(c.is_hash_type_nt);
        assert!(!c.is_hash_type_lm);
    }

    #[test]
    fn skip_malformed_lines_in_bulk() {
        let contents =
            "\nINVALID\nDOMAIN\\A:1:x:y:z:extra\nDOMAIN\\B:2::31d6cfe0d16ae931b73c59d7e0c089c0\n";
        let creds = parse_dit_contents(contents);
        // B has null NT; LM empty counts as non-null, but we set flags accordingly
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].sam_account_name, "A");
        assert_eq!(creds[1].sam_account_name, "B");
    }
}
