//! Parser for target lists.
//!
//! Accepts any non-empty trimmed line as a target name. Case-insensitive
//! matching is applied later by the `engine` when tagging credentials.
pub fn parse_targets(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_ignores_blank() {
        let v = parse_targets("\nAdmin\n \n DA \n");
        assert_eq!(v, vec!["Admin", "DA"]);
    }
}
