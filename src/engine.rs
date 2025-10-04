//! Engine: orchestrates parsing inputs, merging potfiles, deduplicating
//! credentials, and marking targets. Provides streaming file-based loaders with
//! optional memory-mapped I/O for performance on large inputs.
//!
//! Typical usage:
//!
//! ```no_run
//! use tattletale::engine::Engine;
//! # fn main() -> anyhow::Result<()> {
//! let mut engine = Engine::new();
//! engine.load_from_file_paths(&["/path/to/ntds.txt"], &[], &[])?;
//! println!("{}", tattletale::report::render_summary(&engine));
//! # Ok(())
//! # }
//! ```
use std::collections::{HashMap, HashSet};

use crate::dit::parse_dit_line;
use crate::io::{DEFAULT_MMAP_THRESHOLD_BYTES, iter_lines_auto};
use crate::{
    credential::Credential, dit::parse_dit_contents, pot::parse_pot_contents,
    targets::parse_targets,
};
use anyhow::Result;
use std::path::Path;

/// Aggregates parsed credentials and exposes loading helpers.
#[derive(Debug, Default)]
pub struct Engine {
    pub credentials: Vec<Credential>,
}

impl Engine {
    /// Create an empty engine with no loaded credentials.
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    /// Load inputs already in-memory. Intended for tests and small programmatic
    /// integrations. Performs cracking, deduplication, and target marking.
    pub fn load_from_strings(&mut self, dits: &[&str], pots: &[&str], targets: &[&str]) {
        // Parse inputs
        let mut all_creds: Vec<Credential> = Vec::new();
        for d in dits {
            all_creds.extend(parse_dit_contents(d));
        }
        let mut pot_merged: HashMap<String, String> = HashMap::new();
        for p in pots {
            pot_merged.extend(parse_pot_contents(p));
        }
        let mut target_names: HashSet<String> = HashSet::new();
        for t in targets {
            for name in parse_targets(t) {
                target_names.insert(name.to_lowercase());
            }
        }

        // Mark cracked
        for c in &mut all_creds {
            if let Some(pw) = pot_merged.get(&c.hashtext) {
                c.crack(pw);
            }
        }

        // Dedup using Hash + Eq
        let set: HashSet<Credential> = all_creds.into_iter().collect();
        self.credentials = set.into_iter().collect();

        // Mark targets by sam account name (case-insensitive)
        for c in &mut self.credentials {
            if target_names.contains(&c.sam_account_name.to_lowercase()) {
                c.is_target = true;
            }
        }
    }

    /// Streamingly load from file paths using line iterators and optional mmap.
    /// Parses DIT, POT, and Target files in a memory-efficient way.
    pub fn load_from_file_paths_with_threshold<P: AsRef<Path>>(
        &mut self,
        dit_paths: &[P],
        pot_paths: &[P],
        target_paths: &[P],
        mmap_threshold_bytes: u64,
    ) -> Result<()> {
        use std::collections::{HashMap, HashSet};
        let mut all_creds: Vec<Credential> = Vec::new();
        // DIT: parse line-by-line
        for p in dit_paths {
            let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
            for line in iter.flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(c) = parse_dit_line(trimmed) {
                    all_creds.push(c);
                }
            }
        }
        // POT: merge to hashmap
        let mut pot_merged: HashMap<String, String> = HashMap::new();
        for p in pot_paths {
            let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
            for line in iter.flatten() {
                let s = line.trim();
                if s.is_empty() {
                    continue;
                }
                if let Ok((h, pw)) = crate::pot::parse_pot_line(s) {
                    pot_merged.insert(h, pw);
                }
            }
        }
        // Targets: collect names lowercase
        let mut target_names: HashSet<String> = HashSet::new();
        for p in target_paths {
            let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
            for line in iter.flatten() {
                let name = line.trim();
                if !name.is_empty() {
                    target_names.insert(name.to_lowercase());
                }
            }
        }
        // Crack
        for c in &mut all_creds {
            if let Some(pw) = pot_merged.get(&c.hashtext) {
                c.crack(pw);
            }
        }
        // Dedup and mark targets
        let set: std::collections::HashSet<Credential> = all_creds.into_iter().collect();
        self.credentials = set.into_iter().collect();
        for c in &mut self.credentials {
            if target_names.contains(&c.sam_account_name.to_lowercase()) {
                c.is_target = true;
            }
        }
        Ok(())
    }

    /// Convenience wrapper that uses the default mmap threshold.
    pub fn load_from_file_paths<P: AsRef<Path>>(
        &mut self,
        dit_paths: &[P],
        pot_paths: &[P],
        target_paths: &[P],
    ) -> Result<()> {
        self.load_from_file_paths_with_threshold(
            dit_paths,
            pot_paths,
            target_paths,
            DEFAULT_MMAP_THRESHOLD_BYTES,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_cracked_and_targets_and_dedups() {
        let dit = "DOMAIN\\Admin:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\nDOMAIN\\User:2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let pot =
            "8846f7eaee8fb117ad06bdd830b7586c:password\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:letmein";
        let targets = "Admin\nUnused";

        let mut e = Engine::new();
        e.load_from_strings(&[dit], &[pot], &[targets]);
        assert_eq!(e.credentials.len(), 2);
        let admin = e
            .credentials
            .iter()
            .find(|c| c.sam_account_name == "Admin")
            .unwrap();
        assert!(admin.is_cracked);
        assert!(admin.is_target);
        assert_eq!(admin.cleartext, "password");
    }
}
