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
    /// Optional counts collected during parsing
    pub parse_stats: Option<ParseStats>,
}

impl Engine {
    /// Create an empty engine with no loaded credentials.
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            parse_stats: None,
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
        // clear parse stats for string-based path
        self.parse_stats = None;
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
        let mut dit_malformed = 0usize;
        for p in dit_paths {
            let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
            for line in iter.flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(c) = parse_dit_line(trimmed) {
                    all_creds.push(c);
                } else {
                    dit_malformed += 1;
                }
            }
        }
        // POT: merge to hashmap
        let mut pot_merged: HashMap<String, String> = HashMap::new();
        let mut pot_malformed = 0usize;
        for p in pot_paths {
            let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
            for line in iter.flatten() {
                let s = line.trim();
                if s.is_empty() {
                    continue;
                }
                if let Ok((h, pw)) = crate::pot::parse_pot_line(s) {
                    pot_merged.insert(h, pw);
                } else {
                    pot_malformed += 1;
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
        self.parse_stats = Some(ParseStats { dit_malformed, pot_malformed });
        Ok(())
    }

    /// Parallel variant of `load_from_file_paths_with_threshold`.
    /// Parses DIT, POT, and Target files concurrently across files to leverage
    /// multiple cores, then performs the same cracking, deduplication, and target
    /// tagging as the sequential version.
    pub fn load_from_file_paths_parallel_with_threshold<P: AsRef<Path> + Send + Sync>(
        &mut self,
        dit_paths: &[P],
        pot_paths: &[P],
        target_paths: &[P],
        mmap_threshold_bytes: u64,
    ) -> Result<()> {
        use crate::io::iter_lines_auto;
        use rayon::prelude::*;

        // DIT: parse lines per file in parallel, then flatten
        let dit_malformed = std::sync::atomic::AtomicUsize::new(0);
        let all_creds: Vec<Credential> = dit_paths
            .par_iter()
            .map(|p| -> Result<Vec<Credential>> {
                let mut v = Vec::new();
                let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
                for line in iter.flatten() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match crate::dit::parse_dit_line(trimmed) {
                        Ok(c) => v.push(c),
                        Err(_) => {
                            dit_malformed.fetch_add(
                                1,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                    }
                }
                Ok(v)
            })
            .try_reduce(Vec::new, |mut acc, mut next| {
                acc.append(&mut next);
                Ok(acc)
            })?;

        // POT: merge maps in parallel
        let pot_malformed = std::sync::atomic::AtomicUsize::new(0);
        let pot_vecs: Vec<Vec<(String, String)>> = pot_paths
            .par_iter()
            .map(|p| -> Result<Vec<(String, String)>> {
                let mut v = Vec::new();
                let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
                for line in iter.flatten() {
                    let s = line.trim();
                    if s.is_empty() {
                        continue;
                    }
                    match crate::pot::parse_pot_line(s) {
                        Ok((h, pw)) => v.push((h, pw)),
                        Err(_) => {
                            pot_malformed.fetch_add(
                                1,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                    }
                }
                Ok(v)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut pot_merged: HashMap<String, String> = HashMap::new();
        for v in pot_vecs {
            for (h, pw) in v {
                pot_merged.insert(h, pw);
            }
        }

        // Targets: collect names lowercase in parallel
        let target_sets: Vec<HashSet<String>> = target_paths
            .par_iter()
            .map(|p| -> Result<HashSet<String>> {
                let mut s = HashSet::new();
                let iter = iter_lines_auto(p, mmap_threshold_bytes)?;
                for line in iter.flatten() {
                    let name = line.trim();
                    if !name.is_empty() {
                        s.insert(name.to_lowercase());
                    }
                }
                Ok(s)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut target_names: HashSet<String> = HashSet::new();
        for s in target_sets {
            target_names.extend(s);
        }

        // Crack
        let mut cracked = all_creds;
        for c in &mut cracked {
            if let Some(pw) = pot_merged.get(&c.hashtext) {
                c.crack(pw);
            }
        }

        // Dedup and mark targets
        let set: std::collections::HashSet<Credential> = cracked.into_iter().collect();
        self.credentials = set.into_iter().collect();
        for c in &mut self.credentials {
            if target_names.contains(&c.sam_account_name.to_lowercase()) {
                c.is_target = true;
            }
        }
        self.parse_stats = Some(ParseStats {
            dit_malformed: dit_malformed.load(std::sync::atomic::Ordering::Relaxed),
            pot_malformed: pot_malformed.load(std::sync::atomic::Ordering::Relaxed),
        });
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

/// Counts of malformed/ignored lines encountered during parsing.
#[derive(Debug, Default, Clone, Copy)]
pub struct ParseStats {
    pub dit_malformed: usize,
    pub pot_malformed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    #[test]
    fn parallel_loader_matches_sequential_results() {
        let tmp = tempdir().unwrap();
        let dit1 = tmp.path().join("a.txt");
        let dit2 = tmp.path().join("b.txt");
        let pot = tmp.path().join("pot.txt");
        let tgt = tmp.path().join("targets.txt");

        std::fs::write(
            &dit1,
            "DOM\\A:1:aad3b435b51404eeaad3b435b51404ee:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        std::fs::write(
            &dit2,
            "DOM\\B:2:aad3b435b51404eeaad3b435b51404ee:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();
        std::fs::write(
            &pot,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:pw1\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:pw2\n",
        )
        .unwrap();
        std::fs::write(&tgt, "A\n").unwrap();

        let mut e_seq = Engine::new();
        e_seq
            .load_from_file_paths_with_threshold(&[&dit1, &dit2], &[&pot], &[&tgt], 0)
            .unwrap();

        let mut e_par = Engine::new();
        // new API to be implemented
        e_par
            .load_from_file_paths_parallel_with_threshold(&[&dit1, &dit2], &[&pot], &[&tgt], 0)
            .unwrap();

        // Same number of creds and same cracked/target counts
        assert_eq!(e_seq.credentials.len(), e_par.credentials.len());
        let seq_cracked = e_seq.credentials.iter().filter(|c| c.is_cracked).count();
        let par_cracked = e_par.credentials.iter().filter(|c| c.is_cracked).count();
        assert_eq!(seq_cracked, par_cracked);
        let seq_targets = e_seq.credentials.iter().filter(|c| c.is_target).count();
        let par_targets = e_par.credentials.iter().filter(|c| c.is_target).count();
        assert_eq!(seq_targets, par_targets);
    }
}
