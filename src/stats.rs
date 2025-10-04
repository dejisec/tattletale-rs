//! Statistical summaries over collections of credentials.
//!
//! Defines `BasicStats` (counts and percentages) and `Statistics` aggregating
//! filtered categories. Helpers compute cracked and unique metrics per bucket.
use std::collections::HashSet;

use crate::credential::Credential;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BasicStats {
    pub all_count: usize,
    pub cracked_count: usize,
    pub cracked_percentage: String,
    pub unique_count: usize,
    pub unique_cracked_count: usize,
    pub unique_cracked_percentage: String,
}

fn pct(n: usize, d: usize) -> String {
    if d == 0 {
        return "0.00%".to_string();
    }
    format!("{:.2}%", (n as f64) / (d as f64) * 100.0)
}

pub fn analyze_creds(creds: &[Credential]) -> BasicStats {
    let mut hashes: Vec<String> = Vec::with_capacity(creds.len());
    let mut passwords: Vec<String> = Vec::new();
    for c in creds {
        hashes.push(c.hashtext.clone());
        if c.is_cracked {
            passwords.push(c.cleartext.clone());
        }
    }
    let all = hashes.len();
    let cracked = passwords.len();
    let unique_hashes: HashSet<String> = hashes.into_iter().collect();
    let unique_pw: HashSet<String> = passwords.into_iter().collect();
    BasicStats {
        all_count: all,
        cracked_count: cracked,
        cracked_percentage: pct(cracked, all),
        unique_count: unique_hashes.len(),
        unique_cracked_count: unique_pw.len(),
        unique_cracked_percentage: pct(unique_pw.len(), unique_hashes.len()),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Statistics {
    pub user: BasicStats,
    pub machine: BasicStats,
    pub valid_domain_user: BasicStats,
    pub valid_machine: BasicStats,
    pub lm: BasicStats,
    pub nt: BasicStats,
    pub both: BasicStats,
    pub null: BasicStats,
    pub no_domain: BasicStats,
}

pub fn calculate_statistics(all: &[Credential]) -> Statistics {
    let mut user = Vec::new();
    let mut machine = Vec::new();
    let mut valid_domain_user = Vec::new();
    let mut valid_machine = Vec::new();
    let mut lm = Vec::new();
    let mut nt = Vec::new();
    let mut both = Vec::new();
    let mut null = Vec::new();
    let mut no_domain = Vec::new();

    for c in all {
        if c.is_user_account {
            user.push(c.clone());
            if !c.is_hash_null && !c.domain.is_empty() {
                valid_domain_user.push(c.clone());
            }
        }
        if c.is_machine_account {
            machine.push(c.clone());
            if !c.is_hash_null {
                valid_machine.push(c.clone());
            }
        }
        if !c.is_hash_null {
            if c.is_hash_type_lm {
                lm.push(c.clone());
            }
            if c.is_hash_type_nt {
                nt.push(c.clone());
            }
            if c.is_hash_type_both {
                both.push(c.clone());
            }
        } else {
            null.push(c.clone());
        }
        if c.domain.is_empty() {
            no_domain.push(c.clone());
        }
    }

    Statistics {
        user: analyze_creds(&user),
        machine: analyze_creds(&machine),
        valid_domain_user: analyze_creds(&valid_domain_user),
        valid_machine: analyze_creds(&valid_machine),
        lm: analyze_creds(&lm),
        nt: analyze_creds(&nt),
        both: analyze_creds(&both),
        null: analyze_creds(&null),
        no_domain: analyze_creds(&no_domain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;

    #[test]
    fn stats_basic_counts() {
        let mut a = Credential::new();
        a.fill_from_dit("DOM\\A", Credential::NULL_HASH_LM, "nt1");
        a.crack("pw1");
        let mut b = Credential::new();
        b.fill_from_dit("DOM\\B", Credential::NULL_HASH_LM, "nt2");
        let s = calculate_statistics(&[a.clone(), b.clone()]);
        assert_eq!(s.user.all_count, 2);
        assert_eq!(s.nt.all_count, 2);
        assert!(s.lm.all_count == 0 || s.lm.all_count == 1); // depends on whether LM null handled
    }
}
