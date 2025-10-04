//! Human-readable report rendering for terminal output.
//!
//! Produces a colored summary including overall statistics, high-value target
//! status, and shared hash groupings (both target-inclusive and overall).
use colored::*;

use crate::{engine::Engine, stats::calculate_statistics};

pub fn render_summary(engine: &Engine) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        "TattleTale: Domain Secrets (NTDS) Analysis Results".bold()
    ));
    out.push_str(&format!("{}\n", "Password Hash Statistics".bold()));
    let stats = calculate_statistics(&engine.credentials);
    out.push_str(&format!("Total creds: {}\n", engine.credentials.len()));
    out.push_str(&format!("All User Hashes: {}\n", stats.user.all_count));
    out.push_str(&format!(
        "All Machine Hashes: {}\n",
        stats.machine.all_count
    ));
    out.push_str(&format!(
        "Removable Empty Hashes: {}\n",
        stats.null.all_count
    ));
    out.push_str(&format!(
        "No-Domain Hashes: {}\n",
        stats.no_domain.all_count
    ));
    out.push_str(&format!(
        "Remaining User Hashes: {}\n",
        stats.valid_domain_user.all_count
    ));
    out.push('\n');
    for (label, s) in [
        ("Valid Domain User", &stats.valid_domain_user),
        ("No Domain", &stats.no_domain),
        ("LM", &stats.lm),
        ("NT", &stats.nt),
    ] {
        out.push_str(&format!("{}\n", label.bold()));
        out.push_str(&format!("  All: {}\n", s.all_count));
        out.push_str(&format!("  Cracked: {}\n", s.cracked_count));
        out.push_str(&format!("  Cracked Percentage: {}\n", s.cracked_percentage));
        out.push_str(&format!("  Unique: {}\n", s.unique_count));
        out.push_str(&format!("  Cracked Unique: {}\n", s.unique_cracked_count));
        out.push_str(&format!(
            "  Cracked Unique Percentage: {}\n",
            s.unique_cracked_percentage
        ));
    }

    // High-Value Targets
    out.push('\n');
    out.push_str(&format!("{}\n", "High-Value Targets".bold()));
    let mut cracked_users: Vec<_> = engine
        .credentials
        .iter()
        .filter(|c| c.is_target && c.is_cracked)
        .collect();
    let mut uncracked_users: Vec<_> = engine
        .credentials
        .iter()
        .filter(|c| c.is_target && !c.is_cracked)
        .collect();
    cracked_users.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
    uncracked_users.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
    if cracked_users.is_empty() && uncracked_users.is_empty() {
        out.push_str("(No target files provided or no targets matched)\n");
    } else {
        out.push_str(&format!(
            "Cracked {}/{}\n",
            cracked_users.len(),
            cracked_users.len() + uncracked_users.len()
        ));
        for c in cracked_users {
            out.push_str(&format!("  {}: {}\n", c.down_level_logon_name, c.cleartext));
        }
        for c in uncracked_users {
            out.push_str(&format!("  {}: (Not cracked)\n", c.down_level_logon_name));
        }
    }

    // Shared Password Hashes (with at least 1 target)
    out.push('\n');
    out.push_str(&format!(
        "{}\n",
        "Shared Password Hashes (with at least 1 high-value target)".bold()
    ));
    let mut shared: std::collections::HashMap<&str, Vec<&crate::credential::Credential>> =
        std::collections::HashMap::new();
    for c in &engine.credentials {
        if !c.is_hash_null && !c.hashtext.is_empty() {
            shared.entry(c.hashtext.as_str()).or_default().push(c);
        }
    }
    let mut any_with_target = false;
    for (hash, creds) in shared.iter() {
        if creds.len() > 1 && creds.iter().any(|c| c.is_target) {
            any_with_target = true;
            let cracked_cleartext = creds
                .iter()
                .find(|c| c.is_cracked)
                .map(|c| c.cleartext.as_str());
            match cracked_cleartext {
                Some(p) => out.push_str(&format!(
                    "{} - {} ({} Accounts)\n",
                    hash,
                    p.red(),
                    creds.len()
                )),
                None => out.push_str(&format!(
                    "{} - (Not Cracked) ({} Accounts)\n",
                    hash,
                    creds.len()
                )),
            }
            let mut list = creds.clone();
            list.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
            for c in list {
                if c.is_target {
                    out.push_str(&format!(
                        "  {}: {}\n",
                        c.down_level_logon_name,
                        "(Target)".red()
                    ));
                } else {
                    out.push_str(&format!("  {}: (Not a target)\n", c.down_level_logon_name));
                }
            }
        }
    }
    if !any_with_target {
        out.push_str("(No shared hashes with targets)\n");
    }

    // Shared Password Hashes
    out.push('\n');
    out.push_str(&format!("{}\n", "Shared Password Hashes".bold()));
    let mut any_shared = false;
    for (hash, creds) in shared.iter() {
        if creds.len() > 1 {
            any_shared = true;
            let cracked_cleartext = creds
                .iter()
                .find(|c| c.is_cracked)
                .map(|c| c.cleartext.as_str());
            match cracked_cleartext {
                Some(p) => out.push_str(&format!(
                    "{} - {} ({} Accounts)\n",
                    hash,
                    p.red(),
                    creds.len()
                )),
                None => out.push_str(&format!(
                    "{} - (Not Cracked) ({} Accounts)\n",
                    hash,
                    creds.len()
                )),
            }
            let mut list = creds.clone();
            list.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
            for c in list {
                if c.is_target {
                    out.push_str(&format!(
                        "  {}: {}\n",
                        c.down_level_logon_name,
                        "(Target)".red()
                    ));
                } else {
                    out.push_str(&format!("  {}: (Not a target)\n", c.down_level_logon_name));
                }
            }
        }
    }
    if !any_shared {
        out.push_str("(No shared hashes)\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn snapshot_summary() {
        let mut e = Engine::new();
        let dit = "DOM\\A:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c";
        let pot = "8846f7eaee8fb117ad06bdd830b7586c:pw";
        e.load_from_strings(&[dit], &[pot], &[]);
        let s = render_summary(&e);
        insta::assert_snapshot!(s);
    }
}
