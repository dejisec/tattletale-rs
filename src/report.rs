//! Human-readable report rendering for terminal output.
//!
//! Produces a colored summary including overall statistics, high-value target
//! status, and shared hash groupings (both target-inclusive and overall).
use colored::*;

use crate::{
    engine::Engine,
    stats::{calculate_statistics, domains_breakdown, top_reused_passwords},
};

fn visible_len(s: &str) -> usize {
    // Strip ANSI escape sequences (\x1b[ ... m) to compute printable width
    let mut len = 0;
    let mut iter = s.chars().peekable();
    while let Some(ch) = iter.next() {
        if ch == '\u{1b}' {
            if let Some('[') = iter.peek().cloned() {
                let _ = iter.next();
            }
            for c in iter.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            len += 1;
        }
    }
    len
}

fn section_header(title: &str) -> String {
    let len = visible_len(title);
    let mut s = String::new();
    s.push('\n');
    s.push_str(title);
    s.push('\n');
    s.push_str(&"─".repeat(len));
    s.push_str("\n\n");
    s
}

pub fn render_summary(engine: &Engine) -> String {
    render_summary_with_top(engine, 10)
}

pub fn render_summary_with_top(engine: &Engine, top_n: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        "TattleTale: Domain Secrets (NTDS) Analysis Results"
            .bold()
            .cyan()
    ));

    // Password statistics
    let stats = calculate_statistics(&engine.credentials);
    let mut stats_lines: Vec<String> = Vec::new();
    stats_lines.push(format!("Total creds: {}", engine.credentials.len()));
    stats_lines.push(format!("All User Hashes: {}", stats.user.all_count));
    stats_lines.push(format!("All Machine Hashes: {}", stats.machine.all_count));
    stats_lines.push(format!("Removable Empty Hashes: {}", stats.null.all_count));
    stats_lines.push(format!("No-Domain Hashes: {}", stats.no_domain.all_count));
    stats_lines.push(format!(
        "Remaining User Hashes: {}",
        stats.valid_domain_user.all_count
    ));
    for (label, s) in [
        ("Valid Domain User", &stats.valid_domain_user),
        ("No Domain", &stats.no_domain),
        ("LM", &stats.lm),
        ("NT", &stats.nt),
    ] {
        stats_lines.push(label.bold().blue().to_string());
        stats_lines.push(format!("  All: {}", s.all_count));
        stats_lines.push(format!("  Cracked: {}", s.cracked_count));
        stats_lines.push(format!("  Cracked Percentage: {}", s.cracked_percentage));
        stats_lines.push(format!("  Unique: {}", s.unique_count));
        stats_lines.push(format!("  Cracked Unique: {}", s.unique_cracked_count));
        stats_lines.push(format!(
            "  Cracked Unique Percentage: {}",
            s.unique_cracked_percentage
        ));
    }
    out.push_str(&section_header(
        &"Password Hash Statistics".bold().yellow().to_string(),
    ));
    for line in stats_lines {
        out.push_str(&line);
        out.push('\n');
    }

    // High-Value Targets
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
    let mut hvt_lines: Vec<String> = Vec::new();
    if cracked_users.is_empty() && uncracked_users.is_empty() {
        hvt_lines.push("(No target files provided or no targets matched)".to_string());
    } else {
        hvt_lines.push(format!(
            "Cracked {}/{}",
            cracked_users.len(),
            cracked_users.len() + uncracked_users.len()
        ));
        for c in cracked_users {
            hvt_lines.push(format!("  {}: {}", c.down_level_logon_name, c.cleartext));
        }
        for c in uncracked_users {
            hvt_lines.push(format!(
                "  {}: {}",
                c.down_level_logon_name,
                "(Not cracked)".dimmed()
            ));
        }
    }
    out.push_str(&section_header(
        &"High-Value Targets".bold().cyan().to_string(),
    ));
    for line in hvt_lines {
        out.push_str(&line);
        out.push('\n');
    }

    // Shared Password Hashes (with at least 1 target)
    let title_with_target = "Shared Password Hashes (with at least 1 high-value target)"
        .bold()
        .cyan()
        .to_string();
    let mut shared: std::collections::HashMap<&str, Vec<&crate::credential::Credential>> =
        std::collections::HashMap::new();
    for c in &engine.credentials {
        if !c.is_hash_null && !c.hashtext.is_empty() {
            shared.entry(c.hashtext.as_str()).or_default().push(c);
        }
    }
    let mut any_with_target = false;
    let mut with_target_lines: Vec<String> = Vec::new();
    for (hash, creds) in shared.iter() {
        if creds.len() > 1 && creds.iter().any(|c| c.is_target) {
            any_with_target = true;
            let cracked_cleartext = creds
                .iter()
                .find(|c| c.is_cracked)
                .map(|c| c.cleartext.as_str());
            with_target_lines.push(match cracked_cleartext {
                Some(p) => format!("{} - {} ({} Accounts)", hash, p.red(), creds.len()),
                None => format!(
                    "{} - {} ({} Accounts)",
                    hash,
                    "(Not Cracked)".dimmed(),
                    creds.len()
                ),
            });
            let mut list = creds.clone();
            list.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
            for c in list {
                if c.is_target {
                    with_target_lines.push(format!(
                        "  {}: {}",
                        c.down_level_logon_name,
                        "(Target)".red()
                    ));
                } else {
                    with_target_lines.push(format!(
                        "  {}: {}",
                        c.down_level_logon_name,
                        "(Not a target)".dimmed()
                    ));
                }
            }
        }
    }
    if !any_with_target {
        with_target_lines.push("(No shared hashes with targets)".to_string());
    }
    out.push_str(&section_header(&title_with_target));
    for line in with_target_lines {
        out.push_str(&line);
        out.push('\n');
    }

    // Shared Password Hashes
    let mut any_shared = false;
    let mut shared_lines: Vec<String> = Vec::new();
    for (hash, creds) in shared.iter() {
        if creds.len() > 1 {
            any_shared = true;
            let cracked_cleartext = creds
                .iter()
                .find(|c| c.is_cracked)
                .map(|c| c.cleartext.as_str());
            shared_lines.push(match cracked_cleartext {
                Some(p) => format!("{} - {} ({} Accounts)", hash, p.red(), creds.len()),
                None => format!(
                    "{} - {} ({} Accounts)",
                    hash,
                    "(Not Cracked)".dimmed(),
                    creds.len()
                ),
            });
            let mut list = creds.clone();
            list.sort_by(|a, b| a.down_level_logon_name.cmp(&b.down_level_logon_name));
            for c in list {
                if c.is_target {
                    shared_lines.push(format!(
                        "  {}: {}",
                        c.down_level_logon_name,
                        "(Target)".red()
                    ));
                } else {
                    shared_lines.push(format!(
                        "  {}: {}",
                        c.down_level_logon_name,
                        "(Not a target)".dimmed()
                    ));
                }
            }
        }
    }
    if !any_shared {
        shared_lines.push("(No shared hashes)".to_string());
    }
    out.push_str(&section_header(
        &"Shared Password Hashes".bold().cyan().to_string(),
    ));
    for line in shared_lines {
        out.push_str(&line);
        out.push('\n');
    }

    // Domain Breakdown
    let mut domain_lines: Vec<String> = Vec::new();
    let mut by_domain = domains_breakdown(&engine.credentials)
        .into_iter()
        .collect::<Vec<(String, crate::stats::BasicStats)>>();
    by_domain.sort_by(|a, b| a.0.cmp(&b.0));
    if by_domain.is_empty() {
        domain_lines.push("(No domains)".to_string());
    } else {
        for (dom, s) in by_domain {
            domain_lines.push(format!("{}", dom.bold().green()));
            domain_lines.push(format!("  All: {}", s.all_count));
            domain_lines.push(format!("  Cracked: {}", s.cracked_count));
            domain_lines.push(format!("  Cracked Percentage: {}", s.cracked_percentage));
            domain_lines.push(format!("  Unique: {}", s.unique_count));
            domain_lines.push(format!("  Cracked Unique: {}", s.unique_cracked_count));
            domain_lines.push(format!(
                "  Cracked Unique Percentage: {}",
                s.unique_cracked_percentage
            ));
        }
    }
    out.push_str(&section_header(
        &"Domain Breakdown".bold().cyan().to_string(),
    ));
    for line in domain_lines {
        out.push_str(&line);
        out.push('\n');
    }

    // Top Reused Passwords
    let mut top_lines: Vec<String> = Vec::new();
    let top = top_reused_passwords(&engine.credentials, top_n);
    if top.is_empty() {
        top_lines.push("(No cracked passwords)".to_string());
    } else {
        for (pw, count) in top {
            top_lines.push(format!("  {}: {}", pw, count));
        }
    }
    out.push_str(&section_header(
        &"Top Reused Passwords".bold().magenta().to_string(),
    ));
    for line in top_lines {
        out.push_str(&line);
        out.push('\n');
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

    #[test]
    fn top_reused_respects_limit() {
        let mut e = Engine::new();
        // three creds, two with password "pw", one with "other"
        let dit = "DOM\\A:1:aad3b435b51404eeaad3b435b51404ee:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nDOM\\B:2:aad3b435b51404eeaad3b435b51404ee:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nDOM\\C:3:aad3b435b51404eeaad3b435b51404ee:cccccccccccccccccccccccccccccccc";
        let pot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:pw\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:pw\ncccccccccccccccccccccccccccccccc:other";
        e.load_from_strings(&[dit], &[pot], &[]);
        let s = super::render_summary_with_top(&e, 1);
        assert!(s.contains("Top Reused Passwords"));
        assert!(s.contains("pw: 2"));
        assert!(!s.contains("other: 1"));
    }
}
