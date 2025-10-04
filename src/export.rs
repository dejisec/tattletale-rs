//! Export helpers for writing results to CSV and plain text files.
//!
//! - `save_shared_hashes_csv` writes pairs of (hash, username) only for hashes
//!   shared by more than one account.
//! - `save_user_pass_txt` writes `DOMAIN\\User:cleartext` for cracked entries.
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use csv::Writer;

use crate::engine::Engine;

pub fn save_shared_hashes_csv<P: AsRef<Path>>(engine: &Engine, path: P) -> Result<()> {
    let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for c in &engine.credentials {
        if !c.is_hash_null && !c.hashtext.is_empty() {
            map.entry(c.hashtext.clone())
                .or_default()
                .push(c.down_level_logon_name.clone());
        }
    }
    let mut wtr = Writer::from_path(path)?;
    wtr.write_record(["Hash", "Username"])?;
    for (hash, users) in map.into_iter() {
        if users.len() > 1 {
            for u in users {
                wtr.write_record([hash.as_str(), u.as_str()])?;
            }
        }
    }
    wtr.flush()?;
    Ok(())
}

pub fn save_user_pass_txt<P: AsRef<Path>>(engine: &Engine, path: P) -> Result<()> {
    let mut f = File::create(path)?;
    for c in &engine.credentials {
        if c.is_cracked {
            writeln!(f, "{}:{}", c.down_level_logon_name, c.cleartext)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use tempfile::tempdir;

    #[test]
    fn writes_csv_and_txt() {
        let mut e = Engine::new();
        let dit = "DOM\\A:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nDOM\\B:2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let pot = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:pw";
        e.load_from_strings(&[dit], &[pot], &[]);
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("shared.csv");
        let txt_path = dir.path().join("userpass.txt");
        save_shared_hashes_csv(&e, &csv_path).unwrap();
        save_user_pass_txt(&e, &txt_path).unwrap();
        let csv_content = std::fs::read_to_string(csv_path).unwrap();
        let txt_content = std::fs::read_to_string(txt_path).unwrap();
        assert!(csv_content.contains("Hash,Username"));
        assert!(csv_content.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(txt_content.contains("DOM\\A:pw"));
        assert!(txt_content.contains("DOM\\B:pw"));
    }
}
