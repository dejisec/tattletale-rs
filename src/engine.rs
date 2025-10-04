use std::collections::{HashMap, HashSet};

use crate::{credential::Credential, dit::parse_dit_contents, pot::parse_pot_contents, targets::parse_targets};

#[derive(Debug, Default)]
pub struct Engine {
	pub credentials: Vec<Credential>,
}

impl Engine {
	pub fn new() -> Self { Self { credentials: Vec::new() } }

	pub fn load_from_strings(&mut self, dits: &[&str], pots: &[&str], targets: &[&str]) {
		// Parse inputs
		let mut all_creds: Vec<Credential> = Vec::new();
		for d in dits { all_creds.extend(parse_dit_contents(d)); }
		let mut pot_merged: HashMap<String, String> = HashMap::new();
		for p in pots { pot_merged.extend(parse_pot_contents(p)); }
		let mut target_names: HashSet<String> = HashSet::new();
		for t in targets { for name in parse_targets(t) { target_names.insert(name.to_lowercase()); } }

		// Mark cracked
		for c in &mut all_creds {
			if let Some(pw) = pot_merged.get(&c.hashtext) { c.crack(pw); }
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
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn marks_cracked_and_targets_and_dedups() {
		let dit = "DOMAIN\\Admin:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\nDOMAIN\\User:2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
		let pot = "8846f7eaee8fb117ad06bdd830b7586c:password\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:letmein";
		let targets = "Admin\nUnused";

		let mut e = Engine::new();
		e.load_from_strings(&[dit], &[pot], &[targets]);
		assert_eq!(e.credentials.len(), 2);
		let admin = e.credentials.iter().find(|c| c.sam_account_name == "Admin").unwrap();
		assert!(admin.is_cracked);
		assert!(admin.is_target);
		assert_eq!(admin.cleartext, "password");
	}
}
