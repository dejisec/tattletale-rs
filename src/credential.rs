//! Credential data model and helpers for parsing user/machine accounts from
//! NTDS export lines, tracking hash types (LM/NT/both/null), crack status, and
//! target flags.
//!
//! Instances of `Credential` are deduplicated by `down_level_logon_name` and
//! effective `hashtext` within the `engine` orchestrator.
//!
//! Use [`Credential::fill_from_dit`] to populate a credential from a DIT line
//! and [`Credential::crack`] to set the cleartext when present in potfiles.
#[derive(Debug, Clone, Eq)]
/// Represents a parsed account entry with associated hash metadata and state.
pub struct Credential {
    pub down_level_logon_name: String,
    pub sam_account_name: String,
    pub user_principal_name: String,
    pub is_user_account: bool,
    pub is_machine_account: bool,
    pub domain: String,
    pub domain_netbios: String,
    pub hashtext: String,
    pub cleartext: String,
    pub lm_hashtext: String,
    pub nt_hashtext: String,
    pub is_target: bool,
    pub target_filenames: Vec<String>,
    pub is_hash_type_lm: bool,
    pub is_hash_type_nt: bool,
    pub is_hash_type_both: bool,
    pub is_hash_null: bool,
    pub is_cracked: bool,
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.down_level_logon_name == other.down_level_logon_name && self.hashtext == other.hashtext
    }
}

impl std::hash::Hash for Credential {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        format!("{}:{}", self.down_level_logon_name, self.hashtext).hash(state);
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

impl Credential {
    /// Well-known null LM hash value.
    pub const NULL_HASH_LM: &'static str = "aad3b435b51404eeaad3b435b51404ee";
    /// Well-known null NT hash value.
    pub const NULL_HASH_NT: &'static str = "31d6cfe0d16ae931b73c59d7e0c089c0";

    /// Construct an empty credential with sensible defaults.
    pub fn new() -> Self {
        Self {
            down_level_logon_name: String::new(),
            sam_account_name: String::new(),
            user_principal_name: String::new(),
            is_user_account: true,
            is_machine_account: false,
            domain: String::new(),
            domain_netbios: String::new(),
            hashtext: String::new(),
            cleartext: String::new(),
            lm_hashtext: String::new(),
            nt_hashtext: String::new(),
            is_target: false,
            target_filenames: Vec::new(),
            is_hash_type_lm: false,
            is_hash_type_nt: false,
            is_hash_type_both: false,
            is_hash_null: false,
            is_cracked: false,
        }
    }

    /// Populate identity fields from a `DOMAIN\\User` or `User` value.
    pub fn fill_with_username(&mut self, username: &str) {
        self.down_level_logon_name = username.to_string();
        self.is_machine_account = self.down_level_logon_name.trim_end().ends_with('$');
        self.is_user_account = !self.is_machine_account;

        let parts: Vec<&str> = self.down_level_logon_name.split('\\').collect();
        if parts.len() > 1 {
            self.domain = parts[0].trim().to_string();
            self.sam_account_name = parts[1].trim().to_string();
        } else {
            self.sam_account_name = self.down_level_logon_name.clone();
        }
        self.user_principal_name = if !self.domain.is_empty() {
            format!("{}@{}", self.sam_account_name, self.domain)
        } else {
            self.sam_account_name.clone()
        };
    }

    /// Populate fields derived from a DIT export line parts. Determines user/
    /// machine flags, domain components, and hash type flags, and sets the
    /// effective `hashtext` to the non-null LM/NT value (NT wins if both).
    pub fn fill_from_dit(
        &mut self,
        down_level_logon_name: &str,
        lm_hashtext: &str,
        nt_hashtext: &str,
    ) {
        self.down_level_logon_name = down_level_logon_name.to_string();
        self.lm_hashtext = lm_hashtext.to_string();
        self.nt_hashtext = nt_hashtext.to_string();

        self.is_machine_account = self.down_level_logon_name.trim_end().ends_with('$');
        self.is_user_account = !self.is_machine_account;

        let parts: Vec<&str> = self.down_level_logon_name.split('\\').collect();
        if parts.len() > 1 {
            self.domain = parts[0].trim().to_string();
            self.sam_account_name = parts[1].trim().to_string();
        } else {
            self.sam_account_name = self.down_level_logon_name.clone();
        }
        self.user_principal_name = if !self.domain.is_empty() {
            format!("{}@{}", self.sam_account_name, self.domain)
        } else {
            self.sam_account_name.clone()
        };

        if self.lm_hashtext == Self::NULL_HASH_LM && self.nt_hashtext == Self::NULL_HASH_NT {
            self.is_hash_null = true;
        }
        if self.lm_hashtext != Self::NULL_HASH_LM {
            self.is_hash_type_lm = true;
            self.is_hash_null = false;
            self.hashtext = self.lm_hashtext.clone();
        }
        if self.nt_hashtext != Self::NULL_HASH_NT {
            self.is_hash_type_nt = true;
            self.is_hash_null = false;
            self.hashtext = self.nt_hashtext.clone();
        }
        if self.is_hash_type_lm && self.is_hash_type_nt {
            self.is_hash_type_both = true;
        }
    }

    /// Record cracked password cleartext and set `is_cracked` if non-empty.
    pub fn crack(&mut self, cleartext: &str) {
        self.cleartext = cleartext.to_string();
        if !self.cleartext.is_empty() {
            self.is_cracked = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_with_username_sets_flags_and_names() {
        let mut c = Credential::new();
        c.fill_with_username("DOMAIN\\Alice");
        assert!(c.is_user_account);
        assert!(!c.is_machine_account);
        assert_eq!(c.domain, "DOMAIN");
        assert_eq!(c.sam_account_name, "Alice");
        assert_eq!(c.user_principal_name, "Alice@DOMAIN");
    }

    #[test]
    fn machine_account_detection() {
        let mut c = Credential::new();
        c.fill_with_username("DOMAIN\\HOST$");
        assert!(c.is_machine_account);
        assert!(!c.is_user_account);
    }

    #[test]
    fn fill_from_dit_sets_hash_types_and_null() {
        let mut c = Credential::new();
        c.fill_from_dit(
            "DOMAIN\\Bob",
            Credential::NULL_HASH_LM,
            "8846f7eaee8fb117ad06bdd830b7586c",
        );
        assert!(c.is_hash_type_nt);
        assert!(!c.is_hash_type_lm);
        assert_eq!(c.hashtext, "8846f7eaee8fb117ad06bdd830b7586c");
        assert!(!c.is_hash_null);
    }

    #[test]
    fn crack_sets_is_cracked_when_nonempty() {
        let mut c = Credential::new();
        c.crack("");
        assert!(!c.is_cracked);
        c.crack("Password1!");
        assert!(c.is_cracked);
    }
}
