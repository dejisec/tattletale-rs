use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn e2e_runs_and_writes_outputs() {
	let tmp = tempdir().unwrap();
	let dit_path = tmp.path().join("ntds.txt");
	let pot_path = tmp.path().join("hashcat.potfile");
	let tgt_path = tmp.path().join("targets.txt");
	let outdir = tmp.path().join("out");
	fs::create_dir_all(&outdir).unwrap();

	{
		let mut f = fs::File::create(&dit_path).unwrap();
		writeln!(f, "DOM\\Admin:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c").unwrap();
		writeln!(f, "DOM\\User:2:aad3b435b51404eeaad3b435b51404ee:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
	}
	{
		let mut f = fs::File::create(&pot_path).unwrap();
		writeln!(f, "8846f7eaee8fb117ad06bdd830b7586c:Password1!").unwrap();
		writeln!(f, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:P@ssw0rd").unwrap();
	}
	{
		let mut f = fs::File::create(&tgt_path).unwrap();
		writeln!(f, "Admin").unwrap();
	}

	let mut cmd = Command::cargo_bin("tattletale").unwrap();
	cmd.arg("-d").arg(&dit_path)
		.arg("-p").arg(&pot_path)
		.arg("-t").arg(&tgt_path)
		.arg("-o").arg(&outdir);
	cmd.assert()
		.success()
		.stdout(predicate::str::contains("Password Hash Statistics"));

	let files: Vec<_> = fs::read_dir(&outdir).unwrap().collect();
	assert!(files.len() >= 2);
}
