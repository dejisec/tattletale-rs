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
        writeln!(
            f,
            "DOM\\Admin:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        )
        .unwrap();
        writeln!(
            f,
            "DOM\\User:2:aad3b435b51404eeaad3b435b51404ee:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        .unwrap();
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
    cmd.arg("-d")
        .arg(&dit_path)
        .arg("-p")
        .arg(&pot_path)
        .arg("-t")
        .arg(&tgt_path)
        .arg("-o")
        .arg(&outdir);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Password Hash Statistics"));

    let files: Vec<_> = fs::read_dir(&outdir).unwrap().collect();
    assert!(files.len() >= 2);
}

#[test]
fn mmap_threshold_and_streaming_works() {
    let tmp = tempdir().unwrap();
    let dit_path = tmp.path().join("ntds_big.txt");
    let pot_path = tmp.path().join("hashcat_big.potfile");
    let tgt_path = tmp.path().join("targets_big.txt");

    // Create files larger than a tiny mmap threshold to force mmap path
    let force_threshold: u64 = 32; // 32 bytes
    {
        let mut f = fs::File::create(&dit_path).unwrap();
        for _ in 0..10 {
            writeln!(
                f,
                "DOM\\U:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
            )
            .unwrap();
        }
    }
    {
        let mut f = fs::File::create(&pot_path).unwrap();
        writeln!(f, "8846f7eaee8fb117ad06bdd830b7586c:pw").unwrap();
    }
    {
        let mut f = fs::File::create(&tgt_path).unwrap();
        writeln!(f, "U").unwrap();
    }

    // Use library engine API directly to verify streaming+mmap produces cracked creds
    let mut e = tattletale::engine::Engine::new();
    let _ = e.load_from_file_paths_with_threshold(
        &[&dit_path],
        &[&pot_path],
        &[&tgt_path],
        force_threshold,
    );
    assert!(e.credentials.iter().all(|c| c.is_cracked));
}

#[test]
fn missing_dit_file_causes_non_zero_exit() {
    let tmp = tempdir().unwrap();
    let missing_dit = tmp.path().join("missing-ntds.txt");
    let mut cmd = Command::cargo_bin("tattletale").unwrap();
    cmd.arg("-d").arg(&missing_dit);
    cmd.assert().failure();
}

#[test]
fn missing_potfile_warns_but_succeeds() {
    let tmp = tempdir().unwrap();
    let dit_path = tmp.path().join("ntds.txt");
    let outdir = tmp.path().join("out");
    {
        let mut f = fs::File::create(&dit_path).unwrap();
        writeln!(
            f,
            "DOM\\U:1:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        .unwrap();
    }
    let mut cmd = Command::cargo_bin("tattletale").unwrap();
    cmd.arg("-d")
        .arg(&dit_path)
        .arg("-p")
        .arg(outdir.join("doesnotexist.pot"));
    cmd.assert().success();
}

#[test]
fn export_failure_causes_non_zero_exit() {
    let tmp = tempdir().unwrap();
    let dit_path = tmp.path().join("ntds.txt");
    {
        let mut f = fs::File::create(&dit_path).unwrap();
        writeln!(
            f,
            "DOM\\U:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        )
        .unwrap();
    }
    let pot_path = tmp.path().join("hashcat.potfile");
    {
        let mut f = fs::File::create(&pot_path).unwrap();
        writeln!(f, "8846f7eaee8fb117ad06bdd830b7586c:pw").unwrap();
    }
    let outdir = tmp.path().join("out");
    // Provide a file path instead of directory to cause export create_dir_all to fail later
    fs::write(&outdir, b"not a dir").unwrap();
    let mut cmd = Command::cargo_bin("tattletale").unwrap();
    cmd.arg("-d")
        .arg(&dit_path)
        .arg("-p")
        .arg(&pot_path)
        .arg("-o")
        .arg(&outdir);
    cmd.assert().failure();
}

#[test]
fn e2e_runs_and_writes_outputs_parallel() {
    let tmp = tempdir().unwrap();
    let dit_path1 = tmp.path().join("ntds1.txt");
    let dit_path2 = tmp.path().join("ntds2.txt");
    let pot_path = tmp.path().join("hashcat.potfile");
    let tgt_path = tmp.path().join("targets.txt");
    let outdir = tmp.path().join("out");
    fs::create_dir_all(&outdir).unwrap();

    {
        let mut f1 = fs::File::create(&dit_path1).unwrap();
        writeln!(
            f1,
            "DOM\\Admin:1:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        )
        .unwrap();
        let mut f2 = fs::File::create(&dit_path2).unwrap();
        writeln!(
            f2,
            "DOM\\User:2:aad3b435b51404eeaad3b435b51404ee:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        .unwrap();
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
    cmd.arg("-d")
        .arg(&dit_path1)
        .arg("-d")
        .arg(&dit_path2)
        .arg("-p")
        .arg(&pot_path)
        .arg("-t")
        .arg(&tgt_path)
        .arg("--parallel")
        .arg("-o")
        .arg(&outdir);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Password Hash Statistics"));

    let files: Vec<_> = fs::read_dir(&outdir).unwrap().collect();
    assert!(files.len() >= 2);
}
