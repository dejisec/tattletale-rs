# tattletale-rs

Rust port of the [TattleTale](https://github.com/coryavra/tattletale) NTDS dump reporter. Parses NTDS export lines, hashcat potfiles, and target lists to produce a summary and optional exports.

## Install

```bash
cargo build --release
```

## Usage

```bash
  tattletale \
  -d /path/to/ntds_export.txt \
  -p /path/to/hashcat.potfile \
  -t /path/to/targets.txt \
  -o ./reports
```

- `-d/--ditfiles` (required): One or more NTDS export files. Each line: `DOMAIN\\User:RID:LM:NT`.
- `-p/--potfiles` (optional): One or more hashcat potfiles. Format: `hash:password` (only first `:` splits).
- `-t/--targetfiles` (optional): One or more files with target usernames (one per line).
- `-o/--output` (optional): Directory to write CSV of shared hashes and `user:pass` text file.

## Outputs
- Terminal summary with counts and percentages.
- CSV: `tattletale_shared_hashes_<timestamp>.csv` (hash, username for shared hashes).
- Text: `tattletale_user_pass_<timestamp>.txt` (only for cracked creds).

## Testing

```bash
cargo test
```

Snapshot tests use `cargo-insta` for approval:

```bash
cargo install cargo-insta
cargo insta accept
```
