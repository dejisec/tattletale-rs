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
  -o ./reports \
  --mmap-threshold 16777216 \
  --parallel \
  --log-parse-stats \
  -vv
```

- `-d/--ditfiles` (required): One or more NTDS export files. Each line: `DOMAIN\\User:RID:LM:NT`.
- `-p/--potfiles` (optional): One or more hashcat potfiles. Format: `hash:password` (only first `:` splits).
- `-t/--targetfiles` (optional): One or more files with target usernames (one per line).
- `-o/--output` (optional): Directory to write CSV of shared hashes and `user:pass` text file.
- `--mmap-threshold` (optional): File-size threshold in bytes to use memory-mapped I/O (default: 16777216 ≈ 16 MiB). Set to `0` to disable mmap (always buffered streaming).
- `--parallel` (optional): Parse input files in parallel to leverage multiple CPU cores.
- `--log-parse-stats` (optional): Log counts of skipped/malformed lines while parsing DIT/POT files.
- `-v` (optional): Increase verbosity. Repeat for more detail (`-v`, `-vv`, `-vvv`).

## Outputs

- Terminal summary with counts and percentages.
- CSV: `tattletale_shared_hashes_<timestamp>.csv` (columns: `Hash,Username,Cracked`) for shared hashes only.
- Text: `tattletale_user_pass_<timestamp>.txt` (only for cracked creds).
  
The summary also includes:
- Domain Breakdown: per-domain counts and cracked rates.
- Top Reused Passwords: the most frequent cracked passwords.

## Performance & Memory

- The tool processes input files in a streaming, line-by-line fashion to minimize memory usage.
- For files whose size is at or above `--mmap-threshold`, memory-mapped I/O is used for faster scanning with low overhead.
- Set `--mmap-threshold 0` to disable mmap entirely (pure buffered streaming).
- Parallel loading: with `--parallel`, DIT, POT, and target files are parsed concurrently across files (using Rayon). Results are identical to sequential mode; ordering of internal processing may differ.

## Testing

```bash
cargo test
```

Snapshot tests use `cargo-insta` for approval:

```bash
cargo install cargo-insta
cargo insta accept
```
