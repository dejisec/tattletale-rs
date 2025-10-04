//! TattleTale (Rust)
//!
//! This crate provides the core library for parsing NTDS export lines, merging
//! crack results from hashcat potfiles, marking high-value targets, computing
//! statistics, and rendering human-readable reports. The companion binary
//! `tattletale` wires these pieces together for CLI usage.
//!
//! High-level components:
//! - `credential` defines the `Credential` data model and helpers
//! - `dit`, `pot`, and `targets` provide line/contents parsers
//! - `io` offers streaming and mmap-backed line iteration for large files
//! - `engine` coordinates parsing, cracking, deduplication, and target tagging
//! - `stats` computes aggregate statistics
//! - `report` renders a colored terminal summary
//! - `export` persists CSV/TXT outputs
//!
//! Most applications should construct an `engine::Engine`, load input files (or
//! strings for tests), then either render a summary via `report::render_summary`
//! or export results with functions in `export`.
//!
//! A minimal example (error handling elided):
//!
//! ```no_run
//! use tattletale::engine::Engine;
//! # fn main() -> anyhow::Result<()> {
//! let mut engine = Engine::new();
//! engine.load_from_file_paths(&["/path/to/ntds.txt"], &[], &[])?;
//! println!("{}", tattletale::report::render_summary(&engine));
//! # Ok(())
//! # }
//! ```
pub mod credential;
pub mod dit;
pub mod engine;
pub mod export;
pub mod io;
pub mod pot;
pub mod report;
pub mod stats;
pub mod targets;

pub mod prelude {
    pub use crate::credential::Credential;
}
