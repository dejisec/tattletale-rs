//! CLI entrypoint for `tattletale`.
//!
//! Parses command-line arguments, validates input files, loads data through the
//! library engine with optional mmap threshold selection, prints a terminal
//! summary, and optionally writes CSV/TXT exports when an output directory is
//! provided.
use std::fs;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use log::{LevelFilter, error, warn};
use tattletale::{
    engine::Engine,
    export::{save_shared_hashes_csv, save_user_pass_txt},
    io::DEFAULT_MMAP_THRESHOLD_BYTES,
    report::render_summary,
};

#[derive(Parser, Debug)]
#[command(
    name = "tattletale-rs",
    version,
    about = "NTDS dumpfile reporter (Rust)"
)]
struct Args {
    /// Path to the NTDS export file(s)
    #[arg(short = 'd', long = "ditfiles", required = true)]
    ditfiles: Vec<PathBuf>,

    /// Path to the hashcat potfile
    #[arg(short = 'p', long = "potfiles")]
    potfiles: Vec<PathBuf>,

    /// Path to the target file(s)
    #[arg(short = 't', long = "targetfiles")]
    targetfiles: Vec<PathBuf>,

    /// Path to the output directory
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Override mmap threshold in bytes. If zero, disable mmap.
    #[arg(long = "mmap-threshold", default_value_t = DEFAULT_MMAP_THRESHOLD_BYTES)]
    mmap_threshold: u64,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

#[allow(dead_code)]
fn read_files(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .collect()
}

fn init_logger(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    let _ = env_logger::Builder::from_default_env()
        .filter_level(level)
        .try_init();
}

fn verify_inputs(args: &Args) -> Result<()> {
    if args.ditfiles.is_empty() {
        bail!("no DIT files provided (-d/--ditfiles)");
    }
    for p in &args.ditfiles {
        if !p.exists() {
            bail!("DIT file not found: {}", p.display());
        }
    }
    for p in &args.potfiles {
        if !p.exists() {
            warn!("potfile not found: {} (continuing)", p.display());
        }
    }
    for p in &args.targetfiles {
        if !p.exists() {
            warn!("target file not found: {} (continuing)", p.display());
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    init_logger(args.verbose);
    if let Err(e) = verify_inputs(&args) {
        error!("{}", e);
        std::process::exit(2);
    }
    let mut engine = Engine::new();
    let threshold = if args.mmap_threshold == 0 {
        u64::MAX
    } else {
        args.mmap_threshold
    };
    let potfiles_existing: Vec<PathBuf> = args
        .potfiles
        .iter()
        .filter(|p| p.exists())
        .cloned()
        .collect();
    let targetfiles_existing: Vec<PathBuf> = args
        .targetfiles
        .iter()
        .filter(|p| p.exists())
        .cloned()
        .collect();
    if let Err(e) = engine.load_from_file_paths_with_threshold(
        &args.ditfiles,
        &potfiles_existing,
        &targetfiles_existing,
        threshold,
    ) {
        error!("failed to load inputs: {}", e);
        std::process::exit(3);
    }

    let summary = render_summary(&engine);
    println!("{}", summary);

    if let Some(outdir) = args.output {
        if let Err(e) = fs::create_dir_all(&outdir) {
            error!(
                "failed to create output directory {}: {}",
                outdir.display(),
                e
            );
            std::process::exit(4);
        }
        let ts = chrono::Local::now().format("%Y.%m.%d_%H.%M.%S");
        let csv = outdir.join(format!("tattletale_shared_hashes_{}.csv", ts));
        let txt = outdir.join(format!("tattletale_user_pass_{}.txt", ts));
        if let Err(e) = save_shared_hashes_csv(&engine, &csv) {
            error!("failed to write {}: {}", csv.display(), e);
            std::process::exit(5);
        }
        if let Err(e) = save_user_pass_txt(&engine, &txt) {
            error!("failed to write {}: {}", txt.display(), e);
            std::process::exit(6);
        }
    }
}
