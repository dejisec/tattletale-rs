use std::fs;
use std::path::PathBuf;

use clap::Parser;
use tattletale::{
    engine::Engine,
    export::{save_shared_hashes_csv, save_user_pass_txt},
    report::render_summary,
};

#[derive(Parser, Debug)]
#[command(
    name = "tattletale-rs",
    version,
    about = "NTDS dumpfile reporter (Rust)"
)]
struct Args {
    #[arg(short = 'd', long = "ditfiles", required = true)]
    ditfiles: Vec<PathBuf>,

    #[arg(short = 'p', long = "potfiles")]
    potfiles: Vec<PathBuf>,

    #[arg(short = 't', long = "targetfiles")]
    targetfiles: Vec<PathBuf>,

    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

fn read_files(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .collect()
}

fn main() {
    let args = Args::parse();
    let dit_contents = read_files(&args.ditfiles);
    let pot_contents = read_files(&args.potfiles);
    let target_contents = read_files(&args.targetfiles);

    let mut engine = Engine::new();
    let dit_refs: Vec<&str> = dit_contents.iter().map(|s| s.as_str()).collect();
    let pot_refs: Vec<&str> = pot_contents.iter().map(|s| s.as_str()).collect();
    let target_refs: Vec<&str> = target_contents.iter().map(|s| s.as_str()).collect();
    engine.load_from_strings(&dit_refs, &pot_refs, &target_refs);

    let summary = render_summary(&engine);
    println!("{}", summary);

    if let Some(outdir) = args.output {
        let _ = fs::create_dir_all(&outdir);
        let ts = chrono::Local::now().format("%Y.%m.%d_%H.%M.%S");
        let csv = outdir.join(format!("tattletale_shared_hashes_{}.csv", ts));
        let txt = outdir.join(format!("tattletale_user_pass_{}.txt", ts));
        let _ = save_shared_hashes_csv(&engine, csv);
        let _ = save_user_pass_txt(&engine, txt);
    }
}
