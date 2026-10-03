// SPDX-License-Identifier: GPL-3.0-only

use rootwatch::analysis::{self, AnalysisConfig, AnalysisInputs};
use rootwatch::cli::{self, HELP};
use rootwatch::nix;
use rootwatch::output::{self, ReportOptions};
use rootwatch::privilege;
use rootwatch::scanner::scan;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn run() -> Result<(), String> {
    let cli = cli::parse(std::env::args_os().skip(1))?;
    if cli.help {
        print!("{HELP}");
        return Ok(());
    }
    if cli.version {
        println!("rootwatch {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let root = fs::canonicalize(&cli.root)
        .map_err(|e| format!("cannot open {}: {e}", cli.root.display()))?;
    if !fs::metadata(&root).map_err(|e| e.to_string())?.is_dir() {
        return Err(format!("scan root is not a directory: {}", root.display()));
    }

    let config = cli.scan_config();
    let started = Instant::now();
    let result = scan(&root, &config).map_err(|e| format!("scan failed: {e}"))?;
    let elapsed = started.elapsed();

    if cli.worker {
        let mut out = io::stdout().lock();
        let _ = privilege::write_worker_report(&result, &mut out);
        return Ok(());
    }

    let dead = cli
        .nix_gc
        .then(|| nix::query_dead_paths(Duration::from_secs(300)));
    let inputs = AnalysisInputs {
        nix_dead: dead.as_ref(),
        ..AnalysisInputs::default()
    };
    let analysis = analysis::analyze_with(&result, &AnalysisConfig::default(), &inputs);

    let (impact, impact_err) = if cli.privileged && !privilege::is_root() {
        match privilege::run_privileged_worker(&cli.elevate, &cli.worker_args(&root)) {
            Ok(w) => (Some(privilege::compare(&result, &analysis.coverage, &w)), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };

    let report = output::render_report(
        &result,
        &analysis,
        elapsed,
        &ReportOptions {
            top: cli.top,
            permission: impact.as_ref(),
            permission_error: impact_err.as_deref(),
            privileged_run: privilege::is_root(),
        },
    );
    match io::stdout().lock().write_all(report.as_bytes()) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e.to_string()),
        _ => Ok(()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("rootwatch: {msg}");
            ExitCode::from(2)
        }
    }
}
