// SPDX-License-Identifier: GPL-3.0-only
// Prints how long each pipeline stage takes: cargo run --release --example profile_phases -- /path
use rootwatch::analysis::{AnalysisConfig, analyze};
use rootwatch::scanner::{ScanConfig, scan};
use std::path::Path;
use std::time::Instant;
fn main() {
    let root = std::env::args().nth(1).unwrap();
    let t = Instant::now();
    let r = scan(Path::new(&root), &ScanConfig::default()).unwrap();
    let t_scan = t.elapsed();
    let t = Instant::now();
    let a = analyze(&r, &AnalysisConfig::default());
    let t_an = t.elapsed();
    let t = Instant::now();
    let big = r.largest_directories(20);
    let t_rank = t.elapsed();
    println!(
        "N={} D={}  scan(incl. O(D) aggregation)={:.1}ms  analysis={:.1}ms  top-20 ranking={:.2}ms  findings={} node_mem~{}MiB",
        r.totals.counts.entries,
        r.index.len(),
        t_scan.as_secs_f64() * 1e3,
        t_an.as_secs_f64() * 1e3,
        t_rank.as_secs_f64() * 1e3,
        a.findings.len(),
        r.index.len() * std::mem::size_of::<rootwatch::model::DirNode>() / (1 << 20)
    );
    let _ = big;
}
