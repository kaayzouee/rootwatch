// SPDX-License-Identifier: GPL-3.0-only
// Measures the cost of the TUI paths on a large tree:
//   cargo run --release --example tui_bench -- /path
use ratatui::{Terminal, backend::TestBackend};
use rootwatch::analysis::{AnalysisConfig, analyze};
use rootwatch::scanner::{ScanConfig, ScanProgress, scan};
use rootwatch::tui::state::{AppState, View};
use rootwatch::tui::ui;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let root = std::env::args().nth(1).expect("path");
    let t = Instant::now();
    let plain = scan(Path::new(&root), &ScanConfig::default()).unwrap();
    let t_plain = t.elapsed();
    let progress = Arc::new(ScanProgress::default());
    let cfg = ScanConfig {
        progress: Some(progress),
        top_files: 200,
        ..ScanConfig::default()
    };
    let t = Instant::now();
    let r = scan(Path::new(&root), &cfg).unwrap();
    let t_prog = t.elapsed();
    println!(
        "scan without progress sink: {:.0} ms   with: {:.0} ms   (dirs {})",
        t_plain.as_secs_f64() * 1e3,
        t_prog.as_secs_f64() * 1e3,
        r.index.len()
    );
    drop(plain);

    let t = Instant::now();
    let a = analyze(&r, &AnalysisConfig::default());
    println!("analysis: {:.1} ms", t.elapsed().as_secs_f64() * 1e3);

    let mut s = AppState::new(root.into(), String::new());
    s.begin_scan();
    let t = Instant::now();
    s.scan_finished(Arc::new(r));
    println!(
        "scan_finished (tree reset, top-level, coverage facts): {:.1} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
    s.analysis_finished(Arc::new(a));

    let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let res = s.result.clone().unwrap();
    let mut time_view = |s: &mut AppState, v: View, label: &str| {
        s.view = v;
        term.draw(|f| ui::render(f, s)).unwrap();
        let t = Instant::now();
        for _ in 0..50 {
            term.draw(|f| ui::render(f, s)).unwrap();
        }
        println!(
            "{label:<34} {:.2} ms/frame",
            t.elapsed().as_secs_f64() * 1e3 / 50.0
        );
    };
    for v in View::ALL {
        time_view(&mut s, v, &format!("{} view", v.title()));
    }

    // worst case for the tree: everything expanded -> one row per directory
    s.tree.expanded = res.index.ids().collect();
    let t = Instant::now();
    s.tree.rebuild(&res);
    println!(
        "expand ALL ({} rows) projection: {:.1} ms",
        s.tree.rows.len(),
        t.elapsed().as_secs_f64() * 1e3
    );
    s.tree.bottom();
    time_view(&mut s, View::Tree, "Tree, all expanded, at bottom");
    let t = Instant::now();
    s.tree.toggle(&res);
    s.tree.top();
    println!(
        "one collapse/expand toggle + jump: {:.1} ms",
        t.elapsed().as_secs_f64() * 1e3
    );

    let t = Instant::now();
    s.tree.set_filter(&res, "d1");
    println!(
        "tree name search over {} dirs: {:.1} ms ({} matches shown)",
        res.index.len(),
        t.elapsed().as_secs_f64() * 1e3,
        s.tree.matches.len()
    );
    time_view(&mut s, View::Tree, "Tree search results");
}
