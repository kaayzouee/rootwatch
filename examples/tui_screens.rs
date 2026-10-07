// SPDX-License-Identifier: GPL-3.0-only
//
// Renders the TUI views of a small SYNTHETIC tree into plain-text captures
// (colours are not represented). Used to produce docs/screenshots/*.txt:
//   cargo run --release --example tui_screens -- docs/screenshots
//
// The tree lives on a real filesystem but the "pool" numbers are pretended
// (64 MiB disk, 73% used) so that severities and coverage states are visible.

use ratatui::{Terminal, backend::TestBackend};
use rootwatch::analysis::{AnalysisConfig, analyze};
use rootwatch::model::{FilesystemInfo, ScanResult};
use rootwatch::scanner::{ScanConfig, scan};
use rootwatch::tui::state::{AppState, View};
use rootwatch::tui::ui;
use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const NOW: i64 = 1_800_000_000;
const MIB: usize = 1 << 20;

fn file(root: &Path, rel: &str, bytes: usize, age_days: i64) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, vec![7u8; bytes]).unwrap();
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
    let t = Timespec {
        tv_sec: NOW - age_days * 86_400,
        tv_nsec: 0,
    };
    utimensat(
        CWD,
        &p,
        &Timestamps {
            last_access: t,
            last_modification: t,
        },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
}

fn build_demo(root: &Path) {
    let _ = fs::remove_dir_all(root);
    file(root, "home/kay/Downloads/ubuntu.iso", 12 * MIB, 400);
    file(root, "home/kay/.cache/mozilla/cache2.bin", 6 * MIB, 200);
    file(root, "home/kay/.cargo/registry/crates.tar", 3 * MIB, 20);
    file(root, "home/kay/projects/rootwatch/Cargo.toml", 400, 1);
    file(root, "home/kay/projects/rootwatch/src/main.rs", 9000, 1);
    file(
        root,
        "home/kay/projects/rootwatch/target/debug/rootwatch",
        9 * MIB,
        2,
    );
    file(root, "tmp/build-4711/objects.o", 5 * MIB, 30);
    file(root, "tmp/session.db", MIB, 0);
    file(root, "var/log/journal/system.journal", 4 * MIB, 1);
    file(root, "usr/lib/libbig.so", 3 * MIB, 90);
}

fn scan_demo(root: &Path) -> ScanResult {
    let r = root.display().to_string();
    let cfg = ScanConfig {
        now_unix: Some(NOW),
        top_files: 200,
        zones: ZoneConfig {
            rules: vec![
                ZoneRule::class(&format!("{r}/home"), PathClass::Home),
                ZoneRule::zone(&format!("{r}/home/*"), PathClass::Home, Role::HomeZone),
                ZoneRule::zone(&format!("{r}/tmp"), PathClass::Temporary, Role::TempZone),
                ZoneRule::class(&format!("{r}/var"), PathClass::Var),
                ZoneRule::class(&format!("{r}/usr"), PathClass::System),
            ],
            excluded: vec![],
        },
        ..ScanConfig::default()
    };
    scan(root, &cfg).unwrap()
}

fn set_pool(r: &mut ScanResult, total: u64, used: u64) {
    r.subtree_scan = false;
    let info = FilesystemInfo {
        total_bytes: total,
        used_bytes: used,
        available_bytes: total - used,
    };
    r.pools[0].info = info.clone();
    r.filesystems[0].info = info.clone();
    r.filesystem = info;
}

fn state(r: ScanResult, root: &Path) -> AppState {
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            temp_stale_min_bytes: MIB as u64,
            ..Default::default()
        },
    );
    let mut s = AppState::new(root.to_path_buf(), "root filesystem only".into());
    s.begin_scan();
    s.scan_finished(Arc::new(r));
    s.analysis_finished(Arc::new(a));
    s.scan_secs = Some(0.42);
    s
}

fn capture(s: &mut AppState, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| ui::render(f, s)).unwrap();
    let buf = t.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        let line: String = (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn main() {
    let out_dir = PathBuf::from(std::env::args().nth(1).expect("output dir"));
    fs::create_dir_all(&out_dir).unwrap();
    let root = std::env::temp_dir().join("rootwatch-demo");
    build_demo(&root);
    let save = |name: &str, body: String| fs::write(out_dir.join(name), body).unwrap();

    let mut r = scan_demo(&root);
    set_pool(&mut r, 64 << 20, 47 << 20);
    // a complete scan: pretend the pool holds exactly what we walked
    let walked = r.totals.allocated_bytes;
    set_pool(&mut r, 64 << 20, walked);
    let mut s = state(r.clone(), &root);
    s.view = View::Overview;
    save("overview-complete.txt", capture(&mut s, 100, 30));

    s.view = View::Findings;
    s.findings.detail_open = true;
    save("findings-detail.txt", capture(&mut s, 120, 30));

    s.view = View::Tree;
    s.tree.detail_open = true;
    let root_node = s.result.clone().unwrap().root_node();
    let res = s.result.clone().unwrap();
    for id in res
        .index
        .ids()
        .filter(|&i| res.index.node(i).depth <= res.index.node(root_node).depth + 3)
    {
        s.tree.expanded.insert(id);
    }
    s.tree.rebuild(&res);
    save("tree-detail.txt", capture(&mut s, 120, 34));

    s.view = View::Zones;
    save("zones-temporary.txt", capture(&mut s, 110, 34));

    // the same scan, but the pool is a 100 GiB disk that is 95% full
    let mut partial = r.clone();
    set_pool(&mut partial, 100 << 30, 95u64 << 30);
    let mut s = state(partial, &root);
    s.view = View::Overview;
    save("overview-partial.txt", capture(&mut s, 100, 30));
    s.view = View::Coverage;
    save("coverage-partial.txt", capture(&mut s, 100, 30));

    let _ = fs::remove_dir_all(&root);
}
