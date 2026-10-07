// SPDX-License-Identifier: GPL-3.0-only
//  Copyright (C) 2026 kaayzouee
// Author: https://github.com/kaayzouee
mod common;

use common::*;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use rootwatch::analysis::{AnalysisConfig, AnalysisResult, analyze};
use rootwatch::model::*;
use rootwatch::scanner::{ScanConfig, scan};
use rootwatch::tui::app::App;
use rootwatch::tui::command::Command;
use rootwatch::tui::event::{Event, EventHandler};
use rootwatch::tui::state::{AppState, ScanStatus, View};
use rootwatch::tui::tree::{self, TreeSort, TreeState};
use rootwatch::tui::ui;
use rootwatch::tui::update::Effect;
use rootwatch::tui::worker::ScanRequest;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

const NOW: i64 = 1_800_000_000;
const MIB: usize = 1 << 20;

fn scan_fx(fx: &Fixture) -> ScanResult {
    scan(
        &fx.root,
        &ScanConfig {
            now_unix: Some(NOW),
            ..ScanConfig::default()
        },
    )
    .unwrap()
}

fn tree_fixture() -> Fixture {
    let fx = Fixture::new("tui");
    fx.file("alpha/one/a.bin", 3 * MIB);
    fx.file("alpha/two/b.bin", MIB);
    fx.file("beta/c.bin", 2 * MIB);
    fx.file("gamma/deep/er/est/d.bin", MIB / 2);
    fx
}

/// A ready AppState over a real scan; `used_pct` makes findings appear
fn ready_state(fx: &Fixture, mutate: impl FnOnce(&mut ScanResult)) -> AppState {
    let mut r = scan_fx(fx);
    mutate(&mut r);
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            ..Default::default()
        },
    );
    let mut s = AppState::new(fx.root.clone(), "root filesystem only".into());
    s.begin_scan();
    s.scan_finished(Arc::new(r));
    s.analysis_finished(Arc::new(a));
    s
}

fn make_disk(r: &mut ScanResult, total: u64, used: u64) {
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

fn draw(s: &mut AppState, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| ui::render(f, s)).unwrap();
    let buf = t.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        for x in 0..w {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn key(c: KeyCode) -> Event {
    Event::Key(KeyEvent::new(c, KeyModifiers::NONE))
}
fn ch(c: char) -> Event {
    key(KeyCode::Char(c))
}
fn press(s: &mut AppState, ev: Event) -> Effect {
    s.handle_event(ev)
}

// ---------------- tree projection (RW-TUI-034) ----------------

#[test]
fn projection_root_only_then_expanded_with_correct_depths() {
    let fx = tree_fixture();
    let r = scan_fx(&fx);
    let root = r.root_node();
    let mut expanded: HashSet<NodeId> = HashSet::new();

    let rows = tree::project(&r.index, root, &expanded, TreeSort::Size);
    assert_eq!(rows.len(), 1, "collapsed root shows only itself");
    assert!(rows[0].has_children && !rows[0].expanded);

    expanded.insert(root);
    let rows = tree::project(&r.index, root, &expanded, TreeSort::Size);
    assert_eq!(rows.len(), 4, "root + alpha, beta, gamma");
    assert_eq!(rows[0].depth, 0);
    assert!(rows[1..].iter().all(|x| x.depth == 1));
    // sorted by size: alpha (4 MiB) > beta (2) > gamma
    let names: Vec<_> = rows[1..]
        .iter()
        .map(|x| r.index.name(x.node).to_vec())
        .collect();
    assert_eq!(
        names,
        [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
    );
    assert!(rows.last().unwrap().last && !rows[1].last);

    let alpha = rows[1].node;
    expanded.insert(alpha);
    let rows = tree::project(&r.index, root, &expanded, TreeSort::Size);
    assert_eq!(rows.len(), 6);
    assert_eq!(rows[2].depth, 2);
    // children appear directly below their parent (pre-order)
    assert_eq!(r.index.node(rows[2].node).parent, alpha);
    assert_eq!(r.index.node(rows[3].node).parent, alpha);
}

#[test]
fn projection_name_sort_and_every_row_is_a_real_node() {
    let fx = tree_fixture();
    let r = scan_fx(&fx);
    let expanded: HashSet<NodeId> = r.index.ids().collect();
    let rows = tree::project(&r.index, r.root_node(), &expanded, TreeSort::Name);
    assert_eq!(
        rows.len(),
        r.index.len(),
        "everything expanded shows every directory once"
    );
    let uniq: HashSet<_> = rows.iter().map(|x| x.node).collect();
    assert_eq!(uniq.len(), rows.len());
    assert!(
        rows.iter().all(|x| x.node.idx() < r.index.len()),
        "every row maps to a NodeId"
    );
    let top: Vec<_> = rows
        .iter()
        .filter(|x| x.depth == 1)
        .map(|x| r.index.name(x.node).to_vec())
        .collect();
    assert_eq!(
        top,
        [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
    );
}

#[test]
fn collapsing_an_ancestor_moves_the_cursor_to_a_visible_row() {
    let fx = tree_fixture();
    let r = scan_fx(&fx);
    let mut t = TreeState::default();
    t.reset(&r);
    // reveal the deepest directory
    let deepest = r
        .index
        .ids()
        .max_by_key(|&i| r.index.node(i).depth)
        .unwrap();
    t.reveal(&r, deepest);
    assert_eq!(t.selected_node(), Some(deepest));
    assert!(t.rows.iter().any(|x| x.node == deepest));

    // collapse the top-level ancestor of the cursor
    let mut anc = deepest;
    while r.index.node(anc).parent != r.root_node() {
        anc = r.index.node(anc).parent;
    }
    t.expanded.remove(&anc);
    t.rebuild(&r);
    assert!(
        t.rows.iter().any(|x| x.node == t.cursor),
        "cursor never dangles"
    );
    assert_eq!(t.cursor, anc, "falls back to the nearest visible ancestor");
    assert_eq!(t.selected_node(), Some(anc));
    assert!(t.list.selected().unwrap() < t.rows.len());
}

#[test]
fn tree_navigation_expand_collapse_parent_and_bounds() {
    let fx = tree_fixture();
    let r = scan_fx(&fx);
    let mut t = TreeState::default();
    t.reset(&r);
    assert_eq!(t.rows.len(), 4);
    t.move_by(-5);
    assert_eq!(
        t.list.selected(),
        Some(0),
        "cannot move above the first row"
    );
    t.move_by(100);
    assert_eq!(t.list.selected(), Some(3), "cannot move past the last row");
    t.top();
    t.move_by(1); // alpha
    t.right(&r); // expand
    assert_eq!(t.rows.len(), 6);
    t.right(&r); // already expanded: step into first child
    assert_eq!(t.list.selected(), Some(2));
    t.left(&r); // child is a leaf-ish dir: goes to parent
    assert_eq!(t.list.selected(), Some(1));
    t.left(&r); // expanded: collapse
    assert_eq!(t.rows.len(), 4);
    t.bottom();
    assert_eq!(t.list.selected(), Some(3));
}

#[test]
fn tree_search_matches_names_case_insensitively_and_jumps() {
    let fx = tree_fixture();
    let r = scan_fx(&fx);
    let mut t = TreeState::default();
    t.reset(&r);
    t.set_filter(&r, "EST");
    assert!(t.searching());
    assert_eq!(t.matches.len(), 1, "only 'est' matches (case-insensitive)");
    assert_eq!(r.index.name(t.matches[0]), b"est");
    t.set_filter(&r, "zzz");
    assert!(t.matches.is_empty());
    assert_eq!(t.selected_node(), None);
    t.set_filter(&r, "one");
    assert!(t.jump_to_selected_match(&r));
    assert!(!t.searching());
    let n = t.selected_node().unwrap();
    assert_eq!(r.index.name(n), b"one");
    assert!(
        t.rows.iter().any(|x| x.node == n),
        "ancestors were expanded"
    );
    t.set_filter(&r, "");
    assert!(!t.searching());
    assert!(!t.jump_to_selected_match(&r));
}

#[test]
fn search_results_are_largest_first_and_bounded() {
    let fx = Fixture::new("tuisearch");
    for i in 0..30 {
        fx.file(&format!("d{i:02}/x/f"), (i + 1) * 4096);
    }
    let r = scan_fx(&fx);
    let mut t = TreeState::default();
    t.reset(&r);
    t.set_filter(&r, "d");
    let sizes: Vec<u64> = t.matches.iter().map(|&n| r.usage(n).bytes).collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]));
    assert!(t.matches.len() <= tree::MAX_SEARCH_RESULTS);
    assert!(tree::contains_ascii_ci(b"HeLLo", b"ell"));
    assert!(!tree::contains_ascii_ci(b"hi", b"hello"));
}

// ---------------- filtering (RW-TUI-035) ----------------

fn findings_state(fx: &Fixture) -> AppState {
    ready_state(fx, |r| make_disk(r, 12 * MIB as u64, 11 * MIB as u64))
}

#[test]
fn findings_filter_by_path_kind_severity_and_no_match() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    let a = s.analysis.clone().unwrap();
    let total = a.findings.len();
    assert!(
        total >= 3,
        "fixture must produce several findings, got {total}"
    );

    s.findings.refilter(&a, "alpha");
    assert!(!s.findings.filtered_indices.is_empty());
    assert!(
        s.findings.filtered_indices.iter().all(|&i| a.findings[i]
            .path
            .display()
            .to_string()
            .contains("alpha"))
    );

    // kind and class labels
    s.findings.refilter(&a, "directory");
    assert!(s.findings.filtered_indices.len() <= total);
    s.findings.refilter(&a, "temporary");
    assert!(s.findings.filtered_indices.iter().all(|&i| {
        let f = &a.findings[i];
        f.kind == rootwatch::analysis::FindingKind::Temporary
            || f.class.label() == "temporary"
            || f.path.display().to_string().contains("temporary")
    }));

    // severity word, case-insensitive
    let sev = a.findings[0].severity.label();
    s.findings.refilter(&a, &sev.to_lowercase());
    assert!(s.findings.filtered_indices.contains(&0));

    // AND semantics across terms; and no match
    s.findings.refilter(&a, "alpha beta");
    assert!(s.findings.filtered_indices.is_empty());
    assert!(s.findings.selected(&a).is_none());
    s.findings.refilter(&a, "");
    assert_eq!(s.findings.filtered_indices.len(), total);
    assert_eq!(s.findings.table.selected(), Some(0));
}

#[test]
fn findings_filter_matches_synthetic_titles() {
    let fx = Fixture::new("tuititle");
    fx.file("t/old/blob", 12 * MIB);
    fx.set_age_days("t/old/blob", 60, NOW);
    use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};
    let mut c = ScanConfig {
        now_unix: Some(NOW),
        ..ScanConfig::default()
    };
    c.zones = ZoneConfig {
        rules: vec![ZoneRule::zone(
            fx.path("t").to_str().unwrap(),
            PathClass::Temporary,
            Role::TempZone,
        )],
        excluded: vec![],
    };
    let mut r = scan(&fx.root, &c).unwrap();
    make_disk(&mut r, 50 * MIB as u64, 40 * MIB as u64);
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            temp_stale_min_bytes: MIB as u64,
            ..Default::default()
        },
    );
    let mut s = AppState::new(fx.root.clone(), String::new());
    s.begin_scan();
    s.scan_finished(Arc::new(r));
    let a = Arc::new(a);
    s.analysis_finished(a.clone());
    s.findings.refilter(&a, "stale temporary");
    assert!(
        !s.findings.filtered_indices.is_empty(),
        "title text is searchable"
    );
    let f = s.findings.selected(&a).unwrap();
    assert!(f.title.as_deref().unwrap().contains("stale temporary"));
}

#[test]
fn files_and_pools_filters() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    let r = s.result.clone().unwrap();
    assert!(!s.files.order.is_empty());
    s.files.set_filter(&r, "b.bin");
    assert_eq!(s.files.order.len(), 1);
    assert!(
        s.files
            .selected(&r)
            .unwrap()
            .path
            .ends_with("alpha/two/b.bin")
    );
    s.files.set_filter(&r, "nothing-here");
    assert!(s.files.order.is_empty() && s.files.selected(&r).is_none());
    s.files.set_filter(&r, "");
    let before = s.files.order.clone();
    s.files.toggle_sort(&r); // age
    s.files.toggle_sort(&r); // path
    let paths: Vec<_> = s
        .files
        .order
        .iter()
        .map(|&i| r.top_files[i].path.clone())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
    s.files.toggle_sort(&r); // back to size
    assert_eq!(s.files.order, before);

    assert_eq!(s.pools.rows.len(), r.pools.len());
    s.pools.set_filter(&r, "definitely-not-a-pool");
    assert!(s.pools.rows.is_empty());
    s.pools.set_filter(&r, &r.filesystems[0].fstype);
    assert_eq!(s.pools.rows.len(), 1);
}

// ---------------- rendering (RW-TUI-036) ----------------

#[test]
fn every_view_renders_at_80x24_without_panicking() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    for v in View::ALL {
        s.view = v;
        let out = draw(&mut s, 80, 24);
        assert!(out.contains("ROOTWATCH"), "{v:?}");
        assert!(out.contains(v.title()), "{v:?} tab visible");
        assert!(out.contains("Quit"), "{v:?} footer visible");
    }
}

#[test]
fn views_render_at_all_target_sizes() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    s.findings.detail_open = true;
    s.tree.detail_open = true;
    s.files.detail_open = true;
    for (w, h) in [(80, 24), (100, 30), (120, 40), (160, 50)] {
        for v in View::ALL {
            s.view = v;
            let out = draw(&mut s, w, h);
            assert_eq!(out.lines().count(), h as usize);
            assert!(out.contains("ROOTWATCH"), "{v:?} at {w}x{h}");
        }
    }
}

#[test]
fn overview_shows_verdict_coverage_and_largest_areas() {
    let fx = tree_fixture();
    let mut s = ready_state(&fx, |r| make_disk(r, 12 * MIB as u64, 11 * MIB as u64));
    let out = draw(&mut s, 100, 30);
    for needle in [
        "Status",
        "Overall",
        "Risk",
        "Coverage",
        "Confidence",
        "Findings",
        "Filesystems",
        "Largest areas",
        "/alpha",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
    }
}

#[test]
fn partial_coverage_is_unmistakable_on_the_overview() {
    let fx = tree_fixture();
    let mut s = ready_state(&fx, |r| make_disk(r, 100 << 30, 95 << 30)); // saw ~7 MiB of 95 GiB
    let out = draw(&mut s, 100, 30);
    assert!(out.contains("MINIMAL SCAN"), "{out}");
    assert!(
        out.contains("UNDETERMINED") || out.contains("at least"),
        "{out}"
    );
    assert!(out.contains("do NOT show where the space went"), "{out}");
    assert!(out.contains("MINIMAL"), "badge");
}

#[test]
fn complete_scans_have_no_warning_banner() {
    let fx = tree_fixture();
    let mut s = ready_state(&fx, |r| {
        let used = r.totals.allocated_bytes;
        make_disk(r, 1 << 30, used);
    });
    let out = draw(&mut s, 100, 30);
    assert!(!out.contains("SCAN:"), "{out}");
    assert!(out.contains("COMPLETE"));
}

#[test]
fn findings_view_lists_rows_and_opens_details() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    press(&mut s, ch('2'));
    assert_eq!(s.view, View::Findings);
    let out = draw(&mut s, 100, 30);
    for h in ["Severity", "Score", "Size", "Type", "Path"] {
        assert!(out.contains(h), "{h}");
    }
    assert!(out.contains("alpha"));
    press(&mut s, key(KeyCode::Enter));
    assert!(s.findings.detail_open);
    let out = draw(&mut s, 100, 30);
    for h in ["Finding", "Reasons", "Coverage", "Growth", "Confidence"] {
        assert!(out.contains(h), "detail missing {h}:\n{out}");
    }
    assert!(out.contains("off (no baseline scan supplied)"), "{out}");
    press(&mut s, key(KeyCode::Esc));
    assert!(!s.findings.detail_open);
}

#[test]
fn tree_view_shows_structure_badges_and_details() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    press(&mut s, ch('3'));
    let out = draw(&mut s, 100, 30);
    assert!(out.contains("├─") || out.contains("└─"), "{out}");
    assert!(
        out.contains("▸") && out.contains("▾"),
        "expand markers: {out}"
    );
    assert!(out.contains("alpha") && out.contains("beta") && out.contains("gamma"));
    press(&mut s, ch('j'));
    press(&mut s, key(KeyCode::Right));
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("one") && out.contains("two"),
        "expanded children: {out}"
    );
    press(&mut s, key(KeyCode::Enter));
    let out = draw(&mut s, 100, 30);
    for h in [
        "Directory",
        "Filesystem",
        "Pool",
        "Newest",
        "Age of data",
        "Contents",
    ] {
        assert!(out.contains(h), "tree detail missing {h}:\n{out}");
    }
}

#[test]
fn coverage_pools_files_and_zones_views_render_their_content() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    s.view = View::Coverage;
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("Coverage")
            && out.contains("Storage pools")
            && out.contains("Permission denied"),
        "{out}"
    );
    s.view = View::Pools;
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("Pressure") && out.contains("Mounts on this pool"),
        "{out}"
    );
    s.view = View::Files;
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("Largest files") && out.contains("a.bin"),
        "{out}"
    );
    s.view = View::Zones;
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("Temporary") && out.contains("Home") && out.contains("Nix"),
        "{out}"
    );
}

#[test]
fn nix_panel_distinguishes_queried_not_queried_and_unavailable() {
    use rootwatch::analysis::{AnalysisInputs, analyze_with};
    use rootwatch::nix::DeadPaths;
    use rootwatch::tui::state::ZoneTab;
    use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};

    let fx = Fixture::new("tuinix");
    let h = "a".repeat(32);
    fx.file(&format!("n/store/{h}-glibc-2.39/lib/libc.so"), 400_000);
    let n = fx.path("n").display().to_string();
    let mut c = ScanConfig {
        now_unix: Some(NOW),
        ..ScanConfig::default()
    };
    c.zones = ZoneConfig {
        rules: vec![
            ZoneRule::class(&n, PathClass::Nix),
            ZoneRule::role(&format!("{n}/store"), Role::NixStore),
        ],
        excluded: vec![],
    };
    let r = scan(&fx.root, &c).unwrap();

    let render = |dead: Option<&DeadPaths>| {
        let a = analyze_with(
            &r,
            &AnalysisConfig::default(),
            &AnalysisInputs {
                nix_dead: dead,
                ..Default::default()
            },
        );
        let mut s = AppState::new(fx.root.clone(), String::new());
        s.begin_scan();
        s.scan_finished(Arc::new(r.clone()));
        s.analysis_finished(Arc::new(a));
        s.view = View::Zones;
        s.zones.tab = ZoneTab::Nix;
        draw(&mut s, 110, 34)
    };
    assert!(render(None).contains("NOT QUERIED"));
    assert!(
        render(Some(&DeadPaths::Unavailable("nix-store: not found".into())))
            .contains("UNAVAILABLE")
    );
    let found = DeadPaths::Found(vec![format!("/nix/store/{h}-glibc-2.39").into_bytes()]);
    assert!(render(Some(&found)).contains("QUERIED:"));
}

#[test]
fn empty_directory_renders_everywhere() {
    let fx = Fixture::new("tuiempty");
    let mut s = ready_state(&fx, |_| {});
    for v in View::ALL {
        s.view = v;
        let out = draw(&mut s, 80, 24);
        assert!(out.contains("ROOTWATCH"), "{v:?}");
    }
    s.view = View::Findings;
    assert!(draw(&mut s, 80, 24).contains("No findings"));
    s.view = View::Files;
    assert!(draw(&mut s, 80, 24).contains("No files"));
    s.view = View::Zones;
    assert!(draw(&mut s, 80, 24).contains("No temporary zone"));
}

#[test]
fn state_screens_idle_scanning_analyzing_failed() {
    let mut s = AppState::new(PathBuf::from("/x"), "scope".into());
    assert!(draw(&mut s, 80, 24).contains("Starting"));
    s.begin_scan();
    s.progress = Some(rootwatch::scanner::ProgressSnapshot {
        entries: 284_192,
        directories: 31_802,
        bytes: 5 << 30,
        current_path: Some(PathBuf::from("/home/kay/projects/deep/path")),
    });
    let out = draw(&mut s, 80, 24);
    for needle in [
        "Scanning",
        "284,192",
        "31,802",
        "/home/kay/projects/deep/path",
        "entries",
        "directories",
    ] {
        assert!(out.contains(needle), "{needle}: {out}");
    }
    s.scan_failed("scan of /x failed: No such file or directory".into());
    let out = draw(&mut s, 80, 24);
    assert!(
        out.contains("Scan failed") && out.contains("No such file") && out.contains("try again"),
        "{out}"
    );
    // data views cannot show stale/absent data
    s.view = View::Tree;
    assert!(draw(&mut s, 80, 24).contains("Scan failed"));
}

#[test]
fn undersized_terminals_show_a_message_instead_of_panicking() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    for (w, h) in [(79, 24), (80, 23), (40, 10), (1, 1), (0, 0), (200, 3)] {
        let out = draw(&mut s, w, h);
        if (w, h) == (0, 0) {
            continue;
        }
        if (w < 80 || h < 24) && w >= 24 && h >= 3 {
            assert!(
                out.contains("Terminal too small") || out.contains("small"),
                "{w}x{h}: {out}"
            );
        }
    }
    let out = draw(&mut s, 60, 20);
    assert!(out.contains("Resize to at least 80x24"), "{out}");
    assert!(out.contains("60x20"));
}

#[test]
fn tabs_and_help_overlay() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    press(&mut s, key(KeyCode::Tab));
    assert_eq!(s.view, View::Findings);
    press(
        &mut s,
        Event::Key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)),
    );
    assert_eq!(s.view, View::Overview);
    press(
        &mut s,
        Event::Key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)),
    );
    assert_eq!(s.view, View::Zones, "wraps around");
    press(&mut s, ch('?'));
    assert!(s.help_open);
    assert!(draw(&mut s, 100, 30).contains("Read-only"));
    press(&mut s, ch('j')); // ignored while help is open
    assert!(s.help_open);
    press(&mut s, key(KeyCode::Esc));
    assert!(!s.help_open);
}

// ---------------- search UX ----------------

#[test]
fn search_prompt_filters_live_commits_and_cancels() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    let total = s.findings.filtered_indices.len();
    press(&mut s, ch('2'));
    press(&mut s, ch('/'));
    assert!(s.search.active);
    for c in "alpha".chars() {
        press(&mut s, ch(c));
    }
    assert_eq!(s.search.input.value(), "alpha");
    assert!(
        s.findings.filtered_indices.len() < total,
        "filters while typing"
    );
    // 'q' and digits are text in search mode, not commands
    press(&mut s, ch('q'));
    assert!(s.running && s.search.active);
    press(&mut s, key(KeyCode::Backspace));
    assert!(
        draw(&mut s, 100, 30).contains("/alpha"),
        "prompt drawn in footer"
    );
    press(&mut s, key(KeyCode::Enter));
    assert!(!s.search.active);
    assert_eq!(s.findings.filter, "alpha", "Enter keeps the filter");
    press(&mut s, key(KeyCode::Esc));
    assert_eq!(s.findings.filter, "", "Esc outside the prompt clears it");
    assert_eq!(s.findings.filtered_indices.len(), total);

    press(&mut s, ch('/'));
    press(&mut s, ch('x'));
    press(&mut s, key(KeyCode::Esc));
    assert!(
        !s.search.active && s.findings.filter.is_empty(),
        "Esc in the prompt cancels"
    );
}

#[test]
fn search_is_refused_on_views_without_it_and_tree_enter_jumps() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    press(&mut s, ch('5')); // coverage
    press(&mut s, ch('/'));
    assert!(!s.search.active);
    assert!(s.message.is_some());

    press(&mut s, ch('3'));
    press(&mut s, ch('/'));
    for c in "est".chars() {
        press(&mut s, ch(c));
    }
    press(&mut s, key(KeyCode::Enter)); // keep
    assert!(s.tree.searching());
    assert!(draw(&mut s, 100, 30).contains("Tree search 'est'"));
    press(&mut s, key(KeyCode::Enter)); // jump
    assert!(!s.tree.searching());
    let r = s.result.clone().unwrap();
    assert_eq!(r.index.name(s.tree.selected_node().unwrap()), b"est");
}

// ---------------- mouse (RW-TUI-031) ----------------

fn mouse(kind: MouseEventKind, x: u16, y: u16) -> Event {
    Event::Mouse(MouseEvent {
        kind,
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    })
}

#[test]
fn mouse_selects_tabs_rows_and_scrolls() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    draw(&mut s, 100, 30);
    let (rect, view) = s.layout.tabs[1];
    assert_eq!(view, View::Findings);
    press(
        &mut s,
        mouse(MouseEventKind::Down(MouseButton::Left), rect.x + 1, rect.y),
    );
    assert_eq!(s.view, View::Findings);

    draw(&mut s, 100, 30);
    let hit = s
        .layout
        .list
        .expect("findings table registered for hit-testing");
    let n = s.findings.filtered_indices.len();
    assert!(n >= 3);
    press(
        &mut s,
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            hit.rows_area.x + 2,
            hit.rows_area.y + 2,
        ),
    );
    assert_eq!(s.findings.table.selected(), Some(2));
    assert!(!s.findings.detail_open);
    press(
        &mut s,
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            hit.rows_area.x + 2,
            hit.rows_area.y + 2,
        ),
    );
    assert!(s.findings.detail_open, "clicking the selected row opens it");

    // wheel moves the selection; clicks outside rows do nothing
    press(&mut s, mouse(MouseEventKind::ScrollUp, 5, 5));
    assert_eq!(s.findings.table.selected(), Some(0));
    press(&mut s, mouse(MouseEventKind::ScrollDown, 5, 5));
    assert!(s.findings.table.selected().unwrap() > 0);
    let before = s.findings.table.selected();
    press(
        &mut s,
        mouse(MouseEventKind::Down(MouseButton::Left), 0, 29),
    );
    assert_eq!(s.findings.table.selected(), before);
}

// ---------------- key handling effects ----------------

#[test]
fn quit_rescan_and_refresh_commands() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    assert_eq!(s.handle_command(Command::Refresh), Effect::None);
    assert_eq!(s.handle_command(Command::Rescan), Effect::StartScan);
    s.scan_status = ScanStatus::Scanning;
    assert_eq!(
        s.handle_command(Command::Rescan),
        Effect::None,
        "no overlapping scans"
    );
    assert!(s.message.as_deref().unwrap().contains("already running"));
    s.scan_status = ScanStatus::Ready;
    assert!(s.running);
    press(
        &mut s,
        Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
    );
    assert!(!s.running, "Ctrl-C quits");
}

// ---------------- scan lifecycle & worker (RW-TUI-007/009/037) ----------------

fn request(root: &std::path::Path) -> ScanRequest {
    ScanRequest {
        root: root.to_path_buf(),
        config: ScanConfig {
            top_files: 200,
            ..ScanConfig::default()
        },
        analysis: AnalysisConfig::default(),
        nix_gc: false,
    }
}

fn run_until_ready(app: &mut App) {
    loop {
        let ev = app.events.next().expect("worker keeps the channel open");
        app.update(ev);
        match &app.state.scan_status {
            ScanStatus::Ready | ScanStatus::Failed(_) => break,
            _ => {}
        }
    }
    app.join_worker();
}

#[test]
fn worker_scan_flows_through_events_into_state_and_renders() {
    let fx = tree_fixture();
    let mut app = App::new(request(&fx.root), EventHandler::headless());
    assert_eq!(app.state.scan_status, ScanStatus::Idle);
    app.start_scan();
    assert_eq!(
        app.state.scan_status,
        ScanStatus::Scanning,
        "UI is in scanning state before any result exists"
    );
    assert!(!app.state.ready());

    let mut saw_scanned = false;
    let mut saw_analyzing = false;
    loop {
        let ev = app.events.next().unwrap();
        let is_scan_done = matches!(ev, Event::ScanFinished(_));
        app.update(ev);
        if is_scan_done {
            saw_scanned = app.state.result.is_some() && app.state.analysis.is_none();
            saw_analyzing = app.state.scan_status == ScanStatus::Analyzing;
            // a half-done state must render as a status screen, not data
            assert!(draw(&mut app.state, 80, 24).contains("Analyzing"));
        }
        if app.state.scan_status == ScanStatus::Ready {
            break;
        }
    }
    app.join_worker();
    assert!(
        saw_scanned && saw_analyzing,
        "scan result arrives before the analysis"
    );
    assert!(app.state.ready());
    assert!(app.state.scan_secs.is_some());

    // identical to scanning + analysing directly: the UI adds nothing
    let direct = scan_fx(&fx);
    let r = app.state.result.clone().unwrap();
    assert_eq!(r.totals.allocated_bytes, direct.totals.allocated_bytes);
    assert_eq!(r.totals.counts.entries, direct.totals.counts.entries);
    let a: Arc<AnalysisResult> = app.state.analysis.clone().unwrap();
    assert_eq!(
        a.coverage.completeness,
        analyze(&direct, &AnalysisConfig::default())
            .coverage
            .completeness
    );

    app.state.view = View::Overview;
    let out = draw(&mut app.state, 100, 30);
    assert!(out.contains("ready"), "{out}");
    assert!(out.contains("Largest areas"));
}

#[test]
fn rescan_resets_every_piece_of_state_and_finishes_again() {
    let fx = tree_fixture();
    let mut app = App::new(request(&fx.root), EventHandler::headless());
    app.start_scan();
    run_until_ready(&mut app);

    // dirty the UI state
    app.update(ch('3'));
    app.update(ch('j'));
    app.update(key(KeyCode::Right));
    app.update(key(KeyCode::Enter));
    app.update(ch('/'));
    app.update(ch('a'));
    app.update(key(KeyCode::Enter));
    assert!(app.state.tree.expanded.len() > 1 && app.state.tree.filter == "a");

    fx.file("brand-new/file", 2 * MIB); // the filesystem changed meanwhile
    app.update(ch('r'));
    assert_eq!(app.state.scan_status, ScanStatus::Scanning);
    assert!(
        app.state.result.is_none() && app.state.analysis.is_none(),
        "previous results cannot leak"
    );
    assert!(app.state.tree.expanded.is_empty() && app.state.tree.filter.is_empty());
    assert!(app.state.findings.filtered_indices.is_empty());
    assert!(!app.state.search.active && app.state.search.input.value().is_empty());
    assert_eq!(app.state.view, View::Tree, "the current view is kept");

    // pressing r while scanning does not start a second worker
    app.update(ch('r'));
    assert_eq!(
        app.state.message.as_deref(),
        Some("a scan is already running")
    );

    run_until_ready(&mut app);
    assert!(app.state.ready());
    let r = app.state.result.clone().unwrap();
    assert!(
        r.top_files
            .iter()
            .any(|f| f.path.ends_with("brand-new/file")),
        "the rescan saw the new file"
    );
    assert_eq!(
        app.state.tree.expanded.len(),
        1,
        "fresh tree: only the root is expanded"
    );
    assert_eq!(app.state.tree.selected_node(), Some(r.root_node()));
}

#[test]
fn failed_scans_surface_the_error_and_allow_retry() {
    let mut app = App::new(
        request(std::path::Path::new("/definitely/not/here")),
        EventHandler::headless(),
    );
    app.start_scan();
    run_until_ready(&mut app);
    match &app.state.scan_status {
        ScanStatus::Failed(m) => assert!(m.contains("/definitely/not/here"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(!app.state.ready());
    assert!(draw(&mut app.state, 80, 24).contains("Scan failed"));
    // retry works from the failed state
    let fx = tree_fixture();
    app.update(ch('r'));
    assert_eq!(app.state.scan_status, ScanStatus::Scanning);
    run_until_ready(&mut app);
    assert!(
        matches!(app.state.scan_status, ScanStatus::Failed(_)),
        "same bad root fails again, cleanly"
    );
    drop(fx);
}

#[test]
fn stale_or_out_of_order_events_are_ignored() {
    let mut s = AppState::new(PathBuf::from("/x"), String::new());
    // results with no scan running must not create a "ready" state
    s.handle_event(Event::ScanFinished(Err("late".into())));
    assert_eq!(s.scan_status, ScanStatus::Idle);
    s.handle_event(Event::ScanProgress(Default::default()));
    assert!(s.progress.is_none());
    s.begin_scan();
    s.handle_event(Event::AnalysisFinished(Err("early".into())));
    assert_eq!(
        s.scan_status,
        ScanStatus::Scanning,
        "analysis cannot arrive before the scan"
    );
}

#[test]
fn progress_events_update_the_live_counters() {
    let fx = Fixture::new("tuiprog");
    for i in 0..50 {
        fx.file(&format!("d{i}/f"), 100);
    }
    let progress = Arc::new(rootwatch::scanner::ScanProgress::default());
    let cfg = ScanConfig {
        progress: Some(progress.clone()),
        ..ScanConfig::default()
    };
    let r = scan(&fx.root, &cfg).unwrap();
    let snap = progress.snapshot();
    assert_eq!(
        snap.directories,
        r.index.len() as u64,
        "every directory was read once"
    );
    assert_eq!(snap.entries, r.totals.counts.entries);
    // progress counts file bytes only; directory inode blocks are accounted separately
    assert!(snap.bytes > 0 && snap.bytes <= r.totals.allocated_bytes);
    assert!(
        snap.current_path.is_some(),
        "the first directory always publishes a path"
    );
}

// ---------------- regressions found while building the views ----------------

#[test]
fn footer_always_keeps_help_and_quit_visible_at_80_columns() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    let check = |s: &mut AppState, what: &str| {
        let out = draw(s, 80, 24);
        let footer = out.lines().last().unwrap().to_string();
        assert!(
            footer.contains("Quit") && footer.contains("Help"),
            "{what}: {footer:?}"
        );
        assert!(footer.chars().count() <= 80);
    };
    for v in View::ALL {
        s.view = v;
        check(&mut s, &format!("{v:?}"));
    }
    s.view = View::Tree;
    s.tree.set_filter(&s.result.clone().unwrap(), "a");
    check(&mut s, "tree search results");
    // more hints than fit: the least important are the ones dropped
    use rootwatch::tui::widgets::footer::{fit_hints, hints};
    s.view = View::Tree;
    s.tree.set_filter(&s.result.clone().unwrap(), "");
    let fitted = fit_hints(hints(&s), 30);
    assert!(fitted.iter().any(|h| h.1 == "Quit") && fitted.iter().any(|h| h.1 == "Help"));
    assert!(fitted.len() < hints(&s).len());
}

#[test]
fn finding_details_show_coverage_and_growth_even_at_80x24() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    press(&mut s, ch('2'));
    press(&mut s, key(KeyCode::Enter));
    let out = draw(&mut s, 80, 24);
    for needle in ["Confidence", "Growth", "Reasons", "Size", "Score"] {
        assert!(out.contains(needle), "{needle} cut off at 80x24:\n{out}");
    }
}

#[test]
fn titled_findings_are_distinguishable_and_wording_is_natural() {
    use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};
    let fx = Fixture::new("tuiwording");
    fx.file("t/old/blob", 12 * MIB);
    fx.set_age_days("t/old/blob", 60, NOW);
    let mut c = ScanConfig {
        now_unix: Some(NOW),
        ..ScanConfig::default()
    };
    c.zones = ZoneConfig {
        rules: vec![ZoneRule::zone(
            fx.path("t").to_str().unwrap(),
            PathClass::Temporary,
            Role::TempZone,
        )],
        excluded: vec![],
    };
    let mut r = scan(&fx.root, &c).unwrap();
    make_disk(&mut r, 50 * MIB as u64, 40 * MIB as u64);
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            temp_stale_min_bytes: MIB as u64,
            ..Default::default()
        },
    );
    let mut s = AppState::new(fx.root.clone(), String::new());
    s.begin_scan();
    s.scan_finished(Arc::new(r));
    s.analysis_finished(Arc::new(a));
    s.view = View::Findings;
    // at the narrowest width the *title* must still be recognisable
    let out = draw(&mut s, 80, 24);
    assert!(
        out.contains("stale temporary data"),
        "title start visible:\n{out}"
    );
    s.view = View::Tree;
    s.tree.detail_open = true;
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains("(60 days ago)") && !out.contains("ago ago"),
        "{out}"
    );
    assert!(out.contains("never scored"), "root explained:\n{out}");
}

#[test]
fn dashboard_counts_are_internally_consistent() {
    let fx = tree_fixture();
    let mut s = findings_state(&fx);
    let a = s.analysis.clone().unwrap();
    let total: u64 = a.severity_counts.iter().sum();
    let out = draw(&mut s, 100, 30);
    assert!(
        out.contains(&format!("{total} in total, {} listed", a.findings.len())),
        "{out}"
    );
}

// ---------------- remaining RW-TUI-037 scenarios ----------------

#[test]
fn multiple_pools_show_scanned_and_unscanned_with_their_mounts() {
    use rootwatch::mounts::FsKind;
    let fx = tree_fixture();
    let mut s = ready_state(&fx, |r| {
        make_disk(r, 100 << 30, 40 << 30);
        r.pools.push(StoragePool {
            label: "/dev/sdb1".into(),
            fstype: "ext4".into(),
            kind: FsKind::Disk,
            info: FilesystemInfo {
                total_bytes: 4000 << 30,
                used_bytes: 3000 << 30,
                available_bytes: 1000 << 30,
            },
        });
        r.mount_boundaries.push(MountBoundary {
            path: PathBuf::from("/mnt/data"),
            filesystem: r.pools[1].info.clone(),
            device: 7,
            mount_id: Some(3),
            fstype: "ext4".into(),
            source: "/dev/sdb1".into(),
            kind: FsKind::Disk,
            pool: 1,
            decision: BoundaryDecision::Skipped(SkipReason::OutOfScope),
        });
    });
    s.view = View::Pools;
    let root_pool_label = s
        .result
        .as_ref()
        .expect("ready state has a scan result")
        .pools[0]
        .label
        .clone();
    let out = draw(&mut s, 110, 30);
    assert!(
        out.contains(&root_pool_label) && out.contains("/dev/sdb1"),
        "{out}"
    );
    assert!(
        out.contains("not scanned"),
        "unscanned pool is labelled: {out}"
    );
    assert_eq!(s.pools.rows.len(), 2);
    // select the second pool: its skipped mount and the reason are listed
    press(&mut s, ch('j'));
    let out = draw(&mut s, 110, 30);
    assert!(
        out.contains("/mnt/data") && out.contains("outside the selected scope"),
        "{out}"
    );
    // the Overview jump goes to the matching pool
    s.view = View::Overview;
    press(&mut s, ch('j'));
    press(&mut s, key(KeyCode::Enter));
    assert_eq!(s.view, View::Pools);
    // the separate disk does not turn the coverage into a hole
    s.view = View::Coverage;
    draw(&mut s, 110, 30);
    assert!(
        !draw(&mut s, 110, 30).contains("Separate disks not counted"),
        "below the fold until scrolled"
    );
    press(&mut s, ch('G')); // bottom: the renderer clamps to the real content height
    let out = draw(&mut s, 110, 30);
    assert!(
        out.contains("Separate disks not counted") && out.contains("/mnt/data"),
        "{out}"
    );
    assert!(
        s.coverage.scroll < u16::MAX,
        "scroll offset was clamped to the content"
    );
    press(&mut s, ch('g'));
    assert_eq!(s.coverage.scroll, 0);
}

#[test]
fn permission_errors_flow_through_the_worker_into_the_coverage_view() {
    if is_root() {
        eprintln!("SKIP: root bypasses permissions (run the test binary as an unprivileged user)");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new("tuiperm");
    fx.file("open/f", 20_000);
    fx.file("locked/secret", 900_000);
    std::fs::set_permissions(fx.path("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut app = App::new(request(&fx.root), EventHandler::headless());
    app.start_scan();
    run_until_ready(&mut app);
    std::fs::set_permissions(fx.path("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(app.state.ready());
    assert_eq!(app.state.coverage.facts.denied_total, 1);
    app.update(ch('5'));
    let out = draw(&mut app.state, 100, 30);
    assert!(out.contains("Permission denied (1)"), "{out}");
    assert!(out.contains("locked"), "{out}");
    assert!(out.contains("1 permission denied"), "summary line: {out}");
    // the tree marks the directory
    app.update(ch('3'));
    app.update(key(KeyCode::Right));
    let out = draw(&mut app.state, 100, 30);
    assert!(out.contains("locked (denied)"), "{out}");
    // and the overview reports the issue
    app.update(ch('1'));
    assert!(draw(&mut app.state, 100, 30).contains("1 permission denied"));
}

#[test]
fn subtree_scans_say_so_instead_of_showing_a_fake_coverage_percentage() {
    let fx = tree_fixture();
    let mut s = ready_state(&fx, |_| {});
    let a = s.analysis.clone().unwrap();
    assert!(a.coverage.subtree);
    let out = draw(&mut s, 100, 30);
    assert!(out.contains("n/a (subtree scan)"), "{out}");
    s.view = View::Coverage;
    assert!(draw(&mut s, 100, 30).contains("does not apply to a scan of a directory"));
}
