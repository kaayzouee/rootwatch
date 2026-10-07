// SPDX-License-Identifier: GPL-3.0-only
//  Copyright (C) 2026 kaayzouee
// Author: https://github.com/kaayzouee
mod common;

use common::*;
use rootwatch::analysis::*;
use rootwatch::coverage::{Completeness, GapKind, ScanConfidence};
use rootwatch::model::*;
use rootwatch::mounts::FsKind;
use rootwatch::scanner::{ScanConfig, scan};
use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};
use std::path::PathBuf;

const NOW: i64 = 1_800_000_000;
const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

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

/// Pretend the scanned filesystem is a whole-disk scan of a 100 GiB disk that
/// has `used_pct` percent used
fn as_disk(r: &mut ScanResult, used_pct: u64) {
    r.subtree_scan = false;
    let total = 100 * GIB;
    let used = total / 100 * used_pct;
    let info = FilesystemInfo {
        total_bytes: total,
        used_bytes: used,
        available_bytes: total - used,
    };
    r.pools[0].info = info.clone();
    r.filesystems[0].info = info.clone();
    r.filesystem = info;
}

/// Replace the pool with an explicit total/used pair (pressure follows)
fn with_pool(r: &mut ScanResult, total: u64, used: u64) {
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

fn big_fixture() -> Fixture {
    let fx = Fixture::new("an");
    fx.file("hog/a.bin", 6 * MIB as usize);
    fx.file("hog/b.bin", 6 * MIB as usize);
    fx.file("other/c.bin", 2 * MIB as usize);
    fx
}

#[test]
fn low_coverage_scans_are_flagged_unreliable_and_undetermined() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    as_disk(&mut r, 95); // 95 GiB "used", we saw ~14 MiB: the 0.5% situation
    let a = analyze(&r, &AnalysisConfig::default());
    assert_eq!(a.coverage.completeness, Completeness::Minimal);
    assert_eq!(a.confidence, ScanConfidence::Low);
    let (rel, caveat) = a.ranking_reliability();
    assert_eq!(rel, Reliability::Unreliable);
    assert!(caveat.unwrap().contains("do NOT show where the space went"));
    assert!(
        a.findings
            .iter()
            .all(|f| f.lower_bound && f.confidence == ScanConfidence::Low)
    );
    // The disk is 95% full: capacity alone is critical, and it must not be
    // reported as "confirmed" nor as healthy
    assert_eq!(a.overall.severity, Severity::Critical);
    assert_eq!(a.overall.qualifier, Qualifier::AtLeast);
    assert!(
        a.risk
            .components
            .iter()
            .any(|c| c.name == "blind spot" && c.value > 0.9)
    );
}

#[test]
fn healthy_disk_with_low_coverage_is_undetermined_not_healthy() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    as_disk(&mut r, 30);
    // pretend 30 GiB used but only a sliver seen
    let a = analyze(&r, &AnalysisConfig::default());
    assert_eq!(a.overall.severity, Severity::Low);
    assert_eq!(a.overall.qualifier, Qualifier::Undetermined);
}

#[test]
fn complete_scan_is_confirmed_and_reliable() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    // make filesystem usage equal to what we walked
    let used = r.totals.allocated_bytes;
    r.subtree_scan = false;
    r.pools[0].info = FilesystemInfo {
        total_bytes: 100 * GIB,
        used_bytes: used,
        available_bytes: 100 * GIB - used,
    };
    let a = analyze(&r, &AnalysisConfig::default());
    assert_eq!(a.coverage.completeness, Completeness::Complete);
    assert_eq!(a.ranking_reliability().0, Reliability::Reliable);
    assert_eq!(a.overall.qualifier, Qualifier::Confirmed);
}

#[test]
fn subtree_scans_do_not_pretend_coverage_matters() {
    let fx = big_fixture();
    let r = scan_fx(&fx);
    assert!(r.subtree_scan || r.mounts.is_empty());
    let a = analyze(&r, &AnalysisConfig::default());
    if r.subtree_scan {
        assert!(a.coverage.subtree);
        assert_eq!(a.coverage.completeness, Completeness::Complete);
        assert_eq!(a.confidence, ScanConfidence::High);
        assert!(
            a.coverage
                .gaps
                .iter()
                .all(|g| g.kind != GapKind::Unattributed)
        );
    }
}

#[test]
fn skipped_sibling_mounts_on_a_shared_pool_explain_the_gap() {
    // The checklist's "95 GiB used, 520 MiB observed" case: btrfs-style siblings
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    as_disk(&mut r, 95);
    r.mount_boundaries.push(MountBoundary {
        path: PathBuf::from("/nix"),
        filesystem: r.pools[0].info.clone(),
        device: 0x42,
        mount_id: Some(9),
        fstype: "btrfs".into(),
        source: "/dev/mapper/crypt".into(),
        kind: FsKind::Disk,
        pool: 0,
        decision: BoundaryDecision::Skipped(SkipReason::OutOfScope),
    });
    let a = analyze(&r, &AnalysisConfig::default());
    let gap = a
        .coverage
        .gaps
        .iter()
        .find(|g| g.kind == GapKind::SkippedSamePool)
        .expect("explained");
    assert!(gap.detail.contains("/nix"));
    assert!(
        a.coverage
            .advice
            .iter()
            .any(|h| h.contains("--scope all") && h.contains("/nix"))
    );
    assert_eq!(a.coverage.pools[0].skipped, vec![PathBuf::from("/nix")]);
}

#[test]
fn separate_disks_do_not_count_against_coverage() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    let used = r.totals.allocated_bytes;
    r.subtree_scan = false;
    r.pools[0].info = FilesystemInfo {
        total_bytes: 100 * GIB,
        used_bytes: used,
        available_bytes: 100 * GIB - used,
    };
    r.pools.push(StoragePool {
        label: "/dev/sdb1".into(),
        fstype: "ext4".into(),
        kind: FsKind::Disk,
        info: FilesystemInfo {
            total_bytes: 4000 * GIB,
            used_bytes: 3000 * GIB,
            available_bytes: 1000 * GIB,
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
    let a = analyze(&r, &AnalysisConfig::default());
    assert_eq!(
        a.coverage.completeness,
        Completeness::Complete,
        "a different disk is not a coverage hole"
    );
    assert_eq!(a.coverage.out_of_scope.len(), 1);
    assert_eq!(a.coverage.out_of_scope[0].path, PathBuf::from("/mnt/data"));
}

#[test]
fn urgency_makes_the_same_directory_worse_on_a_fuller_disk() {
    let fx = big_fixture();
    let sev_at = |pct| {
        let mut r = scan_fx(&fx);
        as_disk(&mut r, pct);
        // keep the share constant: used == 100 MiB-ish scaled
        r.pools[0].info.used_bytes = r.pools[0].info.total_bytes / 100 * pct;
        let a = analyze(
            &r,
            &AnalysisConfig {
                min_finding_bytes: MIB,
                ..Default::default()
            },
        );
        a.findings.iter().map(|f| f.score).fold(0.0, f64::max)
    };
    assert!(sev_at(30) <= sev_at(70));
    assert!(sev_at(70) < sev_at(97));
}

#[test]
fn dominant_child_chain_reports_the_frontier_not_every_ancestor() {
    let fx = Fixture::new("dom");
    fx.file("a/b/c/huge.bin", 8 * MIB as usize);
    fx.file("a/tiny", 100);
    let mut r = scan_fx(&fx);
    with_pool(&mut r, 11 * MIB, 10 * MIB);
    let a = analyze(&r, &AnalysisConfig::default());
    let paths: Vec<_> = a.findings.iter().map(|f| f.path.clone()).collect();
    assert!(
        paths.contains(&fx.path("a/b/c")),
        "deepest dominant directory is reported: {paths:?}"
    );
    assert!(
        !paths.contains(&fx.path("a/b")),
        "pass-through container suppressed"
    );
}

#[test]
fn top_k_findings_are_bounded_and_sorted() {
    let fx = Fixture::new("topk");
    for i in 0..40 {
        fx.file(&format!("d{i:02}/f"), (i + 1) * 40_000);
    }
    let mut r = scan_fx(&fx);
    as_disk(&mut r, 90);
    let cfg = AnalysisConfig {
        max_findings: 5,
        min_finding_bytes: 1,
        ..Default::default()
    };
    let a = analyze(&r, &cfg);
    assert_eq!(a.findings.len(), 5);
    assert!(a.findings.windows(2).all(|w| w[0].score >= w[1].score));
    assert!(
        a.candidates >= 40,
        "counters cover every candidate, not just the retained ones"
    );
    assert_eq!(a.severity_counts.iter().sum::<u64>(), a.candidates);
    assert_eq!(a.node_score.len(), r.index.len());
    assert_eq!(a.findings[0].path, fx.path("d39"));
}

#[test]
fn errors_below_a_directory_downgrade_its_confidence() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    let used = r.totals.allocated_bytes;
    r.subtree_scan = false;
    r.pools[0].info = FilesystemInfo {
        total_bytes: 100 * GIB,
        used_bytes: used,
        available_bytes: 0,
    };
    let hog = r
        .index
        .ids()
        .find(|&i| r.index.path(i) == fx.path("hog"))
        .unwrap();
    // inject an error under hog
    let mut idx = r.index.clone();
    let _ = &mut idx;
    // use the public aggregate: errors live in usage.counts
    let n = &mut r.index_mut_for_test(hog).usage.counts;
    n.errors = 3;
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            ..Default::default()
        },
    );
    let f = a
        .findings
        .iter()
        .find(|f| f.path == fx.path("hog"))
        .unwrap();
    assert_eq!(f.confidence, ScanConfidence::Medium);
    assert!(f.lower_bound);
    assert!(f.reasons.iter().any(|r| r.contains("inaccessible/error")));
}

#[test]
fn growth_against_a_baseline_raises_score_and_flags_suspicious() {
    let fx = Fixture::new("growth");
    fx.file("stable/f", 4 * MIB as usize);
    fx.file("grower/a", 2 * MIB as usize);
    let mut before = scan_fx(&fx);
    with_pool(&mut before, 170 * MIB, 100 * MIB);
    let baseline = Baseline::from_scan(&before, 1);
    assert!(!baseline.is_empty());

    fx.file("grower/b", 30 * MIB as usize);
    let mut after = scan(
        &fx.root,
        &ScanConfig {
            now_unix: Some(NOW + 3600),
            ..ScanConfig::default()
        },
    )
    .unwrap();
    with_pool(&mut after, 170 * MIB, 100 * MIB); // grower's +30 MiB is a big slice of "used"

    let cfg = AnalysisConfig {
        min_finding_bytes: 1,
        ..Default::default()
    };
    let plain = analyze(&after, &cfg);
    let withg = analyze_with(
        &after,
        &cfg,
        &AnalysisInputs {
            baseline: Some(&baseline),
            ..Default::default()
        },
    );

    let score = |a: &AnalysisResult, p: PathBuf| {
        a.findings
            .iter()
            .find(|f| f.path == p)
            .map(|f| f.score)
            .unwrap()
    };
    let g = withg
        .findings
        .iter()
        .find(|f| f.path == fx.path("grower"))
        .unwrap();
    let growth = g.growth.expect("growth detected");
    assert!(growth.delta_bytes >= 30 * MIB);
    assert!(growth.percent.unwrap() > 500.0);
    assert!(score(&withg, fx.path("grower")) > score(&plain, fx.path("grower")) + 10.0);
    assert_eq!(g.expectation, Expectation::Suspicious);
    assert!(g.reasons.iter().any(|r| r.contains("grew by")));
    assert!(
        withg
            .findings
            .iter()
            .find(|f| f.path == fx.path("stable"))
            .unwrap()
            .growth
            .is_none()
    );
    assert!(withg.has_baseline && !plain.has_baseline);
    assert!(
        withg
            .risk
            .components
            .iter()
            .any(|c| c.name == "growth" && c.value > 0.5)
    );
}

#[test]
fn stale_large_temp_data_becomes_a_temporary_finding() {
    let fx = Fixture::new("tmpf");
    fx.file("t/old/blob", 12 * MIB as usize);
    fx.file("t/new/blob", MIB as usize);
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
    with_pool(&mut r, 50 * MIB, 40 * MIB);
    let cfg = AnalysisConfig {
        min_finding_bytes: 1,
        temp_stale_min_bytes: MIB,
        ..Default::default()
    };
    let a = analyze(&r, &cfg);
    let t = &a.temp[0];
    assert!(matches!(
        t.assessment,
        rootwatch::temp::TempAssessment::Stale | rootwatch::temp::TempAssessment::LargeAndStale
    ));
    assert!(t.stale_bytes >= 12 * MIB && t.stale_percent > 80.0);
    assert_eq!(t.stale_after_days, 7);
    assert_eq!(t.top_children[0].path, fx.path("t/old"));
    assert!(!t.owners.is_empty());
    let f = a
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Temporary && f.title.is_some())
        .expect("temporary-data finding");
    assert!(f.title.as_ref().unwrap().contains("stale temporary data"));
    assert_eq!(f.expectation, Expectation::Suspicious);
    let old = a
        .findings
        .iter()
        .find(|f| f.path == fx.path("t/old"))
        .unwrap();
    assert_eq!(old.expectation, Expectation::Suspicious);
    assert!(old.stale_percent > 90.0);
}

#[test]
fn risk_is_a_bounded_noisy_or() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    as_disk(&mut r, 99);
    let a = analyze(&r, &AnalysisConfig::default());
    assert!(a.risk.score > 0.0 && a.risk.score <= 100.0);
    let max_component = a
        .risk
        .components
        .iter()
        .map(|c| c.value * 100.0)
        .fold(0.0, f64::max);
    assert!(
        a.risk.score >= max_component - 1e-9,
        "combining never lowers the worst component"
    );
    assert_eq!(a.risk.level, Severity::Critical);
}

#[test]
fn node_severity_vector_supports_tree_views() {
    let fx = big_fixture();
    let mut r = scan_fx(&fx);
    with_pool(&mut r, 21 * MIB, 20 * MIB); // 95% full, hog holds 60% of what is used
    let a = analyze(
        &r,
        &AnalysisConfig {
            min_finding_bytes: 1,
            ..Default::default()
        },
    );
    let hog = r
        .index
        .ids()
        .find(|&i| r.index.path(i) == fx.path("hog"))
        .unwrap();
    assert!(a.node_severity[hog.idx()] >= Severity::High);
    assert_eq!(
        a.node_score[r.root_node().idx()],
        0.0,
        "scan root is never scored"
    );
}
