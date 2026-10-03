// SPDX-License-Identifier: GPL-3.0-only
//
// Human-readable report. Rendered into a String and written once, so a closed
// pipe (`rootwatch | head`) ends quietly instead of panicking.

use crate::analysis::*;
use crate::coverage::GapKind;
use crate::model::*;
use crate::nix::GcEstimate;
use crate::privilege::PermissionImpact;
use crate::temp::age_days;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

const ISSUE_LIMIT: usize = 12;
const FINDING_LIMIT: usize = 12;

pub struct ReportOptions<'a> {
    pub top: usize,
    pub permission: Option<&'a PermissionImpact>,
    pub permission_error: Option<&'a str>,
    pub privileged_run: bool,
}

pub fn format_bytes(bytes: u64) -> String {
    fmt_bytes(bytes)
}

pub fn format_percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0.0%".to_string();
    }
    format!("{:.1}%", (part as f64 / whole as f64) * 100.0)
}

macro_rules! p {
    ($o:expr) => { { let _ = writeln!($o); } };
    ($o:expr, $($a:tt)*) => { { let _ = writeln!($o, $($a)*); } };
}

fn age_label(days: Option<u64>) -> String {
    match days {
        Some(0) => "today".into(),
        Some(d) => format!("{d}d ago"),
        None => "n/a".into(),
    }
}

fn age_line(age: &[u64; AGE_BUCKETS], total: u64) -> String {
    (0..AGE_BUCKETS)
        .map(|i| format!("{} {}", AGE_LABELS[i], format_percent(age[i], total)))
        .collect::<Vec<_>>()
        .join("  ")
}

pub fn render_report(
    result: &ScanResult,
    analysis: &AnalysisResult,
    elapsed: Duration,
    opts: &ReportOptions,
) -> String {
    let mut o = String::new();
    let top = opts.top.max(1);
    let cov = &analysis.coverage;

    p!(o, "rootwatch v{}", env!("CARGO_PKG_VERSION"));
    p!(o, "root:                 {}", result.root.display());
    p!(o, "scope:                {}", result.scope.label());
    if opts.privileged_run {
        p!(o, "privileges:           running as root");
    }
    p!(o);

    // ---- filesystems ----
    p!(o, "filesystems scanned");
    for fs in &result.filesystems {
        let pool = &result.pools[fs.pool];
        p!(
            o,
            "  {}  [{} / {}]  pool: {} used / {} total ({})",
            fs.mountpoint.display(),
            fs.fstype,
            fs.kind.label(),
            format_bytes(pool.info.used_bytes),
            format_bytes(pool.info.total_bytes),
            format_percent(pool.info.used_bytes, pool.info.total_bytes)
        );
        p!(
            o,
            "      walked {} here, available {}",
            format_bytes(fs.walked_bytes),
            format_bytes(pool.info.available_bytes)
        );
    }
    p!(o);

    p!(o, "scan");
    p!(o, "  entries:            {}", result.totals.counts.entries);
    p!(o, "  regular files:      {}", result.totals.counts.regular_files);
    p!(o, "  directories:        {}", result.totals.counts.directories);
    p!(o, "  symlinks:           {}", result.totals.counts.symlinks);
    p!(o, "  other:              {}", result.totals.counts.other);
    p!(o, "  inaccessible/errors: {}", result.totals.counts.errors);
    p!(o, "  walked allocation:  {}", format_bytes(result.totals.allocated_bytes));
    p!(o, "  elapsed:            {:.2}s", elapsed.as_secs_f64());
    p!(o);

    // ---- coverage ----
    p!(o, "coverage");
    if cov.subtree {
        p!(o, "  subtree scan: whole-filesystem coverage is not applicable");
    } else {
        p!(
            o,
            "  walked {} of {} used across scanned filesystems ({:.1}%)",
            format_bytes(cov.walked_bytes),
            format_bytes(cov.used_bytes),
            cov.coverage_percent
        );
    }
    p!(o, "  completeness:       {}", cov.completeness.label());
    p!(o, "  confidence:         {}", cov.confidence.label());
    for pc in &cov.pools {
        if cov.subtree {
            break;
        }
        p!(
            o,
            "  pool {}: {:.1}% walked ({} of {}), confidence {}",
            pc.label,
            pc.coverage_percent,
            format_bytes(pc.walked_bytes),
            format_bytes(pc.used_bytes),
            pc.confidence.label()
        );
    }
    if !cov.gaps.is_empty() {
        p!(o, "  why walked allocation differs from filesystem usage:");
        for g in &cov.gaps {
            let tag = match g.kind {
                GapKind::SkippedSamePool => "skipped mounts",
                GapKind::PermissionDenied => "permissions",
                GapKind::Unreadable => "I/O errors",
                GapKind::Pruned => "pruned",
                GapKind::SharedExtents => "overcount",
                GapKind::Unattributed => "unattributed",
            };
            match g.bytes {
                Some(b) => p!(o, "    - [{tag}] ~{}: {}", format_bytes(b), g.detail),
                None => p!(o, "    - [{tag}] {}", g.detail),
            }
        }
    }
    for a in &cov.advice {
        p!(o, "  hint: {a}");
    }
    p!(o);

    // ---- scope boundaries ----
    p!(o, "scan scope");
    let skipped: Vec<_> = result
        .mount_boundaries
        .iter()
        .filter(|b| matches!(b.decision, BoundaryDecision::Skipped(_)))
        .collect();
    if skipped.is_empty() {
        p!(o, "  skipped mount boundaries: none");
    } else {
        p!(o, "  skipped mount boundaries: {}", skipped.len());
        for b in skipped.iter().take(top) {
            let reason = match b.decision {
                BoundaryDecision::Skipped(r) => r.label(),
                BoundaryDecision::Entered => "",
            };
            p!(
                o,
                "  {:>12} used / {:>12} total ({:>6})  dev {:>8x}  {:<8} {}  -- {}",
                format_bytes(b.filesystem.used_bytes),
                format_bytes(b.filesystem.total_bytes),
                format_percent(b.filesystem.used_bytes, b.filesystem.total_bytes),
                b.device,
                b.fstype,
                b.path.display(),
                reason
            );
        }
        if skipped.len() > top {
            p!(o, "  ... {} more", skipped.len() - top);
        }
    }
    if !cov.out_of_scope.is_empty() {
        p!(o, "  separate disks not counted in coverage:");
        for f in cov.out_of_scope.iter().take(top) {
            p!(
                o,
                "    {} [{}] {} used / {} total",
                f.path.display(),
                f.kind.label(),
                format_bytes(f.used_bytes),
                format_bytes(f.total_bytes)
            );
        }
    }
    p!(o);

    // ---- rankings, with an honesty banner ----
    let (rel, caveat) = analysis.ranking_reliability();
    p!(o, "top-level directories");
    if let Some(c) = &caveat {
        p!(o, "  !! {c}");
    }
    for id in result.top_level_directories().into_iter().take(top) {
        let n = result.index.node(id);
        let tag = if n.flags & flags::SKIPPED_MOUNT != 0 { "  (mount, not scanned)" } else { "" };
        p!(
            o,
            "  {:>12}  {:>7}  {}{}",
            format_bytes(n.usage.bytes),
            format_percent(n.usage.bytes, result.totals.allocated_bytes),
            result.index.path(id).display(),
            tag
        );
    }
    p!(o, "  (percent of walked allocation)");
    p!(o);
    p!(o, "largest directories{}", match rel {
        Reliability::Reliable => "",
        Reliability::Provisional => "  [PROVISIONAL]",
        Reliability::Unreliable => "  [UNRELIABLE]",
    });
    if let Some(c) = &caveat {
        p!(o, "  !! {c}");
    }
    for id in result.largest_directories(top) {
        let n = result.index.node(id);
        let pool = result.pool_of(id);
        p!(
            o,
            "  {:>12}  {:>7}  {}",
            format_bytes(n.usage.bytes),
            format_percent(n.usage.fs_bytes, pool.info.total_bytes),
            result.index.path(id).display()
        );
    }
    p!(o, "  (percent of filesystem capacity)");
    p!(o);

    // ---- analysis ----
    p!(o, "analysis");
    let qual = match analysis.overall.qualifier {
        Qualifier::Confirmed => "".to_string(),
        Qualifier::AtLeast => " (at least: scan incomplete)".to_string(),
        Qualifier::Undetermined => format!(
            " (UNDETERMINED: only {:.1}% of used space seen, cannot call this healthy)",
            cov.coverage_percent
        ),
    };
    p!(o, "  overall severity:   {}{}", analysis.overall.severity.label(), qual);
    p!(
        o,
        "  risk score:         {:.0}/100 ({})",
        analysis.risk.score,
        analysis.risk.level.label()
    );
    for c in analysis.risk.components.iter().filter(|c| c.value > 0.0) {
        p!(o, "    {:<15} {:>4.0}%  {}", c.name, c.value * 100.0, c.detail);
    }
    for ps in &analysis.pool_scores {
        p!(
            o,
            "  filesystem {}: {:.1}% full, {} free -> {} (urgency x{:.2})",
            ps.label,
            ps.used_percent,
            format_bytes(ps.available_bytes),
            ps.severity.label(),
            ps.urgency
        );
    }
    p!(
        o,
        "  findings:           {} candidates  (critical {} / high {} / medium {} / low {})",
        analysis.candidates,
        analysis.severity_count(Severity::Critical),
        analysis.severity_count(Severity::High),
        analysis.severity_count(Severity::Medium),
        analysis.severity_count(Severity::Low)
    );
    p!(
        o,
        "  ownership:          system {}, users {}, other {}",
        format_bytes(result.ownership.system_bytes),
        format_bytes(result.ownership.user_bytes),
        format_bytes(result.ownership.other_bytes)
    );
    for f in analysis.ranked().take(FINDING_LIMIT) {
        let lb = if f.lower_bound { ">=" } else { "  " };
        p!(
            o,
            "  {:<8} score {:>5.1} size {}{:>12} fs-used {:>6.1}% {:<10} {:<9} {}",
            f.severity.label(),
            f.score,
            lb,
            format_bytes(f.bytes),
            f.percent_of_fs_used,
            f.expectation.label(),
            f.class.label(),
            f.path.display()
        );
        if let Some(t) = &f.title {
            p!(o, "             about: {t}");
        }
        for r in &f.reasons {
            p!(o, "             reason: {r}");
        }
    }
    if analysis.findings.len() > FINDING_LIMIT {
        p!(o, "  ... {} more findings", analysis.findings.len() - FINDING_LIMIT);
    }
    p!(o);

    // ---- temp ----
    if !analysis.temp.is_empty() {
        p!(o, "temporary data");
        for t in &analysis.temp {
            p!(
                o,
                "  {}  [{}{}]  {}  {} of fs used  assessment: {}",
                t.label,
                t.fstype,
                if t.ram_backed { ", RAM-backed" } else { "" },
                format_bytes(t.bytes),
                format!("{:.1}%", t.percent_of_fs_used),
                t.assessment.label()
            );
            p!(
                o,
                "      {} files, newest change {}; stale (>{}d): {} ({:.0}%)",
                t.files,
                age_label(t.newest_age_days),
                t.stale_after_days,
                format_bytes(t.stale_bytes),
                t.stale_percent
            );
            p!(o, "      by age: {}", age_line(&t.age, t.bytes));
            for ow in t.owners.iter().take(3) {
                p!(o, "      owner {:<12} {:>12} ({:.0}%)", ow.name, format_bytes(ow.bytes), ow.percent);
            }
            for c in t.top_children.iter().take(5) {
                p!(
                    o,
                    "      {:>12}  {}  (owner {}, changed {})",
                    format_bytes(c.bytes),
                    c.path.display(),
                    c.owner,
                    age_label(c.newest_age_days)
                );
            }
        }
        p!(o);
    }

    // ---- home ----
    for h in &analysis.home {
        p!(
            o,
            "home: {}  (owner {})  {}  {:.1}% of fs used",
            h.label,
            h.owner_name,
            format_bytes(h.bytes),
            h.percent_of_fs_used
        );
        p!(
            o,
            "      owned by {}: {}, root-owned: {}, other users: {}",
            h.owner_name,
            format_bytes(h.owned_by_user_bytes),
            format_bytes(h.root_owned_bytes),
            format_bytes(h.other_owned_bytes)
        );
        p!(o, "      by age: {}", age_line(&h.age, h.bytes));
        for b in h.buckets.iter().take(8) {
            p!(
                o,
                "      {:>12} {:>5.1}%  {:<28} stale(>90d) {}",
                format_bytes(b.bytes),
                b.percent_of_home,
                b.bucket.label(),
                format_bytes(b.stale_bytes)
            );
            for (path, bytes) in b.top_children.iter().take(2) {
                p!(o, "          {:>12}  {}", format_bytes(*bytes), path.display());
            }
        }
        if !h.projects.is_empty() {
            p!(
                o,
                "      projects: {} total, {} of it regenerable build artifacts",
                format_bytes(h.project_total_bytes),
                format_bytes(h.artifact_total_bytes)
            );
            for pr in h.projects.iter().take(5) {
                let arts = if pr.artifacts.is_empty() {
                    String::new()
                } else {
                    format!(
                        "  [{}]",
                        pr.artifacts
                            .iter()
                            .map(|(n, b)| format!("{n} {}", format_bytes(*b)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                p!(
                    o,
                    "          {:>12}  {} ({}){}",
                    format_bytes(pr.bytes),
                    pr.path.display(),
                    pr.kind.label(),
                    arts
                );
            }
        }
        for f in h.large_files.iter().take(3) {
            p!(o, "      large file {:>12}  {}", format_bytes(f.allocated_bytes), f.path.display());
        }
        p!(o);
    }

    // ---- nix ----
    if let Some(n) = &analysis.nix {
        p!(o, "nix");
        for line in &n.explanation {
            p!(o, "  - {line}");
        }
        if let Some(db) = n.db_bytes {
            p!(o, "  database: {}  profiles: {}", format_bytes(db), format_bytes(n.profiles_bytes.unwrap_or(0)));
        }
        if !n.top_packages.is_empty() {
            p!(o, "  largest packages (all versions):");
            for pk in n.top_packages.iter().take(5) {
                p!(o, "    {:>12}  {} ({} path{})", format_bytes(pk.bytes), pk.name, pk.versions, if pk.versions == 1 { "" } else { "s" });
            }
        }
        if let GcEstimate::Estimated { measured_paths, dead_paths, .. } = n.gc {
            p!(o, "  gc estimate sized {measured_paths} of {dead_paths} dead paths");
        }
        for s in &n.suggestions {
            p!(o, "  note: {s}");
        }
        p!(o);
    }

    // ---- permission impact ----
    if let Some(pi) = opts.permission {
        p!(o, "permission impact");
        let pct = |v: f64| if cov.subtree { "n/a".to_string() } else { format!("{v:.1}%") };
        p!(
            o,
            "  unprivileged walked {} (coverage {}), privileged walked {} (coverage {})",
            format_bytes(pi.unprivileged_bytes),
            pct(pi.unprivileged_coverage),
            format_bytes(pi.privileged_bytes),
            pct(pi.privileged_coverage)
        );
        p!(
            o,
            "  hidden by permissions: {} in {} entries across {} denied path(s)",
            format_bytes(pi.hidden_bytes),
            pi.hidden_entries,
            pi.denied_paths
        );
        for (path, bytes) in pi.hidden_dirs.iter().take(top.min(10)) {
            p!(o, "    {:>12}  {}", format_bytes(*bytes), path.display());
        }
        if pi.denied_dirs_not_listed > 0 {
            p!(o, "    ... {} smaller denied path(s) not listed", pi.denied_dirs_not_listed);
        }
        p!(o);
    } else if let Some(e) = opts.permission_error {
        p!(o, "permission impact");
        p!(o, "  privileged comparison failed: {e}");
        p!(o);
    }

    if !result.top_files.is_empty() {
        p!(o, "largest files");
        for f in result.top_files.iter().take(top.min(10)) {
            p!(
                o,
                "  {:>12}  {}  (changed {})",
                format_bytes(f.allocated_bytes),
                f.path.display(),
                age_label(age_days(result.started_unix, f.mtime))
            );
        }
        p!(o);
    }

    p!(o, "scan issues");
    p!(o, "  total:              {}", result.issues.len());
    p!(o, "  permission denied:  {}", result.permission_denied_count());
    for issue in result.issues.iter().take(ISSUE_LIMIT) {
        let label = match issue.kind {
            ScanIssueKind::PermissionDenied => "permission",
            ScanIssueKind::Io => "io",
        };
        p!(o, "  [{label}] {}: {}", issue.path.display(), issue.message);
    }
    if result.issues.len() > ISSUE_LIMIT {
        p!(o, "  ... {} more", result.issues.len() - ISSUE_LIMIT);
    }
    if result.root == Path::new("/") {
        p!(o);
        p!(o, "note: /proc, /sys, /dev and /run are excluded by default");
    }
    o
}
