// SPDX-License-Identifier: GPL-3.0-only
//
// Coverage: how much of the used space was seen, and why the rest was not.
// The completeness level is always shown as an explicit badge.

use super::{bullet, kv, kv_plain, panel, section};
use crate::analysis::AnalysisResult;
use crate::coverage::{Completeness, GapKind};
use crate::model::{BoundaryDecision, ScanResult};
use crate::tui::fmt;
use crate::tui::state::{AppState, CoverageFacts};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let (Some(r), Some(a)) = (s.result.clone(), s.analysis.clone()) else {
        return;
    };
    let [head, body] = Layout::vertical([Constraint::Length(6), Constraint::Min(3)]).areas(area);

    // ---- summary ----
    let cov = &a.coverage;
    let hb = panel("Coverage");
    let hi = hb.inner(head);
    f.render_widget(hb, head);
    let bar_color = match cov.completeness {
        Completeness::Complete => Color::Green,
        Completeness::Substantial => Color::Yellow,
        _ => Color::Red,
    };
    let top = if cov.subtree {
        Line::from(vec![
            Span::raw("n/a (subtree scan)  "),
            Span::styled(
                format!(" {} ", cov.completeness.label()),
                fmt::completeness_style(cov.completeness),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                fmt::bar(cov.coverage_percent / 100.0, 30),
                Style::new().fg(bar_color),
            ),
            Span::raw(format!(" {:.1}%  ", cov.coverage_percent)),
            Span::styled(
                format!(" {} ", cov.completeness.label()),
                fmt::completeness_style(cov.completeness),
            ),
        ])
    };
    let walked = if cov.subtree {
        "whole-filesystem coverage does not apply to a scan of a directory".to_string()
    } else {
        format!(
            "walked {} of {} used",
            fmt::bytes(cov.walked_bytes),
            fmt::bytes(cov.used_bytes)
        )
    };
    let lines = vec![
        top,
        Line::from(Span::styled(walked, fmt::dim())),
        kv(
            "Confidence",
            vec![Span::styled(
                cov.confidence.label(),
                fmt::confidence_style(cov.confidence),
            )],
        ),
        kv_plain(
            "Problems",
            format!(
                "{} permission denied, {} error entries",
                fmt::count(s.coverage.facts.denied_total as u64),
                fmt::count(cov.error_entries)
            ),
        ),
    ];
    f.render_widget(Paragraph::new(lines), hi);

    // ---- scrollable explanation ----
    let bb = panel("Why walked allocation can differ from filesystem usage");
    let bi = bb.inner(body);
    f.render_widget(bb, body);
    let lines = build_lines(&r, &a, &s.coverage.facts, bi.width as usize);
    let max_scroll = lines.len().saturating_sub(bi.height as usize) as u16;
    s.coverage.scroll = s.coverage.scroll.min(max_scroll);
    f.render_widget(Paragraph::new(lines).scroll((s.coverage.scroll, 0)), bi);
}

pub fn build_lines(
    r: &ScanResult,
    a: &AnalysisResult,
    facts: &CoverageFacts,
    width: usize,
) -> Vec<Line<'static>> {
    let cov = &a.coverage;
    let mut l: Vec<Line> = Vec::new();
    let normal = Style::new();

    if cov.gaps.is_empty() {
        l.push(Line::from(Span::styled(
            "No coverage gaps were found.",
            Style::new().fg(Color::Green),
        )));
    }
    for g in &cov.gaps {
        let (tag, color) = match g.kind {
            GapKind::SkippedSamePool => ("skipped mounts", Color::LightRed),
            GapKind::PermissionDenied => ("permissions", Color::LightRed),
            GapKind::Unreadable => ("I/O errors", Color::LightRed),
            GapKind::Pruned => ("pruned", Color::Yellow),
            GapKind::SharedExtents => ("shared extents", Color::Yellow),
            GapKind::Unattributed => ("unattributed", Color::Yellow),
        };
        let size = g
            .bytes
            .map_or(String::new(), |b| format!(" ~{}", fmt::bytes(b)));
        l.push(Line::from(Span::styled(
            format!("[{tag}]{size}"),
            Style::new().fg(color).add_modifier(Modifier::BOLD),
        )));
        for line in super::wrap(&g.detail, width.saturating_sub(2)) {
            l.push(Line::from(format!("  {line}")));
        }
    }

    for hint in &cov.advice {
        l.extend(bullet(
            &format!("hint: {hint}"),
            width,
            Style::new().fg(Color::Cyan),
        ));
    }

    l.push(Line::raw(""));
    l.push(section("Storage pools"));
    for p in &cov.pools {
        if cov.subtree {
            l.push(Line::from(format!(
                "{} ({})",
                fmt::safe_text(&p.label),
                fmt::safe_text(&p.fstype)
            )));
        } else {
            l.push(Line::from(vec![
                Span::raw(format!(
                    "{}  ",
                    fmt::truncate_right(&p.label, width.saturating_sub(40).max(10))
                )),
                Span::raw(format!("{:.1}% ", p.coverage_percent)),
                Span::styled(
                    format!(
                        "({} of {}) ",
                        fmt::bytes(p.walked_bytes),
                        fmt::bytes(p.used_bytes)
                    ),
                    fmt::dim(),
                ),
                Span::styled(p.confidence.label(), fmt::confidence_style(p.confidence)),
            ]));
        }
    }

    list_section(
        &mut l,
        "Permission denied",
        facts.denied_total,
        &facts.denied,
        width,
    );
    list_section(
        &mut l,
        "Unreadable (I/O error)",
        facts.io_total,
        &facts.io,
        width,
    );
    list_section(
        &mut l,
        "Pruned paths",
        facts.pruned_total,
        &facts.pruned,
        width,
    );

    let skipped: Vec<_> = r
        .mount_boundaries
        .iter()
        .filter(|b| matches!(b.decision, BoundaryDecision::Skipped(_)))
        .collect();
    l.push(Line::raw(""));
    l.push(section(&format!("Skipped mounts ({})", skipped.len())));
    if skipped.is_empty() {
        l.push(Line::from(Span::styled("none", fmt::dim())));
    }
    for b in skipped.iter().take(40) {
        let reason = match b.decision {
            BoundaryDecision::Skipped(rs) => rs.label(),
            BoundaryDecision::Entered => "",
        };
        l.push(Line::from(vec![
            Span::raw(format!(
                "{} ",
                fmt::truncate_left(
                    &b.path.display().to_string(),
                    width.saturating_sub(34).max(10)
                )
            )),
            Span::styled(
                format!("[{}] {}", fmt::safe_text(&b.fstype), reason),
                fmt::dim(),
            ),
        ]));
    }
    if !cov.out_of_scope.is_empty() {
        l.push(Line::raw(""));
        l.push(section("Separate disks not counted in coverage"));
        for d in &cov.out_of_scope {
            l.push(Line::from(format!(
                "{} [{}] {} used of {}",
                fmt::safe_path(&d.path),
                d.kind.label(),
                fmt::bytes(d.used_bytes),
                fmt::bytes(d.total_bytes)
            )));
        }
    }
    let _ = normal;
    l
}

fn list_section(
    l: &mut Vec<Line<'static>>,
    title: &str,
    total: usize,
    paths: &[std::path::PathBuf],
    width: usize,
) {
    l.push(Line::raw(""));
    l.push(section(&format!("{title} ({})", fmt::count(total as u64))));
    if total == 0 {
        l.push(Line::from(Span::styled("none", fmt::dim())));
        return;
    }
    for p in paths {
        l.push(Line::from(fmt::truncate_left(
            &p.display().to_string(),
            width,
        )));
    }
    if total > paths.len() {
        l.push(Line::from(Span::styled(
            format!("… {} more", total - paths.len()),
            fmt::dim(),
        )));
    }
}
