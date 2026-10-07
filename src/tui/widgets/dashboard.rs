// SPDX-License-Identifier: GPL-3.0-only
//
// Overview: verdict, risk, coverage, pressure, largest areas, finding counts.
// Partial or undetermined scans get a banner so they cannot be mistaken for a
// clean result.

use super::{kv, panel};
use crate::analysis::{AnalysisResult, Qualifier, Reliability, Severity};
use crate::coverage::Completeness;
use crate::model::ScanResult;
use crate::tui::fmt;
use crate::tui::state::AppState;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn banner(a: &AnalysisResult) -> Option<(Vec<String>, Style)> {
    let cov = &a.coverage;
    let (rel, caveat) = a.ranking_reliability();
    if cov.completeness == Completeness::Complete && a.overall.qualifier == Qualifier::Confirmed {
        return None;
    }
    let head = format!(
        "{} SCAN: {:.1}% of used space seen",
        cov.completeness.label(),
        cov.coverage_percent
    );
    let mut lines = vec![head];
    if let Some(c) = caveat {
        lines.push(c);
    }
    match a.overall.qualifier {
        Qualifier::Undetermined => lines.push(
            "overall verdict is UNDETERMINED: too little was seen to call this system healthy"
                .into(),
        ),
        Qualifier::AtLeast => lines.push(format!(
            "overall severity is at least {}: the scan is incomplete",
            a.overall.severity.label()
        )),
        Qualifier::Confirmed => {}
    }
    let color = match (rel, cov.completeness) {
        (Reliability::Unreliable, _) | (_, Completeness::Minimal) => Color::Red,
        (_, Completeness::Partial) => Color::LightRed,
        _ => Color::Yellow,
    };
    Some((lines, Style::new().fg(color).add_modifier(Modifier::BOLD)))
}

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let (Some(r), Some(a)) = (s.result.clone(), s.analysis.clone()) else {
        return;
    };

    let ban = banner(&a);
    let ban_h = ban.as_ref().map_or(0, |(l, _)| l.len() as u16 + 2);
    let [ban_area, top, bottom] = Layout::vertical([
        Constraint::Length(ban_h),
        Constraint::Length(8),
        Constraint::Min(4),
    ])
    .areas(area);

    if let Some((lines, style)) = ban {
        let block = Block::new().borders(Borders::ALL).border_style(style);
        let inner = block.inner(ban_area);
        f.render_widget(block, ban_area);
        let text: Vec<Line> = lines
            .into_iter()
            .enumerate()
            .map(|(i, l)| {
                Line::from(Span::styled(
                    fmt::truncate_right(&l, inner.width as usize),
                    if i == 0 {
                        style
                    } else {
                        Style::new().fg(style.fg.unwrap_or(Color::Yellow))
                    },
                ))
            })
            .collect();
        f.render_widget(Paragraph::new(text), inner);
    }

    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    render_status(f, left, &r, &a, s.scan_secs);
    render_findings(f, right, &a);

    let [pools, areas] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);
    render_pools(f, pools, &a, s.overview.selected_pool);
    render_areas(f, areas, &r, s);
}

fn render_status(f: &mut Frame, area: Rect, r: &ScanResult, a: &AnalysisResult, secs: Option<f64>) {
    let cov = &a.coverage;
    let qual = match a.overall.qualifier {
        Qualifier::Confirmed => "",
        Qualifier::AtLeast => " (at least)",
        Qualifier::Undetermined => " (UNDETERMINED)",
    };
    let coverage = if cov.subtree {
        vec![
            Span::raw("n/a (subtree scan)  "),
            Span::styled(
                format!(" {} ", cov.completeness.label()),
                fmt::completeness_style(cov.completeness),
            ),
        ]
    } else {
        vec![
            Span::raw(format!("{:.1}%  ", cov.coverage_percent)),
            Span::styled(
                format!(" {} ", cov.completeness.label()),
                fmt::completeness_style(cov.completeness),
            ),
        ]
    };
    let lines = vec![
        kv(
            "Overall",
            vec![
                Span::styled(
                    format!(" {} ", a.overall.severity.label()),
                    fmt::severity_style(a.overall.severity),
                ),
                Span::raw(qual),
            ],
        ),
        kv(
            "Risk",
            vec![
                Span::styled(
                    format!("{:.0}/100 ", a.risk.score),
                    fmt::severity_style(a.risk.level),
                ),
                Span::raw(a.risk.level.label()),
            ],
        ),
        kv("Coverage", coverage),
        kv(
            "Confidence",
            vec![Span::styled(
                a.confidence.label(),
                fmt::confidence_style(a.confidence),
            )],
        ),
        kv(
            "Scanned",
            vec![Span::raw(format!(
                "{} entries, {} dirs{}",
                fmt::count(r.totals.counts.entries),
                fmt::count(r.index.len() as u64),
                secs.map_or(String::new(), |t| format!(", {}", fmt::duration_secs(t)))
            ))],
        ),
        kv(
            "Issues",
            vec![Span::raw(format!(
                "{} errors, {} permission denied",
                fmt::count(r.totals.counts.errors),
                fmt::count(r.permission_denied_count() as u64)
            ))],
        ),
    ];
    f.render_widget(Paragraph::new(lines).block(panel("Status")), area);
}

fn render_findings(f: &mut Frame, area: Rect, a: &AnalysisResult) {
    let total: u64 = a.severity_counts.iter().sum::<u64>().max(1);
    let mut lines: Vec<Line> = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let n = a.severity_count(sev);
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", sev.label()), fmt::severity_style(sev)),
            Span::raw(format!("{:>6}  ", fmt::count(n))),
            Span::styled(
                fmt::bar(n as f64 / total as f64, 14),
                Style::new().fg(match sev {
                    Severity::Critical => Color::Red,
                    Severity::High => Color::LightRed,
                    Severity::Medium => Color::Yellow,
                    Severity::Low => Color::Green,
                }),
            ),
        ]));
    }
    lines.push(Line::from(Span::styled(
        format!(
            "{} in total, {} listed in Findings",
            fmt::count(a.severity_counts.iter().sum::<u64>()),
            a.findings.len()
        ),
        fmt::dim(),
    )));
    if let Some(c) = a
        .risk
        .components
        .iter()
        .filter(|c| c.value > 0.0)
        .max_by(|x, y| x.value.total_cmp(&y.value))
    {
        lines.push(Line::from(Span::styled(
            format!("main risk: {} ({:.0}%)", c.name, c.value * 100.0),
            fmt::dim(),
        )));
    }
    f.render_widget(Paragraph::new(lines).block(panel("Findings")), area);
}

fn render_pools(f: &mut Frame, area: Rect, a: &AnalysisResult, selected: Option<usize>) {
    let block = panel("Filesystems");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width as usize;
    let name_w = (w / 3).clamp(10, 24);
    let mut lines = Vec::new();
    for (i, ps) in a.pool_scores.iter().enumerate() {
        let sel = selected == Some(i);
        let bar_w = 12;
        let cov = a
            .coverage
            .pools
            .iter()
            .find(|c| c.pool == ps.pool)
            .map_or(String::new(), |c| {
                if a.coverage.subtree {
                    String::new()
                } else {
                    format!(" cov {:.0}%", c.coverage_percent)
                }
            });
        let mut line = Line::from(vec![
            Span::raw(if sel { "▸" } else { " " }),
            Span::raw(format!(
                "{:<name_w$} ",
                fmt::truncate_right(&ps.label, name_w)
            )),
            Span::styled(
                fmt::bar(ps.used_percent / 100.0, bar_w),
                Style::new().fg(fmt::pressure_color(ps.used_percent)),
            ),
            Span::raw(format!(" {:>4}", fmt::percent(ps.used_percent))),
            Span::styled(cov, fmt::dim()),
        ]);
        if sel {
            line = line.style(Style::new().add_modifier(Modifier::BOLD));
        }
        lines.push(line);
        lines.push(Line::from(Span::styled(
            format!("   {} free", fmt::bytes(ps.available_bytes)),
            fmt::dim(),
        )));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_areas(f: &mut Frame, area: Rect, r: &ScanResult, s: &AppState) {
    let block = panel("Largest areas");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let total = r.totals.allocated_bytes.max(1);
    let name_w = (inner.width as usize).saturating_sub(10 + 7 + 8);
    let lines: Vec<Line> = s
        .overview
        .areas
        .iter()
        .take(inner.height as usize)
        .map(|&id| {
            let n = r.index.node(id);
            let name = String::from_utf8_lossy(r.index.name(id)).into_owned();
            let mut spans = vec![
                Span::raw(format!("{:>10} ", fmt::bytes(n.usage.bytes))),
                Span::raw(format!(
                    "{:>5} ",
                    fmt::percent(fmt::ratio_percent(n.usage.bytes, total))
                )),
                Span::styled(
                    fmt::bar(n.usage.bytes as f64 / total as f64, 6),
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw(format!(" /{}", fmt::truncate_right(&name, name_w))),
            ];
            let badges = fmt::node_badges(n.flags);
            if !badges.is_empty() {
                spans.push(Span::styled(format!(" [{badges}]"), fmt::dim()));
            }
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}
