// SPDX-License-Identifier: GPL-3.0-only
//
// Findings table (Severity | Score | Size | Type | Path) with a detail pane.

use super::{bullet, kv, kv_plain, master_detail, panel, section};
use crate::analysis::{AnalysisResult, Finding};
use crate::model::ScanResult;
use crate::tui::fmt;
use crate::tui::state::{AppState, ListHit};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let (Some(r), Some(a)) = (s.result.clone(), s.analysis.clone()) else {
        return;
    };
    let (list_area, detail_area) = master_detail(
        area,
        s.findings.detail_open,
        s.findings.filtered_indices.len(),
    );

    let title = if s.findings.filter.is_empty() {
        format!(
            "Findings {}/{}",
            s.findings.filtered_indices.len(),
            a.findings.len()
        )
    } else {
        format!(
            "Findings {}/{}  filter: {}",
            s.findings.filtered_indices.len(),
            a.findings.len(),
            s.findings.filter
        )
    };
    let block = panel(title);
    let inner = block.inner(list_area);

    if s.findings.filtered_indices.is_empty() {
        f.render_widget(block, list_area);
        let msg = if a.findings.is_empty() {
            "No findings: nothing in this scan scored above the reporting threshold."
        } else {
            "No findings match the filter. Esc clears it."
        };
        f.render_widget(Paragraph::new(Span::styled(msg, fmt::dim())), inner);
    } else {
        let fixed = 9 + 6 + 13 + 10 + 4;
        let path_w = (inner.width as usize).saturating_sub(fixed + 2).max(8);
        let rows: Vec<Row> = s
            .findings
            .filtered_indices
            .iter()
            .map(|&i| {
                let fi = &a.findings[i];
                // A title ("stale temporary data in /tmp") is identified by
                // its beginning; a bare path by its end.
                let label = match &fi.title {
                    Some(t) => fmt::truncate_right(t, path_w),
                    None => fmt::truncate_left(&fi.path.display().to_string(), path_w),
                };
                Row::new(vec![
                    Cell::from(Span::styled(
                        format!("{:<8}", fi.severity.label()),
                        fmt::severity_style(fi.severity),
                    )),
                    Cell::from(format!("{:>5.1}", fi.score)),
                    Cell::from(format!(
                        "{:>12}",
                        format!(
                            "{}{}",
                            if fi.lower_bound { "≥" } else { "" },
                            fmt::bytes(fi.bytes)
                        )
                    )),
                    Cell::from(fmt::kind_label(fi.kind)),
                    Cell::from(label),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(13),
                Constraint::Length(10),
                Constraint::Min(8),
            ],
        )
        .header(Row::new(["Severity", "Score", "Size", "Type", "Path"]).style(fmt::heading()))
        .block(block)
        .row_highlight_style(fmt::selected_row());
        f.render_stateful_widget(table, list_area, &mut s.findings.table);
        s.layout.list = Some(ListHit {
            rows_area: Rect {
                x: inner.x,
                y: inner.y + 1,
                width: inner.width,
                height: inner.height.saturating_sub(1),
            },
            offset: s.findings.table.offset(),
        });
    }

    if let Some(d) = detail_area {
        let block = panel("Finding");
        let inner = block.inner(d);
        f.render_widget(block, d);
        let lines = match s.findings.selected(&a) {
            Some(fi) => detail_lines(fi, &a, &r, inner.width as usize),
            None => vec![Line::from(Span::styled("nothing selected", fmt::dim()))],
        };
        f.render_widget(Paragraph::new(lines), inner);
    }
}

pub fn detail_lines(
    fi: &Finding,
    a: &AnalysisResult,
    r: &ScanResult,
    width: usize,
) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    for (i, part) in super::wrap(&fi.path.display().to_string(), width)
        .into_iter()
        .enumerate()
    {
        l.push(Line::from(Span::styled(
            part,
            if i == 0 {
                Style::new().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            },
        )));
    }
    if let Some(t) = &fi.title {
        l.push(Line::from(Span::styled(fmt::safe_text(t), fmt::heading())));
    }
    l.push(kv(
        "Size",
        vec![Span::raw(format!(
            "{}{}  ({} of fs used)",
            if fi.lower_bound { "≥ " } else { "" },
            fmt::bytes(fi.bytes),
            fmt::percent(fi.percent_of_fs_used)
        ))],
    ));
    l.push(kv(
        "Score",
        vec![
            Span::raw(format!("{:.1}  ", fi.score)),
            Span::styled(
                format!(" {} ", fi.severity.label()),
                fmt::severity_style(fi.severity),
            ),
        ],
    ));
    l.push(kv_plain(
        "Class",
        format!(
            "{} · {} · {}",
            fi.class.label(),
            fi.expectation.label(),
            fmt::kind_label(fi.kind)
        ),
    ));
    if let Some(fs) = r.filesystems.get(fi.fs as usize) {
        l.push(kv_plain("Filesystem", fmt::fs_name(fs)));
    }
    if fi.stale_percent >= 1.0 {
        l.push(kv_plain(
            "Stale",
            format!("{:.0}% of data is old", fi.stale_percent),
        ));
    }
    l.push(kv(
        "Confidence",
        vec![
            Span::styled(fi.confidence.label(), fmt::confidence_style(fi.confidence)),
            Span::styled(
                if fi.lower_bound {
                    "  size is a lower bound"
                } else {
                    "  size is exact"
                },
                fmt::dim(),
            ),
        ],
    ));
    if fi.error_count > 0 {
        l.push(kv_plain(
            "Errors",
            format!(
                "{} entries below could not be read",
                fmt::count(fi.error_count)
            ),
        ));
    }
    l.push(match (&fi.growth, a.has_baseline) {
        (Some(g), _) => kv_plain(
            "Growth",
            format!(
                "+{} since baseline{}",
                fmt::bytes(g.delta_bytes),
                g.percent.map_or(String::new(), |p| format!(" (+{p:.0}%)"))
            ),
        ),
        (None, true) => kv(
            "Growth",
            vec![Span::styled("no significant growth", fmt::dim())],
        ),
        (None, false) => kv(
            "Growth",
            vec![Span::styled("off (no baseline scan supplied)", fmt::dim())],
        ),
    });
    l.push(Line::raw(""));
    l.push(section("Reasons"));
    if fi.reasons.is_empty() {
        l.push(Line::from(Span::styled("none recorded", fmt::dim())));
    }
    for reason in &fi.reasons {
        l.extend(bullet(reason, width, Style::new()));
    }
    l
}
