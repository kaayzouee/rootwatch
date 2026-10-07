// SPDX-License-Identifier: GPL-3.0-only
//
// Storage pools. On btrfs several mounted subvolumes share one pool, so this is
// where "/ and /nix are the same disk" becomes visible.

use super::panel;
use crate::analysis::Severity;
use crate::model::{BoundaryDecision, ScanResult};
use crate::tui::fmt;
use crate::tui::state::{AppState, ListHit};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let (Some(r), Some(a)) = (s.result.clone(), s.analysis.clone()) else {
        return;
    };
    let table_h = (s.pools.rows.len() as u16 + 3).clamp(5, 11);
    let [top, bottom] =
        Layout::vertical([Constraint::Length(table_h), Constraint::Min(4)]).areas(area);

    let title = if s.pools.filter.is_empty() {
        format!("Storage pools ({})", s.pools.rows.len())
    } else {
        format!(
            "Storage pools {}/{}  filter: {}",
            s.pools.rows.len(),
            r.pools.len(),
            s.pools.filter
        )
    };
    let block = panel(title);
    let inner = block.inner(top);

    let label_w = (inner.width as usize / 4).clamp(12, 26);
    let rows: Vec<Row> = s
        .pools
        .rows
        .iter()
        .map(|&p| {
            let pool = &r.pools[p];
            let used_pct = fmt::ratio_percent(pool.info.used_bytes, pool.info.total_bytes);
            let cov = a.coverage.pools.iter().find(|c| c.pool == p);
            let cov_txt = match cov {
                None => "not scanned".to_string(),
                Some(_) if a.coverage.subtree => "n/a".to_string(),
                Some(c) => format!("{:.0}%", c.coverage_percent),
            };
            let scanned = r.filesystems.iter().filter(|f| f.pool == p).count();
            let skipped = r
                .mount_boundaries
                .iter()
                .filter(|b| b.pool == p && matches!(b.decision, BoundaryDecision::Skipped(_)))
                .count();
            let sev = a
                .pool_scores
                .iter()
                .find(|ps| ps.pool == p)
                .map(|ps| ps.severity);
            Row::new(vec![
                Cell::from(fmt::truncate_right(&pool.label, label_w)),
                Cell::from(pool.fstype.clone()),
                Cell::from(format!("{:>10}", fmt::bytes(pool.info.used_bytes))),
                Cell::from(format!("{:>10}", fmt::bytes(pool.info.available_bytes))),
                Cell::from(Line::from(vec![
                    Span::styled(
                        fmt::bar(used_pct / 100.0, 8),
                        Style::new().fg(fmt::pressure_color(used_pct)),
                    ),
                    Span::raw(format!(" {:>4}", fmt::percent(used_pct))),
                ])),
                Cell::from(cov_txt),
                Cell::from(format!("{scanned}+{skipped}")),
                match sev {
                    Some(sv) => Cell::from(Span::styled(sv.label(), fmt::severity_style(sv))),
                    None => Cell::from(Span::styled("-", fmt::dim())),
                },
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(label_w as u16),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new([
            "Pool",
            "Type",
            "Used",
            "Available",
            "Pressure",
            "Coverage",
            "Mounts",
            "Severity",
        ])
        .style(fmt::heading()),
    )
    .block(block)
    .row_highlight_style(fmt::selected_row());
    f.render_stateful_widget(table, top, &mut s.pools.table);
    s.layout.list = Some(ListHit {
        rows_area: Rect {
            x: inner.x,
            y: inner.y + 1,
            width: inner.width,
            height: inner.height.saturating_sub(1),
        },
        offset: s.pools.table.offset(),
    });

    // ---- mounts of the selected pool ----
    let block = panel("Mounts on this pool (scanned + skipped)");
    let bi = block.inner(bottom);
    f.render_widget(block, bottom);
    let lines = match s.pools.selected_pool() {
        Some(p) => mount_lines(&r, p, bi.width as usize),
        None => vec![Line::from(Span::styled("no pool selected", fmt::dim()))],
    };
    f.render_widget(Paragraph::new(lines), bi);
}

pub fn mount_lines(r: &ScanResult, pool: usize, width: usize) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    let path_w = width.saturating_sub(34).max(10);
    for fs in r.filesystems.iter().filter(|f| f.pool == pool) {
        l.push(Line::from(vec![
            Span::styled("✓ ", Style::new().fg(ratatui::style::Color::Green)),
            Span::styled(
                fmt::truncate_left(&fs.mountpoint.display().to_string(), path_w),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "  [{} / {}] walked {}",
                    fs.fstype,
                    fs.kind.label(),
                    fmt::bytes(fs.walked_bytes)
                ),
                fmt::dim(),
            ),
        ]));
    }
    for b in r.mount_boundaries.iter().filter(|b| b.pool == pool) {
        match b.decision {
            BoundaryDecision::Entered => {}
            BoundaryDecision::Skipped(reason) => l.push(Line::from(vec![
                Span::styled("✗ ", Style::new().fg(ratatui::style::Color::LightRed)),
                Span::raw(fmt::truncate_left(&b.path.display().to_string(), path_w)),
                Span::styled(
                    format!("  [{}] {}", fmt::safe_text(&b.fstype), reason.label()),
                    fmt::dim(),
                ),
            ])),
        }
    }
    if l.is_empty() {
        l.push(Line::from(Span::styled(
            "no mounts recorded for this pool",
            fmt::dim(),
        )));
    }
    let _ = Severity::Low;
    l
}
