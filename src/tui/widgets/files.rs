// SPDX-License-Identifier: GPL-3.0-only
//
// Largest files (`ScanResult::top_files`), with sort, filter and a detail pane.

use super::{kv, kv_plain, master_detail, panel};
use crate::model::FileRecord;
use crate::tui::fmt;
use crate::tui::state::{AppState, ListHit};
use crate::users::UserNames;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let Some(r) = s.result.clone() else { return };
    let (list_area, detail_area) = master_detail(area, s.files.detail_open, s.files.order.len());
    let title = format!(
        "Largest files {}/{}  sort: {}{}",
        s.files.order.len(),
        r.top_files.len(),
        s.files.sort.label(),
        if s.files.filter.is_empty() {
            String::new()
        } else {
            format!("  filter: {}", s.files.filter)
        }
    );
    let block = panel(title);
    let inner = block.inner(list_area);

    if s.files.order.is_empty() {
        f.render_widget(block, list_area);
        let msg = if r.top_files.is_empty() {
            "No files with allocated space were found."
        } else {
            "No files match the filter. Esc clears it."
        };
        f.render_widget(Paragraph::new(Span::styled(msg, fmt::dim())), inner);
    } else {
        let fixed = 12 + 10 + 11;
        let path_w = (inner.width as usize).saturating_sub(fixed + 3).max(8);
        let rows: Vec<Row> = s
            .files
            .order
            .iter()
            .map(|&i| {
                let fr = &r.top_files[i];
                Row::new(vec![
                    Cell::from(format!("{:>11}", fmt::bytes(fr.allocated_bytes))),
                    Cell::from(fmt::age_label(fmt::age_days(r.started_unix, fr.mtime))),
                    Cell::from(fmt::truncate_right(&s.users.name(fr.uid), 10)),
                    Cell::from(fmt::truncate_left(&fr.path.display().to_string(), path_w)),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(11),
                Constraint::Min(8),
            ],
        )
        .header(Row::new(["Size", "Age", "Owner", "Path"]).style(fmt::heading()))
        .block(block)
        .row_highlight_style(fmt::selected_row());
        f.render_stateful_widget(table, list_area, &mut s.files.table);
        s.layout.list = Some(ListHit {
            rows_area: Rect {
                x: inner.x,
                y: inner.y + 1,
                width: inner.width,
                height: inner.height.saturating_sub(1),
            },
            offset: s.files.table.offset(),
        });
    }

    if let Some(d) = detail_area {
        let block = panel("File");
        let dinner = block.inner(d);
        f.render_widget(block, d);
        let lines = match s.files.selected(&r) {
            Some(fr) => detail_lines(fr, r.started_unix, &s.users, dinner.width as usize),
            None => vec![Line::from(Span::styled("nothing selected", fmt::dim()))],
        };
        f.render_widget(Paragraph::new(lines), dinner);
    }
}

pub fn detail_lines(
    fr: &FileRecord,
    now: i64,
    users: &UserNames,
    width: usize,
) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    for (i, part) in super::wrap(&fr.path.display().to_string(), width)
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
    l.push(kv_plain("Allocated", fmt::bytes(fr.allocated_bytes)));
    l.push(kv_plain("Apparent", fmt::bytes(fr.apparent_bytes)));
    let note = if fr.apparent_bytes > fr.allocated_bytes.saturating_mul(2)
        && fr.apparent_bytes > (1 << 20)
    {
        "sparse: far larger than the space it uses"
    } else if fr.allocated_bytes > fr.apparent_bytes.saturating_mul(2)
        && fr.allocated_bytes > (1 << 20)
    {
        "allocation exceeds content (block rounding or preallocation)"
    } else {
        "normal"
    };
    l.push(kv("Layout", vec![Span::styled(note, fmt::dim())]));
    l.push(kv_plain(
        "Modified",
        format!(
            "{} ({})",
            fmt::date(fr.mtime),
            fmt::ago(fmt::age_days(now, fr.mtime))
        ),
    ));
    l.push(kv_plain(
        "Owner",
        format!("{} (uid {})", users.name(fr.uid), fr.uid),
    ));
    l
}
