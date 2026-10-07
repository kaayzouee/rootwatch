// SPDX-License-Identifier: GPL-3.0-only
//
// Shown whenever there is no complete result to display: before the first
// scan starts, while scanning and analysing (with live counters that need no
// finished ScanResult), and after a failure.

use super::{kv_plain, panel, wrap};
use crate::tui::fmt;
use crate::tui::state::{AppState, ScanStatus};
use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

pub fn render(f: &mut Frame, area: Rect, s: &AppState) {
    let block = panel("Scan");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let width = inner.width.saturating_sub(4) as usize;
    let spin = SPINNER[(s.tick as usize) % SPINNER.len()];
    let elapsed = s
        .scan_started
        .map(|t| fmt::duration_secs(t.elapsed().as_secs_f64()))
        .unwrap_or_default();

    let mut lines: Vec<Line> = Vec::new();
    match &s.scan_status {
        ScanStatus::Idle => lines.push(Line::from("Starting…")),
        ScanStatus::Scanning => {
            lines.push(Line::from(Span::styled(
                format!("{spin} Scanning…"),
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::raw(""));
            let p = s.progress.clone().unwrap_or_default();
            lines.push(kv_plain("entries", fmt::count(p.entries)));
            lines.push(kv_plain("directories", fmt::count(p.directories)));
            lines.push(kv_plain("allocated", fmt::bytes(p.bytes)));
            lines.push(kv_plain("elapsed", elapsed));
            lines.push(Line::raw(""));
            if let Some(path) = &p.current_path {
                lines.push(Line::from(Span::styled(
                    fmt::truncate_left(&path.display().to_string(), width),
                    fmt::dim(),
                )));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "the interface stays responsive; q quits at any time",
                fmt::dim(),
            )));
        }
        ScanStatus::Analyzing => {
            lines.push(Line::from(Span::styled(
                format!("{spin} Analyzing…"),
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::raw(""));
            if let Some(r) = &s.result {
                lines.push(kv_plain("entries", fmt::count(r.totals.counts.entries)));
                lines.push(kv_plain("directories", fmt::count(r.index.len() as u64)));
                lines.push(kv_plain("allocated", fmt::bytes(r.totals.allocated_bytes)));
            }
            lines.push(kv_plain("elapsed", elapsed));
        }
        ScanStatus::Failed(msg) => {
            lines.push(Line::from(Span::styled(
                "Scan failed",
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::raw(""));
            for l in wrap(msg, width) {
                lines.push(Line::from(l));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "r  try again      q  quit",
                fmt::dim(),
            )));
        }
        ScanStatus::Ready => lines.push(Line::from("Ready")),
    }

    let h = lines.len() as u16;
    let y = inner.y + inner.height.saturating_sub(h) / 2;
    let area = Rect {
        x: inner.x,
        y,
        width: inner.width,
        height: h.min(inner.height),
    };
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}
