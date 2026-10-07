// SPDX-License-Identifier: GPL-3.0-only

use crate::tui::fmt;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

const KEYS: &[(&str, &str)] = &[
    ("j k  ↑ ↓", "move selection"),
    ("h l  ← →", "collapse / expand (tree), zone type (zones)"),
    ("Enter", "open details / show search hit in tree"),
    ("Esc", "close details, clear filter"),
    ("Tab  Shift-Tab", "next / previous view"),
    ("1 … 7", "jump to a view"),
    ("g  G", "top / bottom"),
    ("PgUp PgDn", "page (Ctrl-u / Ctrl-d)"),
    ("Space  + -", "toggle / expand / collapse (tree)"),
    ("/", "search the current view"),
    ("s", "change sort order (tree, files)"),
    ("r", "rescan"),
    ("Ctrl-L", "redraw"),
    ("?", "this help"),
    ("q  Ctrl-C", "quit"),
];

pub fn render(f: &mut Frame, area: Rect) {
    let w = 66.min(area.width.saturating_sub(2));
    let h = (KEYS.len() as u16 + 6).min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let block = super::panel("Keys");
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    let mut lines: Vec<Line> = KEYS
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(
                    format!("{k:<16}"),
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(d.to_string()),
            ])
        })
        .collect();
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Read-only: rootwatch never modifies or deletes anything.",
        fmt::dim(),
    )));
    f.render_widget(Paragraph::new(lines), inner);
}
