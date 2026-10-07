// SPDX-License-Identifier: GPL-3.0-only
//
// Contextual key hints (or the search prompt while `/` is active).

use crate::tui::state::{AppState, View, ZoneTab};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

/// A key hint with a drop priority: when the footer is too narrow the lowest
/// priority hint goes first; `? Help` and `q Quit` (priority 9) never do.
pub type Hint = (&'static str, &'static str, u8);

pub fn hints(s: &AppState) -> Vec<Hint> {
    if s.search.active {
        return vec![
            ("Enter", "keep filter", 9),
            ("Esc", "clear", 9),
            ("↑↓", "move", 5),
        ];
    }
    let mut h: Vec<Hint> = Vec::new();
    if s.ready() {
        match s.view {
            View::Overview => h.extend([("↑↓", "Pool", 5), ("Enter", "Open pool", 4)]),
            View::Findings => h.extend([
                ("↑↓", "Select", 6),
                ("Enter", "Details", 7),
                ("Esc", "Close", 3),
            ]),
            View::Tree => {
                if s.tree.searching() {
                    h.extend([
                        ("↑↓", "Select", 6),
                        ("Enter", "Show in tree", 7),
                        ("Esc", "Clear", 5),
                    ]);
                } else {
                    h.extend([
                        ("↑↓", "Move", 6),
                        ("→", "Expand", 5),
                        ("←", "Collapse", 5),
                        ("Enter", "Details", 7),
                        ("s", "Sort", 3),
                    ]);
                }
            }
            View::Files => h.extend([
                ("↑↓", "Select", 6),
                ("Enter", "Details", 7),
                ("s", "Sort", 3),
            ]),
            View::Coverage => h.push(("↑↓", "Scroll", 6)),
            View::Pools => h.push(("↑↓", "Select", 6)),
            View::Zones => {
                h.push(("←→", "Zone type", 6));
                h.push((
                    "↑↓",
                    if s.zones.tab != ZoneTab::Nix {
                        "Select"
                    } else {
                        "Scroll"
                    },
                    5,
                ));
            }
        }
        if s.view.searchable() {
            h.push(("/", "Search", 4));
        }
    }
    h.extend([
        ("Tab", "Next view", 8),
        ("r", "Rescan", 2),
        ("?", "Help", 9),
        ("q", "Quit", 9),
    ]);
    h
}

fn hint_width(h: &[Hint]) -> usize {
    h.iter()
        .map(|(k, d, _)| k.chars().count() + 1 + d.chars().count())
        .sum::<usize>()
        + h.len().saturating_sub(1) * 2
}

/// Drop the least important hints until the rest fit in `width` columns.
pub fn fit_hints(mut h: Vec<Hint>, width: usize) -> Vec<Hint> {
    while hint_width(&h) > width && h.len() > 1 {
        // lowest priority; among equals, the one furthest right
        let idx = h
            .iter()
            .enumerate()
            .min_by(|(ia, a), (ib, b)| a.2.cmp(&b.2).then(ib.cmp(ia)))
            .map(|(i, _)| i)
            .unwrap_or(0);
        h.remove(idx);
    }
    h
}

pub fn render(f: &mut Frame, area: Rect, s: &AppState) {
    if s.search.active {
        let prompt = format!("/{}", s.search.input.value());
        let hint = "  Enter keep · Esc clear";
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(prompt, Style::new().add_modifier(Modifier::BOLD)),
                Span::styled(hint, Style::new().fg(Color::DarkGray)),
            ])),
            area,
        );
        let x = area.x + 1 + s.search.input.visual_cursor() as u16;
        f.set_cursor_position((x.min(area.x + area.width.saturating_sub(1)), area.y));
        return;
    }
    if let Some(msg) = &s.message {
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {msg}"),
                Style::new().fg(Color::Yellow),
            )),
            area,
        );
        return;
    }
    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, desc, _)) in fit_hints(hints(s), area.width as usize)
        .into_iter()
        .enumerate()
    {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            key.to_string(),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {desc}")));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
