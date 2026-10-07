// SPDX-License-Identifier: GPL-3.0-only
//
// Widgets: functions `render(frame, area, &state)` that draw one view. They
// read `AppState` (and the immutable results inside it); they own nothing and
// never perform I/O.

pub mod coverage;
pub mod dashboard;
pub mod files;
pub mod findings;
pub mod footer;
pub mod help;
pub mod pools;
pub mod status;
pub mod tree;
pub mod zones;

use super::fmt;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};

pub fn panel(title: impl Into<String>) -> Block<'static> {
    let title = fmt::safe_text(&title.into());
    Block::new()
        .borders(Borders::ALL)
        .border_style(fmt::dim())
        .title(Span::styled(format!(" {title} "), fmt::heading()))
}

/// "label  value" line with an aligned, dim label.
pub fn kv(label: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{label:<12}"), fmt::dim())];
    spans.extend(value);
    Line::from(spans)
}

pub fn kv_plain(label: &str, value: impl Into<String>) -> Line<'static> {
    kv(label, vec![Span::raw(fmt::safe_text(&value.into()))])
}

pub fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        fmt::safe_text(title),
        Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    ))
}

/// Split `area` into a list and an optional detail pane. Wide terminals put
/// the detail beside the list. On narrow ones the list is sized to its content
/// (`list_rows` data rows plus header and borders, between 6 rows and 45% of
/// the height) and the detail pane gets everything else.
pub fn master_detail(area: Rect, detail_open: bool, list_rows: usize) -> (Rect, Option<Rect>) {
    if !detail_open {
        return (area, None);
    }
    if area.width >= 110 {
        let [l, d] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .areas(area);
        (l, Some(d))
    } else {
        let cap = (area.height as usize * 45 / 100).max(6);
        let list_h = (list_rows + 3).clamp(6, cap) as u16;
        let [l, d] = Layout::vertical([Constraint::Length(list_h), Constraint::Min(5)]).areas(area);
        (l, Some(d))
    }
}

/// Greedy word wrap; words longer than `width` are hard-split.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let text = fmt::safe_text(text);
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let mut word = word.to_string();
        while word.chars().count() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let head: String = word.chars().take(width).collect();
            word = word.chars().skip(width).collect();
            lines.push(head);
        }
        let need = cur.chars().count() + usize::from(!cur.is_empty()) + word.chars().count();
        if need > width && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(&word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Bullet list entry that wraps under the bullet.
pub fn bullet(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    wrap(text, width.saturating_sub(2))
        .into_iter()
        .enumerate()
        .map(|(i, l)| {
            Line::from(vec![
                Span::styled(if i == 0 { "• " } else { "  " }, style),
                Span::styled(l, style),
            ])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_respects_width_and_splits_long_words() {
        assert_eq!(wrap("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
        assert_eq!(wrap("", 5), [""]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert!(
            wrap("one two three four five", 10)
                .iter()
                .all(|l| l.chars().count() <= 10)
        );
    }
}
