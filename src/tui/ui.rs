// SPDX-License-Identifier: GPL-3.0-only
//
// The shared outer layout:  header / tabs / main view / footer.
// Everything here is a pure function of `AppState`; nothing touches the
// filesystem while drawing.

use super::fmt;
use super::state::{AppState, LayoutCache, ScanStatus, View};
use super::widgets;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn render(f: &mut Frame, state: &mut AppState) {
    let area = f.area();
    state.layout = LayoutCache::default();

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(f, area);
        return;
    }

    let [header, tabs, main, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(f, header, state);
    render_tabs(f, tabs, state);
    render_main(f, main, state);
    widgets::footer::render(f, footer, state);
    if state.help_open {
        widgets::help::render(f, area);
    }
}

fn render_too_small(f: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "Terminal too small",
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("Resize to at least {MIN_WIDTH}x{MIN_HEIGHT}")),
        Line::from(format!("(now {}x{})", area.width, area.height)),
    ];
    f.render_widget(
        Paragraph::new(text).alignment(Alignment::Center),
        center_vertically(area, 3),
    );
}

fn center_vertically(area: Rect, height: u16) -> Rect {
    let h = height.min(area.height);
    Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: area.width,
        height: h,
    }
}

fn render_header(f: &mut Frame, area: Rect, s: &AppState) {
    let left = Line::from(vec![
        Span::styled(
            format!(" ROOTWATCH v{} ", env!("CARGO_PKG_VERSION")),
            Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ),
        Span::raw(" "),
        Span::styled(
            fmt::truncate_left(&s.root.display().to_string(), 40),
            Style::new().add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {}", s.scope_label), fmt::dim()),
    ]);
    f.render_widget(Paragraph::new(left), area);

    const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
    let spin = SPINNER[(s.tick as usize) % SPINNER.len()];
    let (text, style) = match &s.scan_status {
        ScanStatus::Idle => ("idle".to_string(), fmt::dim()),
        ScanStatus::Scanning => (format!("{spin} scanning"), Style::new().fg(Color::Yellow)),
        ScanStatus::Analyzing => (format!("{spin} analyzing"), Style::new().fg(Color::Yellow)),
        ScanStatus::Ready => (
            match s.scan_secs {
                Some(t) => format!("ready ({})", fmt::duration_secs(t)),
                None => "ready".to_string(),
            },
            Style::new().fg(Color::Green),
        ),
        ScanStatus::Failed(_) => (
            "scan failed".to_string(),
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };
    f.render_widget(
        Paragraph::new(Span::styled(format!("{text} "), style)).alignment(Alignment::Right),
        area,
    );
}

fn render_tabs(f: &mut Frame, area: Rect, s: &mut AppState) {
    let ready = s.ready();
    let mut spans = Vec::new();
    let mut x = area.x;
    for v in View::ALL {
        let label = format!(" {} {} ", v.index() + 1, v.title());
        let width = label.chars().count() as u16;
        let style = if v == s.view {
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if ready || v == View::Overview {
            Style::new()
        } else {
            fmt::dim()
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
        if x + width <= area.x + area.width {
            s.layout.tabs.push((
                Rect {
                    x,
                    y: area.y,
                    width,
                    height: 1,
                },
                v,
            ));
        }
        x += width + 1;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_main(f: &mut Frame, area: Rect, s: &mut AppState) {
    if !s.ready() {
        widgets::status::render(f, area, s);
        return;
    }
    match s.view {
        View::Overview => widgets::dashboard::render(f, area, s),
        View::Findings => widgets::findings::render(f, area, s),
        View::Tree => widgets::tree::render(f, area, s),
        View::Files => widgets::files::render(f, area, s),
        View::Coverage => widgets::coverage::render(f, area, s),
        View::Pools => widgets::pools::render(f, area, s),
        View::Zones => widgets::zones::render(f, area, s),
    }
}
