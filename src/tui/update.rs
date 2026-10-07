// SPDX-License-Identifier: GPL-3.0-only
//
// Events and commands -> state changes. Pure logic: no terminal, no threads, no
// filesystem. Anything that needs the outside world (starting a scan) is
// returned as an `Effect` for the application shell to perform.

use super::command::{Command, InputMode, input_request, map_key};
use super::event::Event;
use super::state::*;
use ratatui::crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    None,
    StartScan,
}

const WHEEL_STEP: isize = 3;

impl AppState {
    pub fn handle_event(&mut self, event: Event) -> Effect {
        match event {
            Event::Tick => {
                self.tick = self.tick.wrapping_add(1);
            }
            Event::Key(k) => return self.handle_key(k),
            Event::Mouse(m) => return self.handle_mouse(m),
            // The next draw simply uses the new size.
            Event::Resize(..) => {}

            Event::ScanStarted => {
                if !self.scan_status.busy() {
                    self.begin_scan();
                }
            }
            Event::ScanProgress(p) => {
                if self.scan_status == ScanStatus::Scanning {
                    self.progress = Some(p);
                }
            }
            Event::ScanFinished(res) => {
                if self.scan_status == ScanStatus::Scanning {
                    match res {
                        Ok(r) => self.scan_finished(r),
                        Err(e) => self.scan_failed(e),
                    }
                }
            }
            Event::AnalysisFinished(res) => {
                if self.scan_status == ScanStatus::Analyzing {
                    match res {
                        Ok(a) => self.analysis_finished(a),
                        Err(e) => self.scan_failed(e),
                    }
                }
            }
        }
        Effect::None
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Effect {
        let mode = self.input_mode();
        let cmd = map_key(key, mode);
        if mode == InputMode::Search && cmd == Command::None {
            if let Some(req) = input_request(key) {
                self.search.input.handle(req);
                let text = self.search.input.value().to_string();
                self.apply_filter(&text);
            }
            return Effect::None;
        }
        self.handle_command(cmd)
    }

    pub fn set_view(&mut self, view: View) {
        if self.search.active {
            self.search_commit();
        }
        self.view = view;
        self.message = None;
    }

    pub fn handle_command(&mut self, cmd: Command) -> Effect {
        if cmd == Command::Quit {
            self.running = false;
            return Effect::None;
        }

        if self.help_open {
            if matches!(cmd, Command::Help | Command::Back | Command::Enter) {
                self.help_open = false;
            }
            return Effect::None;
        }

        if self.search.active {
            match cmd {
                Command::Back => self.search_cancel(),
                Command::Enter => self.search_commit(),
                Command::NextTab => self.set_view(self.view.next()),
                Command::PreviousTab => self.set_view(self.view.previous()),
                Command::Up | Command::Down | Command::PageUp | Command::PageDown => {
                    self.view_command(cmd)
                }
                _ => {}
            }
            return Effect::None;
        }

        match cmd {
            Command::NextTab => self.set_view(self.view.next()),
            Command::PreviousTab => self.set_view(self.view.previous()),
            Command::GoTo(v) => self.set_view(v),
            Command::Help => self.help_open = true,
            Command::Refresh | Command::None => {}
            Command::Rescan => {
                if self.scan_status.busy() {
                    self.message = Some("a scan is already running".into());
                } else {
                    return Effect::StartScan;
                }
            }
            Command::Search => self.start_search(),
            Command::Back => self.back(),
            other => self.view_command(other),
        }
        Effect::None
    }

    /// Esc: close the innermost thing that is open.
    fn back(&mut self) {
        match self.view {
            View::Findings if self.findings.detail_open => self.findings.detail_open = false,
            View::Findings if !self.findings.filter.is_empty() => self.apply_filter(""),
            View::Files if self.files.detail_open => self.files.detail_open = false,
            View::Files if !self.files.filter.is_empty() => self.apply_filter(""),
            View::Tree if self.tree.detail_open => self.tree.detail_open = false,
            View::Tree if self.tree.searching() => self.apply_filter(""),
            View::Pools if !self.pools.filter.is_empty() => self.apply_filter(""),
            _ => {}
        }
        self.message = None;
    }

    fn view_command(&mut self, cmd: Command) {
        if !self.ready() {
            return;
        }
        let page = self.layout.page_rows() as isize;
        // Normalise vertical movement into a signed step (None = absolute jump).
        let step = match cmd {
            Command::Up => Some(-1),
            Command::Down => Some(1),
            Command::PageUp => Some(-page),
            Command::PageDown => Some(page),
            _ => None,
        };
        match self.view {
            View::Overview => self.overview_command(cmd, step),
            View::Findings => self.findings_command(cmd, step),
            View::Tree => self.tree_command(cmd, step),
            View::Files => self.files_command(cmd, step),
            View::Coverage => self.scroll_command(cmd, step, View::Coverage),
            View::Pools => self.pools_command(cmd, step),
            View::Zones => self.zones_command(cmd, step),
        }
    }

    fn overview_command(&mut self, cmd: Command, step: Option<isize>) {
        let Some(a) = self.analysis.clone() else {
            return;
        };
        let n = a.pool_scores.len();
        match (cmd, step) {
            (_, Some(d)) => {
                self.overview.selected_pool = clamp_move(self.overview.selected_pool, n, d.signum())
            }
            (Command::Top, _) => self.overview.selected_pool = clamp_move(None, n, 0),
            (Command::Bottom, _) => self.overview.selected_pool = n.checked_sub(1),
            (Command::Enter, _) => {
                // Jump to that pool in the Pools view.
                if let (Some(sel), Some(r)) = (self.overview.selected_pool, self.result.clone())
                    && let Some(ps) = a.pool_scores.get(sel)
                {
                    self.pools.set_filter(&r, "");
                    let row = self.pools.rows.iter().position(|&p| p == ps.pool);
                    self.pools.table.select(row);
                    self.set_view(View::Pools);
                }
            }
            _ => {}
        }
    }

    fn findings_command(&mut self, cmd: Command, step: Option<isize>) {
        let Some(a) = self.analysis.clone() else {
            return;
        };
        let len = self.findings.filtered_indices.len();
        match (cmd, step) {
            (_, Some(d)) => self.findings.move_by(d),
            (Command::Top, _) => self.findings.table.select(clamp_move(None, len, 0)),
            (Command::Bottom, _) => self.findings.table.select(len.checked_sub(1)),
            (Command::Enter | Command::Right, _) if self.findings.selected(&a).is_some() => {
                self.findings.detail_open = cmd == Command::Right || !self.findings.detail_open;
            }
            (Command::Left, _) => self.findings.detail_open = false,
            _ => {}
        }
    }

    fn files_command(&mut self, cmd: Command, step: Option<isize>) {
        let Some(r) = self.result.clone() else { return };
        let len = self.files.order.len();
        match (cmd, step) {
            (_, Some(d)) => self.files.move_by(d),
            (Command::Top, _) => self.files.table.select(clamp_move(None, len, 0)),
            (Command::Bottom, _) => self.files.table.select(len.checked_sub(1)),
            (Command::Enter | Command::Right, _) if self.files.selected(&r).is_some() => {
                self.files.detail_open = cmd == Command::Right || !self.files.detail_open;
            }
            (Command::Left, _) => self.files.detail_open = false,
            (Command::Sort, _) => self.files.toggle_sort(&r),
            _ => {}
        }
    }

    fn tree_command(&mut self, cmd: Command, step: Option<isize>) {
        let Some(r) = self.result.clone() else { return };
        match (cmd, step) {
            (_, Some(d)) => self.tree.move_by(d),
            (Command::Top, _) => self.tree.top(),
            (Command::Bottom, _) => self.tree.bottom(),
            (Command::Right, _) => self.tree.right(&r),
            (Command::Left, _) => self.tree.left(&r),
            (Command::Expand, _) => self.tree.toggle(&r),
            (Command::Collapse, _) => self.tree.collapse(&r),
            (Command::Sort, _) => self.tree.toggle_sort(&r),
            (Command::Enter, _) => {
                if !self.tree.jump_to_selected_match(&r) {
                    self.tree.detail_open = !self.tree.detail_open;
                } else {
                    // the search result list is gone; clear the prompt text too
                    self.search.input = Default::default();
                }
            }
            _ => {}
        }
    }

    fn pools_command(&mut self, cmd: Command, step: Option<isize>) {
        let len = self.pools.rows.len();
        match (cmd, step) {
            (_, Some(d)) => self.pools.move_by(d),
            (Command::Top, _) => self.pools.table.select(clamp_move(None, len, 0)),
            (Command::Bottom, _) => self.pools.table.select(len.checked_sub(1)),
            _ => {}
        }
    }

    fn scroll_command(&mut self, cmd: Command, step: Option<isize>, view: View) {
        let scroll = match view {
            View::Coverage => &mut self.coverage.scroll,
            _ => &mut self.zones.scroll,
        };
        match (cmd, step) {
            (_, Some(d)) => *scroll = (*scroll as isize + d).max(0) as u16,
            (Command::Top, _) => *scroll = 0,
            // The renderer clamps to the real content height.
            (Command::Bottom, _) => *scroll = u16::MAX,
            _ => {}
        }
    }

    fn zones_command(&mut self, cmd: Command, step: Option<isize>) {
        let Some(a) = self.analysis.clone() else {
            return;
        };
        match cmd {
            Command::Left | Command::Right => {
                let i =
                    self.zones.tab.index() as isize + if cmd == Command::Right { 1 } else { -1 };
                let n = ZoneTab::ALL.len() as isize;
                self.zones.tab = ZoneTab::ALL[i.rem_euclid(n) as usize];
                self.zones.scroll = 0;
            }
            Command::Up | Command::Down => {
                let d = step.unwrap_or(0);
                match self.zones.tab {
                    ZoneTab::Temp => {
                        self.zones.temp_sel =
                            clamp_move(Some(self.zones.temp_sel), a.temp.len(), d).unwrap_or(0)
                    }
                    ZoneTab::Home => {
                        self.zones.home_sel =
                            clamp_move(Some(self.zones.home_sel), a.home.len(), d).unwrap_or(0)
                    }
                    ZoneTab::Nix => self.scroll_command(cmd, step, View::Zones),
                }
                if self.zones.tab != ZoneTab::Nix {
                    self.zones.scroll = 0;
                }
            }
            _ => self.scroll_command(cmd, step, View::Zones),
        }
    }

    pub fn handle_mouse(&mut self, m: MouseEvent) -> Effect {
        if self.help_open {
            return Effect::None;
        }
        match m.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let cmd = if m.kind == MouseEventKind::ScrollUp {
                    Command::Up
                } else {
                    Command::Down
                };
                for _ in 0..WHEEL_STEP {
                    self.view_command(cmd);
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some((_, v)) = self
                    .layout
                    .tabs
                    .iter()
                    .find(|(r, _)| m.column >= r.x && m.column < r.x + r.width && m.row == r.y)
                    .copied()
                {
                    self.set_view(v);
                    return Effect::None;
                }
                if let Some(row) = self.layout.row_at(m.column, m.row) {
                    self.click_row(row);
                }
            }
            _ => {}
        }
        Effect::None
    }

    /// Click selects a row; clicking the already-selected row acts like Enter.
    fn click_row(&mut self, row: usize) {
        if !self.ready() {
            return;
        }
        let (already, in_range) = match self.view {
            View::Findings => (
                self.findings.table.selected() == Some(row),
                row < self.findings.filtered_indices.len(),
            ),
            View::Files => (
                self.files.table.selected() == Some(row),
                row < self.files.order.len(),
            ),
            View::Pools => (
                self.pools.table.selected() == Some(row),
                row < self.pools.rows.len(),
            ),
            View::Tree => {
                let len = if self.tree.searching() {
                    self.tree.matches.len()
                } else {
                    self.tree.rows.len()
                };
                (self.tree.selected_index() == Some(row), row < len)
            }
            _ => return,
        };
        if !in_range {
            return;
        }
        match self.view {
            View::Findings => self.findings.table.select(Some(row)),
            View::Files => self.files.table.select(Some(row)),
            View::Pools => self.pools.table.select(Some(row)),
            View::Tree => self.tree.select_index(row),
            _ => {}
        }
        if already {
            self.view_command(if self.view == View::Tree && !self.tree.searching() {
                Command::Expand
            } else {
                Command::Enter
            });
        }
    }
}
