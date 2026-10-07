// SPDX-License-Identifier: GPL-3.0-only
//
// Terminal lifecycle (`Tui`) and the application shell (`App`).
//
// Restoration is deliberately redundant:
//   * normal exit      -> `Tui::exit` / `Drop`
//   * panic            -> a panic hook restores the terminal *before* the
//                         message is printed (essential: release builds use
//                         `panic = "abort"`, so no destructor would ever run)
//   * Ctrl-C           -> raw mode turns it into a key event, which maps to
//                         `Command::Quit` and leaves through the normal path
// `restore_terminal` is idempotent, so running it twice is harmless.

use super::event::{Event, EventHandler};
use super::state::AppState;
use super::ui;
use super::update::Effect;
use super::worker::{self, ScanRequest};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use std::io::{self, Stdout};
use std::panic;
use std::sync::Once;
use std::thread::JoinHandle;
use std::time::Duration;

pub const TICK_RATE: Duration = Duration::from_millis(100);

/// Leave raw mode / the alternate screen / mouse capture. Safe to call twice.
pub fn restore_terminal() -> io::Result<()> {
    let raw = disable_raw_mode();
    let screen = execute!(
        io::stdout(),
        DisableMouseCapture,
        LeaveAlternateScreen,
        Show
    );
    raw.and(screen)
}

fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let original = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            // Restore first so the panic message lands on the normal screen.
            let _ = restore_terminal();
            original(info);
        }));
    });
}

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active: bool,
}

impl Tui {
    pub fn enter() -> io::Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
            let _ = restore_terminal();
            return Err(e);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(t) => t,
            Err(e) => {
                let _ = restore_terminal();
                return Err(e);
            }
        };
        Ok(Self {
            terminal,
            active: true,
        })
    }

    pub fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> io::Result<()> {
        self.terminal.draw(render).map(|_| ())
    }

    pub fn exit(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        restore_terminal()?;
        self.terminal.show_cursor()
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.exit();
    }
}

pub struct App {
    pub state: AppState,
    pub events: EventHandler,
    request: ScanRequest,
    worker: Option<JoinHandle<()>>,
}

impl App {
    pub fn new(request: ScanRequest, events: EventHandler) -> Self {
        let state = AppState::new(
            request.root.clone(),
            request.config.scope.label().to_string(),
        );
        Self {
            state,
            events,
            request,
            worker: None,
        }
    }

    /// Reset the UI state and start a worker. Used for the first scan and for
    /// every rescan, so both follow exactly the same path.
    pub fn start_scan(&mut self) {
        self.state.begin_scan();
        self.worker = Some(worker::spawn(self.request.clone(), self.events.sender()));
    }

    pub fn update(&mut self, event: Event) {
        if self.state.handle_event(event) == Effect::StartScan {
            self.start_scan();
        }
    }

    /// Wait for the worker to finish (tests; the UI never joins).
    pub fn join_worker(&mut self) {
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }

    pub fn run(&mut self, tui: &mut Tui) -> io::Result<()> {
        self.start_scan();
        while self.state.running {
            tui.draw(|f| ui::render(f, &mut self.state))?;
            // Block for the next event (a tick arrives every 100 ms, so the
            // spinner moves and progress refreshes), then drain whatever else
            // is queued so a burst of input costs one redraw, not many.
            let first = self
                .events
                .next()
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            self.update(first);
            while self.state.running {
                match self.events.try_next() {
                    Ok(ev) => self.update(ev),
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }
}
