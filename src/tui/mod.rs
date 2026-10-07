// SPDX-License-Identifier: GPL-3.0-only
//
// Ratatui presentation layer. It consumes `ScanResult` and `AnalysisResult`
// and never does filesystem I/O of its own: scanning and analysis run on a
// worker thread (`worker`) and arrive as events.
//
//   scanner ─▶ ScanResult ─▶ analysis ─▶ AnalysisResult ─▶ tui (read only)

pub mod app;
pub mod command;
pub mod event;
pub mod fmt;
pub mod state;
pub mod tree;
pub mod ui;
pub mod update;
pub mod widgets;
pub mod worker;

use crate::analysis::AnalysisConfig;
use crate::cli::Cli;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

/// Launch the interactive UI for `cli` (scan root already canonicalised).
pub fn run(cli: &Cli, root: PathBuf) -> io::Result<()> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        return Err(io::Error::other(
            "--tui needs an interactive terminal (stdin and stdout must be a tty)",
        ));
    }
    let mut config = cli.scan_config();
    config.top_files = worker::TUI_TOP_FILES;
    let request = worker::ScanRequest {
        root,
        config,
        analysis: AnalysisConfig::default(),
        nix_gc: cli.nix_gc,
    };
    let events = event::EventHandler::new(app::TICK_RATE);
    let mut app = app::App::new(request, events);
    let mut tui = app::Tui::enter()?;
    let result = app.run(&mut tui);
    tui.exit()?;
    result
}
