// SPDX-License-Identifier: GPL-3.0-only
// Enters the TUI terminal mode and then panics, to verify the terminal is
// restored by the panic hook (release builds abort, so no destructor runs):
//   cargo run --release --example panic_probe
use rootwatch::tui::app::Tui;
use std::time::Duration;

fn main() {
    let mut tui = Tui::enter().expect("terminal");
    tui.draw(|_| {}).expect("draw");
    std::thread::sleep(Duration::from_millis(200));
    panic!("probe panic");
}
