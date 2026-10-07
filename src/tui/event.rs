// SPDX-License-Identifier: GPL-3.0-only
//
// One event path for everything: terminal input, timer ticks and results from
// the scan worker all arrive on the same channel, so the UI thread has a single
// place to wait and never blocks on any one source.

use crate::analysis::AnalysisResult;
use crate::model::ScanResult;
use crate::scanner::ProgressSnapshot;
use ratatui::crossterm::event::{self, Event as CtEvent, KeyEvent, KeyEventKind, MouseEvent};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Event {
    Tick,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),

    ScanStarted,
    ScanProgress(ProgressSnapshot),
    ScanFinished(Result<Arc<ScanResult>, String>),

    AnalysisFinished(Result<Arc<AnalysisResult>, String>),
}

pub struct EventHandler {
    tx: Sender<Event>,
    rx: Receiver<Event>,
}

impl EventHandler {
    /// A handler with a thread that forwards terminal events and ticks.
    pub fn new(tick_rate: Duration) -> Self {
        let handler = Self::headless();
        let tx = handler.tx.clone();
        thread::spawn(move || terminal_thread(tx, tick_rate));
        handler
    }

    /// Only the channel, no terminal thread: for tests and embedding.
    pub fn headless() -> Self {
        let (tx, rx) = mpsc::channel();
        Self { tx, rx }
    }

    /// A sender that background workers use to report results.
    pub fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }

    pub fn next(&self) -> Result<Event, RecvError> {
        self.rx.recv()
    }

    pub fn try_next(&self) -> Result<Event, TryRecvError> {
        self.rx.try_recv()
    }
}

fn terminal_thread(tx: Sender<Event>, tick_rate: Duration) {
    let mut last_tick = Instant::now();
    loop {
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        match event::poll(timeout) {
            Ok(true) => {
                let sent = match event::read() {
                    // Windows reports key releases too; act on presses only.
                    Ok(CtEvent::Key(k)) if k.kind == KeyEventKind::Press => tx.send(Event::Key(k)),
                    Ok(CtEvent::Mouse(m)) => tx.send(Event::Mouse(m)),
                    Ok(CtEvent::Resize(w, h)) => tx.send(Event::Resize(w, h)),
                    Ok(_) => Ok(()),
                    Err(_) => return,
                };
                if sent.is_err() {
                    return;
                }
            }
            Ok(false) => {}
            Err(_) => return,
        }
        if last_tick.elapsed() >= tick_rate {
            if tx.send(Event::Tick).is_err() {
                return;
            }
            last_tick = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_results_and_input_share_one_channel() {
        let h = EventHandler::headless();
        let tx = h.sender();
        tx.send(Event::ScanStarted).unwrap();
        tx.send(Event::Tick).unwrap();
        tx.send(Event::ScanFinished(Err("boom".into()))).unwrap();
        assert!(matches!(h.next().unwrap(), Event::ScanStarted));
        assert!(matches!(h.try_next().unwrap(), Event::Tick));
        assert!(matches!(h.next().unwrap(), Event::ScanFinished(Err(_))));
        assert!(matches!(h.try_next(), Err(TryRecvError::Empty)));
    }
}
