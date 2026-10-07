// SPDX-License-Identifier: GPL-3.0-only

// Scan worker thread

use super::event::Event;
use crate::analysis::{self, AnalysisConfig, AnalysisInputs};
use crate::model::ScanResult;
use crate::nix;
use crate::scanner::{ScanConfig, ScanProgress, scan};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const NIX_GC_TIMEOUT: Duration = Duration::from_secs(300);
/// The TUI shows the largest files in a table, so keep more than the report.
pub const TUI_TOP_FILES: usize = 200;

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub root: PathBuf,
    pub config: ScanConfig,
    pub analysis: AnalysisConfig,
    /// Ask the Nix tools for the garbage-collectable size (opt-in, read-only).
    pub nix_gc: bool,
}

pub fn spawn(request: ScanRequest, tx: Sender<Event>) -> JoinHandle<()> {
    thread::Builder::new()
        .name("rootwatch-scan".into())
        .spawn(move || run(request, tx))
        .expect("spawning the scan worker thread")
}

fn run(request: ScanRequest, tx: Sender<Event>) {
    let _ = tx.send(Event::ScanStarted);

    // A reporter thread turns the scanner's atomic counters into events.
    let progress = Arc::new(ScanProgress::default());
    let done = Arc::new(AtomicBool::new(false));
    let reporter = {
        let (progress, done, tx) = (progress.clone(), done.clone(), tx.clone());
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                thread::sleep(PROGRESS_INTERVAL);
                if tx.send(Event::ScanProgress(progress.snapshot())).is_err() {
                    break;
                }
            }
        })
    };

    let mut config = request.config.clone();
    config.progress = Some(progress);
    let scanned = catch_unwind(AssertUnwindSafe(|| scan(&request.root, &config)));
    done.store(true, Ordering::Relaxed);
    let _ = reporter.join();

    let result: Arc<ScanResult> = match scanned {
        Ok(Ok(r)) => Arc::new(r),
        Ok(Err(e)) => {
            let _ = tx.send(Event::ScanFinished(Err(format!(
                "scan of {} failed: {e}",
                request.root.display()
            ))));
            return;
        }
        Err(_) => {
            let _ = tx.send(Event::ScanFinished(Err("the scanner panicked".into())));
            return;
        }
    };
    if tx.send(Event::ScanFinished(Ok(result.clone()))).is_err() {
        return;
    }

    // Analysis (and the optional, potentially slow, nix query) also stay off
    // the UI thread.
    let analysed = catch_unwind(AssertUnwindSafe(|| {
        let dead = request
            .nix_gc
            .then(|| nix::query_dead_paths(NIX_GC_TIMEOUT));
        let inputs = AnalysisInputs {
            nix_dead: dead.as_ref(),
            ..AnalysisInputs::default()
        };
        analysis::analyze_with(&result, &request.analysis, &inputs)
    }));
    let _ = tx.send(Event::AnalysisFinished(match analysed {
        Ok(a) => Ok(Arc::new(a)),
        Err(_) => Err("the analysis panicked".into()),
    }));
}
