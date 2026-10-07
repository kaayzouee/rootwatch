# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0]

### Added
- `rootwatch --tui`: interactive terminal UI (opt-in; the text report stays the default).
  - Views: Overview, Findings (details pane, `/` filter), Tree (expand/collapse, details pane, name search with jump-to-match), Files (sort by size/age/path, filter, details), Coverage, Storage pools, Zones (temporary data, home, Nix).
  - Scan and analysis run on a worker thread; live progress (entries, directories, allocated bytes, current path); `r` rescans with a full state reset.
  - Partial coverage is impossible to miss: warning banner on the Overview, `≥` lower-bound sizes, verdict "at least X" or UNDETERMINED instead of "healthy".
  - Nix panel shows the GC estimate as QUERIED / NOT QUERIED / UNAVAILABLE.
  - Search prompt (`tui-input`), mouse (wheel, row click, tab click), help overlay (`?`), `1`–`7` view jumps, "Terminal too small" below 80×24.
  - Terminal is restored on quit, Ctrl-C and panic (the restore lives in the panic hook because release builds use `panic = "abort"`).
- `ScanConfig::progress`: optional lock-free progress sink in the scanner (`None` by default; updated once per directory).
- `examples/tui_screens` (text captures -> `docs/screenshots/`), `examples/tui_bench`, `examples/panic_probe`.
- `scripts/pty_smoke.py` and `scripts/pty_panic.py`: drive the real binary on a pseudo-terminal.
- 58 new tests (`tests/tui.rs` and unit tests): command mapping, tree projection, filtering, render tests for every view and state, mouse, worker->event->state->render integration (success, rescan, failure, permission errors, partial coverage, empty tree, subtree scan, multiple pools, Nix states).
- `ROADMAP.md` (replaces `CHECKLIST.md`): backend done -> TUI -> Historical Monitoring -> Output & Automation -> Packaging.
- README: TUI usage, architecture, keys, coverage/`PROVISIONAL`/`UNRELIABLE`, terminal requirements.

### Changed
- Dependencies: `ratatui` 0.30 (crossterm backend only, via its re-export) and `tui-input` (no backend of its own).
- `--privileged` is rejected together with `--tui` (sudo needs the terminal for its password prompt).

### Security
- Terminal-facing text now escapes control characters in filesystem-derived paths and other dynamic TUI/report text to prevent terminal escape injection.
- Root `--nix-gc` execution now ignores relative, non-root-owned, or group/other-writable `PATH` entries instead of trusting them for `nix-store` / `nix-collect-garbage`.
- Added `SECURITY.md` with vulnerability-reporting guidance and the security-relevant trust boundaries.

### Known limitations
- No GIF/PNG screenshots yet (text captures only).
- TUI tree search matches directory names only; Findings and Largest files are capped at 200.
- `SIGTERM`/`SIGHUP` are not handled specially.
- Verified with a pty harness and `TestBackend`; not yet by hand on real terminal emulators or on NixOS.

## [0.3.0]

### Added
- Scanner rewrite: iterative DFS with `openat` + raw `getdents64`, one `statx` per entry relative to the parent fd, name pool and node arena, bottom-up aggregation. O(N + D log K + M); 2.8–5× faster than v0.2.2; byte totals match `du`.
- Filesystem model: mount discovery, storage pools (btrfs subvolumes share a pool), scan scopes `root` / `select` / `all`, bind and self-bind mount handling (NixOS `/nix/store`).
- Scan accuracy: per-pool coverage, completeness levels, confidence, explanation of the used-vs-walked gap.
- Analysis: urgency-weighted scoring, confidence-aware severity, expected/notable/suspicious, age and growth scoring (in-memory baseline), per-pool scores, combined risk score.
- Zone intelligence for `/tmp` and `/var/tmp`, `/home/*` and `/root`, and Nix (generations, packages, optional `nix-store` GC estimate).
- `--privileged` worker comparison measuring what permissions hide.

### Changed
- A directory's own inode blocks now count toward its subtree total (du-style).
- Severity thresholds and scoring changed, so severities differ from v0.2.2.
- `walkdir` removed; crate is now library + binary.
- Requires Linux ≥ 5.8 for mount ids (older kernels fall back to device comparison).
