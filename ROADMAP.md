# Rootwatch roadmap

```text
1. Core Scanner                   [DONE]
2. Filesystem Model               [DONE]
3. Analysis Engine                [DONE]
4. Zone Intelligence              [DONE]
5. Permission Handling            [DONE]
6. Scan Accuracy                  [DONE]
        ──────── backend baseline ────────
7. TUI                            [DONE: see notes below]
8. Historical Monitoring          [NEXT]
9. Output & Automation
10. Packaging
```

Rootwatch stays **read-only**. Safe remediation is a separate, later track.

## 1–6 Backend baseline: done

Scanner (one `statx` per entry, no per-entry allocation, O(N + D log K + M)),
multi-filesystem model with storage pools and explicit scan scope, scoring with
confidence/age/growth/expectation, `/tmp` · `/home` · Nix intelligence, optional
privileged comparison, per-pool coverage and completeness. See `README.md`.

## 7 TUI: implemented

Ticket numbers refer to the Ratatui roadmap (RW-TUI-nnn).

### Foundation
- [x] 001 Ratatui + tui-input (crossterm backend only, via Ratatui's re-export: one crossterm version)
- [x] 002 `src/tui/` module structure; scanner/analysis do not depend on it
- [x] 003 Terminal lifecycle: raw mode, alternate screen, mouse capture, restore on exit, **restore inside the panic hook** (release builds abort, so no destructor would run), resize
- [x] 004 Semantic `Command`s; all key bindings in `command.rs`
- [x] 005 One event channel for terminal input, ticks and worker results
- [x] 006 `AppState`; results held in `Arc`, immutable while displayed

### Scan lifecycle
- [x] 007 Scan and analysis run on a worker thread; the UI thread never scans
- [x] 008 `ScanStatus` + live progress (entries, directories, bytes, current path) from a lock-free sink in the scanner (`ScanConfig::progress`, `None` by default)
- [x] 009 Rescan (`r`): full state reset, no overlapping scans, no stale event can leak

### Layout and shared widgets
- [x] 010 Header / tabs / main / footer; "Terminal too small" below 80×24
- [x] 011 Shared formatting and styles (`tui/fmt.rs`)
- [x] 012 Contextual footer; least important hints drop first, `? Help` and `q Quit` never do

### Views
- [x] 013–014 Overview (verdict, risk, coverage, pressure, largest areas, finding counts, warning banner)
- [x] 015–018 Findings table, details pane, `/` filter (path, title, kind, severity, expectation, class; AND of terms)
- [x] 019–022 Tree: projection over `DirectoryIndex`, expand/collapse, severity/score/badges, details pane, name search with jump-to-match
- [x] 023 Largest files: sort (size / age / path), filter, details
- [x] 024 Coverage: completeness badge, gaps, denied/unreadable/pruned/skipped lists, scrollable
- [x] 025 Storage pools with their scanned and skipped mounts
- [x] 026–028 Zones: temporary data, home, Nix (GC estimate shown as QUERIED / NOT QUERIED / UNAVAILABLE)

### Interaction
- [x] 029 Search prompt (`/`) on Findings, Tree, Files, Pools (`tui-input`)
- [x] 030 Navigation model (j/k h/l Enter Esc Tab g/G / r q, `1`–`7`, `?`)
- [x] 031 Mouse: wheel, row click, tab click (never required)
- [x] 032 Tested at 80×24, 100×30, 120×40, 160×50 and below the minimum

### Testing
- [x] 033 Command mapping · 034 tree projection · 035 filtering
- [x] 036 `TestBackend` render tests (every view, empty, failed, scanning, partial coverage, too small)
- [x] 037 Scan->worker->event->state->render integration: success, rescan, failure, permission errors (run as an unprivileged user), incomplete coverage, empty tree, subtree scan, multiple pools, Nix not queried / unavailable
- [x] Real-terminal checks: `scripts/pty_smoke.py` (alternate screen, quit, Ctrl-C, navigation, resize) and `scripts/pty_panic.py` (panic restores the terminal)

### CLI and docs
- [x] 038 `--tui`; report mode stays the default; `--privileged` is rejected with `--tui`
- [x] 039 Report-mode behaviour unchanged (existing report/scan tests untouched and green; the TUI worker produces the same totals and coverage as a direct scan)
- [~] 040 Docs: keyboard reference, architecture, coverage/confidence, terminal requirements, **text** captures in `docs/screenshots/`. *No GIF/PNG screenshots yet.*

### Known limitations
- `--privileged` is not available in the TUI (sudo needs the terminal for its password prompt).
- Tree search matches directory names only; the index holds directories, not individual files.
- Findings are capped at 200 and Largest files at 200.
- `SIGTERM`/`SIGHUP` are not handled specially (a killed process cannot restore the terminal; `reset` fixes it). Normal exit, `q`, Ctrl-C and panics are all covered.
- Verified in a pseudo-terminal harness and `TestBackend`, not yet by hand on real terminal emulators or on NixOS.

## 8 Historical Monitoring: next

Persistent baselines are storage plus lifecycle around the existing in-memory `Baseline`;
they do not block the TUI, which already shows growth when a baseline is supplied.

- [ ] Persist `Baseline`
- [ ] Load the previous baseline automatically
- [ ] Versioned on-disk format
- [ ] Compare the current scan against history ("since last scan" findings)
- [ ] Per-filesystem history
- [ ] Growth trends and velocity
- [ ] Historical risk changes
- [ ] TUI trend view

## 9 Output & Automation

- [ ] JSON schema and stable machine-readable output
- [ ] Exit-code contract (severity-based)
- [ ] Config file, CLI/config precedence
- [ ] Custom attention zones and severity thresholds
- [ ] Quiet / verbose modes
- [ ] Documentation

## 10 Packaging

- [ ] Nix derivation (`PKG-CLI-rootwatch.nix`), add to `PKG-CLI-monitoring.nix`
- [ ] Flake output, `nixos-rebuild` test
- [ ] Installation documentation, release packaging
