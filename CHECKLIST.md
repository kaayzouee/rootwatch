# Status against the development checklist (everything before "TUI")

All items in these sections are implemented and covered by tests unless noted.

* Core scanner: done (+ no per-entry allocation, one statx per entry).
* Filesystem model: full multi-filesystem abstraction (pools, filesystems, boundaries with decisions); root vs all vs selected scope; user-selectable via `--scope/--include/--exclude`.
* Analysis engine: better scoring, confidence-aware severity, per-filesystem (per-pool) scoring, growth-rate scoring (in-memory `Baseline`), age-based scoring, expected/notable/suspicious classification, combined risk score.
* `/tmp` intelligence, `/home` intelligence, Nix analysis: done. `nix-store` integration is opt-in (`--nix-gc`).
* Permission handling: optional privileged scan, sudo-aware worker, unprivileged-vs-privileged comparison, hidden-data explanation; never required.
* Scan accuracy: per-pool aggregation, skipped-mount accounting, explanation of the used/walked gap, completeness state, confidence-aware rankings with low-coverage warnings.

Not done (belong to later sections): persistence of baselines (Historical monitoring), JSON/exit codes/config file (Output), packaging (NixOS).
