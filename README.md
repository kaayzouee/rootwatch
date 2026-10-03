# rootwatch

Read-only Linux filesystem scanner for a future SOC-style disk TUI.

<table border="1" cellpadding="5" cellspacing="0">
  <tr>
    <th colspan="2"><code>rootwatch [OPTIONS] [PATH]</code></th>
  </tr>
  <tr>
    <td colspan="2">PATH defaults to <code>/</code></td>
  </tr>
</table>

<br>

<table border="1" cellpadding="5" cellspacing="0">
  <thead>
    <tr>
      <th>Option</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--scope root|all|select</code></td>
      <td>which filesystems are entered (default: root)</td>
    </tr>
    <tr>
      <td><code>--include MOUNT</code></td>
      <td>enter this mountpoint too (repeatable)</td>
    </tr>
    <tr>
      <td><code>--exclude PATH</code></td>
      <td>never descend into PATH (repeatable)</td>
    </tr>
    <tr>
      <td><code>--no-prune</code></td>
      <td>do not prune /proc /sys /dev /run</td>
    </tr>
    <tr>
      <td><code>--privileged</code></td>
      <td>measure what permissions hide (re-runs via sudo)</td>
    </tr>
    <tr>
      <td><code>--elevate-with CMD</code></td>
      <td>elevation command (default: sudo)</td>
    </tr>
    <tr>
      <td><code>--nix-gc</code></td>
      <td>ask nix-store for the garbage-collectable size</td>
    </tr>
    <tr>
      <td><code>--top N</code></td>
      <td>rows per ranking</td>
    </tr>
  </tbody>
</table>

## v0.3.0

### Pipeline and complexity

N = entries, D = directories, M = mounts, K = rows shown, H = depth.

<table border="1" cellpadding="5" cellspacing="0">
  <thead>
    <tr>
      <th>stage</th>
      <th>cost</th>
      <th>how</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>mount discovery</td>
      <td>O(M)</td>
      <td><code>/proc/self/mountinfo</code> read once</td>
    </tr>
    <tr>
      <td>traversal</td>
      <td>O(N)</td>
      <td>iterative DFS, <code>openat</code> + raw <code>getdents64</code>, O(H) open fds</td>
    </tr>
    <tr>
      <td>metadata</td>
      <td>O(N)</td>
      <td><strong>one <code>statx</code> per entry</strong>, relative to the parent dir fd (inode, blocks, mtime, uid, nlink, mount id)</td>
    </tr>
    <tr>
      <td>hard-link dedup</td>
      <td>O(1)/entry</td>
      <td>Fx-hashed <code>(dev, ino)</code> set, only for <code>nlink &gt; 1</code></td>
    </tr>
    <tr>
      <td>classification</td>
      <td>O(1)/dir</td>
      <td>component trie stepped during the DFS; no path matching afterwards</td>
    </tr>
    <tr>
      <td>aggregation</td>
      <td>O(D)</td>
      <td>arena of dir nodes, children always have larger ids than parents, one reverse pass</td>
    </tr>
    <tr>
      <td>scoring</td>
      <td>O(D)</td>
      <td>one pass; reason strings built only for retained rows</td>
    </tr>
    <tr>
      <td>ranking</td>
      <td>O(D log K)</td>
      <td>bounded min-heaps, no global sort</td>
    </tr>
    <tr>
      <td>report / TUI</td>
      <td>O(rows shown)</td>
      <td>consumes the model, never touches the filesystem</td>
    </tr>
  </tbody>
</table>

Total: **O(N + D log K + M)**. Paths are rebuilt (O(depth)) only for rows that are displayed.

Measured against v0.2.2 (warm cache, 1 vCPU sandbox, median of 5):

<table border="1" cellpadding="5" cellspacing="0">
  <thead>
    <tr>
      <th>tree</th>
      <th>v0.2.2</th>
      <th>v0.3.0</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>351k entries, depth 34</td>
      <td>2.48 s</td>
      <td>0.49 s (5.0×)</td>
    </tr>
    <tr>
      <td><code>/usr</code> (114k entries)</td>
      <td>0.54 s</td>
      <td>0.19 s (2.8×)</td>
    </tr>
    <tr>
      <td><code>/home</code></td>
      <td>0.45 s</td>
      <td>0.12 s (3.6×)</td>
    </tr>
  </tbody>
</table>

Analysis of the 351k-entry tree takes 1 ms; top-20 ranking 0.13 ms. The remaining
time is the kernel answering `statx`. Byte totals equal `du` exactly. Scanning is
still single-threaded on purpose: profile first, parallelise only if benchmarks on
real hardware justify it (the walker is isolated in `scanner.rs`).

### Filesystem model

* `ScanScope::Root` (default): only the filesystem holding the scan root; other mounts are listed with the reason they were skipped.
* `ScanScope::All`: plus every local disk-backed or tmpfs mount. Pseudo (`proc`, `sysfs`, ...), network/FUSE, overlay and squashfs/erofs image mounts are never entered implicitly.
* `ScanScope::Selected`: plus the mounts named with `--include`. An include forces a mount in regardless of kind, and implies its ancestor mounts.
* Mount identity per directory comes from `statx`'s `stx_mnt_id`, so bind mounts are detected (a bind of content that is scanned elsewhere is skipped, not double counted). **Self binds** - NixOS's read-only `/nix/store` - are recognised and traversed.
* Filesystems are grouped into **storage pools**. On btrfs every subvolume reports the whole pool through `statvfs`, so `/`, `/nix` and `/home` must be judged together. This is what turns "95 GiB used, 520 MiB observed" from a mystery into an explicit "these sibling mounts share the pool and were not walked".

### Scan accuracy

Coverage is computed per pool. The report states a completeness level
(COMPLETE ≥95%, SUBSTANTIAL ≥80%, PARTIAL ≥40%, MINIMAL), a confidence, and a list
of causes for `used − walked`: skipped sibling mounts, permission-denied paths,
I/O errors, pruned paths, shared extents (walked > used), or unattributed
metadata/snapshots/deleted-open files. Separate disks that were not scanned are
listed but do not count against coverage. Subtree scans (`rootwatch /home/kay`)
are judged by errors only; whole-filesystem coverage is not applicable.

When coverage is low the report says so next to every ranking
(`[PROVISIONAL]` / `[UNRELIABLE]`), findings are marked as lower bounds (`>=`),
and the overall verdict becomes *at least X* or *UNDETERMINED* - never "healthy".

### Scoring

```text
share    = bytes on the pool / pool used * 100
urgency  = 0.1 up to 50% full, linear to 1.0 at 90%, 1.3 at 100%
weight   = path class: /tmp 2.0, /home 1.5, /var 1.25, generic 1.0, /nix 0.75, system 0.5
expected = 0.8 expected, 1.0 notable, 1.5 suspicious
age      = 1 + 0.5 * stale fraction (temp, 7d) | 1 + 0.25 * stale fraction (home, 90d)
growth   = up to +40 when a Baseline is supplied: 40 * sat(rate %/day / 5) * sat(relative growth / 2)

score    = min(100, share * urgency * weight * expected * age + growth)
severity = LOW < 5 <= MEDIUM < 15 <= HIGH < 35 <= CRITICAL
```

Directories whose single child holds ≥90% of their bytes are pass-through
containers and are not reported themselves; the frontier is. A combined **risk
score** is a bounded noisy-OR of capacity, concentration, temporary data, growth
and blind-spot components. Per-pool scores, severity counters and per-node
score/severity vectors (for a tree view) are in `AnalysisResult`.

### Specialised zones

* **Temporary data** (`/tmp`, `/var/tmp`): per-zone age distribution, stale bytes (7 d / 30 d), owners, largest children and files, RAM-backed (tmpfs) detection, assessment (normal / large / stale).
* **Home** (`/home/*`, `/root`, each a zone): buckets (Downloads, .cache, .local, .cargo, .config, toolchains, other hidden, other), user-owned vs root-owned vs other-owned bytes, age distribution, largest files, detected projects (git, Cargo, Node, Python, Go, Nix, JVM, CMake) and their regenerable artifact directories (`target`, `node_modules`, `.venv`, ...).
* **Nix**: store size, path count, database/profile sizes, generations per profile, largest paths, largest packages with version counts, and with `--nix-gc` the garbage-collectable size from `nix-store --gc --print-dead` (falls back to `nix-collect-garbage --dry-run`). Rootwatch never runs a collection.

### Permissions

Rootwatch never needs root. `--privileged` re-runs the same scan as a worker via
`sudo` (or `--elevate-with`) and compares: bytes and entries hidden, coverage
before/after, and the denied directories with their real sizes. The worker is not
given paths to read, so elevating it cannot probe arbitrary locations.

### Library layout

`lib.rs` exposes `scanner`, `model`, `mounts`, `zones`, `coverage`, `analysis`,
`temp`, `home`, `nix`, `privilege`, `output`, `cli`. The future Ratatui layer
should consume `ScanResult` (`DirectoryIndex` with `children()`, `path()`,
`usage`) and `AnalysisResult`.

### Behaviour changes from v0.2.2

* A directory's own inode blocks are now part of its subtree total (du-style); totals are v0.2.2's plus the root directory's blocks.
* Severity thresholds and scoring changed (see above), so severities differ from v0.2.2.
* `walkdir` is gone; `rustix` gains the `process` feature (fd limit, euid).
* Requires Linux ≥ 5.8 for mount ids; older kernels fall back to device comparison (no bind-mount detection).
* Crate is now library + binary; `Finding`, `AnalysisConfig`, `ScanConfig` changed shape.

### FAQ

* Where's 0.2.2?: I don't release 0.2.2 because it contained a lot of security issues.