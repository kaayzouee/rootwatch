// SPDX-License-Identifier: GPL-3.0-only
//
// Optional privileged scanning, deliberately outside the core scanner.
//
// Rootwatch never needs root. When asked (`--privileged`) the normal scan runs
// unprivileged in-process; then the same binary is re-run as a *worker*
// through an elevation command (sudo by default). The worker performs an
// identical scan with the same scope and prints a compact report on stdout.
// Comparing the two measures exactly how much data permissions hid.
//
// The worker receives only the scan configuration explicitly selected by the
// user: root, scope, includes, excludes, and pruning.

use crate::coverage::CoverageReport;
use crate::fxhash::{FxHashSet, hash_path_bytes};
use crate::model::*;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const WORKER_DIR_LIMIT: usize = 2000;
const MAGIC: &str = "rootwatch-worker 1";

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[derive(Debug, Clone, Default)]
pub struct WorkerSummary {
    pub walked_bytes: u64,
    pub entries: u64,
    pub errors: u64,
    pub denied: u64,
    /// Largest directories by allocated bytes.
    pub dirs: Vec<(PathBuf, u64)>,
}

fn escape(path: &[u8], out: &mut Vec<u8>) {
    for &b in path {
        if b <= 0x20 || b == b'%' || b == 0x7f {
            out.extend_from_slice(format!("%{b:02x}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%'
            && i + 2 < s.len()
            && let Ok(h) = u8::from_str_radix(&String::from_utf8_lossy(&s[i + 1..i + 3]), 16)
        {
            out.push(h);
            i += 3;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

pub fn write_worker_report(result: &ScanResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{MAGIC}")?;
    writeln!(out, "walked_bytes {}", result.totals.allocated_bytes)?;
    writeln!(out, "entries {}", result.totals.counts.entries)?;
    writeln!(out, "errors {}", result.totals.counts.errors)?;
    writeln!(out, "denied {}", result.permission_denied_count())?;
    for id in result.largest_directories(WORKER_DIR_LIMIT) {
        let mut line = Vec::new();
        line.extend_from_slice(format!("dir {} ", result.usage(id).bytes).as_bytes());
        escape(result.index.path(id).as_os_str().as_bytes(), &mut line);
        line.push(b'\n');
        out.write_all(&line)?;
    }
    writeln!(out, "end")
}

pub fn parse_worker_report(data: &[u8]) -> Option<WorkerSummary> {
    let mut lines = data.split(|&b| b == b'\n');
    if lines.next()? != MAGIC.as_bytes() {
        return None;
    }
    let mut s = WorkerSummary::default();
    let mut ended = false;
    for line in lines {
        if line == b"end" {
            ended = true;
            break;
        }
        let text_end = line.iter().position(|&b| b == b' ')?;
        let key = &line[..text_end];
        let rest = &line[text_end + 1..];
        let num = |r: &[u8]| std::str::from_utf8(r).ok()?.parse::<u64>().ok();
        match key {
            b"walked_bytes" => s.walked_bytes = num(rest)?,
            b"entries" => s.entries = num(rest)?,
            b"errors" => s.errors = num(rest)?,
            b"denied" => s.denied = num(rest)?,
            b"dir" => {
                let sp = rest.iter().position(|&b| b == b' ')?;
                let bytes = num(&rest[..sp])?;
                let path = PathBuf::from(OsString::from_vec(unescape(&rest[sp + 1..])));
                s.dirs.push((path, bytes));
            }
            _ => {}
        }
    }
    ended.then_some(s)
}

#[derive(Debug, Clone)]
pub struct PermissionImpact {
    pub unprivileged_bytes: u64,
    pub privileged_bytes: u64,
    /// Data only the privileged scan could see.
    pub hidden_bytes: u64,
    pub hidden_entries: u64,
    pub unprivileged_coverage: f64,
    pub privileged_coverage: f64,
    pub denied_paths: usize,
    pub privileged_errors: u64,
    /// Permission-denied directories, with the size the privileged scan found.
    pub hidden_dirs: Vec<(PathBuf, u64)>,
    /// How many denied directories were too small to appear in the worker's list.
    pub denied_dirs_not_listed: usize,
}

pub fn compare(
    unpriv: &ScanResult,
    cov: &CoverageReport,
    worker: &WorkerSummary,
) -> PermissionImpact {
    let denied: FxHashSet<u64> = unpriv
        .index
        .nodes()
        .iter()
        .filter(|n| n.flags & flags::DENIED != 0)
        .map(|n| n.path_hash)
        .collect();
    let mut hidden_dirs: Vec<(PathBuf, u64)> = worker
        .dirs
        .iter()
        .filter(|(p, _)| denied.contains(&hash_path_bytes(p.as_os_str().as_bytes())))
        .cloned()
        .collect();
    hidden_dirs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let used = cov.used_bytes.max(1);
    PermissionImpact {
        unprivileged_bytes: unpriv.totals.allocated_bytes,
        privileged_bytes: worker.walked_bytes,
        hidden_bytes: worker
            .walked_bytes
            .saturating_sub(unpriv.totals.allocated_bytes),
        hidden_entries: worker.entries.saturating_sub(unpriv.totals.counts.entries),
        unprivileged_coverage: cov.coverage_percent,
        privileged_coverage: if cov.subtree {
            cov.coverage_percent
        } else {
            (worker.walked_bytes as f64 / used as f64 * 100.0).min(100.0)
        },
        denied_paths: denied.len(),
        privileged_errors: worker.errors,
        denied_dirs_not_listed: denied.len().saturating_sub(hidden_dirs.len()),
        hidden_dirs,
    }
}

/// Re-run this binary as a worker through `elevate` (e.g. ["sudo"]).
pub fn run_privileged_worker(
    elevate: &[String],
    scan_args: &[OsString],
) -> Result<WorkerSummary, String> {
    let (cmd, pre) = elevate.split_first().ok_or("empty elevation command")?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own executable: {e}"))?;
    let output = Command::new(cmd)
        .args(pre)
        .arg(exe)
        .arg("--worker")
        .args(scan_args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot run '{cmd}': {e}"))?;
    if !output.status.success() {
        return Err(format!("'{cmd}' failed ({})", output.status));
    }
    parse_worker_report(&output.stdout).ok_or_else(|| "worker produced an unreadable report".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_report_roundtrip_with_awkward_paths() {
        let mut data = Vec::new();
        data.extend_from_slice(
            b"rootwatch-worker 1\nwalked_bytes 100\nentries 7\nerrors 1\ndenied 2\n",
        );
        data.extend_from_slice(b"dir 50 /a%20b/c%25d\ndir 5 /x\nend\n");
        let s = parse_worker_report(&data).unwrap();
        assert_eq!(s.walked_bytes, 100);
        assert_eq!(s.dirs[0].0, PathBuf::from("/a b/c%d"));
        assert_eq!(s.dirs.len(), 2);
    }

    #[test]
    fn truncated_or_foreign_reports_are_rejected() {
        assert!(parse_worker_report(b"nonsense\n").is_none());
        assert!(parse_worker_report(b"rootwatch-worker 1\nwalked_bytes 1\n").is_none());
    }

    #[test]
    fn escape_roundtrip() {
        let raw = b"/tmp/we ird\tname%\x01";
        let mut e = Vec::new();
        escape(raw, &mut e);
        assert!(!e.contains(&b' ') && !e.contains(&b'\t'));
        assert_eq!(unescape(&e), raw);
    }
}
