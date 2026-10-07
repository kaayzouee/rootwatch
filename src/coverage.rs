// SPDX-License-Identifier: GPL-3.0-only
//
// Scan accuracy: how much of the used space did the walk actually see, and if
// it did not see all of it, why not?
//
// Coverage is computed per *storage pool*, not per mount. On btrfs every
// subvolume reports the whole pool's usage through statvfs, so judging "/"
// against its own walked bytes while "/nix" and "/home" (same pool) were not
// walked produces exactly the "95 GiB used, 520 MiB observed" picture. Pools
// make the comparison like-for-like.

use crate::model::*;
use crate::mounts::FsKind;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Completeness {
    /// Nothing material is missing (>= 95% of used space seen).
    Complete,
    /// >= 80%
    Substantial,
    /// >= 40%
    Partial,
    /// Less than 40%: rankings say little about where the space went.
    Minimal,
}

impl Completeness {
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Substantial => "SUBSTANTIAL",
            Self::Partial => "PARTIAL",
            Self::Minimal => "MINIMAL",
        }
    }

    pub fn from_percent(p: f64) -> Self {
        if p >= 95.0 {
            Self::Complete
        } else if p >= 80.0 {
            Self::Substantial
        } else if p >= 40.0 {
            Self::Partial
        } else {
            Self::Minimal
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanConfidence {
    Low,
    Medium,
    High,
}

impl ScanConfidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }

    pub fn downgrade(self) -> Self {
        match self {
            Self::High => Self::Medium,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolCoverage {
    pub pool: usize,
    pub label: String,
    pub fstype: String,
    pub kind: FsKind,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub walked_bytes: u64,
    pub coverage_percent: f64,
    pub confidence: ScanConfidence,
    /// Mountpoints of the filesystems of this pool that were walked.
    pub scanned: Vec<PathBuf>,
    /// Mounts of this pool that were *not* walked.
    pub skipped: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapKind {
    /// Other mounts (btrfs subvolumes) of the same pool were not walked.
    SkippedSamePool,
    PermissionDenied,
    Unreadable,
    /// Directories pruned by default rules or by the user.
    Pruned,
    /// Walked allocation exceeds filesystem usage.
    SharedExtents,
    /// Filesystem metadata, journal, snapshots, deleted-but-open files,
    /// reserved blocks: not attributable to any path.
    Unattributed,
}

#[derive(Debug, Clone)]
pub struct Gap {
    pub kind: GapKind,
    /// Exact size when it is known; most causes are by nature unmeasured.
    pub bytes: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct OutOfScopeFs {
    pub path: PathBuf,
    pub fstype: String,
    pub kind: FsKind,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub reason: SkipReason,
}

#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Scan root is a directory inside a filesystem: whole-filesystem
    /// coverage is not a meaningful completeness measure.
    pub subtree: bool,
    pub used_bytes: u64,
    pub walked_bytes: u64,
    pub coverage_percent: f64,
    pub completeness: Completeness,
    pub confidence: ScanConfidence,
    pub pools: Vec<PoolCoverage>,
    /// Separate disks/filesystems that were not walked and do not take part
    /// in the coverage figure above.
    pub out_of_scope: Vec<OutOfScopeFs>,
    pub gaps: Vec<Gap>,
    pub denied_dirs: usize,
    pub error_entries: u64,
    pub advice: Vec<String>,
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        100.0
    } else {
        (part as f64 / whole as f64 * 100.0).min(100.0)
    }
}

pub fn pool_confidence(coverage_percent: f64, subtree: bool, errors: u64) -> ScanConfidence {
    if subtree {
        return match errors {
            0 => ScanConfidence::High,
            1..=10 => ScanConfidence::Medium,
            _ => ScanConfidence::Low,
        };
    }
    match Completeness::from_percent(coverage_percent) {
        Completeness::Complete => ScanConfidence::High,
        Completeness::Substantial => ScanConfidence::Medium,
        _ => ScanConfidence::Low,
    }
}

pub fn assess(result: &ScanResult) -> CoverageReport {
    let subtree = result.subtree_scan;
    let denied_dirs = result
        .index
        .nodes()
        .iter()
        .filter(|n| n.flags & flags::DENIED != 0)
        .count();
    let unreadable_dirs = result
        .index
        .nodes()
        .iter()
        .filter(|n| n.flags & flags::UNREADABLE != 0)
        .count();
    let error_entries = result.totals.counts.errors;

    // Which pools did we actually walk?
    let mut pools: Vec<PoolCoverage> = Vec::new();
    for (pid, pool) in result.pools.iter().enumerate() {
        let scanned_fs: Vec<&FilesystemScan> = result
            .filesystems
            .iter()
            .filter(|f| f.pool == pid)
            .collect();
        if scanned_fs.is_empty() {
            continue;
        }
        let walked: u64 = scanned_fs.iter().map(|f| f.walked_bytes).sum();
        let cov = percent(walked, pool.info.used_bytes);
        let skipped: Vec<PathBuf> = result
            .mount_boundaries
            .iter()
            .filter(|b| b.pool == pid && matches!(b.decision, BoundaryDecision::Skipped(r) if r != SkipReason::DuplicateBind))
            .map(|b| b.path.clone())
            .collect();
        pools.push(PoolCoverage {
            pool: pid,
            label: pool.label.clone(),
            fstype: pool.fstype.clone(),
            kind: pool.kind,
            used_bytes: pool.info.used_bytes,
            total_bytes: pool.info.total_bytes,
            available_bytes: pool.info.available_bytes,
            walked_bytes: walked,
            coverage_percent: cov,
            confidence: pool_confidence(cov, subtree, error_entries),
            scanned: scanned_fs.iter().map(|f| f.mountpoint.clone()).collect(),
            skipped,
        });
    }

    let used_bytes: u64 = pools.iter().map(|p| p.used_bytes).sum();
    let walked_bytes: u64 = pools.iter().map(|p| p.walked_bytes).sum();
    let coverage_percent = percent(walked_bytes, used_bytes);

    // Separate disks we did not walk: informational, not part of coverage.
    let scanned_pools: Vec<usize> = pools.iter().map(|p| p.pool).collect();
    let mut out_of_scope = Vec::new();
    let mut seen_pools: Vec<usize> = Vec::new();
    for b in &result.mount_boundaries {
        if let BoundaryDecision::Skipped(reason) = b.decision {
            if reason == SkipReason::DuplicateBind || scanned_pools.contains(&b.pool) {
                continue;
            }
            if b.kind == FsKind::Pseudo {
                continue;
            }
            if seen_pools.contains(&b.pool) {
                continue;
            }
            seen_pools.push(b.pool);
            out_of_scope.push(OutOfScopeFs {
                path: b.path.clone(),
                fstype: b.fstype.clone(),
                kind: b.kind,
                used_bytes: b.filesystem.used_bytes,
                total_bytes: b.filesystem.total_bytes,
                reason,
            });
        }
    }

    // Explain used - walked, pool by pool.
    let mut gaps: Vec<Gap> = Vec::new();
    let mut advice: Vec<String> = Vec::new();
    if !subtree {
        for p in &pools {
            let gap = p.used_bytes as i128 - p.walked_bytes as i128;
            let threshold = (p.used_bytes / 100).max(64 << 20) as i128;

            if !p.skipped.is_empty() {
                let list = p
                    .skipped
                    .iter()
                    .map(|s| s.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                gaps.push(Gap {
                    kind: GapKind::SkippedSamePool,
                    bytes: None,
                    detail: format!(
                        "{} shares one {} pool with the scanned filesystem, and its statvfs usage covers all of them; not walked: {list}",
                        p.label, p.fstype
                    ),
                });
                advice.push(format!(
                    "rerun with --scope all (or --include {}) to walk the other mounts of {}",
                    p.skipped[0].display(),
                    p.label
                ));
            }
            if gap < -(threshold) {
                gaps.push(Gap {
                    kind: GapKind::SharedExtents,
                    bytes: Some((-gap) as u64),
                    detail: format!(
                        "{}: walked allocation exceeds filesystem usage (reflinks, snapshots or compression are counted per file)",
                        p.label
                    ),
                });
            } else if gap > threshold && p.skipped.is_empty() {
                gaps.push(Gap {
                    kind: GapKind::Unattributed,
                    bytes: Some(gap as u64),
                    detail: format!(
                        "{}: filesystem metadata, journal, snapshots, deleted-but-open files or space hidden under mountpoints",
                        p.label
                    ),
                });
            }
        }

        let pruned: Vec<PathBuf> = result
            .index
            .ids()
            .filter(|&id| result.index.node(id).flags & flags::EXCLUDED != 0)
            .map(|id| result.index.path(id))
            .collect();
        if !pruned.is_empty() {
            gaps.push(Gap {
                kind: GapKind::Pruned,
                bytes: None,
                detail: format!(
                    "pruned by rule: {}",
                    pruned
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }
    if denied_dirs > 0 || result.permission_denied_count() > 0 {
        gaps.push(Gap {
            kind: GapKind::PermissionDenied,
            bytes: None,
            detail: format!(
                "{} permission-denied path(s); their contents are not counted (size unknown without a privileged scan)",
                result.permission_denied_count()
            ),
        });
        advice.push("rerun with --privileged to measure how much data permissions hide".into());
    }
    if unreadable_dirs > 0 {
        gaps.push(Gap {
            kind: GapKind::Unreadable,
            bytes: None,
            detail: format!("{unreadable_dirs} director(ies) could not be read (I/O error)"),
        });
    }
    for inc in &result.unreached_includes {
        advice.push(format!(
            "--include {} was not reached (not a mountpoint below the scan root)",
            inc.display()
        ));
    }

    let completeness = if subtree {
        if error_entries == 0 {
            Completeness::Complete
        } else {
            Completeness::Substantial
        }
    } else {
        Completeness::from_percent(coverage_percent)
    };
    let confidence = if subtree {
        pool_confidence(coverage_percent, true, error_entries)
    } else {
        match completeness {
            Completeness::Complete if error_entries == 0 => ScanConfidence::High,
            Completeness::Complete | Completeness::Substantial => ScanConfidence::Medium,
            _ => ScanConfidence::Low,
        }
    };

    CoverageReport {
        subtree,
        used_bytes,
        walked_bytes,
        coverage_percent,
        completeness,
        confidence,
        pools,
        out_of_scope,
        gaps,
        denied_dirs,
        error_entries,
        advice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_thresholds() {
        assert_eq!(Completeness::from_percent(99.0), Completeness::Complete);
        assert_eq!(Completeness::from_percent(85.0), Completeness::Substantial);
        assert_eq!(Completeness::from_percent(50.0), Completeness::Partial);
        assert_eq!(Completeness::from_percent(0.5), Completeness::Minimal);
    }

    #[test]
    fn subtree_confidence_depends_only_on_errors() {
        assert_eq!(pool_confidence(0.1, true, 0), ScanConfidence::High);
        assert_eq!(pool_confidence(0.1, true, 5), ScanConfidence::Medium);
        assert_eq!(pool_confidence(0.1, true, 50), ScanConfidence::Low);
        assert_eq!(pool_confidence(0.5, false, 0), ScanConfidence::Low);
    }
}
