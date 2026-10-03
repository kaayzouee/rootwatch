// SPDX-License-Identifier: GPL-3.0-only
//
// Temporary-data intelligence (/tmp, /var/tmp, ...). Everything here is derived
// from data collected during the walk: per-directory age buckets, per-zone
// owner totals and top files. Cost: O(children of each temp zone root).

use crate::analysis::AnalysisConfig;
use crate::model::*;
use crate::mounts::FsKind;
use crate::topk::TopK;
use crate::users::UserNames;
use crate::zones::Role;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct OwnerShare {
    pub uid: u32,
    pub name: String,
    pub bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone)]
pub struct ChildUsage {
    pub path: PathBuf,
    pub bytes: u64,
    pub newest_age_days: Option<u64>,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempAssessment {
    Normal,
    Large,
    Stale,
    LargeAndStale,
}

impl TempAssessment {
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Large => "unusually large",
            Self::Stale => "stale data",
            Self::LargeAndStale => "unusually large and stale",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TempReport {
    pub label: String,
    pub node: NodeId,
    pub fs: FsId,
    pub fs_kind: FsKind,
    pub fstype: String,
    /// tmpfs/ramfs: contents consume memory and vanish on reboot.
    pub ram_backed: bool,
    pub bytes: u64,
    pub percent_of_fs_used: f64,
    pub files: u64,
    pub dirs: u64,
    pub age: [u64; AGE_BUCKETS],
    pub stale_after_days: u64,
    pub stale_bytes: u64,
    pub stale_percent: f64,
    pub newest_age_days: Option<u64>,
    pub owners: Vec<OwnerShare>,
    pub top_children: Vec<ChildUsage>,
    pub top_files: Vec<FileRecord>,
    pub assessment: TempAssessment,
}

pub(crate) fn age_days(now: i64, mtime: i64) -> Option<u64> {
    (mtime > 0).then(|| ((now - mtime).max(0) / 86_400) as u64)
}

pub fn build(result: &ScanResult, cfg: &AnalysisConfig, users: &UserNames) -> Vec<TempReport> {
    let mut out = Vec::new();
    for zone in result.zones.iter().filter(|z| z.role == Role::TempZone) {
        let node = result.index.node(zone.node);
        let usage = &node.usage;
        let fsinfo = &result.filesystems[zone.fs as usize];
        let pool = &result.pools[fsinfo.pool];

        let stale_after_days = if zone.label.starts_with("/var/tmp") {
            cfg.var_tmp_stale_days
        } else {
            cfg.tmp_stale_days
        };
        let stale_bucket = bucket_from_days(stale_after_days);
        let stale_bytes = usage.bytes_older_than(stale_bucket);
        let stale_percent = if usage.bytes == 0 {
            0.0
        } else {
            stale_bytes as f64 / usage.bytes as f64 * 100.0
        };
        let percent_of_fs_used = usage.fs_bytes as f64 / pool.info.used_bytes.max(1) as f64 * 100.0;

        let owned_total: u64 = zone.owners.iter().map(|o| o.1).sum();
        let owners = zone
            .owners
            .iter()
            .take(5)
            .map(|&(uid, bytes)| OwnerShare {
                uid,
                name: users.name(uid),
                bytes,
                percent: bytes as f64 / owned_total.max(1) as f64 * 100.0,
            })
            .collect();

        let mut heap = TopK::new(5);
        for c in result.index.children(zone.node) {
            let cn = result.index.node(c);
            if cn.flags & (flags::EXCLUDED | flags::SKIPPED_MOUNT) != 0 {
                continue;
            }
            heap.push((cn.usage.bytes, u64::from(c.0)), c);
        }
        let top_children = heap
            .into_sorted_desc()
            .into_iter()
            .map(|c| {
                let cn = result.index.node(c);
                ChildUsage {
                    path: result.index.path(c),
                    bytes: cn.usage.bytes,
                    newest_age_days: age_days(result.started_unix, cn.newest_mtime),
                    owner: users.name(cn.uid),
                }
            })
            .collect();

        let large = usage.fs_bytes >= cfg.temp_large_bytes || percent_of_fs_used >= 2.0;
        let stale = stale_percent >= 50.0 && stale_bytes >= cfg.temp_stale_min_bytes;
        let assessment = match (large, stale) {
            (true, true) => TempAssessment::LargeAndStale,
            (true, false) => TempAssessment::Large,
            (false, true) => TempAssessment::Stale,
            _ => TempAssessment::Normal,
        };

        out.push(TempReport {
            label: zone.label.clone(),
            node: zone.node,
            fs: zone.fs,
            fs_kind: fsinfo.kind,
            fstype: fsinfo.fstype.clone(),
            ram_backed: fsinfo.kind == FsKind::Memory,
            bytes: usage.bytes,
            percent_of_fs_used,
            files: usage.counts.regular_files,
            dirs: usage.counts.directories,
            age: usage.age,
            stale_after_days,
            stale_bytes,
            stale_percent,
            newest_age_days: age_days(result.started_unix, node.newest_mtime),
            owners,
            top_children,
            top_files: zone.top_files.clone(),
            assessment,
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.label.cmp(&b.label)));
    out
}
