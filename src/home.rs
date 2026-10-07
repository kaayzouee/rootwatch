// SPDX-License-Identifier: GPL-3.0-only
//
// Home-directory intelligence. Every /home/<user> (and /root) is a first-class
// zone; the scanner records the first-level buckets (Downloads, .cache,
// .local, .cargo, ...), detected projects and their build-artifact directories
// while it walks, so this module only reads node ids that already exist.

use crate::analysis::AnalysisConfig;
use crate::model::*;
use crate::temp::{OwnerShare, age_days};
use crate::topk::TopK;
use crate::users::UserNames;
use crate::zones::{HomeBucket, ProjectKind, Role};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BucketUsage {
    pub bucket: HomeBucket,
    pub path: PathBuf,
    pub bytes: u64,
    pub percent_of_home: f64,
    /// Bytes not modified for more than 90 days.
    pub stale_bytes: u64,
    pub top_children: Vec<(PathBuf, u64)>,
}

#[derive(Debug, Clone)]
pub struct ProjectUsage {
    pub path: PathBuf,
    pub kind: ProjectKind,
    pub bytes: u64,
    pub artifact_bytes: u64,
    pub artifacts: Vec<(String, u64)>,
    pub newest_age_days: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct HomeReport {
    pub label: String,
    pub node: NodeId,
    pub owner_uid: u32,
    pub owner_name: String,
    pub bytes: u64,
    pub percent_of_fs_used: f64,
    pub age: [u64; AGE_BUCKETS],
    /// Files directly inside the home directory.
    pub loose_bytes: u64,
    pub owned_by_user_bytes: u64,
    pub root_owned_bytes: u64,
    pub other_owned_bytes: u64,
    pub owners: Vec<OwnerShare>,
    pub buckets: Vec<BucketUsage>,
    pub projects: Vec<ProjectUsage>,
    pub project_total_bytes: u64,
    pub artifact_total_bytes: u64,
    pub large_files: Vec<FileRecord>,
}

pub fn build(result: &ScanResult, _cfg: &AnalysisConfig, users: &UserNames) -> Vec<HomeReport> {
    let mut out = Vec::new();
    let stale_bucket = bucket_from_days(90);

    for (zid, zone) in result.zones.iter().enumerate() {
        if zone.role != Role::HomeZone {
            continue;
        }
        let node = result.index.node(zone.node);
        let usage = &node.usage;
        let pool = &result.pools[result.filesystems[zone.fs as usize].pool];

        let mut buckets: Vec<BucketUsage> = result
            .home_buckets
            .iter()
            .filter(|b| b.zone == zid)
            .map(|b| {
                let bn = result.index.node(b.node);
                let mut heap = TopK::new(3);
                for c in result.index.children(b.node) {
                    let cn = result.index.node(c);
                    heap.push((cn.usage.bytes, u64::from(c.0)), c);
                }
                BucketUsage {
                    bucket: b.bucket,
                    path: result.index.path(b.node),
                    bytes: bn.usage.bytes,
                    percent_of_home: bn.usage.bytes as f64 / usage.bytes.max(1) as f64 * 100.0,
                    stale_bytes: bn.usage.bytes_older_than(stale_bucket),
                    top_children: heap
                        .into_sorted_desc()
                        .into_iter()
                        .map(|c| (result.index.path(c), result.index.node(c).usage.bytes))
                        .collect(),
                }
            })
            .collect();
        buckets.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));

        let mut project_total = 0u64;
        let mut artifact_total = 0u64;
        let mut heap = TopK::new(10);
        for p in result
            .projects
            .iter()
            .filter(|p| result.index.node(p.node).zone as usize == zid)
        {
            let pn = result.index.node(p.node);
            let artifacts: Vec<(String, u64)> = result
                .artifacts
                .iter()
                .filter(|a| a.project == p.node)
                .map(|a| {
                    (
                        String::from_utf8_lossy(result.index.name(a.node)).into_owned(),
                        result.index.node(a.node).usage.bytes,
                    )
                })
                .collect();
            let artifact_bytes: u64 = artifacts.iter().map(|a| a.1).sum();
            project_total += pn.usage.bytes;
            artifact_total += artifact_bytes;
            heap.push(
                (pn.usage.bytes, u64::from(p.node.0)),
                ProjectUsage {
                    path: result.index.path(p.node),
                    kind: p.kind,
                    bytes: pn.usage.bytes,
                    artifact_bytes,
                    artifacts,
                    newest_age_days: age_days(result.started_unix, pn.newest_mtime),
                },
            );
        }

        let owned_total: u64 = zone.owners.iter().map(|o| o.1).sum();
        let by_uid = |uid: u32| zone.owners.iter().find(|o| o.0 == uid).map_or(0, |o| o.1);
        let owned_by_user = by_uid(zone.owner_uid);
        let root_owned = if zone.owner_uid == 0 { 0 } else { by_uid(0) };

        out.push(HomeReport {
            label: zone.label.clone(),
            node: zone.node,
            owner_uid: zone.owner_uid,
            owner_name: users.name(zone.owner_uid),
            bytes: usage.bytes,
            percent_of_fs_used: usage.fs_bytes as f64 / pool.info.used_bytes.max(1) as f64 * 100.0,
            age: usage.age,
            loose_bytes: zone.loose_bytes,
            owned_by_user_bytes: owned_by_user,
            root_owned_bytes: root_owned,
            other_owned_bytes: owned_total.saturating_sub(owned_by_user + root_owned),
            owners: zone
                .owners
                .iter()
                .take(5)
                .map(|&(uid, bytes)| OwnerShare {
                    uid,
                    name: users.name(uid),
                    bytes,
                    percent: bytes as f64 / owned_total.max(1) as f64 * 100.0,
                })
                .collect(),
            buckets,
            projects: heap.into_sorted_desc(),
            project_total_bytes: project_total,
            artifact_total_bytes: artifact_total,
            large_files: zone.top_files.clone(),
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.label.cmp(&b.label)));
    out
}
