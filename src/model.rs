// SPDX-License-Identifier: GPL-3.0-only
//
// Scan data model. Everything the analysis engine and the future TUI need is
// produced here by the scanner, so nothing downstream ever touches the
// filesystem again.

use crate::mounts::{FsKind, MountTable};
use crate::topk::TopK;
use crate::zones::{HomeBucket, ProjectKind, Role};
use std::ffi::CStr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Basic value types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FilesystemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

impl FilesystemInfo {
    pub const EMPTY: FilesystemInfo = FilesystemInfo {
        total_bytes: 0,
        available_bytes: 0,
        used_bytes: 0,
    };
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EntryCounts {
    pub entries: u64,
    pub regular_files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub other: u64,
    pub errors: u64,
}

impl EntryCounts {
    #[inline]
    pub fn add(&mut self, other: &EntryCounts) {
        self.entries += other.entries;
        self.regular_files += other.regular_files;
        self.directories += other.directories;
        self.symlinks += other.symlinks;
        self.other += other.other;
        self.errors += other.errors;
    }
}

pub const AGE_BUCKETS: usize = 6;
pub const AGE_LABELS: [&str; AGE_BUCKETS] = ["<1d", "1-7d", "7-30d", "30-90d", "90-365d", ">1y"];
/// Lower bound, in days, of each age bucket.
pub const AGE_LOWER_DAYS: [u64; AGE_BUCKETS] = [0, 1, 7, 30, 90, 365];
const DAY: i64 = 86_400;

#[inline]
pub fn age_bucket(age_secs: i64) -> usize {
    if age_secs < DAY {
        0
    } else if age_secs < 7 * DAY {
        1
    } else if age_secs < 30 * DAY {
        2
    } else if age_secs < 90 * DAY {
        3
    } else if age_secs < 365 * DAY {
        4
    } else {
        5
    }
}

/// First age bucket whose lower bound is at least `days`.
pub fn bucket_from_days(days: u64) -> usize {
    AGE_LOWER_DAYS
        .iter()
        .position(|&d| d >= days)
        .unwrap_or(AGE_BUCKETS - 1)
}

/// Aggregated usage of a directory subtree.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    /// Allocated bytes in the whole subtree, including nested filesystems.
    pub bytes: u64,
    /// Allocated bytes that live on this node's own filesystem only. This is
    /// the number to compare with that filesystem's capacity.
    pub fs_bytes: u64,
    pub counts: EntryCounts,
    /// Allocated bytes by file modification age.
    pub age: [u64; AGE_BUCKETS],
}

impl Usage {
    #[inline]
    pub fn add_child(&mut self, child: &Usage, same_fs: bool) {
        self.bytes += child.bytes;
        if same_fs {
            self.fs_bytes += child.fs_bytes;
        }
        self.counts.add(&child.counts);
        for i in 0..AGE_BUCKETS {
            self.age[i] += child.age[i];
        }
    }

    pub fn bytes_older_than(&self, bucket: usize) -> u64 {
        self.age[bucket.min(AGE_BUCKETS - 1)..].iter().sum()
    }
}

// ---------------------------------------------------------------------------
// Directory arena
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    pub const NONE: NodeId = NodeId(u32::MAX);

    #[inline]
    pub fn idx(self) -> usize {
        self.0 as usize
    }

    #[inline]
    pub fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

pub type FsId = u16;
pub const NO_ZONE: u16 = u16::MAX;

pub mod flags {
    /// Root directory of a filesystem entered during the scan.
    pub const MOUNT_ROOT: u16 = 1;
    /// A mountpoint that was deliberately not entered.
    pub const SKIPPED_MOUNT: u16 = 2;
    /// Could not be opened: permission denied.
    pub const DENIED: u16 = 4;
    /// Could not be read for another reason.
    pub const UNREADABLE: u16 = 8;
    /// Pruned by an exclusion rule.
    pub const EXCLUDED: u16 = 16;
    /// Detected project root (home zones).
    pub const PROJECT: u16 = 32;
    /// Self bind mount traversed as part of the same filesystem.
    pub const SELF_BIND: u16 = 64;
    /// Bits 8..12 hold `HomeBucket as u8 + 1` for nodes inside a home zone.
    pub const BUCKET_SHIFT: u16 = 8;
    pub const BUCKET_MASK: u16 = 0xF << BUCKET_SHIFT;
}

#[derive(Debug, Clone)]
pub struct DirNode {
    pub parent: NodeId,
    pub first_child: NodeId,
    pub next_sibling: NodeId,
    pub(crate) name_off: u32,
    pub(crate) name_len: u16,
    /// Number of path components of the absolute path.
    pub depth: u16,
    pub fs: FsId,
    pub class: crate::zones::PathClass,
    pub zone: u16,
    pub flags: u16,
    pub uid: u32,
    pub own_mtime: i64,
    /// Newest mtime anywhere in the subtree.
    pub newest_mtime: i64,
    /// Incrementally maintained hash of the absolute path.
    pub path_hash: u64,
    pub usage: Usage,
}

impl DirNode {
    pub fn has_flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    pub fn home_bucket(&self) -> Option<HomeBucket> {
        let v = (self.flags & flags::BUCKET_MASK) >> flags::BUCKET_SHIFT;
        if v == 0 {
            None
        } else {
            HomeBucket::from_index((v - 1) as u8)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirectoryIndex {
    pub(crate) nodes: Vec<DirNode>,
    /// NUL-terminated names. Scan roots store their full absolute path; every
    /// other node stores a single component.
    pub(crate) names: Vec<u8>,
}

pub struct Children<'a> {
    index: &'a DirectoryIndex,
    next: NodeId,
}

impl Iterator for Children<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        if self.next.is_none() {
            return None;
        }
        let cur = self.next;
        self.next = self.index.nodes[cur.idx()].next_sibling;
        Some(cur)
    }
}

impl DirectoryIndex {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[inline]
    pub fn node(&self, id: NodeId) -> &DirNode {
        &self.nodes[id.idx()]
    }

    pub fn ids(&self) -> impl Iterator<Item = NodeId> + use<> {
        let n = self.nodes.len() as u32;
        (0..n).map(NodeId)
    }

    pub fn nodes(&self) -> &[DirNode] {
        &self.nodes
    }

    pub fn name(&self, id: NodeId) -> &[u8] {
        let n = &self.nodes[id.idx()];
        &self.names[n.name_off as usize..n.name_off as usize + n.name_len as usize]
    }

    pub fn name_cstr(&self, id: NodeId) -> &CStr {
        let n = &self.nodes[id.idx()];
        let start = n.name_off as usize;
        CStr::from_bytes_with_nul(&self.names[start..start + n.name_len as usize + 1])
            .expect("names are stored NUL-terminated")
    }

    pub fn children(&self, id: NodeId) -> Children<'_> {
        Children {
            index: self,
            next: self.nodes[id.idx()].first_child,
        }
    }

    /// Absolute path of a node: O(depth), only ever done for rows that are
    /// actually displayed.
    pub fn path(&self, id: NodeId) -> PathBuf {
        use std::os::unix::ffi::OsStringExt;
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut cur = id;
        loop {
            parts.push(self.name(cur));
            let p = self.nodes[cur.idx()].parent;
            if p.is_none() {
                break;
            }
            cur = p;
        }
        parts.reverse();
        let mut out: Vec<u8> = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 && !out.ends_with(b"/") {
                out.push(b'/');
            }
            out.extend_from_slice(part);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        PathBuf::from(std::ffi::OsString::from_vec(out))
    }

    pub fn path_of_child(&self, parent: NodeId, name: &[u8]) -> PathBuf {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let mut bytes = self.path(parent).as_os_str().as_bytes().to_vec();
        if !bytes.ends_with(b"/") {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(name);
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    }
}

// ---------------------------------------------------------------------------
// Issues, filesystems, pools, boundaries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanIssueKind {
    PermissionDenied,
    Io,
}

#[derive(Debug, Clone)]
pub struct ScanIssue {
    pub path: PathBuf,
    pub kind: ScanIssueKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A real filesystem that the chosen scope does not include.
    OutOfScope,
    Pseudo,
    Network,
    Image,
    Layered,
    /// Same filesystem content is already reachable through another path.
    DuplicateBind,
}

impl SkipReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::OutOfScope => "outside the selected scope",
            Self::Pseudo => "pseudo filesystem",
            Self::Network => "network/FUSE filesystem",
            Self::Image => "read-only image (already counted as a file)",
            Self::Layered => "layered view (content reachable via its layers)",
            Self::DuplicateBind => "bind mount of content scanned elsewhere",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryDecision {
    Entered,
    Skipped(SkipReason),
}

#[derive(Debug, Clone)]
pub struct MountBoundary {
    pub path: PathBuf,
    pub filesystem: FilesystemInfo,
    pub device: u64,
    pub mount_id: Option<u64>,
    pub fstype: String,
    pub source: String,
    pub kind: FsKind,
    pub pool: usize,
    pub decision: BoundaryDecision,
}

/// A filesystem that the walk actually entered.
#[derive(Debug, Clone)]
pub struct FilesystemScan {
    pub id: FsId,
    pub mountpoint: PathBuf,
    pub device: u64,
    pub mount_id: Option<u64>,
    pub fstype: String,
    pub source: String,
    pub kind: FsKind,
    pub pool: usize,
    pub info: FilesystemInfo,
    pub root_node: NodeId,
    /// Allocated bytes found on this filesystem (excluding nested mounts).
    pub walked_bytes: u64,
}

/// One block pool. Several mounted filesystems (btrfs subvolumes) can sit on
/// the same pool and then share the same `statvfs` numbers.
#[derive(Debug, Clone)]
pub struct StoragePool {
    pub label: String,
    pub fstype: String,
    pub kind: FsKind,
    pub info: FilesystemInfo,
}

#[derive(Debug, Clone, Default)]
pub struct ScanTotals {
    pub counts: EntryCounts,
    pub allocated_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OwnershipTotals {
    /// uid < 1000
    pub system_bytes: u64,
    /// 1000 ..= 60000
    pub user_bytes: u64,
    pub other_bytes: u64,
}

// ---------------------------------------------------------------------------
// Zone data collected during the walk
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub apparent_bytes: u64,
    pub mtime: i64,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct ZoneScan {
    pub role: Role,
    pub label: String,
    pub node: NodeId,
    pub fs: FsId,
    pub owner_uid: u32,
    /// (uid, allocated bytes), largest first.
    pub owners: Vec<(u32, u64)>,
    pub top_files: Vec<FileRecord>,
    /// Files directly inside the zone root (nix store: .drv files etc.).
    pub loose_bytes: u64,
    pub loose_files: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ProjectRec {
    pub node: NodeId,
    pub kind: ProjectKind,
}

#[derive(Debug, Clone, Copy)]
pub struct ArtifactRec {
    pub project: NodeId,
    pub node: NodeId,
}

#[derive(Debug, Clone, Copy)]
pub struct HomeBucketRec {
    pub zone: usize,
    pub bucket: HomeBucket,
    pub node: NodeId,
}

#[derive(Debug, Clone, Default)]
pub struct NixScan {
    pub store_zone: Option<usize>,
    /// Top-level directories of the store (one per store path).
    pub store_entries: Vec<NodeId>,
    pub db: Option<NodeId>,
    pub profiles: Option<NodeId>,
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    /// Only the filesystem that contains the scan root. Mounts are reported,
    /// not entered.
    Root,
    /// Only the root filesystem plus explicitly included mountpoints.
    Selected,
    /// Root filesystem plus every local disk-backed or RAM-backed mount.
    All,
}

impl ScanScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "root filesystem only",
            Self::Selected => "root filesystem + selected mounts",
            Self::All => "all local filesystems",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub root: PathBuf,
    pub scope: ScanScope,
    pub started_unix: i64,
    /// Statvfs of the filesystem holding the scan root.
    pub filesystem: FilesystemInfo,
    pub totals: ScanTotals,
    pub index: DirectoryIndex,
    pub issues: Vec<ScanIssue>,
    pub filesystems: Vec<FilesystemScan>,
    pub pools: Vec<StoragePool>,
    pub mount_boundaries: Vec<MountBoundary>,
    pub zones: Vec<ZoneScan>,
    pub home_buckets: Vec<HomeBucketRec>,
    pub projects: Vec<ProjectRec>,
    pub artifacts: Vec<ArtifactRec>,
    pub nix: NixScan,
    pub top_files: Vec<FileRecord>,
    pub ownership: OwnershipTotals,
    pub mounts: MountTable,
    /// True when the scan root is a directory inside its filesystem rather
    /// than the filesystem's own root, so coverage of the whole filesystem is
    /// not expected.
    pub subtree_scan: bool,
    /// Include paths that were requested but never reached.
    pub unreached_includes: Vec<PathBuf>,
}

impl ScanResult {
    pub fn root_node(&self) -> NodeId {
        NodeId(0)
    }

    /// Mutable node access for tests and synthetic fixtures.
    #[doc(hidden)]
    pub fn index_mut_for_test(&mut self, id: NodeId) -> &mut DirNode {
        &mut self.index.nodes[id.idx()]
    }

    pub fn usage(&self, id: NodeId) -> &Usage {
        &self.index.node(id).usage
    }

    /// Top-K directories by allocated bytes (excluding the scan root).
    /// O(D log K): no global sort.
    pub fn largest_directories(&self, k: usize) -> Vec<NodeId> {
        let mut heap = TopK::new(k);
        for id in self.index.ids().skip(1) {
            let n = self.index.node(id);
            if n.flags & (flags::EXCLUDED | flags::SKIPPED_MOUNT) != 0 {
                continue;
            }
            heap.push((n.usage.bytes, u64::MAX - u64::from(id.0)), id);
        }
        heap.into_sorted_desc()
    }

    pub fn top_level_directories(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .index
            .children(self.root_node())
            .filter(|&c| self.index.node(c).flags & flags::EXCLUDED == 0)
            .collect();
        v.sort_unstable_by(|&a, &b| {
            self.usage(b)
                .bytes
                .cmp(&self.usage(a).bytes)
                .then_with(|| self.index.name(a).cmp(self.index.name(b)))
        });
        v
    }

    pub fn permission_denied_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.kind == ScanIssueKind::PermissionDenied)
            .count()
    }

    pub fn fs_of(&self, id: NodeId) -> &FilesystemScan {
        &self.filesystems[self.index.node(id).fs as usize]
    }

    pub fn pool_of(&self, id: NodeId) -> &StoragePool {
        &self.pools[self.fs_of(id).pool]
    }
}
