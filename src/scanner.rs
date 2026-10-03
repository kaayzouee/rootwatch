// SPDX-License-Identifier: GPL-3.0-only
//
// The scanner.
//
// Cost model (N = entries, D = directories, H = depth, M = mounts):
//
//   mount discovery          O(M)      one read of /proc/self/mountinfo
//   traversal                O(N)      iterative DFS, O(H) open fds, no recursion
//   metadata                 O(N)      exactly ONE statx() per entry, issued
//                                      relative to the parent directory fd, so
//                                      the kernel resolves one path component
//                                      instead of the whole path
//   hard-link dedup          O(1)/entry expected, only for nlink > 1
//   per-directory accounting O(1)/entry, written once per directory
//   aggregation              O(D)      one reverse pass over the node arena
//                                      (children always have larger ids than
//                                      their parent), never O(N * H)
//
// Allocation: no per-entry allocation at all. Names live in one shared byte
// pool, directory listings go through a single reused getdents buffer, and the
// only heap objects created per directory are its node (amortised Vec growth)
// and its name bytes.

use crate::fxhash::{mix_component, hash_path_bytes, FxHashMap, FxHashSet};
use crate::model::*;
use crate::mounts::{FsKind, MountInfo, MountTable, PoolKey};
use crate::topk::TopK;
use crate::zones::{Cursor, HomeBucket, ProjectKind, Role, Trie, ZoneConfig};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RawDir, StatxFlags, makedev, open, openat, statvfs, statx,
};
use rustix::io::Errno;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

const ALLOCATED_BLOCK_SIZE: u64 = 512;
const GETDENTS_BUFFER: usize = 128 * 1024;
/// Safety valve for the u32 node ids and name offsets.
const MAX_NODES: usize = (u32::MAX - 1024) as usize;
const MAX_NAME_POOL: usize = (u32::MAX - (1 << 20)) as usize;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub scope: ScanScope,
    /// Mountpoints to enter in addition to the root filesystem. Overrides the
    /// kind-based filtering, so even a pseudo or network mount can be forced.
    pub include: Vec<PathBuf>,
    /// Directories to prune.
    pub exclude: Vec<PathBuf>,
    /// Prune /proc, /sys, /dev and /run (unless an include lives below them).
    pub prune_pseudo: bool,
    pub zones: ZoneConfig,
    pub top_files: usize,
    pub zone_top_files: usize,
    /// Fixed "now" for age bucketing (tests); defaults to the wall clock.
    pub now_unix: Option<i64>,
    /// Pre-read mount table (tests); defaults to /proc/self/mountinfo.
    pub mounts: Option<MountTable>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scope: ScanScope::Root,
            include: Vec::new(),
            exclude: Vec::new(),
            prune_pseudo: true,
            zones: ZoneConfig::default(),
            top_files: 20,
            zone_top_files: 10,
            now_unix: None,
            mounts: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InodeKey {
    dev: u64,
    ino: u64,
}

pub fn filesystem_info(path: &Path) -> io::Result<FilesystemInfo> {
    let stats = statvfs(path).map_err(io::Error::from)?;
    let block_size = if stats.f_frsize != 0 {
        stats.f_frsize
    } else {
        stats.f_bsize
    };
    let total_bytes = stats.f_blocks.saturating_mul(block_size);
    let available_bytes = stats.f_bavail.saturating_mul(block_size);
    let free_bytes = stats.f_bfree.saturating_mul(block_size);
    Ok(FilesystemInfo {
        total_bytes,
        available_bytes,
        used_bytes: total_bytes.saturating_sub(free_bytes),
    })
}

fn raise_nofile_limit() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let cur = getrlimit(Resource::Nofile);
    let target = cur.maximum.map_or(65_536, |m| m.min(65_536));
    if cur.current.is_some_and(|c| c < target) {
        let _ = setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(target),
                maximum: cur.maximum,
            },
        );
    }
}

const STATX_MASK: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::NLINK)
    .union(StatxFlags::UID)
    .union(StatxFlags::MTIME)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::BLOCKS)
    .union(StatxFlags::MNT_ID);

fn statx_at_flags() -> AtFlags {
    AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT | AtFlags::STATX_DONT_SYNC
}

#[inline]
fn dev_of(st: &rustix::fs::Statx) -> u64 {
    makedev(st.stx_dev_major, st.stx_dev_minor)
}

#[inline]
fn uid_class(uid: u32) -> usize {
    if uid < 1000 {
        0
    } else if uid <= 60_000 {
        1
    } else {
        2
    }
}

// ---------------------------------------------------------------------------
// Walk-time state
// ---------------------------------------------------------------------------

/// Everything a directory passes down to its children.
#[derive(Clone, Copy)]
struct Ctx {
    cursor: Cursor,
    zone: u16,
    fs: FsId,
    mnt: u64,
    dev: u64,
    bucket: Option<HomeBucket>,
    in_project: bool,
}

#[derive(Clone, Copy)]
struct Pending {
    node: NodeId,
    ctx: Ctx,
}

struct Frame {
    fd: OwnedFd,
    next: usize,
    end: usize,
    start: usize,
}

struct FileCand {
    parent: NodeId,
    name: Box<[u8]>,
    apparent: u64,
    bytes: u64,
    mtime: i64,
    uid: u32,
}

struct ZoneRec {
    role: Role,
    root: NodeId,
    fs: FsId,
    uid: u32,
    track_owners: bool,
    owners: FxHashMap<u32, u64>,
    top: TopK<FileCand>,
    loose_bytes: u64,
    loose_files: u64,
}

enum Outcome {
    Skip,
    SameFs,
    Enter(FsId),
}

struct Scanner<'a> {
    config: &'a ScanConfig,
    trie: Trie,
    mounts: MountTable,
    index: DirectoryIndex,
    pending: Vec<Pending>,
    seen: FxHashSet<InodeKey>,
    issues: Vec<ScanIssue>,
    filesystems: Vec<FilesystemScan>,
    pools: Vec<StoragePool>,
    pool_ids: FxHashMap<PoolKey, usize>,
    entered_devs: FxHashMap<u64, FsId>,
    boundaries: Vec<MountBoundary>,
    zones: Vec<ZoneRec>,
    home_buckets: Vec<HomeBucketRec>,
    projects: Vec<ProjectRec>,
    artifacts: Vec<ArtifactRec>,
    nix: NixScan,
    top_files: TopK<FileCand>,
    ownership: [u64; 3],
    now: i64,
    subtree: bool,
    includes: Vec<PathBuf>,
    include_reached: Vec<bool>,
    buf: Vec<MaybeUninit<u8>>,
}

fn errno_to_kind(e: Errno) -> ScanIssueKind {
    if e == Errno::ACCESS || e == Errno::PERM {
        ScanIssueKind::PermissionDenied
    } else {
        ScanIssueKind::Io
    }
}

impl<'a> Scanner<'a> {
    // -- node arena ---------------------------------------------------------

    fn push_node(
        &mut self,
        parent: NodeId,
        name: &[u8],
        st: Option<&rustix::fs::Statx>,
        ctx: &Ctx,
        node_flags: u16,
    ) -> Option<NodeId> {
        if self.index.nodes.len() >= MAX_NODES || self.index.names.len() > MAX_NAME_POOL {
            return None;
        }
        let id = NodeId(self.index.nodes.len() as u32);
        let name_off = self.index.names.len() as u32;
        self.index.names.extend_from_slice(name);
        self.index.names.push(0);

        let (depth, path_hash) = if parent.is_none() {
            let comps = name.split(|&b| b == b'/').filter(|c| !c.is_empty()).count();
            (comps as u16, hash_path_bytes(name))
        } else {
            let p = &self.index.nodes[parent.idx()];
            (p.depth.saturating_add(1), mix_component(p.path_hash, name))
        };

        let mut usage = Usage::default();
        let (mtime, uid) = match st {
            Some(st) => {
                let mtime = st.stx_mtime.tv_sec;
                let bytes = st.stx_blocks.saturating_mul(ALLOCATED_BLOCK_SIZE);
                usage.bytes = bytes;
                usage.fs_bytes = bytes;
                usage.age[age_bucket(self.now - mtime)] = bytes;
                (mtime, st.stx_uid)
            }
            None => (0, 0),
        };

        let node_flags = match ctx.bucket {
            Some(b) => node_flags | ((b as u16 + 1) << flags::BUCKET_SHIFT),
            None => node_flags,
        };

        let next_sibling = if parent.is_none() {
            NodeId::NONE
        } else {
            let p = &mut self.index.nodes[parent.idx()];
            let prev = p.first_child;
            p.first_child = id;
            prev
        };

        self.index.nodes.push(DirNode {
            parent,
            first_child: NodeId::NONE,
            next_sibling,
            name_off,
            name_len: name.len().min(u16::MAX as usize) as u16,
            depth,
            fs: ctx.fs,
            class: ctx.cursor.class,
            zone: ctx.zone,
            flags: node_flags,
            uid,
            own_mtime: mtime,
            newest_mtime: mtime,
            path_hash,
            usage,
        });
        Some(id)
    }

    // -- issues -------------------------------------------------------------

    fn record_node_issue(&mut self, node: NodeId, errno: Errno, what: &str) {
        let path = self.index.path(node);
        self.push_issue(path, errno, what);
        let n = &mut self.index.nodes[node.idx()];
        n.usage.counts.errors += 1;
        n.flags |= match errno_to_kind(errno) {
            ScanIssueKind::PermissionDenied => flags::DENIED,
            ScanIssueKind::Io => flags::UNREADABLE,
        };
    }

    fn push_issue(&mut self, path: PathBuf, errno: Errno, what: &str) {
        self.issues.push(ScanIssue {
            path,
            kind: errno_to_kind(errno),
            message: format!("{what}: {}", io::Error::from(errno)),
        });
    }

    // -- mounts / pools -----------------------------------------------------

    fn pool_for(&mut self, info: Option<&MountInfo>, dev: u64, path: &Path) -> usize {
        let key = info.map_or(PoolKey::Device(dev), MountInfo::pool_key);
        if let Some(&p) = self.pool_ids.get(&key) {
            return p;
        }
        let (fstype, kind, label) = match info {
            Some(i) => {
                let label = if i.source.is_empty() || i.source == i.fstype {
                    format!("{} {}", i.fstype, i.mountpoint.display())
                } else {
                    i.source.clone()
                };
                (i.fstype.clone(), i.kind, label)
            }
            None => ("unknown".to_string(), FsKind::Disk, path.display().to_string()),
        };
        let id = self.pools.len();
        self.pools.push(StoragePool {
            label,
            fstype,
            kind,
            info: filesystem_info(path).unwrap_or(FilesystemInfo::EMPTY),
        });
        self.pool_ids.insert(key, id);
        id
    }

    fn lookup_mount(&self, mnt: u64, dev: u64, path: &Path) -> Option<MountInfo> {
        if mnt != 0 {
            if let Some(m) = self.mounts.get(mnt) {
                return Some(m.clone());
            }
        }
        self.mounts
            .iter()
            .find(|m| m.dev == dev && m.mountpoint == path)
            .cloned()
    }

    fn register_fs(
        &mut self,
        info: Option<&MountInfo>,
        dev: u64,
        mnt: u64,
        path: &Path,
        root_node: NodeId,
    ) -> FsId {
        let pool = self.pool_for(info, dev, path);
        let id = self.filesystems.len() as FsId;
        self.filesystems.push(FilesystemScan {
            id,
            mountpoint: info.map_or_else(|| path.to_path_buf(), |i| i.mountpoint.clone()),
            device: dev,
            mount_id: (mnt != 0).then_some(mnt),
            fstype: info.map_or_else(|| "unknown".into(), |i| i.fstype.clone()),
            source: info.map(|i| i.source.clone()).unwrap_or_default(),
            kind: info.map_or(FsKind::Disk, |i| i.kind),
            pool,
            info: filesystem_info(path).unwrap_or(FilesystemInfo::EMPTY),
            root_node,
            walked_bytes: 0,
        });
        self.entered_devs.insert(dev, id);
        id
    }

    fn decide_boundary(
        &mut self,
        parent: NodeId,
        name: &[u8],
        dev: u64,
        mnt: u64,
        ctx: &Ctx,
    ) -> Outcome {
        let path = self.index.path_of_child(parent, name);
        let info = self.lookup_mount(mnt, dev, &path);

        // Same device: a bind mount (or a self bind such as NixOS's read-only
        // /nix/store). Self binds show exactly what is underneath, so they are
        // traversed as part of the current filesystem. A bind of content that
        // is reachable elsewhere would be counted twice, so it is skipped —
        // except in subtree scans, where that "elsewhere" is outside the tree.
        if dev == ctx.dev {
            return match &info {
                Some(i) if !self.subtree && !self.mounts.is_self_bind(i) => {
                    self.record_boundary(&path, dev, mnt, Some(i), BoundaryDecision::Skipped(SkipReason::DuplicateBind));
                    Outcome::Skip
                }
                _ => Outcome::SameFs,
            };
        }

        let (kind, fstype, source) = info
            .as_ref()
            .map(|i| (i.kind, i.fstype.clone(), i.source.clone()))
            .unwrap_or((FsKind::Disk, "unknown".into(), String::new()));
        let _ = (fstype, source);

        if self.entered_devs.contains_key(&dev) {
            self.record_boundary(&path, dev, mnt, info.as_ref(), BoundaryDecision::Skipped(SkipReason::DuplicateBind));
            return Outcome::Skip;
        }

        let include_hit = self
            .includes
            .iter()
            .enumerate()
            .filter(|(_, inc)| inc.starts_with(&path))
            .map(|(i, inc)| (i, **inc == *path))
            .collect::<Vec<_>>();
        for &(i, exact) in &include_hit {
            if exact {
                self.include_reached[i] = true;
            }
        }
        let included = !include_hit.is_empty();
        let allowed = included
            || (self.config.scope == ScanScope::All
                && matches!(kind, FsKind::Disk | FsKind::Memory));

        if !allowed {
            let reason = match kind {
                FsKind::Pseudo => SkipReason::Pseudo,
                FsKind::Network => SkipReason::Network,
                FsKind::Image => SkipReason::Image,
                FsKind::Layered => SkipReason::Layered,
                FsKind::Disk | FsKind::Memory => SkipReason::OutOfScope,
            };
            self.record_boundary(&path, dev, mnt, info.as_ref(), BoundaryDecision::Skipped(reason));
            return Outcome::Skip;
        }

        let fs = self.register_fs(info.as_ref(), dev, mnt, &path, NodeId::NONE);
        self.record_boundary(&path, dev, mnt, info.as_ref(), BoundaryDecision::Entered);
        Outcome::Enter(fs)
    }

    fn record_boundary(
        &mut self,
        path: &Path,
        dev: u64,
        mnt: u64,
        info: Option<&MountInfo>,
        decision: BoundaryDecision,
    ) {
        let pool = self.pool_for(info, dev, path);
        self.boundaries.push(MountBoundary {
            path: path.to_path_buf(),
            filesystem: filesystem_info(path).unwrap_or(FilesystemInfo::EMPTY),
            device: dev,
            mount_id: (mnt != 0).then_some(mnt),
            fstype: info.map_or_else(|| "unknown".into(), |i| i.fstype.clone()),
            source: info.map(|i| i.source.clone()).unwrap_or_default(),
            kind: info.map_or(FsKind::Disk, |i| i.kind),
            pool,
            decision,
        });
    }

    // -- zones ----------------------------------------------------------------

    fn new_zone(&mut self, role: Role, root: NodeId, fs: FsId, uid: u32) -> u16 {
        let id = self.zones.len() as u16;
        self.zones.push(ZoneRec {
            role,
            root,
            fs,
            uid,
            track_owners: role != Role::NixStore,
            owners: FxHashMap::default(),
            top: TopK::new(self.config.zone_top_files),
            loose_bytes: 0,
            loose_files: 0,
        });
        id
    }

    // -- directory reading ----------------------------------------------------

    /// Read one directory: statx every entry, account files immediately,
    /// create nodes for subdirectories and queue them. Returns nothing; the
    /// queued children are `pending[start..]`.
    fn read_dir(&mut self, fd: &OwnedFd, node: NodeId, ctx: &Ctx) {
        let start = self.pending.len();
        let mut buf = std::mem::take(&mut self.buf);

        let mut acc = Usage::default();
        let mut newest = i64::MIN;
        let mut project_kind: Option<ProjectKind> = None;

        let zone = ctx.zone;
        let (zone_role, at_zone_root) = if zone != NO_ZONE {
            let z = &self.zones[zone as usize];
            (Some(z.role), z.root == node)
        } else {
            (None, false)
        };
        let detect_projects = zone_role == Some(Role::HomeZone)
            && !ctx.in_project
            && ctx.bucket.is_some_and(HomeBucket::may_hold_projects);
        let now = self.now;

        {
            let mut dir = RawDir::new(fd, &mut buf);
            while let Some(res) = dir.next() {
                let entry = match res {
                    Ok(e) => e,
                    Err(errno) => {
                        self.record_node_issue(node, errno, "reading directory");
                        break;
                    }
                };
                let cname = entry.file_name();
                let name = cname.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if detect_projects {
                    if let Some(k) = ProjectKind::from_marker(name) {
                        project_kind = Some(project_kind.map_or(k, |p| p.stronger(k)));
                    }
                }

                let st = match statx(fd, cname, statx_at_flags(), STATX_MASK) {
                    Ok(st) => st,
                    // Vanished between getdents and statx: not an error.
                    Err(Errno::NOENT) => continue,
                    Err(errno) => {
                        acc.counts.errors += 1;
                        let path = self.index.path_of_child(node, name);
                        self.push_issue(path, errno, "stat");
                        continue;
                    }
                };

                let file_type = FileType::from_raw_mode(u32::from(st.stx_mode));
                if file_type == FileType::Directory {
                    self.handle_subdir(node, ctx, name, &st, &mut acc, at_zone_root);
                    continue;
                }

                // ---- non-directory entry: the hot path ----
                acc.counts.entries += 1;
                match file_type {
                    FileType::RegularFile => acc.counts.regular_files += 1,
                    FileType::Symlink => acc.counts.symlinks += 1,
                    _ => acc.counts.other += 1,
                }
                let mtime = st.stx_mtime.tv_sec;
                if mtime > newest {
                    newest = mtime;
                }

                let counted = st.stx_nlink <= 1
                    || self.seen.insert(InodeKey {
                        dev: dev_of(&st),
                        ino: st.stx_ino,
                    });
                if !counted {
                    continue;
                }
                let bytes = st.stx_blocks.saturating_mul(ALLOCATED_BLOCK_SIZE);
                if bytes == 0 {
                    continue;
                }
                acc.bytes += bytes;
                acc.age[age_bucket(now - mtime)] += bytes;
                self.ownership[uid_class(st.stx_uid)] += bytes;

                let is_regular = file_type == FileType::RegularFile;
                if zone != NO_ZONE {
                    let z = &mut self.zones[zone as usize];
                    if z.track_owners {
                        *z.owners.entry(st.stx_uid).or_insert(0) += bytes;
                    }
                    if at_zone_root {
                        z.loose_bytes += bytes;
                        z.loose_files += 1;
                    }
                    if is_regular && z.top.might_accept(bytes) {
                        z.top.push(
                            (bytes, st.stx_ino),
                            FileCand {
                                parent: node,
                                name: name.into(),
                                apparent: st.stx_size,
                                bytes,
                                mtime,
                                uid: st.stx_uid,
                            },
                        );
                    }
                }
                if is_regular && self.top_files.might_accept(bytes) {
                    self.top_files.push(
                        (bytes, st.stx_ino),
                        FileCand {
                            parent: node,
                            name: name.into(),
                            apparent: st.stx_size,
                            bytes,
                            mtime,
                            uid: st.stx_uid,
                        },
                    );
                }
            }
        }
        self.buf = buf;

        // One write of the directory's direct totals.
        {
            let n = &mut self.index.nodes[node.idx()];
            n.usage.bytes += acc.bytes;
            n.usage.fs_bytes += acc.bytes;
            n.usage.counts.add(&acc.counts);
            for i in 0..AGE_BUCKETS {
                n.usage.age[i] += acc.age[i];
            }
            if newest > n.newest_mtime {
                n.newest_mtime = newest;
            }
        }

        // Project / artifact fix-up for the children we just queued.
        if let Some(kind) = project_kind {
            self.index.nodes[node.idx()].flags |= flags::PROJECT;
            self.projects.push(ProjectRec { node, kind });
            let artifact_names = kind.artifact_names();
            for i in start..self.pending.len() {
                self.pending[i].ctx.in_project = true;
                if !artifact_names.is_empty() {
                    let child = self.pending[i].node;
                    if artifact_names.contains(&self.index.name(child)) {
                        self.artifacts.push(ArtifactRec {
                            project: node,
                            node: child,
                        });
                    }
                }
            }
        }
    }

    fn handle_subdir(
        &mut self,
        parent: NodeId,
        ctx: &Ctx,
        name: &[u8],
        st: &rustix::fs::Statx,
        acc: &mut Usage,
        at_zone_root: bool,
    ) {
        let step = self.trie.step(ctx.cursor, name);
        let mut child_ctx = *ctx;
        child_ctx.cursor = step.cursor;

        if step.excluded {
            let _ = self.push_node(parent, name, None, &child_ctx, flags::EXCLUDED);
            return;
        }

        let dev = dev_of(st);
        let mnt = if st.stx_mask & StatxFlags::MNT_ID.bits() != 0 {
            st.stx_mnt_id
        } else {
            0
        };
        let boundary = dev != ctx.dev || (mnt != 0 && ctx.mnt != 0 && mnt != ctx.mnt);

        let mut node_flags = 0u16;
        let mut entered_fs = None;
        if boundary {
            match self.decide_boundary(parent, name, dev, mnt, ctx) {
                Outcome::Skip => {
                    let _ = self.push_node(parent, name, None, &child_ctx, flags::SKIPPED_MOUNT);
                    return;
                }
                Outcome::SameFs => {
                    child_ctx.mnt = mnt;
                    node_flags |= flags::SELF_BIND;
                }
                Outcome::Enter(fs) => {
                    child_ctx.fs = fs;
                    child_ctx.mnt = mnt;
                    child_ctx.dev = dev;
                    node_flags |= flags::MOUNT_ROOT;
                    entered_fs = Some(fs);
                }
            }
        }

        acc.counts.entries += 1;
        acc.counts.directories += 1;

        let next_id = NodeId(self.index.nodes.len() as u32);
        let mut zone_role_here = None;
        let mut home_bucket_rec = None;
        if let Some(role) = step.role {
            if role.is_zone() {
                let zid = self.new_zone(role, next_id, child_ctx.fs, st.stx_uid);
                child_ctx.zone = zid;
                zone_role_here = Some((role, zid));
                child_ctx.bucket = None;
                child_ctx.in_project = false;
            }
        } else if at_zone_root && ctx.zone != NO_ZONE {
            if self.zones[ctx.zone as usize].role == Role::HomeZone {
                let b = HomeBucket::classify(name);
                child_ctx.bucket = Some(b);
                home_bucket_rec = Some((ctx.zone as usize, b));
            }
        }

        let Some(id) = self.push_node(parent, name, Some(st), &child_ctx, node_flags) else {
            self.issues.push(ScanIssue {
                path: self.index.path(parent),
                kind: ScanIssueKind::Io,
                message: "directory index full; remaining subdirectories not scanned".into(),
            });
            return;
        };
        debug_assert_eq!(id, next_id);

        if let Some(fs) = entered_fs {
            self.filesystems[fs as usize].root_node = id;
        }
        if let Some((role, zid)) = zone_role_here {
            match role {
                Role::NixStore => self.nix.store_zone = Some(zid as usize),
                _ => {}
            }
        }
        if let Some((zone, bucket)) = home_bucket_rec {
            self.home_buckets.push(HomeBucketRec {
                zone,
                bucket,
                node: id,
            });
        }
        match step.role {
            Some(Role::NixDb) => self.nix.db = Some(id),
            Some(Role::NixProfiles) => self.nix.profiles = Some(id),
            _ => {}
        }
        if at_zone_root
            && ctx.zone != NO_ZONE
            && self.zones[ctx.zone as usize].role == Role::NixStore
        {
            self.nix.store_entries.push(id);
        }

        self.pending.push(Pending {
            node: id,
            ctx: child_ctx,
        });
    }

    // -- the walk -------------------------------------------------------------

    fn walk(&mut self, root_fd: OwnedFd, root: NodeId, root_ctx: Ctx) {
        self.read_dir(&root_fd, root, &root_ctx);
        let mut stack = vec![Frame {
            fd: root_fd,
            start: 0,
            next: 0,
            end: self.pending.len(),
        }];

        let open_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

        while let Some(top) = stack.last_mut() {
            if top.next >= top.end {
                let done = stack.pop().expect("non-empty");
                self.pending.truncate(done.start);
                continue;
            }
            let pend = self.pending[top.next];
            top.next += 1;

            let opened = openat(
                stack.last().expect("non-empty").fd.as_fd(),
                self.index.name_cstr(pend.node),
                open_flags,
                Mode::empty(),
            );
            match opened {
                Ok(fd) => {
                    let start = self.pending.len();
                    self.read_dir(&fd, pend.node, &pend.ctx);
                    stack.push(Frame {
                        fd,
                        start,
                        next: start,
                        end: self.pending.len(),
                    });
                }
                Err(errno) => self.record_node_issue(pend.node, errno, "opening directory"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn scan(root: &Path, config: &ScanConfig) -> io::Result<ScanResult> {
    raise_nofile_limit();

    let mounts = match &config.mounts {
        Some(m) => m.clone(),
        None => MountTable::read().unwrap_or_default(),
    };
    let now = config.now_unix.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    });

    let includes: Vec<PathBuf> = config
        .include
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    let mut zone_config = config.zones.clone();
    zone_config.excluded.extend(config.exclude.iter().cloned());
    if config.prune_pseudo {
        zone_config
            .excluded
            .extend(crate::zones::without_ancestors_of(
                ZoneConfig::default_pruned(),
                &includes,
            ));
    }
    let trie = Trie::build(&zone_config);

    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let root_st = statx(&root_fd, c"", AtFlags::EMPTY_PATH, STATX_MASK).map_err(io::Error::from)?;
    let root_dev = dev_of(&root_st);
    let root_mnt = if root_st.stx_mask & StatxFlags::MNT_ID.bits() != 0 {
        root_st.stx_mnt_id
    } else {
        0
    };

    let mut sc = Scanner {
        config,
        trie,
        mounts,
        index: DirectoryIndex::default(),
        pending: Vec::new(),
        seen: FxHashSet::default(),
        issues: Vec::new(),
        filesystems: Vec::new(),
        pools: Vec::new(),
        pool_ids: FxHashMap::default(),
        entered_devs: FxHashMap::default(),
        boundaries: Vec::new(),
        zones: Vec::new(),
        home_buckets: Vec::new(),
        projects: Vec::new(),
        artifacts: Vec::new(),
        nix: NixScan::default(),
        top_files: TopK::new(config.top_files),
        ownership: [0; 3],
        now,
        subtree: false,
        include_reached: vec![false; includes.len()],
        includes,
        buf: vec![MaybeUninit::uninit(); GETDENTS_BUFFER],
    };

    // Filesystem 0: the one that holds the scan root.
    let root_mount = sc
        .lookup_mount(root_mnt, root_dev, root)
        .or_else(|| sc.mounts.containing(root).cloned());
    let fs0 = sc.register_fs(root_mount.as_ref(), root_dev, root_mnt, root, NodeId(0));
    sc.subtree = root_mount
        .as_ref()
        .is_some_and(|m| m.mountpoint != root);
    let filesystem = sc.filesystems[fs0 as usize].info.clone();

    let (cursor, root_role) = sc.trie.descend_root(root);
    let mut ctx = Ctx {
        cursor,
        zone: NO_ZONE,
        fs: fs0,
        mnt: root_mnt,
        dev: root_dev,
        bucket: None,
        in_project: false,
    };
    use std::os::unix::ffi::OsStrExt;
    if let Some(role) = root_role {
        if role.is_zone() {
            ctx.zone = sc.new_zone(role, NodeId(0), fs0, root_st.stx_uid);
            match role {
                Role::NixStore => sc.nix.store_zone = Some(ctx.zone as usize),
                _ => {}
            }
        } else if role == Role::NixDb {
            sc.nix.db = Some(NodeId(0));
        } else if role == Role::NixProfiles {
            sc.nix.profiles = Some(NodeId(0));
        }
    }
    let root_id = sc
        .push_node(
            NodeId::NONE,
            root.as_os_str().as_bytes(),
            Some(&root_st),
            &ctx,
            0,
        )
        .expect("empty arena cannot be full");
    debug_assert_eq!(root_id, NodeId(0));

    sc.walk(root_fd, root_id, ctx);

    // ---- aggregation: one reverse pass, O(D) ----
    {
        let nodes = &mut sc.index.nodes;
        for i in (1..nodes.len()).rev() {
            let (head, tail) = nodes.split_at_mut(i);
            let child = &tail[0];
            let parent = &mut head[child.parent.idx()];
            parent
                .usage
                .add_child(&child.usage, child.fs == parent.fs);
            if child.newest_mtime > parent.newest_mtime {
                parent.newest_mtime = child.newest_mtime;
            }
        }
    }

    let root_usage = sc.index.nodes[0].usage;
    let totals = ScanTotals {
        counts: root_usage.counts,
        allocated_bytes: root_usage.bytes,
    };
    for fs in &mut sc.filesystems {
        if !fs.root_node.is_none() {
            fs.walked_bytes = sc.index.nodes[fs.root_node.idx()].usage.fs_bytes;
        }
    }

    // ---- finalize records ----
    let index = std::mem::take(&mut sc.index);
    let to_record = |c: FileCand| FileRecord {
        path: index.path_of_child(c.parent, &c.name),
        allocated_bytes: c.bytes,
        apparent_bytes: c.apparent,
        mtime: c.mtime,
        uid: c.uid,
    };
    let top_files: Vec<FileRecord> = std::mem::replace(&mut sc.top_files, TopK::new(0))
        .into_sorted_desc()
        .into_iter()
        .map(&to_record)
        .collect();

    let mut zones = Vec::with_capacity(sc.zones.len());
    for z in std::mem::take(&mut sc.zones) {
        let mut owners: Vec<(u32, u64)> = z.owners.into_iter().collect();
        owners.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        zones.push(ZoneScan {
            role: z.role,
            label: index.path(z.root).display().to_string(),
            node: z.root,
            fs: z.fs,
            owner_uid: z.uid,
            owners,
            top_files: z.top.into_sorted_desc().into_iter().map(&to_record).collect(),
            loose_bytes: z.loose_bytes,
            loose_files: z.loose_files,
        });
    }

    let unreached_includes = sc
        .includes
        .iter()
        .zip(&sc.include_reached)
        .filter(|(p, reached)| !**reached && **p != *root)
        .map(|(p, _)| p.clone())
        .collect();

    let ownership = OwnershipTotals {
        system_bytes: sc.ownership[0],
        user_bytes: sc.ownership[1],
        other_bytes: sc.ownership[2],
    };

    Ok(ScanResult {
        root: root.to_path_buf(),
        scope: config.scope,
        started_unix: now,
        filesystem,
        totals,
        index,
        issues: sc.issues,
        filesystems: sc.filesystems,
        pools: sc.pools,
        mount_boundaries: sc.boundaries,
        zones,
        home_buckets: sc.home_buckets,
        projects: sc.projects,
        artifacts: sc.artifacts,
        nix: sc.nix,
        top_files,
        ownership,
        mounts: sc.mounts,
        subtree_scan: sc.subtree,
        unreached_includes,
    })
}
