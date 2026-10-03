// SPDX-License-Identifier: GPL-3.0-only
//
// Mount discovery from /proc/self/mountinfo (read once, O(M)).
//
// Per-entry mount identity during the walk comes from statx's `stx_mnt_id`,
// which is the same id space as the first column of mountinfo, so deciding
// what a boundary *is* costs one hash lookup per boundary.

use crate::fxhash::FxHashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsKind {
    /// Block-device backed (ext4, xfs, btrfs, vfat, ntfs, zfs, ...).
    Disk,
    /// RAM backed (tmpfs, ramfs): holds real data but consumes memory.
    Memory,
    /// Kernel interfaces (proc, sysfs, cgroup, devtmpfs, ...).
    Pseudo,
    /// Remote or FUSE: can hang or be enormous, never scanned implicitly.
    Network,
    /// Read-only images (squashfs, erofs): backed by a file already counted.
    Image,
    /// Union views (overlayfs): content is reachable through its layers.
    Layered,
}

impl FsKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Memory => "memory",
            Self::Pseudo => "pseudo",
            Self::Network => "network/fuse",
            Self::Image => "image",
            Self::Layered => "layered",
        }
    }

    pub fn classify(fstype: &str) -> Self {
        match fstype {
            "tmpfs" | "ramfs" => Self::Memory,
            "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" | "securityfs"
            | "debugfs" | "tracefs" | "configfs" | "fusectl" | "pstore" | "bpf" | "mqueue"
            | "hugetlbfs" | "autofs" | "binfmt_misc" | "efivarfs" | "selinuxfs" | "nsfs"
            | "rpc_pipefs" | "binderfs" | "devfs" | "fuse.portal" | "fuse.gvfsd-fuse"
            | "fuse.xwayland" => Self::Pseudo,
            "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "afs" | "ceph" | "glusterfs"
            | "lustre" | "9p" | "davfs" | "ncpfs" => Self::Network,
            "squashfs" | "erofs" | "cramfs" => Self::Image,
            "overlay" | "aufs" => Self::Layered,
            // ntfs-3g and friends mount local block devices through FUSE.
            "fuseblk" => Self::Disk,
            t if t == "fuse" || t.starts_with("fuse.") => Self::Network,
            _ => Self::Disk,
        }
    }
}

/// Filesystems that can be several mounts of one shared block pool. Their
/// `statvfs` numbers describe the whole pool, so they must be accounted
/// together.
fn shares_pool(fstype: &str) -> bool {
    matches!(fstype, "btrfs" | "bcachefs")
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PoolKey {
    Device(u64),
    Shared { fstype: String, source: String },
}

#[derive(Debug, Clone)]
pub struct MountInfo {
    pub id: u64,
    pub parent_id: u64,
    pub dev: u64,
    /// Root of this mount inside its filesystem ("/" for a whole-fs mount).
    pub root: Vec<u8>,
    pub mountpoint: PathBuf,
    pub read_only: bool,
    pub fstype: String,
    pub source: String,
    pub kind: FsKind,
}

impl MountInfo {
    pub fn pool_key(&self) -> PoolKey {
        if shares_pool(&self.fstype) && !self.source.is_empty() {
            PoolKey::Shared {
                fstype: self.fstype.clone(),
                source: self.source.clone(),
            }
        } else {
            PoolKey::Device(self.dev)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MountTable {
    mounts: Vec<MountInfo>,
    by_id: FxHashMap<u64, usize>,
}

fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\'
            && i + 4 <= field.len()
            && field[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let v = (field[i + 1] - b'0') as u32 * 64
                + (field[i + 2] - b'0') as u32 * 8
                + (field[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    out
}

fn parse_line(line: &[u8]) -> Option<MountInfo> {
    use std::os::unix::ffi::OsStringExt;
    let fields: Vec<&[u8]> = line.split(|&b| b == b' ').filter(|f| !f.is_empty()).collect();
    if fields.len() < 10 {
        return None;
    }
    let sep = fields.iter().position(|f| *f == b"-")?;
    if sep < 6 || fields.len() < sep + 3 {
        return None;
    }
    let num = |f: &[u8]| std::str::from_utf8(f).ok()?.parse::<u64>().ok();
    let id = num(fields[0])?;
    let parent_id = num(fields[1])?;
    let (maj, min) = std::str::from_utf8(fields[2]).ok()?.split_once(':')?;
    let dev = rustix::fs::makedev(maj.parse().ok()?, min.parse().ok()?);
    let options = String::from_utf8_lossy(fields[5]).into_owned();
    let fstype = String::from_utf8_lossy(fields[sep + 1]).into_owned();
    let source = String::from_utf8_lossy(&unescape(fields[sep + 2])).into_owned();
    Some(MountInfo {
        id,
        parent_id,
        dev,
        root: unescape(fields[3]),
        mountpoint: PathBuf::from(std::ffi::OsString::from_vec(unescape(fields[4]))),
        read_only: options.split(',').any(|o| o == "ro"),
        kind: FsKind::classify(&fstype),
        fstype,
        source,
    })
}

impl MountTable {
    pub fn read() -> io::Result<Self> {
        Ok(Self::parse(&std::fs::read("/proc/self/mountinfo")?))
    }

    pub fn parse(text: &[u8]) -> Self {
        let mut table = MountTable::default();
        for line in text.split(|&b| b == b'\n') {
            if let Some(info) = parse_line(line) {
                table.by_id.insert(info.id, table.mounts.len());
                table.mounts.push(info);
            }
        }
        table
    }

    pub fn get(&self, id: u64) -> Option<&MountInfo> {
        self.by_id.get(&id).map(|&i| &self.mounts[i])
    }

    pub fn iter(&self) -> impl Iterator<Item = &MountInfo> {
        self.mounts.iter()
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// A "self bind mount" maps a directory of a filesystem onto itself (NixOS
    /// does this to `/nix/store` to make it read-only). Walking through it
    /// shows exactly the content underneath, so it is not a new filesystem and
    /// must not be skipped as a duplicate.
    pub fn is_self_bind(&self, info: &MountInfo) -> bool {
        let Some(parent) = self.get(info.parent_id) else {
            return false;
        };
        if parent.dev != info.dev {
            return false;
        }
        let Ok(rel) = info.mountpoint.strip_prefix(&parent.mountpoint) else {
            return false;
        };
        use std::os::unix::ffi::OsStrExt;
        let mut expected = parent.root.clone();
        for comp in rel.components() {
            if !expected.ends_with(b"/") {
                expected.push(b'/');
            }
            expected.extend_from_slice(comp.as_os_str().as_bytes());
        }
        expected == info.root
    }

    /// Innermost mount whose mountpoint is an ancestor of `path`.
    pub fn containing(&self, path: &Path) -> Option<&MountInfo> {
        self.mounts
            .iter()
            .filter(|m| path.starts_with(&m.mountpoint))
            .max_by_key(|m| m.mountpoint.as_os_str().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"\
22 1 0:21 /@ / rw,relatime shared:1 - btrfs /dev/mapper/crypt rw,ssd,subvol=/@\n\
23 22 0:21 /@nix /nix rw,relatime shared:2 - btrfs /dev/mapper/crypt rw,subvol=/@nix\n\
24 23 0:21 /@nix/store /nix/store ro,relatime shared:3 - btrfs /dev/mapper/crypt rw,subvol=/@nix\n\
25 22 0:30 / /tmp rw - tmpfs tmpfs rw\n\
26 22 0:5 / /proc rw - proc proc rw\n\
27 22 8:1 / /mnt/with\\040space rw - ext4 /dev/sda1 rw\n";

    #[test]
    fn parses_fields_and_kinds() {
        let t = MountTable::parse(SAMPLE);
        assert_eq!(t.len(), 6);
        assert_eq!(t.get(25).unwrap().kind, FsKind::Memory);
        assert_eq!(t.get(26).unwrap().kind, FsKind::Pseudo);
        assert_eq!(t.get(27).unwrap().mountpoint, PathBuf::from("/mnt/with space"));
        assert!(t.get(24).unwrap().read_only);
    }

    #[test]
    fn btrfs_subvolumes_share_a_pool() {
        let t = MountTable::parse(SAMPLE);
        assert_eq!(t.get(22).unwrap().pool_key(), t.get(23).unwrap().pool_key());
        assert_ne!(t.get(22).unwrap().pool_key(), t.get(27).unwrap().pool_key());
    }

    #[test]
    fn detects_self_bind_over_nix_store() {
        let t = MountTable::parse(SAMPLE);
        assert!(t.is_self_bind(t.get(24).unwrap()));
        assert!(!t.is_self_bind(t.get(23).unwrap()));
    }

    #[test]
    fn containing_prefers_innermost() {
        let t = MountTable::parse(SAMPLE);
        assert_eq!(t.containing(Path::new("/nix/store/x")).unwrap().id, 24);
        assert_eq!(t.containing(Path::new("/etc")).unwrap().id, 22);
    }

    #[test]
    fn fuse_defaults_to_network_but_fuseblk_is_disk() {
        assert_eq!(FsKind::classify("fuse.sshfs"), FsKind::Network);
        assert_eq!(FsKind::classify("fuseblk"), FsKind::Disk);
        assert_eq!(FsKind::classify("overlay"), FsKind::Layered);
    }
}
