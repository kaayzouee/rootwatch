#![allow(dead_code)]
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct Fixture {
    pub root: PathBuf,
    mounts: Vec<PathBuf>,
}

impl Fixture {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rw-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        Self {
            root,
            mounts: Vec::new(),
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn dir(&self, rel: &str) -> PathBuf {
        let p = self.path(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    pub fn file(&self, rel: &str, bytes: usize) -> PathBuf {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, vec![0xABu8; bytes]).unwrap();
        p
    }

    pub fn set_age_days(&self, rel: &str, days: i64, now: i64) {
        use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
        let t = Timespec {
            tv_sec: now - days * 86_400,
            tv_nsec: 0,
        };
        let ts = Timestamps {
            last_access: t,
            last_modification: t,
        };
        utimensat(CWD, self.path(rel), &ts, AtFlags::SYMLINK_NOFOLLOW).unwrap();
    }

    /// Needs root; returns false (test should skip) when mounting is impossible.
    pub fn mount_tmpfs(&mut self, rel: &str) -> bool {
        let p = self.dir(rel);
        let ok = Command::new("mount")
            .args(["-t", "tmpfs", "-o", "size=16m", "tmpfs"])
            .arg(&p)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            self.mounts.push(p);
        }
        ok
    }

    pub fn bind_mount(&mut self, src: &Path, dst_rel: &str) -> bool {
        let dst = self.dir(dst_rel);
        let ok = Command::new("mount")
            .arg("--bind")
            .arg(src)
            .arg(&dst)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            self.mounts.push(dst);
        }
        ok
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for m in self.mounts.iter().rev() {
            let _ = Command::new("umount").arg(m).status();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Independent reference implementation using only std: du-style allocated
/// bytes with hard-link dedup, not following symlinks, staying on one device.
pub fn reference_bytes(root: &Path) -> u64 {
    fn walk(p: &Path, seen: &mut HashSet<(u64, u64)>, dev: u64, total: &mut u64) {
        let Ok(md) = fs::symlink_metadata(p) else {
            return;
        };
        if md.dev() != dev {
            return;
        }
        if md.nlink() <= 1 || md.is_dir() || seen.insert((md.dev(), md.ino())) {
            *total += md.blocks() * 512;
        }
        if md.is_dir()
            && let Ok(rd) = fs::read_dir(p)
        {
            for e in rd.flatten() {
                walk(&e.path(), seen, dev, total);
            }
        }
    }
    let dev = fs::symlink_metadata(root).unwrap().dev();
    let mut total = 0;
    walk(root, &mut HashSet::new(), dev, &mut total);
    total
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}
