// SPDX-License-Identifier: GPL-3.0-only
//
// Nix / NixOS analysis: explain *why* /nix is large instead of just flagging it.
//
// Sizes come from the walk (each store path is a depth-1 directory node under
// /nix/store, so per-path sizes cost nothing extra). Generation data is read
// from the profile symlinks. An exact "garbage-collectable" estimate needs the
// Nix tools: `nix-store --gc --print-dead` (or `nix-collect-garbage --dry-run`)
// list what a collection *would* delete without deleting anything. Rootwatch
// is read-only and never runs a collection.

use crate::fxhash::FxHashMap;
use crate::model::*;
use crate::topk::TopK;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs};

#[derive(Debug, Clone)]
pub enum DeadPaths {
    Found(Vec<Vec<u8>>),
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub enum GcEstimate {
    NotRequested,
    Unavailable(String),
    Estimated {
        dead_paths: usize,
        measured_paths: usize,
        unmatched_paths: usize,
        bytes: u64,
    },
}

#[derive(Debug, Clone)]
pub struct StorePathUsage {
    pub name: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PackageUsage {
    pub name: String,
    pub bytes: u64,
    pub versions: usize,
}

#[derive(Debug, Clone)]
pub struct GenerationGroup {
    pub profile: String,
    pub count: usize,
    pub current: Option<u64>,
    pub oldest_unix: Option<i64>,
    pub newest_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NixReport {
    pub store_node: Option<NodeId>,
    pub store_bytes: u64,
    pub percent_of_fs_used: f64,
    pub store_paths: usize,
    pub loose_files: u64,
    pub loose_bytes: u64,
    pub db_bytes: Option<u64>,
    pub profiles_bytes: Option<u64>,
    pub generations: Vec<GenerationGroup>,
    pub top_paths: Vec<StorePathUsage>,
    pub top_packages: Vec<PackageUsage>,
    pub gc: GcEstimate,
    pub explanation: Vec<String>,
    pub suggestions: Vec<String>,
}

/// Package name without hash and version: "<32 hash chars>-glibc-2.39-52" ->
/// "glibc". Falls back to the whole name part when there is no version.
pub fn package_name(store_name: &[u8]) -> &[u8] {
    let name = if store_name.len() > 33 && store_name[32] == b'-' {
        &store_name[33..]
    } else {
        store_name
    };
    for i in 0..name.len().saturating_sub(1) {
        if name[i] == b'-' && name[i + 1].is_ascii_digit() {
            return &name[..i];
        }
    }
    name
}

fn display_name(store_name: &[u8]) -> String {
    let n = if store_name.len() > 33 && store_name[32] == b'-' {
        &store_name[33..]
    } else {
        store_name
    };
    String::from_utf8_lossy(n).into_owned()
}

/// Ask the Nix tools what a garbage collection would delete. Read-only.
pub fn query_dead_paths(timeout: Duration) -> DeadPaths {
    let attempts: [(&str, &[&str]); 2] = [
        ("nix-store", &["--gc", "--print-dead"]),
        ("nix-collect-garbage", &["--dry-run"]),
    ];
    let mut last_err = String::from("no Nix tools found in PATH");
    for (cmd, args) in attempts {
        match run_with_timeout(cmd, args, timeout) {
            Ok(out) => {
                let paths: Vec<Vec<u8>> = out
                    .split(|&b| b == b'\n')
                    .filter(|l| l.starts_with(b"/nix/store/"))
                    .map(<[u8]>::to_vec)
                    .collect();
                return DeadPaths::Found(paths);
            }
            Err(e) => last_err = format!("{cmd}: {e}"),
        }
    }
    DeadPaths::Unavailable(last_err)
}

fn trusted_canonical_path(path: &Path, owner_uid: u32) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    let mut cur = canonical.as_path();
    loop {
        let meta = fs::symlink_metadata(cur).ok()?;
        if meta.uid() != owner_uid || meta.permissions().mode() & 0o022 != 0 {
            return None;
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        if parent == cur {
            break;
        }
        cur = parent;
    }
    Some(canonical)
}

fn find_trusted_program(
    name: &str,
    path: &std::ffi::OsStr,
    owner_uid: u32,
) -> Result<PathBuf, String> {
    for dir in env::split_paths(path) {
        if !dir.is_absolute() {
            continue;
        }
        let Some(trusted_dir) = trusted_canonical_path(&dir, owner_uid) else {
            continue;
        };
        let candidate = trusted_dir.join(name);
        let Some(trusted) = trusted_canonical_path(&candidate, owner_uid) else {
            continue;
        };
        let Ok(meta) = fs::symlink_metadata(&trusted) else {
            continue;
        };
        let mode = meta.permissions().mode();
        if meta.is_file() && mode & 0o111 != 0 {
            return Ok(trusted);
        }
    }

    Err(format!("no trusted {name} found on PATH"))
}

fn program_path(name: &str) -> Result<PathBuf, String> {
    if !rustix::process::geteuid().is_root() {
        return Ok(PathBuf::from(name));
    }
    let path = env::var_os("PATH").ok_or("PATH is unset")?;
    find_trusted_program(name, &path, 0)
}

fn run_with_timeout(cmd: &str, args: &[&str], timeout: Duration) -> Result<Vec<u8>, String> {
    let program = program_path(cmd)?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().unwrap_or_default();
                return if status.success() {
                    Ok(out)
                } else {
                    Err(format!("exited with {status}"))
                };
            }
            Ok(None) => {
                if started.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn read_generations(profiles: &Path) -> Vec<GenerationGroup> {
    fn parse_link(name: &str) -> Option<(&str, u64)> {
        let stem = name.strip_suffix("-link")?;
        let (profile, num) = stem.rsplit_once('-')?;
        Some((profile, num.parse().ok()?))
    }

    let mut groups: FxHashMap<String, GenerationGroup> = FxHashMap::default();
    let mut dirs = vec![profiles.to_path_buf()];
    // per-user/<name>/ profiles, one level deep
    if let Ok(rd) = std::fs::read_dir(profiles.join("per-user")) {
        dirs.extend(rd.flatten().map(|e| e.path()));
    }
    for dir in dirs {
        let prefix = if dir == profiles {
            String::new()
        } else {
            format!(
                "{}/",
                dir.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            )
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let entries: Vec<_> = rd.flatten().collect();
        for e in &entries {
            let fname = e.file_name().to_string_lossy().into_owned();
            let Some((profile, num)) = parse_link(&fname) else {
                continue;
            };
            let key = format!("{prefix}{profile}");
            let mtime = e.path().symlink_metadata().ok().map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime()
            });
            let g = groups
                .entry(key.clone())
                .or_insert_with(|| GenerationGroup {
                    profile: key.clone(),
                    count: 0,
                    current: None,
                    oldest_unix: None,
                    newest_unix: None,
                });
            g.count += 1;
            if let Some(t) = mtime {
                g.oldest_unix = Some(g.oldest_unix.map_or(t, |o| o.min(t)));
                g.newest_unix = Some(g.newest_unix.map_or(t, |o| o.max(t)));
            }
            let _ = num;
        }
        // The un-numbered symlink points at the current generation.
        for (key, g) in groups.iter_mut() {
            let bare = key
                .strip_prefix(&prefix)
                .filter(|_| key.starts_with(&prefix));
            if let Some(bare) = bare {
                if bare.contains('/') {
                    continue;
                }
                if let Ok(target) = std::fs::read_link(dir.join(bare))
                    && let Some((_, n)) = parse_link(&target.to_string_lossy())
                {
                    g.current = Some(n);
                }
            }
        }
    }
    let mut v: Vec<_> = groups.into_values().collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.profile.cmp(&b.profile)));
    v
}

pub fn build(result: &ScanResult, dead: Option<&DeadPaths>) -> Option<NixReport> {
    let zone = result.nix.store_zone.map(|z| &result.zones[z]);
    if zone.is_none() && result.nix.store_entries.is_empty() {
        return None;
    }
    let store_node = zone.map(|z| z.node);
    let store_bytes = store_node.map_or(0, |n| result.index.node(n).usage.bytes);
    let used = store_node
        .map(|n| result.pool_of(n).info.used_bytes)
        .unwrap_or(1)
        .max(1);

    let mut top = TopK::new(10);
    let mut pkgs: FxHashMap<&[u8], (u64, usize)> = FxHashMap::default();
    for &id in &result.nix.store_entries {
        let b = result.index.node(id).usage.bytes;
        top.push((b, u64::from(id.0)), id);
        let e = pkgs
            .entry(package_name(result.index.name(id)))
            .or_insert((0, 0));
        e.0 += b;
        e.1 += 1;
    }
    let top_paths: Vec<StorePathUsage> = top
        .into_sorted_desc()
        .into_iter()
        .map(|id| StorePathUsage {
            name: display_name(result.index.name(id)),
            bytes: result.index.node(id).usage.bytes,
        })
        .collect();
    let mut pk: Vec<(&[u8], (u64, usize))> = pkgs.into_iter().collect();
    pk.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(b.0)));
    let top_packages: Vec<PackageUsage> = pk
        .into_iter()
        .take(10)
        .map(|(n, (bytes, versions))| PackageUsage {
            name: String::from_utf8_lossy(n).into_owned(),
            bytes,
            versions,
        })
        .collect();

    let gc = match dead {
        None => GcEstimate::NotRequested,
        Some(DeadPaths::Unavailable(why)) => GcEstimate::Unavailable(why.clone()),
        Some(DeadPaths::Found(paths)) => {
            let sizes: FxHashMap<&[u8], u64> = result
                .nix
                .store_entries
                .iter()
                .map(|&id| (result.index.name(id), result.index.node(id).usage.bytes))
                .collect();
            let (mut bytes, mut measured, mut unmatched) = (0u64, 0usize, 0usize);
            for p in paths {
                let rest = &p[b"/nix/store/".len()..];
                let first = rest.split(|&b| b == b'/').next().unwrap_or(rest);
                match sizes.get(first) {
                    Some(&b) => {
                        bytes += b;
                        measured += 1;
                    }
                    None => unmatched += 1,
                }
            }
            GcEstimate::Estimated {
                dead_paths: paths.len(),
                measured_paths: measured,
                unmatched_paths: unmatched,
                bytes,
            }
        }
    };

    let generations = result
        .nix
        .profiles
        .map(|n| read_generations(&result.index.path(n)))
        .unwrap_or_default();

    let mut report = NixReport {
        store_node,
        store_bytes,
        percent_of_fs_used: store_bytes as f64 / used as f64 * 100.0,
        store_paths: result.nix.store_entries.len(),
        loose_files: zone.map_or(0, |z| z.loose_files),
        loose_bytes: zone.map_or(0, |z| z.loose_bytes),
        db_bytes: result.nix.db.map(|n| result.index.node(n).usage.bytes),
        profiles_bytes: result
            .nix
            .profiles
            .map(|n| result.index.node(n).usage.bytes),
        generations,
        top_paths,
        top_packages,
        gc,
        explanation: Vec::new(),
        suggestions: Vec::new(),
    };
    explain(&mut report, result.started_unix);
    Some(report)
}

fn gib(b: u64) -> String {
    format!("{:.2} GiB", b as f64 / (1u64 << 30) as f64)
}

fn explain(r: &mut NixReport, now: i64) {
    let mut ex = Vec::new();
    let mut sg = Vec::new();
    ex.push(format!(
        "the Nix store holds {} across {} store paths ({:.1}% of used space on its filesystem)",
        gib(r.store_bytes),
        r.store_paths,
        r.percent_of_fs_used
    ));
    if let Some(top) = r.top_paths.first() {
        ex.push(format!(
            "largest single store path: {} ({})",
            top.name,
            gib(top.bytes)
        ));
    }
    if let Some(sys) = r.generations.iter().find(|g| g.profile == "system") {
        let age = sys
            .oldest_unix
            .map(|t| format!(", oldest {} day(s) old", ((now - t).max(0)) / 86_400))
            .unwrap_or_default();
        ex.push(format!(
            "{} system generation(s) are kept{age}; each one keeps its whole closure alive until it is deleted",
            sys.count
        ));
        if sys.count >= 10 {
            sg.push("nix-collect-garbage --delete-older-than 30d  (drops old generations, then collects)".to_string());
        }
    }
    let multi: Vec<&PackageUsage> = r
        .top_packages
        .iter()
        .filter(|p| p.versions > 1)
        .take(3)
        .collect();
    for p in &multi {
        ex.push(format!(
            "{} exists in {} versions/outputs totalling {}",
            p.name,
            p.versions,
            gib(p.bytes)
        ));
    }
    match &r.gc {
        GcEstimate::NotRequested => ex.push(
            "garbage-collectable size not measured; add --nix-gc for an exact estimate".to_string(),
        ),
        GcEstimate::Unavailable(why) => {
            ex.push(format!("garbage-collectable size unavailable ({why})"))
        }
        GcEstimate::Estimated {
            bytes,
            dead_paths,
            unmatched_paths,
            ..
        } => {
            let pct = *bytes as f64 / r.store_bytes.max(1) as f64 * 100.0;
            ex.push(format!(
                "{} ({pct:.1}% of the store) is unreferenced and would be freed by a garbage collection ({dead_paths} paths{})",
                gib(*bytes),
                if *unmatched_paths > 0 {
                    format!(", {unmatched_paths} files not sized")
                } else {
                    String::new()
                }
            ));
            ex.push("estimate: files hard-linked with live paths (store optimisation) are not actually freed".to_string());
            if *bytes > 0 {
                sg.push("nix-collect-garbage  (frees the unreferenced paths above)".to_string());
            }
        }
    }
    if let Some(db) = r.db_bytes
        && db > (1 << 30)
    {
        ex.push(format!("the Nix database is {}", gib(db)));
    }
    sg.push(
        "Rootwatch is read-only and never runs these; run them yourself if you agree".to_string(),
    );
    r.explanation = ex;
    r.suggestions = sg;
}

/// Share of the store that a GC would free, as bytes, if it was measured.
pub fn reclaimable_bytes(r: &NixReport) -> Option<u64> {
    match r.gc {
        GcEstimate::Estimated { bytes, .. } => Some(bytes),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_program_ignores_writable_path_entries() {
        let unsafe_dir = std::env::temp_dir().join(format!("rw-path-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&unsafe_dir);
        std::fs::create_dir_all(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let program_name = "rootwatch-path-trust-test";
        let fake = unsafe_dir.join(program_name);
        std::fs::write(&fake, b"not really executable code").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = std::env::join_paths([unsafe_dir.as_path()]).unwrap();
        assert!(find_trusted_program(program_name, &path, 0).is_err());

        let _ = std::fs::remove_dir_all(&unsafe_dir);
    }

    #[test]
    fn trusted_program_rejects_writable_path_directories() {
        assert!(find_trusted_program("sh", std::ffi::OsStr::new("/tmp"), 0).is_err());
        assert!(find_trusted_program("sh", std::ffi::OsStr::new("."), 0).is_err());
    }

    #[test]
    fn package_names_drop_hash_and_version() {
        let h = "a".repeat(32);
        let n = |s: &str| format!("{h}-{s}");
        assert_eq!(package_name(n("glibc-2.39-52").as_bytes()), b"glibc");
        assert_eq!(
            package_name(n("python3.12-numpy-1.26.4").as_bytes()),
            b"python3.12-numpy"
        );
        assert_eq!(package_name(n("linux-6.6.30-modules").as_bytes()), b"linux");
        assert_eq!(package_name(n("source").as_bytes()), b"source");
    }

    #[test]
    fn generations_parse_profile_links() {
        let dir = std::env::temp_dir().join(format!("rw-gen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in [1, 2, 3] {
            std::os::unix::fs::symlink("/nix/store/x", dir.join(format!("system-{n}-link")))
                .unwrap();
        }
        std::os::unix::fs::symlink("system-3-link", dir.join("system")).unwrap();
        let g = read_generations(&dir);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].profile, "system");
        assert_eq!(g[0].count, 3);
        assert_eq!(g[0].current, Some(3));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
