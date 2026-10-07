// SPDX-License-Identifier: GPL-3.0-only
//  Copyright (C) 2026 kaayzouee
// Author: https://github.com/kaayzouee
mod common;

use common::*;
use rootwatch::model::*;
use rootwatch::scanner::{ScanConfig, scan};
use rootwatch::zones::{PathClass, Role, ZoneConfig, ZoneRule};
use std::fs;
use std::os::unix::fs::symlink;

const NOW: i64 = 1_800_000_000;

fn cfg() -> ScanConfig {
    ScanConfig {
        now_unix: Some(NOW),
        ..ScanConfig::default()
    }
}

fn find(r: &ScanResult, path: &std::path::Path) -> NodeId {
    r.index
        .ids()
        .find(|&id| r.index.path(id) == path)
        .unwrap_or_else(|| panic!("no node for {}", path.display()))
}

#[test]
fn totals_match_independent_reference() {
    let fx = Fixture::new("ref");
    fx.file("a/one.bin", 10_000);
    fx.file("a/b/two.bin", 123_456);
    fx.file("a/b/c/three.bin", 1);
    fx.file("empty/.keep", 0);
    fx.dir("a/b/c/d/e/f");
    let r = scan(&fx.root, &cfg()).unwrap();
    assert_eq!(r.totals.allocated_bytes, reference_bytes(&fx.root));
    assert_eq!(r.totals.counts.regular_files, 4);
    assert_eq!(r.totals.counts.errors, 0);
}

#[test]
fn hard_links_are_counted_once() {
    let fx = Fixture::new("hl");
    let f = fx.file("x/orig.bin", 200_000);
    fs::hard_link(&f, fx.path("x/link1.bin")).unwrap();
    fs::hard_link(
        &f,
        fx.path("y/link2.bin")
            .parent()
            .map(|p| {
                fs::create_dir_all(p).unwrap();
                fx.path("y/link2.bin")
            })
            .unwrap(),
    )
    .unwrap();
    let single = fx.file("z/lone.bin", 200_000);
    let r = scan(&fx.root, &cfg()).unwrap();
    assert_eq!(r.totals.allocated_bytes, reference_bytes(&fx.root));
    let one = fs::metadata(&single).unwrap();
    use std::os::unix::fs::MetadataExt;
    let file_bytes = one.blocks() * 512;
    // 3 names + 1 independent file = 2 allocations, not 4.
    let dirs = r.index.len() as u64 * 4096;
    assert_eq!(r.totals.allocated_bytes, 2 * file_bytes + dirs);
    assert_eq!(r.totals.counts.regular_files, 4);
}

#[test]
fn symlinks_are_not_followed_and_loops_terminate() {
    let fx = Fixture::new("sym");
    fx.file("real/data.bin", 50_000);
    symlink(fx.path("real"), fx.path("link_to_real")).unwrap();
    symlink(&fx.root, fx.path("real/loop")).unwrap();
    symlink("/nonexistent/target", fx.path("dangling")).unwrap();
    let r = scan(&fx.root, &cfg()).unwrap();
    assert_eq!(r.totals.counts.symlinks, 3);
    assert_eq!(r.totals.counts.regular_files, 1);
    assert_eq!(r.totals.allocated_bytes, reference_bytes(&fx.root));
    assert_eq!(r.totals.counts.errors, 0);
}

#[test]
fn sparse_files_count_allocation_not_apparent_size() {
    let fx = Fixture::new("sparse");
    let p = fx.path("sparse.img");
    let f = fs::File::create(&p).unwrap();
    f.set_len(512 << 20).unwrap();
    drop(f);
    let r = scan(&fx.root, &cfg()).unwrap();
    assert!(
        r.totals.allocated_bytes < 1 << 20,
        "got {}",
        r.totals.allocated_bytes
    );
    assert_eq!(
        r.top_files.len(),
        0,
        "a hole-only file has no allocated bytes to rank"
    );
}

#[test]
fn aggregation_is_consistent_and_children_iterate() {
    let fx = Fixture::new("agg");
    fx.file("p/q/f1", 40_000);
    fx.file("p/q/r/f2", 80_000);
    fx.file("p/s/f3", 20_000);
    let r = scan(&fx.root, &cfg()).unwrap();
    for id in r.index.ids() {
        let n = r.index.node(id);
        let kids: u64 = r.index.children(id).map(|c| r.usage(c).bytes).sum();
        assert!(
            n.usage.bytes >= kids,
            "parent smaller than children at {}",
            r.index.path(id).display()
        );
        for c in r.index.children(id) {
            assert_eq!(r.index.node(c).parent, id);
            assert!(c > id, "children must have larger ids than parents");
        }
    }
    let p = find(&r, &fx.path("p"));
    assert_eq!(r.index.children(p).count(), 2);
    assert_eq!(r.usage(p).counts.regular_files, 3);
    assert_eq!(r.usage(p).counts.directories, 3);
    assert_eq!(r.usage(r.root_node()).bytes, r.totals.allocated_bytes);
    assert_eq!(r.index.path(r.root_node()), fx.root);
}

#[test]
fn top_level_and_largest_rankings_are_ordered() {
    let fx = Fixture::new("rank");
    fx.file("big/f", 900_000);
    fx.file("mid/f", 300_000);
    fx.file("small/f", 10_000);
    let r = scan(&fx.root, &cfg()).unwrap();
    let tl: Vec<_> = r
        .top_level_directories()
        .iter()
        .map(|&i| {
            r.index
                .path(i)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(tl, ["big", "mid", "small"]);
    let lg = r.largest_directories(2);
    assert_eq!(lg.len(), 2);
    assert!(r.usage(lg[0]).bytes >= r.usage(lg[1]).bytes);
}

#[test]
fn excluded_directories_are_pruned_and_flagged() {
    let fx = Fixture::new("excl");
    fx.file("keep/f", 30_000);
    fx.file("skipme/huge", 5_000_000);
    let mut c = cfg();
    c.exclude.push(fx.path("skipme"));
    let r = scan(&fx.root, &c).unwrap();
    let n = find(&r, &fx.path("skipme"));
    assert!(r.index.node(n).has_flag(flags::EXCLUDED));
    assert_eq!(r.usage(n).bytes, 0);
    assert!(r.totals.allocated_bytes < 1_000_000);
    assert_eq!(r.totals.counts.regular_files, 1);
}

#[test]
fn age_buckets_follow_mtime() {
    let fx = Fixture::new("age");
    fx.file("fresh", 100_000);
    fx.file("week", 100_000);
    fx.file("old", 100_000);
    fx.set_age_days("week", 3, NOW);
    fx.set_age_days("old", 200, NOW);
    fx.set_age_days("fresh", 0, NOW);
    let r = scan(&fx.root, &cfg()).unwrap();
    let a = r.usage(r.root_node()).age;
    assert!(a[0] >= 100_000, "{a:?}");
    assert!(a[1] >= 100_000, "{a:?}");
    assert!(a[4] >= 100_000, "{a:?}");
    assert_eq!(
        a.iter().sum::<u64>(),
        r.totals.allocated_bytes,
        "age buckets partition the bytes"
    );
    assert_eq!(age_bucket(200 * 86_400), 4);
    assert_eq!(bucket_from_days(7), 2);
}

#[test]
fn temp_zone_collects_owners_age_and_top_files() {
    let fx = Fixture::new("temp");
    fx.file("t/a/big.bin", 600_000);
    fx.file("t/small.bin", 5_000);
    fx.set_age_days("t/a/big.bin", 40, NOW);
    let mut c = cfg();
    c.zones = ZoneConfig {
        rules: vec![ZoneRule::zone(
            fx.path("t").to_str().unwrap(),
            PathClass::Temporary,
            Role::TempZone,
        )],
        excluded: vec![],
    };
    let r = scan(&fx.root, &c).unwrap();
    assert_eq!(r.zones.len(), 1);
    let z = &r.zones[0];
    assert_eq!(z.role, Role::TempZone);
    assert!(!z.owners.is_empty());
    assert_eq!(z.top_files[0].path, fx.path("t/a/big.bin"));
    assert_eq!(z.loose_files, 1);
    let t = find(&r, &fx.path("t/a"));
    assert_eq!(
        r.index.node(t).class,
        PathClass::Temporary,
        "class is inherited by descendants"
    );
}

#[test]
fn home_zone_buckets_projects_and_artifacts() {
    let fx = Fixture::new("home");
    fx.file("h/kay/Downloads/iso.img", 400_000);
    fx.file("h/kay/.cache/blob", 300_000);
    fx.file("h/kay/.cargo/registry/crate", 100_000);
    fx.file("h/kay/code/proj/Cargo.toml", 10);
    fx.file("h/kay/code/proj/src/main.rs", 100);
    fx.file("h/kay/code/proj/target/debug/bin", 700_000);
    fx.file("h/kay/code/proj/inner/Cargo.toml", 10);
    fx.file("h/kay/notes.txt", 4_000);
    let mut c = cfg();
    c.zones = ZoneConfig {
        rules: vec![ZoneRule::zone(
            &format!("{}/h/*", fx.root.display()),
            PathClass::Home,
            Role::HomeZone,
        )],
        excluded: vec![],
    };
    let r = scan(&fx.root, &c).unwrap();
    let mut buckets: Vec<_> = r.home_buckets.iter().map(|b| b.bucket.label()).collect();
    buckets.sort();
    assert_eq!(
        buckets,
        [
            ".cache",
            ".cargo",
            "Downloads",
            "other (projects, documents)"
        ]
    );
    assert_eq!(
        r.projects.len(),
        1,
        "nested project must not be double counted"
    );
    assert_eq!(r.index.path(r.projects[0].node), fx.path("h/kay/code/proj"));
    assert_eq!(r.artifacts.len(), 1);
    assert_eq!(r.index.name(r.artifacts[0].node), b"target");
    assert!(r.usage(r.artifacts[0].node).bytes >= 700_000);
    assert_eq!(
        r.zones[0].loose_files, 1,
        "notes.txt sits directly in the home dir"
    );

    // the analysis layer turns that into a report
    let a = rootwatch::analysis::analyze(&r, &Default::default());
    assert_eq!(a.home.len(), 1);
    assert_eq!(a.home[0].projects.len(), 1);
    assert!(a.home[0].artifact_total_bytes >= 700_000);
}

#[test]
fn nix_store_entries_packages_and_gc_estimate() {
    use rootwatch::nix::{DeadPaths, GcEstimate};
    let fx = Fixture::new("nix");
    let h = |c: char| c.to_string().repeat(32);
    let names = [
        format!("{}-glibc-2.38-1", h('a')),
        format!("{}-glibc-2.39-2", h('b')),
        format!("{}-firefox-120.0", h('c')),
    ];
    fx.file(&format!("n/store/{}/lib/libc.so", names[0]), 300_000);
    fx.file(&format!("n/store/{}/lib/libc.so", names[1]), 300_000);
    fx.file(&format!("n/store/{}/bin/firefox", names[2]), 900_000);
    fx.file(&format!("n/store/{}-foo.drv", h('d')), 2_000);
    fx.dir("n/var/nix/profiles");
    for g in 1..=3 {
        symlink(
            "/nix/store/x",
            fx.path(&format!("n/var/nix/profiles/system-{g}-link")),
        )
        .unwrap();
    }
    symlink("system-3-link", fx.path("n/var/nix/profiles/system")).unwrap();
    fx.dir("n/var/nix/db");

    let mut c = cfg();
    let n = fx.path("n").display().to_string();
    c.zones = ZoneConfig {
        rules: vec![
            ZoneRule::class(&n, PathClass::Nix),
            ZoneRule::role(&format!("{n}/store"), Role::NixStore),
            ZoneRule::role(&format!("{n}/var/nix/profiles"), Role::NixProfiles),
            ZoneRule::role(&format!("{n}/var/nix/db"), Role::NixDb),
        ],
        excluded: vec![],
    };
    let r = scan(&fx.root, &c).unwrap();
    assert_eq!(r.nix.store_entries.len(), 3);
    assert!(r.nix.profiles.is_some() && r.nix.db.is_some());
    assert_eq!(
        r.zones
            .iter()
            .find(|z| z.role == Role::NixStore)
            .unwrap()
            .loose_files,
        1
    );

    let dead = DeadPaths::Found(vec![
        format!("/nix/store/{}", names[0]).into_bytes(),
        format!("/nix/store/{}-foo.drv", h('d')).into_bytes(),
    ]);
    let rep = rootwatch::nix::build(&r, Some(&dead)).unwrap();
    assert_eq!(rep.store_paths, 3);
    let glibc = rep.top_packages.iter().find(|p| p.name == "glibc").unwrap();
    assert_eq!(glibc.versions, 2);
    assert_eq!(rep.generations[0].count, 3);
    assert_eq!(rep.generations[0].current, Some(3));
    match rep.gc {
        GcEstimate::Estimated {
            dead_paths,
            measured_paths,
            unmatched_paths,
            bytes,
        } => {
            assert_eq!((dead_paths, measured_paths, unmatched_paths), (2, 1, 1));
            assert!(bytes >= 300_000);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        rep.explanation
            .iter()
            .any(|l| l.contains("system generation"))
    );
}

#[test]
fn unreadable_directories_are_recorded_and_scanning_continues() {
    if is_root() {
        eprintln!("SKIP: root bypasses permissions (run the test binary as an unprivileged user)");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new("perm");
    fx.file("open/f", 20_000);
    fx.file("locked/secret", 900_000);
    fx.file("locked/inner/deep", 10);
    fs::set_permissions(fx.path("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let r = scan(&fx.root, &cfg()).unwrap();
    fs::set_permissions(fx.path("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(r.permission_denied_count(), 1);
    let n = find(&r, &fx.path("locked"));
    assert!(r.index.node(n).has_flag(flags::DENIED));
    assert_eq!(r.usage(n).counts.errors, 1);
    assert_eq!(r.totals.counts.errors, 1, "error is aggregated to the root");
    assert_eq!(
        r.totals.counts.regular_files, 1,
        "the open sibling was still scanned"
    );
    let a = rootwatch::analysis::analyze(&r, &Default::default());
    assert_eq!(a.coverage.denied_dirs, 1);
    assert!(
        a.coverage
            .gaps
            .iter()
            .any(|g| matches!(g.kind, rootwatch::coverage::GapKind::PermissionDenied))
    );
}

// ---------------- multi-filesystem behaviour (needs root + mount) ----------------

#[test]
fn scope_root_reports_but_does_not_enter_tmpfs() {
    if !is_root() {
        eprintln!("SKIP: needs root");
        return;
    }
    let mut fx = Fixture::new("scoperoot");
    fx.file("plain/f", 10_000);
    if !fx.mount_tmpfs("mnt") {
        eprintln!("SKIP: cannot mount");
        return;
    }
    fs::write(fx.path("mnt/inside"), vec![1u8; 1_000_000]).unwrap();
    let r = scan(&fx.root, &cfg()).unwrap();
    assert_eq!(r.filesystems.len(), 1);
    let b = r
        .mount_boundaries
        .iter()
        .find(|b| b.path == fx.path("mnt"))
        .expect("boundary reported");
    assert_eq!(
        b.decision,
        BoundaryDecision::Skipped(SkipReason::OutOfScope)
    );
    assert_eq!(b.fstype, "tmpfs");
    assert!(
        r.totals.allocated_bytes < 500_000,
        "tmpfs content must not leak into a root-scope scan"
    );
    let n = find(&r, &fx.path("mnt"));
    assert!(r.index.node(n).has_flag(flags::SKIPPED_MOUNT));
}

#[test]
fn scope_all_enters_tmpfs_and_aggregates_per_filesystem() {
    if !is_root() {
        eprintln!("SKIP: needs root");
        return;
    }
    let mut fx = Fixture::new("scopeall");
    fx.file("plain/f", 10_000);
    if !fx.mount_tmpfs("mnt") {
        eprintln!("SKIP: cannot mount");
        return;
    }
    fs::write(fx.path("mnt/inside"), vec![1u8; 1_000_000]).unwrap();
    let mut c = cfg();
    c.scope = ScanScope::All;
    let r = scan(&fx.root, &c).unwrap();
    assert_eq!(r.filesystems.len(), 2);
    let tmp = r.filesystems.iter().find(|f| f.fstype == "tmpfs").unwrap();
    assert!(tmp.walked_bytes >= 1_000_000);
    assert_eq!(tmp.kind, rootwatch::mounts::FsKind::Memory);
    let mnt = find(&r, &fx.path("mnt"));
    assert!(r.index.node(mnt).has_flag(flags::MOUNT_ROOT));
    assert_eq!(r.index.node(mnt).fs, tmp.id);
    // subtree total includes the nested fs, but fs_bytes of the parent does not
    let root = r.usage(r.root_node());
    assert!(root.bytes >= root.fs_bytes + 1_000_000);
    assert_eq!(root.fs_bytes, r.filesystems[0].walked_bytes);
    assert_eq!(
        r.totals.allocated_bytes,
        r.filesystems.iter().map(|f| f.walked_bytes).sum::<u64>()
    );
}

#[test]
fn selected_scope_enters_only_included_mounts() {
    if !is_root() {
        eprintln!("SKIP: needs root");
        return;
    }
    let mut fx = Fixture::new("select");
    if !fx.mount_tmpfs("one") || !fx.mount_tmpfs("two") {
        eprintln!("SKIP: cannot mount");
        return;
    }
    let mut c = cfg();
    c.scope = ScanScope::Selected;
    c.include.push(fx.path("one"));
    let r = scan(&fx.root, &c).unwrap();
    assert_eq!(r.filesystems.len(), 2);
    let entered: Vec<_> = r
        .mount_boundaries
        .iter()
        .filter(|b| b.decision == BoundaryDecision::Entered)
        .map(|b| b.path.clone())
        .collect();
    assert_eq!(entered, vec![fx.path("one")]);
    assert!(r.unreached_includes.is_empty());

    let mut c2 = cfg();
    c2.scope = ScanScope::Selected;
    c2.include.push(fx.path("plain-dir-not-a-mount"));
    fs::create_dir_all(fx.path("plain-dir-not-a-mount")).unwrap();
    let r2 = scan(&fx.root, &c2).unwrap();
    assert_eq!(r2.unreached_includes.len(), 1);
}

#[test]
fn bind_mount_of_scanned_content_is_not_double_counted() {
    if !is_root() {
        eprintln!("SKIP: needs root");
        return;
    }
    let mut fx = Fixture::new("bind");
    if !fx.mount_tmpfs("fs") {
        eprintln!("SKIP: cannot mount");
        return;
    }
    fs::write(fx.path("fs/data"), vec![1u8; 2_000_000]).unwrap();
    let src = fx.path("fs");
    if !fx.bind_mount(&src, "alias") {
        eprintln!("SKIP: cannot bind");
        return;
    }
    let mut c = cfg();
    c.scope = ScanScope::All;
    let r = scan(&fx.root, &c).unwrap();
    let data_copies = r
        .top_files
        .iter()
        .filter(|f| f.allocated_bytes >= 2_000_000)
        .count();
    assert_eq!(
        data_copies, 1,
        "the same tmpfs content is reachable twice but counted once"
    );
    assert!(
        r.mount_boundaries
            .iter()
            .any(|b| b.decision == BoundaryDecision::Skipped(SkipReason::DuplicateBind))
    );
}

#[test]
fn self_bind_mount_is_traversed_like_nixos_nix_store() {
    if !is_root() {
        eprintln!("SKIP: needs root");
        return;
    }
    let fx = Fixture::new("selfbind");
    fx.file("store/pkg/file", 700_000);
    let store = fx.path("store");
    let ok = std::process::Command::new("mount")
        .arg("--bind")
        .arg(&store)
        .arg(&store)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: cannot bind");
        return;
    }
    let r = scan(&fx.root, &cfg());
    let _ = std::process::Command::new("umount").arg(&store).status();
    let r = r.unwrap();
    assert!(
        r.top_files
            .iter()
            .any(|f| f.path.ends_with("store/pkg/file")),
        "content under a self bind must still be scanned"
    );
    assert_eq!(
        r.filesystems.len(),
        1,
        "a self bind is not a new filesystem"
    );
    assert!(r.totals.allocated_bytes >= 700_000);
}

#[test]
fn pseudo_prune_defaults_leave_other_dirs_alone() {
    let r = scan(std::path::Path::new("/etc"), &cfg()).unwrap();
    assert!(r.totals.counts.entries > 10);
    assert_eq!(
        r.totals.allocated_bytes,
        reference_bytes(std::path::Path::new("/etc"))
    );
}
