// SPDX-License-Identifier: GPL-3.0-only

use crate::model::ScanScope;
use crate::scanner::ScanConfig;
use std::ffi::OsString;
use std::path::PathBuf;

pub const HELP: &str = "\
rootwatch - read-only Linux disk usage scanner

USAGE:
    rootwatch [OPTIONS] [PATH]          PATH defaults to /

FILESYSTEM SCOPE:
    --scope root       only the filesystem holding PATH; other mounts are
                       reported but not entered (default)
    --scope all        PATH's filesystem plus every local disk or tmpfs mount
                       (pseudo, network/FUSE, overlay and image mounts are skipped)
    --scope select     PATH's filesystem plus the mounts given with --include
    --include MOUNT    also enter this mountpoint (repeatable; implies
                       --scope select unless --scope all is given; can force
                       pseudo or network mounts)
    --exclude PATH     never descend into PATH (repeatable)
    --no-prune         do not prune /proc, /sys, /dev and /run

PRIVILEGES:
    --privileged       after the normal unprivileged scan, re-run the scan
                       through an elevation command and report how much data
                       permissions hid (rootwatch itself never needs root)
    --elevate-with CMD elevation command, default: sudo

NIX:
    --nix-gc           ask nix-store for the garbage-collectable size
                       (read-only; can take a while on big stores)

OUTPUT:
    --top N            rows per ranking (default 20)
    -h, --help         this text
    -V, --version
";

#[derive(Debug, Clone)]
pub struct Cli {
    pub root: PathBuf,
    pub scope: ScanScope,
    pub include: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
    pub no_prune: bool,
    pub privileged: bool,
    pub elevate: Vec<String>,
    pub nix_gc: bool,
    pub top: usize,
    pub worker: bool,
    pub help: bool,
    pub version: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            scope: ScanScope::Root,
            include: Vec::new(),
            exclude: Vec::new(),
            no_prune: false,
            privileged: false,
            elevate: vec!["sudo".into()],
            nix_gc: false,
            top: 20,
            worker: false,
            help: false,
            version: false,
        }
    }
}

pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut scope_explicit = false;
    let mut it = args.into_iter();
    let mut root_given = false;

    while let Some(arg) = it.next() {
        let text = arg.to_string_lossy().into_owned();
        let (flag, inline) = match text.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (text.clone(), None),
        };
        let mut value = |name: &str| -> Result<OsString, String> {
            if let Some(v) = &inline {
                Ok(OsString::from(v))
            } else {
                it.next().ok_or_else(|| format!("{name} requires a value"))
            }
        };
        match flag.as_str() {
            "-h" | "--help" => cli.help = true,
            "-V" | "--version" => cli.version = true,
            "--worker" => cli.worker = true,
            "--privileged" => cli.privileged = true,
            "--nix-gc" => cli.nix_gc = true,
            "--no-prune" => cli.no_prune = true,
            "--scope" => {
                let v = value("--scope")?;
                cli.scope = match v.to_string_lossy().as_ref() {
                    "root" => ScanScope::Root,
                    "all" => ScanScope::All,
                    "select" | "selected" => ScanScope::Selected,
                    other => return Err(format!("unknown scope '{other}' (root, all, select)")),
                };
                scope_explicit = true;
            }
            "--include" => cli.include.push(PathBuf::from(value("--include")?)),
            "--exclude" => cli.exclude.push(PathBuf::from(value("--exclude")?)),
            "--elevate-with" => {
                let v = value("--elevate-with")?;
                cli.elevate = v
                    .to_string_lossy()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                if cli.elevate.is_empty() {
                    return Err("--elevate-with needs a command".into());
                }
            }
            "--top" => {
                let v = value("--top")?;
                cli.top = v
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "--top needs a number".to_string())?;
            }
            f if f.starts_with('-') && f.len() > 1 => return Err(format!("unknown option '{f}'")),
            _ => {
                if root_given {
                    return Err("only one PATH may be given".into());
                }
                cli.root = PathBuf::from(arg);
                root_given = true;
            }
        }
    }

    if !cli.include.is_empty() && !scope_explicit {
        cli.scope = ScanScope::Selected;
    }
    if cli.scope == ScanScope::Root && !cli.include.is_empty() {
        cli.scope = ScanScope::Selected;
    }
    if cli.scope == ScanScope::Selected && cli.include.is_empty() {
        return Err("--scope select needs at least one --include MOUNT".into());
    }
    Ok(cli)
}

impl Cli {
    pub fn scan_config(&self) -> ScanConfig {
        ScanConfig {
            scope: self.scope,
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            prune_pseudo: !self.no_prune,
            ..ScanConfig::default()
        }
    }

    /// Arguments that reproduce this scan in a worker process.
    pub fn worker_args(&self, canonical_root: &std::path::Path) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec![
            "--scope".into(),
            match self.scope {
                ScanScope::Root => "root",
                ScanScope::All => "all",
                ScanScope::Selected => "select",
            }
            .into(),
        ];
        for i in &self.include {
            a.push("--include".into());
            a.push(i.clone().into_os_string());
        }
        for e in &self.exclude {
            a.push("--exclude".into());
            a.push(e.clone().into_os_string());
        }
        if self.no_prune {
            a.push("--no-prune".into());
        }
        a.push(canonical_root.as_os_str().to_os_string());
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cli, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn defaults_to_root_scope_on_slash() {
        let c = p(&[]).unwrap();
        assert_eq!(c.scope, ScanScope::Root);
        assert_eq!(c.root, PathBuf::from("/"));
    }

    #[test]
    fn include_implies_selected_scope() {
        let c = p(&["--include", "/nix", "/"]).unwrap();
        assert_eq!(c.scope, ScanScope::Selected);
        assert_eq!(c.include, vec![PathBuf::from("/nix")]);
    }

    #[test]
    fn all_scope_keeps_all_with_includes() {
        let c = p(&["--scope=all", "--include=/mnt/x"]).unwrap();
        assert_eq!(c.scope, ScanScope::All);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(p(&["--scope", "everything"]).is_err());
        assert!(p(&["--scope", "select"]).is_err());
        assert!(p(&["--bogus"]).is_err());
        assert!(p(&["/a", "/b"]).is_err());
        assert!(p(&["--top"]).is_err());
    }

    #[test]
    fn worker_args_reproduce_scope() {
        let c = p(&["--scope", "all", "--exclude", "/mnt/big", "/home"]).unwrap();
        let a = c.worker_args(std::path::Path::new("/home"));
        let s: Vec<_> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
        assert_eq!(s, ["--scope", "all", "--exclude", "/mnt/big", "/home"]);
    }
}
