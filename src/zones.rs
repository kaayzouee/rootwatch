// SPDX-License-Identifier: GPL-3.0-only
//
// Path classification and "attention zones".
//
// Rules are compiled into a trie keyed by path components. The scanner steps a
// cursor through the trie while it does its depth-first walk, so classifying a
// directory costs one small lookup (O(1) for the handful of siblings a trie
// node has) instead of matching the full path against every prefix. Once the
// cursor leaves the trie the class is simply inherited, so the vast majority
// of directories cost a single integer comparison.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PathClass {
    Temporary,
    Home,
    Nix,
    Var,
    System,
    Generic,
}

impl PathClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Temporary => "temporary",
            Self::Home => "home",
            Self::Nix => "nix",
            Self::Var => "var",
            Self::System => "system",
            Self::Generic => "generic",
        }
    }
}

/// Special meaning attached to a directory. Zones (`TempZone`, `HomeZone`,
/// `NixStore`) additionally collect per-entry statistics during the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    TempZone,
    HomeZone,
    NixStore,
    NixDb,
    NixProfiles,
}

impl Role {
    pub fn is_zone(self) -> bool {
        matches!(self, Self::TempZone | Self::HomeZone | Self::NixStore)
    }
}

#[derive(Debug, Clone)]
pub struct ZoneRule {
    /// Absolute pattern. A component of `*` matches any single component.
    pub pattern: PathBuf,
    pub class: Option<PathClass>,
    pub role: Option<Role>,
}

impl ZoneRule {
    pub fn class(pattern: &str, class: PathClass) -> Self {
        Self {
            pattern: PathBuf::from(pattern),
            class: Some(class),
            role: None,
        }
    }

    pub fn zone(pattern: &str, class: PathClass, role: Role) -> Self {
        Self {
            pattern: PathBuf::from(pattern),
            class: Some(class),
            role: Some(role),
        }
    }

    pub fn role(pattern: &str, role: Role) -> Self {
        Self {
            pattern: PathBuf::from(pattern),
            class: None,
            role: Some(role),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZoneConfig {
    pub rules: Vec<ZoneRule>,
    /// Directories never descended into (reported as pruned).
    pub excluded: Vec<PathBuf>,
}

impl Default for ZoneConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                ZoneRule::class("/var", PathClass::Var),
                ZoneRule::zone("/tmp", PathClass::Temporary, Role::TempZone),
                ZoneRule::zone("/var/tmp", PathClass::Temporary, Role::TempZone),
                ZoneRule::class("/home", PathClass::Home),
                ZoneRule::zone("/home/*", PathClass::Home, Role::HomeZone),
                ZoneRule::zone("/root", PathClass::Home, Role::HomeZone),
                ZoneRule::class("/nix", PathClass::Nix),
                ZoneRule::role("/nix/store", Role::NixStore),
                ZoneRule::role("/nix/var/nix/db", Role::NixDb),
                ZoneRule::role("/nix/var/nix/profiles", Role::NixProfiles),
                ZoneRule::class("/usr", PathClass::System),
                ZoneRule::class("/etc", PathClass::System),
                ZoneRule::class("/opt", PathClass::System),
            ],
            excluded: Vec::new(),
        }
    }
}

impl ZoneConfig {
    /// Pseudo-filesystem roots that are skipped by default. A path that an
    /// explicit include lives under is never pruned (see `without_ancestors_of`).
    pub fn default_pruned() -> Vec<PathBuf> {
        ["/proc", "/sys", "/dev", "/run"]
            .iter()
            .map(PathBuf::from)
            .collect()
    }
}

const NONE: u32 = u32::MAX;

struct TrieNode {
    children: Vec<(Box<[u8]>, u32)>,
    wildcard: u32,
    class: Option<PathClass>,
    role: Option<Role>,
    excluded: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: Vec::new(),
            wildcard: NONE,
            class: None,
            role: None,
            excluded: false,
        }
    }
}

pub struct Trie {
    nodes: Vec<TrieNode>,
}

/// Position of the walk inside the trie, plus the class inherited so far.
#[derive(Debug, Clone, Copy)]
pub struct Cursor {
    pub trie: u32,
    pub class: PathClass,
}

#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub cursor: Cursor,
    pub role: Option<Role>,
    pub excluded: bool,
}

fn components(path: &Path) -> impl Iterator<Item = &[u8]> {
    use std::os::unix::ffi::OsStrExt;
    path.components().filter_map(|c| match c {
        Component::Normal(s) => Some(s.as_bytes()),
        _ => None,
    })
}

impl Trie {
    pub fn build(config: &ZoneConfig) -> Self {
        let mut trie = Trie {
            nodes: vec![TrieNode::new()],
        };
        for rule in &config.rules {
            let n = trie.insert(&rule.pattern);
            if rule.class.is_some() {
                trie.nodes[n as usize].class = rule.class;
            }
            if rule.role.is_some() {
                trie.nodes[n as usize].role = rule.role;
            }
        }
        for path in &config.excluded {
            let n = trie.insert(path);
            trie.nodes[n as usize].excluded = true;
        }
        trie
    }

    fn insert(&mut self, path: &Path) -> u32 {
        let mut cur = 0u32;
        for comp in components(path) {
            cur = self.child_or_insert(cur, comp);
        }
        cur
    }

    fn child_or_insert(&mut self, at: u32, comp: &[u8]) -> u32 {
        if comp == b"*" {
            let existing = self.nodes[at as usize].wildcard;
            if existing != NONE {
                return existing;
            }
            let id = self.nodes.len() as u32;
            self.nodes.push(TrieNode::new());
            self.nodes[at as usize].wildcard = id;
            return id;
        }
        if let Some(&(_, id)) = self.nodes[at as usize]
            .children
            .iter()
            .find(|(n, _)| &**n == comp)
        {
            return id;
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(TrieNode::new());
        self.nodes[at as usize]
            .children
            .push((comp.to_vec().into_boxed_slice(), id));
        id
    }

    pub fn root_cursor(&self) -> Cursor {
        Cursor {
            trie: 0,
            class: PathClass::Generic,
        }
    }

    #[inline]
    pub fn step(&self, cursor: Cursor, name: &[u8]) -> Step {
        if cursor.trie == NONE {
            return Step {
                cursor,
                role: None,
                excluded: false,
            };
        }
        let node = &self.nodes[cursor.trie as usize];
        let next = node
            .children
            .iter()
            .find(|(n, _)| &**n == name)
            .map(|&(_, id)| id)
            .unwrap_or(node.wildcard);
        if next == NONE {
            return Step {
                cursor: Cursor {
                    trie: NONE,
                    class: cursor.class,
                },
                role: None,
                excluded: false,
            };
        }
        let t = &self.nodes[next as usize];
        Step {
            cursor: Cursor {
                trie: next,
                class: t.class.unwrap_or(cursor.class),
            },
            role: t.role,
            excluded: t.excluded,
        }
    }

    /// Walk the cursor down the components of the scan root (no exclusions are
    /// applied to the root path itself). Returns the cursor and the role of the
    /// final component.
    pub fn descend_root(&self, root: &Path) -> (Cursor, Option<Role>) {
        let mut cur = self.root_cursor();
        let mut role = None;
        for comp in components(root) {
            let s = self.step(cur, comp);
            cur = s.cursor;
            role = s.role;
        }
        (cur, role)
    }
}

/// Remove default prunes that sit above an explicit include path, so asking
/// for `/run/media/me/usb` actually works.
pub fn without_ancestors_of(pruned: Vec<PathBuf>, includes: &[PathBuf]) -> Vec<PathBuf> {
    pruned
        .into_iter()
        .filter(|p| !includes.iter().any(|inc| inc.starts_with(p)))
        .collect()
}

// ---------------------------------------------------------------------------
// Home-directory structure
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HomeBucket {
    Downloads,
    Cache,
    Local,
    Cargo,
    Config,
    Toolchains,
    OtherHidden,
    Other,
}

impl HomeBucket {
    pub fn from_index(i: u8) -> Option<Self> {
        Some(match i {
            0 => Self::Downloads,
            1 => Self::Cache,
            2 => Self::Local,
            3 => Self::Cargo,
            4 => Self::Config,
            5 => Self::Toolchains,
            6 => Self::OtherHidden,
            7 => Self::Other,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Downloads => "Downloads",
            Self::Cache => ".cache",
            Self::Local => ".local",
            Self::Cargo => ".cargo",
            Self::Config => ".config",
            Self::Toolchains => "toolchains/package managers",
            Self::OtherHidden => "other hidden",
            Self::Other => "other (projects, documents)",
        }
    }

    /// Whether directories under this bucket can plausibly be user projects.
    pub fn may_hold_projects(self) -> bool {
        matches!(self, Self::Downloads | Self::Other)
    }

    pub fn classify(name: &[u8]) -> Self {
        match name {
            b"Downloads" | b"downloads" => Self::Downloads,
            b".cache" => Self::Cache,
            b".local" => Self::Local,
            b".cargo" => Self::Cargo,
            b".config" => Self::Config,
            b".rustup" | b".npm" | b".nvm" | b".pnpm-store" | b".gradle" | b".m2" | b".pyenv"
            | b".conda" | b".nix-defexpr" | b".bun" | b".yarn" | b".deno" | b".ghcup"
            | b".stack" | b".opam" | b".go" => Self::Toolchains,
            n if n.first() == Some(&b'.') => Self::OtherHidden,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectKind {
    Cargo,
    Node,
    Python,
    Go,
    Nix,
    Java,
    CMake,
    Git,
}

impl ProjectKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cargo => "Rust",
            Self::Node => "Node",
            Self::Python => "Python",
            Self::Go => "Go",
            Self::Nix => "Nix",
            Self::Java => "JVM",
            Self::CMake => "CMake",
            Self::Git => "git",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Cargo => 0,
            Self::Node => 1,
            Self::Python => 2,
            Self::Go => 3,
            Self::Nix => 4,
            Self::Java => 5,
            Self::CMake => 6,
            Self::Git => 7,
        }
    }

    pub fn from_marker(name: &[u8]) -> Option<Self> {
        Some(match name {
            b"Cargo.toml" => Self::Cargo,
            b"package.json" => Self::Node,
            b"pyproject.toml" | b"setup.py" | b"requirements.txt" => Self::Python,
            b"go.mod" => Self::Go,
            b"flake.nix" => Self::Nix,
            b"pom.xml" | b"build.gradle" | b"build.gradle.kts" => Self::Java,
            b"CMakeLists.txt" => Self::CMake,
            b".git" => Self::Git,
            _ => return None,
        })
    }

    pub fn stronger(self, other: Self) -> Self {
        if other.priority() < self.priority() {
            other
        } else {
            self
        }
    }

    /// Build-artifact directory names that are normally safe to regenerate.
    pub fn artifact_names(self) -> &'static [&'static [u8]] {
        match self {
            Self::Cargo => &[b"target"],
            Self::Node => &[b"node_modules"],
            Self::Python => &[b".venv", b"venv", b".tox"],
            Self::Java => &[b"target", b"build", b".gradle"],
            Self::Nix => &[b".direnv"],
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(trie: &Trie, path: &str) -> (PathClass, Option<Role>) {
        let (c, r) = trie.descend_root(Path::new(path));
        (c.class, r)
    }

    #[test]
    fn classifies_by_prefix_with_deepest_match() {
        let trie = Trie::build(&ZoneConfig::default());
        assert_eq!(walk(&trie, "/tmp/x/y").0, PathClass::Temporary);
        assert_eq!(walk(&trie, "/var/tmp/a").0, PathClass::Temporary);
        assert_eq!(walk(&trie, "/var/log").0, PathClass::Var);
        assert_eq!(walk(&trie, "/home/kay/.cache").0, PathClass::Home);
        assert_eq!(walk(&trie, "/nix/store/abc").0, PathClass::Nix);
        assert_eq!(walk(&trie, "/usr/lib").0, PathClass::System);
        assert_eq!(walk(&trie, "/srv").0, PathClass::Generic);
        // Prefix match is by component, not by string.
        assert_eq!(walk(&trie, "/tmpfoo").0, PathClass::Generic);
    }

    #[test]
    fn wildcard_creates_per_user_home_zones() {
        let trie = Trie::build(&ZoneConfig::default());
        assert_eq!(walk(&trie, "/home/kay").1, Some(Role::HomeZone));
        assert_eq!(walk(&trie, "/home").1, None);
        assert_eq!(walk(&trie, "/root").1, Some(Role::HomeZone));
        assert_eq!(walk(&trie, "/tmp").1, Some(Role::TempZone));
        assert_eq!(walk(&trie, "/nix/store").1, Some(Role::NixStore));
    }

    #[test]
    fn explicit_includes_lift_default_prunes() {
        let kept = without_ancestors_of(
            ZoneConfig::default_pruned(),
            &[PathBuf::from("/run/media/me/usb")],
        );
        assert!(!kept.contains(&PathBuf::from("/run")));
        assert!(kept.contains(&PathBuf::from("/proc")));
    }

    #[test]
    fn home_buckets_and_markers() {
        assert_eq!(HomeBucket::classify(b".cache"), HomeBucket::Cache);
        assert_eq!(HomeBucket::classify(b".mozilla"), HomeBucket::OtherHidden);
        assert_eq!(HomeBucket::classify(b"code"), HomeBucket::Other);
        assert_eq!(ProjectKind::from_marker(b"Cargo.toml"), Some(ProjectKind::Cargo));
        assert_eq!(
            ProjectKind::Git.stronger(ProjectKind::Node),
            ProjectKind::Node
        );
    }
}
