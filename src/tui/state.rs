// SPDX-License-Identifier: GPL-3.0-only
//
// All UI state lives here (or in the per-view structs below). Widgets read it;
// they never own application state. `ScanResult` and `AnalysisResult` are held
// behind `Arc` and are immutable for as long as they are displayed.

use super::command::InputMode;
use super::tree::TreeState;
use crate::analysis::{AnalysisResult, Finding};
use crate::model::{NodeId, ScanIssueKind, ScanResult, flags};
use crate::scanner::ProgressSnapshot;
use crate::users::UserNames;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tui_input::Input;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum View {
    Overview,
    Findings,
    Tree,
    Files,
    Coverage,
    Pools,
    Zones,
}

impl View {
    pub const ALL: [View; 7] = [
        View::Overview,
        View::Findings,
        View::Tree,
        View::Files,
        View::Coverage,
        View::Pools,
        View::Zones,
    ];

    pub fn title(self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Findings => "Findings",
            View::Tree => "Tree",
            View::Files => "Files",
            View::Coverage => "Coverage",
            View::Pools => "Pools",
            View::Zones => "Zones",
        }
    }

    pub fn index(self) -> usize {
        View::ALL.iter().position(|&v| v == self).unwrap_or(0)
    }

    pub fn next(self) -> View {
        View::ALL[(self.index() + 1) % View::ALL.len()]
    }

    pub fn previous(self) -> View {
        View::ALL[(self.index() + View::ALL.len() - 1) % View::ALL.len()]
    }

    /// Views that have a `/` filter.
    pub fn searchable(self) -> bool {
        matches!(
            self,
            View::Findings | View::Tree | View::Files | View::Pools
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Idle,
    Scanning,
    Analyzing,
    Ready,
    Failed(String),
}

impl ScanStatus {
    pub fn busy(&self) -> bool {
        matches!(self, ScanStatus::Scanning | ScanStatus::Analyzing)
    }
}

/// Selection helper shared by the table views: move by `delta`, clamped.
pub fn clamp_move(current: Option<usize>, len: usize, delta: isize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0) as isize;
    Some((cur + delta).clamp(0, len as isize - 1) as usize)
}

// ---------------------------------------------------------------------------
// Per-view state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct OverviewState {
    pub selected_pool: Option<usize>,
    /// Largest top-level directories, computed once per scan.
    pub areas: Vec<NodeId>,
}

#[derive(Debug, Clone, Default)]
pub struct FindingsState {
    pub table: TableState,
    pub filter: String,
    /// Indices into `AnalysisResult::findings` that pass the filter.
    pub filtered_indices: Vec<usize>,
    pub detail_open: bool,
}

/// Whitespace-separated terms; every term must match path, title, kind,
/// severity, expectation or class (case-insensitive).
pub fn finding_matches(f: &Finding, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let hay = format!(
        "{} {} {} {} {} {}",
        f.path.display(),
        f.title.as_deref().unwrap_or(""),
        super::fmt::kind_label(f.kind),
        f.severity.label(),
        f.expectation.label(),
        f.class.label()
    )
    .to_lowercase();
    terms.iter().all(|t| hay.contains(t.as_str()))
}

pub fn split_terms(filter: &str) -> Vec<String> {
    filter
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .collect()
}

impl FindingsState {
    pub fn reset(&mut self, a: &AnalysisResult) {
        *self = Self::default();
        self.refilter(a, "");
    }

    pub fn refilter(&mut self, a: &AnalysisResult, filter: &str) {
        let keep = self.selected_source_index();
        self.filter = filter.trim().to_string();
        let terms = split_terms(&self.filter);
        self.filtered_indices = a
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| finding_matches(f, &terms))
            .map(|(i, _)| i)
            .collect();
        let sel = keep
            .and_then(|k| self.filtered_indices.iter().position(|&i| i == k))
            .or(if self.filtered_indices.is_empty() {
                None
            } else {
                Some(0)
            });
        self.table.select(sel);
    }

    fn selected_source_index(&self) -> Option<usize> {
        self.table
            .selected()
            .and_then(|i| self.filtered_indices.get(i).copied())
    }

    pub fn selected<'a>(&self, a: &'a AnalysisResult) -> Option<&'a Finding> {
        self.selected_source_index().and_then(|i| a.findings.get(i))
    }

    pub fn move_by(&mut self, delta: isize) {
        let n = clamp_move(self.table.selected(), self.filtered_indices.len(), delta);
        self.table.select(n);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSort {
    Size,
    /// Oldest modification first: the stale candidates.
    Age,
    Path,
}

impl FileSort {
    pub fn next(self) -> Self {
        match self {
            Self::Size => Self::Age,
            Self::Age => Self::Path,
            Self::Path => Self::Size,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Age => "age (oldest first)",
            Self::Path => "path",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesState {
    pub table: TableState,
    pub filter: String,
    pub sort: FileSort,
    /// Indices into `ScanResult::top_files`, filtered and sorted.
    pub order: Vec<usize>,
    pub detail_open: bool,
}

impl Default for FilesState {
    fn default() -> Self {
        Self {
            table: TableState::default(),
            filter: String::new(),
            sort: FileSort::Size,
            order: Vec::new(),
            detail_open: false,
        }
    }
}

impl FilesState {
    pub fn reset(&mut self, r: &ScanResult) {
        *self = Self::default();
        self.rebuild(r);
    }

    pub fn set_filter(&mut self, r: &ScanResult, filter: &str) {
        self.filter = filter.trim().to_string();
        self.rebuild(r);
    }

    pub fn toggle_sort(&mut self, r: &ScanResult) {
        self.sort = self.sort.next();
        self.rebuild(r);
    }

    fn rebuild(&mut self, r: &ScanResult) {
        let keep = self
            .table
            .selected()
            .and_then(|i| self.order.get(i).copied());
        let terms = split_terms(&self.filter);
        let mut order: Vec<usize> = r
            .top_files
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                let hay = f.path.display().to_string().to_lowercase();
                terms.iter().all(|t| hay.contains(t.as_str()))
            })
            .map(|(i, _)| i)
            .collect();
        match self.sort {
            FileSort::Size => order.sort_by(|&a, &b| {
                r.top_files[b]
                    .allocated_bytes
                    .cmp(&r.top_files[a].allocated_bytes)
                    .then(a.cmp(&b))
            }),
            FileSort::Age => order.sort_by(|&a, &b| {
                r.top_files[a]
                    .mtime
                    .cmp(&r.top_files[b].mtime)
                    .then(a.cmp(&b))
            }),
            FileSort::Path => order.sort_by(|&a, &b| r.top_files[a].path.cmp(&r.top_files[b].path)),
        }
        self.order = order;
        let sel = keep
            .and_then(|k| self.order.iter().position(|&i| i == k))
            .or(if self.order.is_empty() { None } else { Some(0) });
        self.table.select(sel);
    }

    pub fn selected<'a>(&self, r: &'a ScanResult) -> Option<&'a crate::model::FileRecord> {
        self.table
            .selected()
            .and_then(|i| self.order.get(i))
            .and_then(|&i| r.top_files.get(i))
    }

    pub fn move_by(&mut self, delta: isize) {
        let n = clamp_move(self.table.selected(), self.order.len(), delta);
        self.table.select(n);
    }
}

pub const FACT_LIMIT: usize = 25;

/// The slices of the scan the Coverage view lists. Collected once per scan
/// (the pruned-path search is O(D)), never while rendering, and capped so a
/// scan with 100k permission errors cannot make a frame slow.
#[derive(Debug, Clone, Default)]
pub struct CoverageFacts {
    pub denied: Vec<PathBuf>,
    pub denied_total: usize,
    pub io: Vec<PathBuf>,
    pub io_total: usize,
    pub pruned: Vec<PathBuf>,
    pub pruned_total: usize,
}

impl CoverageFacts {
    pub fn collect(r: &ScanResult) -> Self {
        let mut f = Self::default();
        for issue in &r.issues {
            let (list, total) = match issue.kind {
                ScanIssueKind::PermissionDenied => (&mut f.denied, &mut f.denied_total),
                ScanIssueKind::Io => (&mut f.io, &mut f.io_total),
            };
            *total += 1;
            if list.len() < FACT_LIMIT {
                list.push(issue.path.clone());
            }
        }
        for id in r.index.ids() {
            if r.index.node(id).flags & flags::EXCLUDED != 0 {
                f.pruned_total += 1;
                if f.pruned.len() < FACT_LIMIT {
                    f.pruned.push(r.index.path(id));
                }
            }
        }
        f
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoverageState {
    pub scroll: u16,
    pub facts: CoverageFacts,
}

#[derive(Debug, Clone, Default)]
pub struct PoolsState {
    pub table: TableState,
    pub filter: String,
    /// Indices into `ScanResult::pools`.
    pub rows: Vec<usize>,
}

impl PoolsState {
    pub fn reset(&mut self, r: &ScanResult) {
        *self = Self::default();
        self.set_filter(r, "");
    }

    pub fn set_filter(&mut self, r: &ScanResult, filter: &str) {
        let keep = self
            .table
            .selected()
            .and_then(|i| self.rows.get(i).copied());
        self.filter = filter.trim().to_string();
        let terms = split_terms(&self.filter);
        self.rows = (0..r.pools.len())
            .filter(|&p| {
                if terms.is_empty() {
                    return true;
                }
                let mut hay = format!("{} {}", r.pools[p].label, r.pools[p].fstype);
                for f in r.filesystems.iter().filter(|f| f.pool == p) {
                    hay.push(' ');
                    hay.push_str(&f.mountpoint.display().to_string());
                }
                for b in r.mount_boundaries.iter().filter(|b| b.pool == p) {
                    hay.push(' ');
                    hay.push_str(&b.path.display().to_string());
                }
                let hay = hay.to_lowercase();
                terms.iter().all(|t| hay.contains(t.as_str()))
            })
            .collect();
        let sel = keep
            .and_then(|k| self.rows.iter().position(|&p| p == k))
            .or(if self.rows.is_empty() { None } else { Some(0) });
        self.table.select(sel);
    }

    pub fn selected_pool(&self) -> Option<usize> {
        self.table
            .selected()
            .and_then(|i| self.rows.get(i).copied())
    }

    pub fn move_by(&mut self, delta: isize) {
        let n = clamp_move(self.table.selected(), self.rows.len(), delta);
        self.table.select(n);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneTab {
    Temp,
    Home,
    Nix,
}

impl ZoneTab {
    pub const ALL: [ZoneTab; 3] = [ZoneTab::Temp, ZoneTab::Home, ZoneTab::Nix];

    pub fn title(self) -> &'static str {
        match self {
            ZoneTab::Temp => "Temporary",
            ZoneTab::Home => "Home",
            ZoneTab::Nix => "Nix",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct ZonesState {
    pub tab: ZoneTab,
    pub temp_sel: usize,
    pub home_sel: usize,
    pub scroll: u16,
}

impl Default for ZonesState {
    fn default() -> Self {
        Self {
            tab: ZoneTab::Temp,
            temp_sel: 0,
            home_sel: 0,
            scroll: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchState {
    pub input: Input,
    pub active: bool,
}

/// Where the last render put things, so mouse clicks can be mapped back to
/// rows and tabs. Written by widgets while drawing; read by the update logic.
#[derive(Debug, Clone, Default)]
pub struct LayoutCache {
    pub tabs: Vec<(Rect, View)>,
    pub list: Option<ListHit>,
}

#[derive(Debug, Clone, Copy)]
pub struct ListHit {
    /// Area of the first data row through the last visible row.
    pub rows_area: Rect,
    /// Index of the first visible row.
    pub offset: usize,
}

impl LayoutCache {
    pub fn row_at(&self, x: u16, y: u16) -> Option<usize> {
        let hit = self.list?;
        let a = hit.rows_area;
        if x >= a.x && x < a.x + a.width && y >= a.y && y < a.y + a.height {
            Some(hit.offset + (y - a.y) as usize)
        } else {
            None
        }
    }

    pub fn page_rows(&self) -> usize {
        self.list
            .map_or(10, |h| (h.rows_area.height as usize).max(1))
    }
}

#[derive(Debug)]
pub struct AppState {
    pub running: bool,
    pub view: View,

    pub root: PathBuf,
    pub scope_label: String,

    pub result: Option<Arc<ScanResult>>,
    pub analysis: Option<Arc<AnalysisResult>>,

    pub overview: OverviewState,
    pub findings: FindingsState,
    pub tree: TreeState,
    pub files: FilesState,
    pub coverage: CoverageState,
    pub pools: PoolsState,
    pub zones: ZonesState,

    pub search: SearchState,
    pub scan_status: ScanStatus,
    pub progress: Option<ProgressSnapshot>,
    pub scan_started: Option<Instant>,
    pub scan_secs: Option<f64>,

    pub help_open: bool,
    pub tick: u64,
    pub layout: LayoutCache,
    pub users: UserNames,
    pub message: Option<String>,
}

impl AppState {
    pub fn new(root: PathBuf, scope_label: String) -> Self {
        Self {
            running: true,
            view: View::Overview,
            root,
            scope_label,
            result: None,
            analysis: None,
            overview: OverviewState::default(),
            findings: FindingsState::default(),
            tree: TreeState::default(),
            files: FilesState::default(),
            coverage: CoverageState::default(),
            pools: PoolsState::default(),
            zones: ZonesState::default(),
            search: SearchState::default(),
            scan_status: ScanStatus::Idle,
            progress: None,
            scan_started: None,
            scan_secs: None,
            help_open: false,
            tick: 0,
            layout: LayoutCache::default(),
            users: UserNames::load(),
            message: None,
        }
    }

    pub fn input_mode(&self) -> InputMode {
        if self.search.active {
            InputMode::Search
        } else {
            InputMode::Normal
        }
    }

    /// Both results present: every data view can render.
    pub fn ready(&self) -> bool {
        self.result.is_some() && self.analysis.is_some()
    }

    // ---- scan lifecycle: every transition resets the state it invalidates ----

    /// A new scan starts: nothing from the previous one may survive.
    pub fn begin_scan(&mut self) {
        self.result = None;
        self.analysis = None;
        self.overview = OverviewState::default();
        self.findings = FindingsState::default();
        self.tree = TreeState::default();
        self.files = FilesState::default();
        self.coverage = CoverageState::default();
        self.pools = PoolsState::default();
        self.zones = ZonesState::default();
        self.search = SearchState::default();
        self.help_open = false;
        self.progress = None;
        self.message = None;
        self.scan_secs = None;
        self.scan_started = Some(Instant::now());
        self.scan_status = ScanStatus::Scanning;
    }

    pub fn scan_finished(&mut self, result: Arc<ScanResult>) {
        self.scan_secs = self.scan_started.map(|t| t.elapsed().as_secs_f64());
        self.tree.reset(&result);
        self.files.reset(&result);
        self.pools.reset(&result);
        self.overview.areas = result
            .top_level_directories()
            .into_iter()
            .take(50)
            .collect();
        self.coverage.facts = CoverageFacts::collect(&result);
        self.result = Some(result);
        self.scan_status = ScanStatus::Analyzing;
    }

    pub fn analysis_finished(&mut self, analysis: Arc<AnalysisResult>) {
        self.findings.reset(&analysis);
        self.analysis = Some(analysis);
        self.scan_status = ScanStatus::Ready;
    }

    pub fn scan_failed(&mut self, message: String) {
        self.result = None;
        self.analysis = None;
        self.scan_status = ScanStatus::Failed(message);
    }

    // ---- search ----

    pub fn filter_of(&self, view: View) -> &str {
        match view {
            View::Findings => &self.findings.filter,
            View::Tree => &self.tree.filter,
            View::Files => &self.files.filter,
            View::Pools => &self.pools.filter,
            _ => "",
        }
    }

    /// Apply `text` as the live filter of the current view.
    pub fn apply_filter(&mut self, text: &str) {
        let (Some(result), Some(analysis)) = (self.result.clone(), self.analysis.clone()) else {
            return;
        };
        match self.view {
            View::Findings => self.findings.refilter(&analysis, text),
            View::Tree => self.tree.set_filter(&result, text),
            View::Files => self.files.set_filter(&result, text),
            View::Pools => self.pools.set_filter(&result, text),
            _ => {}
        }
    }

    pub fn start_search(&mut self) {
        if !self.view.searchable() || !self.ready() {
            self.message = Some(format!("{} has no search", self.view.title()));
            return;
        }
        let current = self.filter_of(self.view).to_string();
        self.search.input = Input::new(current);
        self.search.active = true;
    }

    pub fn search_commit(&mut self) {
        self.search.active = false;
    }

    pub fn search_cancel(&mut self) {
        self.apply_filter("");
        self.search.input = Input::default();
        self.search.active = false;
    }
}
