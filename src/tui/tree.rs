// SPDX-License-Identifier: GPL-3.0-only
//
// Tree view model. The tree on screen is a *projection*: a flat list of rows
// derived from the immutable `DirectoryIndex` plus the set of expanded nodes.
// Nothing here mutates the index, and nothing touches the filesystem
//
// Costs: rebuilding the projection is O(rows shown + children of expanded
// nodes) (children are sorted per expanded node only); name search is O(D)
// with an allocation-free ASCII case-insensitive comparison and a bounded
// top-K for the result list

use crate::model::{DirectoryIndex, NodeId, ScanResult};
use crate::topk::TopK;
use ratatui::widgets::ListState;
use std::collections::HashSet;

pub const MAX_SEARCH_RESULTS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeSort {
    Size,
    Name,
}

impl TreeSort {
    pub fn next(self) -> Self {
        match self {
            Self::Size => Self::Name,
            Self::Name => Self::Size,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Name => "name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeRow {
    pub node: NodeId,
    /// Depth relative to the scan root (the root is 0).
    pub depth: usize,
    pub expanded: bool,
    pub has_children: bool,
    /// Last child of its parent (draws `└─` instead of `├─`).
    pub last: bool,
    /// Bit `d` set: the ancestor at depth `d` was a last child, so no `│`
    /// guide is drawn in that column.
    pub guides: u64,
}

fn sorted_children(index: &DirectoryIndex, node: NodeId, sort: TreeSort) -> Vec<NodeId> {
    let mut kids: Vec<NodeId> = index.children(node).collect();
    match sort {
        TreeSort::Size => kids.sort_unstable_by(|&a, &b| {
            index
                .node(b)
                .usage
                .bytes
                .cmp(&index.node(a).usage.bytes)
                .then_with(|| index.name(a).cmp(index.name(b)))
        }),
        TreeSort::Name => kids.sort_unstable_by(|&a, &b| index.name(a).cmp(index.name(b))),
    }
    kids
}

/// Flatten the visible part of the tree below `root`.
pub fn project(
    index: &DirectoryIndex,
    root: NodeId,
    expanded: &HashSet<NodeId>,
    sort: TreeSort,
) -> Vec<TreeRow> {
    let mut rows = Vec::new();
    // (node, depth, last, guides)
    let mut stack: Vec<(NodeId, usize, bool, u64)> = vec![(root, 0, true, 0)];
    while let Some((node, depth, last, guides)) = stack.pop() {
        let has_children = !index.node(node).first_child.is_none();
        let is_expanded = has_children && expanded.contains(&node);
        rows.push(TreeRow {
            node,
            depth,
            expanded: is_expanded,
            has_children,
            last,
            guides,
        });
        if is_expanded {
            let kids = sorted_children(index, node, sort);
            let child_guides = if last && depth < 63 && depth > 0 {
                guides | (1u64 << depth)
            } else {
                guides
            };
            let n = kids.len();
            for (i, &k) in kids.iter().enumerate().rev() {
                stack.push((k, depth + 1, i + 1 == n, child_guides));
            }
        }
    }
    rows
}

/// Case-insensitive ASCII substring test without allocating.
/// `needle` must already be lowercase.
pub fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle)
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

#[derive(Debug, Clone)]
pub struct TreeState {
    pub cursor: NodeId,
    pub expanded: HashSet<NodeId>,
    pub rows: Vec<TreeRow>,
    /// Selection and scroll offset of the browse list.
    pub list: ListState,
    pub sort: TreeSort,
    /// Active name search; non-empty switches the view to a flat result list.
    pub filter: String,
    pub matches: Vec<NodeId>,
    pub match_list: ListState,
    /// Detail pane for the selected directory.
    pub detail_open: bool,
}

impl Default for TreeState {
    fn default() -> Self {
        Self {
            cursor: NodeId::NONE,
            expanded: HashSet::new(),
            rows: Vec::new(),
            list: ListState::default(),
            sort: TreeSort::Size,
            filter: String::new(),
            matches: Vec::new(),
            match_list: ListState::default(),
            detail_open: false,
        }
    }
}

impl TreeState {
    pub fn searching(&self) -> bool {
        !self.filter.is_empty()
    }

    /// Fresh state for a new scan: root expanded, cursor on the root.
    pub fn reset(&mut self, result: &ScanResult) {
        *self = Self::default();
        let root = result.root_node();
        self.cursor = root;
        self.expanded.insert(root);
        self.rebuild(result);
    }

    /// Recompute the projection and keep the cursor on a visible row.
    pub fn rebuild(&mut self, result: &ScanResult) {
        let index = &result.index;
        if index.is_empty() {
            self.rows.clear();
            self.list.select(None);
            return;
        }
        self.rows = project(index, result.root_node(), &self.expanded, self.sort);
        self.sync_cursor(index);
    }

    /// If the cursor's node is no longer visible (an ancestor collapsed), move
    /// to its nearest visible ancestor. The selection can never dangle.
    fn sync_cursor(&mut self, index: &DirectoryIndex) {
        let visible: HashSet<NodeId> = self.rows.iter().map(|r| r.node).collect();
        let mut cur = self.cursor;
        while !cur.is_none() && !visible.contains(&cur) {
            cur = index.node(cur).parent;
        }
        if cur.is_none() {
            cur = self.rows.first().map_or(NodeId::NONE, |r| r.node);
        }
        self.cursor = cur;
        let idx = self.rows.iter().position(|r| r.node == cur);
        self.list.select(idx);
    }

    pub fn selected_index(&self) -> Option<usize> {
        if self.searching() {
            self.match_list.selected()
        } else {
            self.list.selected()
        }
    }

    pub fn selected_node(&self) -> Option<NodeId> {
        if self.searching() {
            self.match_list
                .selected()
                .and_then(|i| self.matches.get(i).copied())
        } else {
            self.list
                .selected()
                .and_then(|i| self.rows.get(i))
                .map(|r| r.node)
        }
    }

    fn len(&self) -> usize {
        if self.searching() {
            self.matches.len()
        } else {
            self.rows.len()
        }
    }

    pub fn select_index(&mut self, i: usize) {
        let len = self.len();
        if len == 0 {
            return;
        }
        let i = i.min(len - 1);
        if self.searching() {
            self.match_list.select(Some(i));
        } else {
            self.list.select(Some(i));
            self.cursor = self.rows[i].node;
        }
    }

    pub fn move_by(&mut self, delta: isize) {
        let len = self.len();
        if len == 0 {
            return;
        }
        let cur = self.selected_index().unwrap_or(0) as isize;
        self.select_index((cur + delta).clamp(0, len as isize - 1) as usize);
    }

    pub fn top(&mut self) {
        self.select_index(0);
    }

    pub fn bottom(&mut self) {
        let len = self.len();
        if len > 0 {
            self.select_index(len - 1);
        }
    }

    pub fn expand(&mut self, result: &ScanResult) {
        if self.searching() {
            return;
        }
        if let Some(row) = self.list.selected().and_then(|i| self.rows.get(i))
            && row.has_children
            && !row.expanded
        {
            self.expanded.insert(row.node);
            self.rebuild(result);
        }
    }

    pub fn collapse(&mut self, result: &ScanResult) {
        if self.searching() {
            return;
        }
        if let Some(row) = self.list.selected().and_then(|i| self.rows.get(i))
            && row.expanded
        {
            self.expanded.remove(&row.node);
            self.rebuild(result);
        }
    }

    pub fn toggle(&mut self, result: &ScanResult) {
        if let Some(row) = self.list.selected().and_then(|i| self.rows.get(i)) {
            if row.expanded {
                self.collapse(result);
            } else {
                self.expand(result);
            }
        }
    }

    /// Right / `l`: expand a collapsed directory, or step into an expanded one.
    pub fn right(&mut self, result: &ScanResult) {
        if self.searching() {
            return;
        }
        let Some(i) = self.list.selected() else {
            return;
        };
        let Some(row) = self.rows.get(i) else { return };
        if !row.has_children {
            return;
        }
        if row.expanded {
            self.select_index(i + 1);
        } else {
            self.expand(result);
        }
    }

    /// Left / `h`: collapse an expanded directory, otherwise go to the parent.
    pub fn left(&mut self, result: &ScanResult) {
        if self.searching() {
            return;
        }
        let Some(i) = self.list.selected() else {
            return;
        };
        let Some(row) = self.rows.get(i) else { return };
        if row.expanded {
            self.collapse(result);
            return;
        }
        let parent = result.index.node(row.node).parent;
        if let Some(p) = self.rows.iter().position(|r| r.node == parent) {
            self.select_index(p);
        }
    }

    /// Make `node` visible (expanding its ancestors) and put the cursor on it.
    pub fn reveal(&mut self, result: &ScanResult, node: NodeId) {
        let mut cur = result.index.node(node).parent;
        while !cur.is_none() {
            self.expanded.insert(cur);
            cur = result.index.node(cur).parent;
        }
        self.filter.clear();
        self.matches.clear();
        self.cursor = node;
        self.rebuild(result);
    }

    pub fn toggle_sort(&mut self, result: &ScanResult) {
        self.sort = self.sort.next();
        self.rebuild(result);
    }

    /// Live name search. An empty filter leaves search mode.
    pub fn set_filter(&mut self, result: &ScanResult, filter: &str) {
        let needle = filter.trim().to_ascii_lowercase();
        self.filter = needle.clone();
        self.matches.clear();
        if needle.is_empty() {
            self.match_list.select(None);
            self.sync_cursor(&result.index);
            return;
        }
        let nb = needle.as_bytes();
        let mut best = TopK::new(MAX_SEARCH_RESULTS);
        for id in result.index.ids() {
            if contains_ascii_ci(result.index.name(id), nb) {
                best.push((result.index.node(id).usage.bytes, u64::from(id.0)), id);
            }
        }
        self.matches = best.into_sorted_desc();
        self.match_list.select(if self.matches.is_empty() {
            None
        } else {
            Some(0)
        });
    }

    /// Enter on a search result: leave search and show that node in the tree.
    pub fn jump_to_selected_match(&mut self, result: &ScanResult) -> bool {
        match self.selected_node() {
            Some(n) if self.searching() => {
                self.reveal(result, n);
                true
            }
            _ => false,
        }
    }
}
