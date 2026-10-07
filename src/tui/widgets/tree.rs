// SPDX-License-Identifier: GPL-3.0-only
//
// Directory tree. Rows come from the `TreeState` projection; only the rows that
// fit on screen are turned into widgets, so a tree with 100k visible rows costs
// the same to draw as one with 20.

use super::{kv, kv_plain, master_detail, panel, section};
use crate::analysis::Severity;
use crate::model::{AGE_LABELS, NO_ZONE, NodeId, ScanResult, flags};
use crate::tui::fmt;
use crate::tui::state::{AppState, ListHit};
use crate::tui::tree::TreeRow;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};

const RIGHT_COLS: usize = 10 + 1 + 5 + 1 + 6;

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let (Some(r), Some(a)) = (s.result.clone(), s.analysis.clone()) else {
        return;
    };
    let (list_area, detail_area) = master_detail(
        area,
        s.tree.detail_open,
        if s.tree.searching() {
            s.tree.matches.len()
        } else {
            s.tree.rows.len()
        },
    );
    let searching = s.tree.searching();

    let title = if searching {
        format!(
            "Tree search '{}': {} match{}",
            s.tree.filter,
            s.tree.matches.len(),
            if s.tree.matches.len() == 1 { "" } else { "es" }
        )
    } else {
        format!("Tree (sorted by {})", s.tree.sort.label())
    };
    let block = panel(title);
    let inner = block.inner(list_area);
    f.render_widget(block, list_area);

    let h = inner.height as usize;
    let w = inner.width as usize;
    let total = r.totals.allocated_bytes.max(1);

    let (len, selected) = if searching {
        (s.tree.matches.len(), s.tree.match_list.selected())
    } else {
        (s.tree.rows.len(), s.tree.list.selected())
    };

    if len == 0 {
        let msg = if searching {
            "No directory name matches. Esc clears the search."
        } else {
            "Nothing to show."
        };
        f.render_widget(Paragraph::new(Span::styled(msg, fmt::dim())), inner);
        return;
    }

    // Keep the selection on screen by adjusting the scroll offset ourselves.
    let list_state: &mut ListState = if searching {
        &mut s.tree.match_list
    } else {
        &mut s.tree.list
    };
    let sel = selected.unwrap_or(0).min(len - 1);
    let mut off = list_state.offset();
    if sel < off {
        off = sel;
    } else if h > 0 && sel >= off + h {
        off = sel + 1 - h;
    }
    off = off.min(len.saturating_sub(h));
    *list_state.offset_mut() = off;

    let end = (off + h).min(len);
    let items: Vec<ListItem> = if searching {
        s.tree.matches[off..end]
            .iter()
            .map(|&id| ListItem::new(match_line(&r, id, w, total)))
            .collect()
    } else {
        s.tree.rows[off..end]
            .iter()
            .map(|row| ListItem::new(row_line(&r, &a, row, w, total)))
            .collect()
    };
    let mut window = ListState::default().with_selected(Some(sel - off));
    f.render_stateful_widget(
        List::new(items).highlight_style(fmt::selected_row()),
        inner,
        &mut window,
    );
    s.layout.list = Some(ListHit {
        rows_area: inner,
        offset: off,
    });

    if let Some(d) = detail_area {
        let block = panel("Directory");
        let dinner = block.inner(d);
        f.render_widget(block, d);
        let lines = match s.tree.selected_node() {
            Some(id) => detail_lines(&r, &a, &s.users, id, dinner.width as usize),
            None => vec![Line::from(Span::styled("nothing selected", fmt::dim()))],
        };
        f.render_widget(Paragraph::new(lines), dinner);
    }
}

fn sev_cell(a: &crate::analysis::AnalysisResult, id: NodeId) -> Span<'static> {
    let score = a.node_score[id.idx()];
    if score <= 0.0 {
        return Span::raw("      ");
    }
    let sev = a.node_severity[id.idx()];
    let (dot, style) = match sev {
        Severity::Low => ("·", fmt::dim()),
        other => (
            "●",
            Style::new().fg(match other {
                Severity::Critical => Color::Red,
                Severity::High => Color::LightRed,
                _ => Color::Yellow,
            }),
        ),
    };
    Span::styled(format!("{dot}{score:>5.1}"), style)
}

fn row_line(
    r: &ScanResult,
    a: &crate::analysis::AnalysisResult,
    row: &TreeRow,
    width: usize,
    total: u64,
) -> Line<'static> {
    let n = r.index.node(row.node);
    let mut prefix = String::new();
    for d in 1..row.depth {
        let last_anc = d < 64 && row.guides & (1u64 << d) != 0;
        prefix.push_str(if last_anc { "   " } else { "│  " });
    }
    if row.depth > 0 {
        prefix.push_str(if row.last { "└─ " } else { "├─ " });
    }
    let marker = if !row.has_children {
        "  "
    } else if row.expanded {
        "▾ "
    } else {
        "▸ "
    };

    let mut name = if row.depth == 0 {
        r.index.path(row.node).display().to_string()
    } else {
        String::from_utf8_lossy(r.index.name(row.node)).into_owned()
    };
    let mut name_style = Style::new();
    if n.flags & (flags::EXCLUDED | flags::SKIPPED_MOUNT) != 0 {
        name_style = fmt::dim();
        name.push_str(if n.flags & flags::EXCLUDED != 0 {
            " (pruned)"
        } else {
            " (mount, not scanned)"
        });
    } else if n.flags & flags::DENIED != 0 {
        name_style = Style::new().fg(Color::Red);
        name.push_str(" (denied)");
    } else if row.has_children {
        name_style = Style::new().add_modifier(Modifier::BOLD);
    }
    let badges =
        fmt::node_badges(n.flags & !(flags::EXCLUDED | flags::SKIPPED_MOUNT | flags::DENIED));
    if !badges.is_empty() {
        name.push_str(&format!(" [{badges}]"));
    }

    let left_fixed = prefix.chars().count() + marker.chars().count();
    let name_w = width.saturating_sub(left_fixed + RIGHT_COLS + 1);
    let name = fmt::truncate_right(&name, name_w);
    let pad = name_w.saturating_sub(name.chars().count());

    Line::from(vec![
        Span::styled(prefix, fmt::dim()),
        Span::raw(marker),
        Span::styled(name, name_style),
        Span::raw(" ".repeat(pad + 1)),
        Span::raw(format!("{:>10} ", fmt::bytes(n.usage.bytes))),
        Span::styled(
            format!(
                "{:>5} ",
                fmt::percent(fmt::ratio_percent(n.usage.bytes, total))
            ),
            fmt::dim(),
        ),
        sev_cell(a, row.node),
    ])
}

fn match_line(r: &ScanResult, id: NodeId, width: usize, _total: u64) -> Line<'static> {
    let n = r.index.node(id);
    let path = fmt::truncate_left(
        &r.index.path(id).display().to_string(),
        width.saturating_sub(12),
    );
    Line::from(vec![
        Span::raw(format!("{:>10}  ", fmt::bytes(n.usage.bytes))),
        Span::raw(path),
    ])
}

fn detail_lines(
    r: &ScanResult,
    a: &crate::analysis::AnalysisResult,
    users: &crate::users::UserNames,
    id: NodeId,
    width: usize,
) -> Vec<Line<'static>> {
    let n = r.index.node(id);
    let mut l: Vec<Line> = Vec::new();
    for (i, part) in super::wrap(&r.index.path(id).display().to_string(), width)
        .into_iter()
        .enumerate()
    {
        l.push(Line::from(Span::styled(
            part,
            if i == 0 {
                Style::new().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            },
        )));
    }
    let fs = &r.filesystems[n.fs as usize];
    let pool = &r.pools[fs.pool];
    l.push(kv_plain(
        "Size",
        format!("{} (subtree)", fmt::bytes(n.usage.bytes)),
    ));
    if n.usage.fs_bytes != n.usage.bytes {
        l.push(kv_plain("On own fs", fmt::bytes(n.usage.fs_bytes)));
    }
    l.push(kv_plain("Filesystem", fmt::fs_name(fs)));
    l.push(kv_plain("Pool", fmt::pool_name(pool)));
    let score = a.node_score[id.idx()];
    l.push(kv(
        "Score",
        if score > 0.0 {
            vec![
                Span::raw(format!("{score:.1}  ")),
                Span::styled(
                    format!(" {} ", a.node_severity[id.idx()].label()),
                    fmt::severity_style(a.node_severity[id.idx()]),
                ),
            ]
        } else {
            vec![Span::styled(
                if id == r.root_node() {
                    "the scan root is never scored"
                } else {
                    "not scored (below the reporting size)"
                },
                fmt::dim(),
            )]
        },
    ));
    l.push(kv_plain("Class", n.class.label()));
    if n.zone != NO_ZONE
        && let Some(z) = r.zones.get(n.zone as usize)
    {
        l.push(kv_plain("Zone", format!("{:?} {}", z.role, z.label)));
    }
    l.push(kv_plain("Owner", users.name(n.uid)));
    l.push(kv_plain(
        "Newest",
        format!(
            "{} ({})",
            fmt::date(n.newest_mtime),
            fmt::ago(fmt::age_days(r.started_unix, n.newest_mtime))
        ),
    ));
    l.push(kv_plain(
        "Contents",
        format!(
            "{} files, {} dirs, {} links, {} errors",
            fmt::count(n.usage.counts.regular_files),
            fmt::count(n.usage.counts.directories),
            fmt::count(n.usage.counts.symlinks),
            fmt::count(n.usage.counts.errors)
        ),
    ));
    let names = fmt::flag_names(n.flags);
    if !names.is_empty() {
        l.push(kv_plain("Flags", names.join(", ")));
    }
    l.push(Line::raw(""));
    l.push(section("Age of data"));
    let total = n.usage.bytes.max(1);
    for (i, label) in AGE_LABELS.iter().enumerate() {
        l.push(Line::from(vec![
            Span::styled(format!("{label:<8}"), fmt::dim()),
            Span::styled(
                fmt::bar(n.usage.age[i] as f64 / total as f64, 14),
                Style::new().fg(Color::Cyan),
            ),
            Span::raw(format!(" {:>10}", fmt::bytes(n.usage.age[i]))),
        ]));
    }
    l
}
