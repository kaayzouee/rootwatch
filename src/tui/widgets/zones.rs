// SPDX-License-Identifier: GPL-3.0-only
//
// Specialised analysis: temporary data, home directories, Nix. These panels
// only present the reports the analysis engine already produced.

use super::{bullet, kv, kv_plain, panel, section, wrap};
use crate::home::HomeReport;
use crate::model::{AGE_BUCKETS, AGE_LABELS};
use crate::nix::{GcEstimate, NixReport};
use crate::temp::{TempAssessment, TempReport};
use crate::tui::fmt;
use crate::tui::state::{AppState, ZoneTab};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, s: &mut AppState) {
    let Some(a) = s.analysis.clone() else { return };
    let [tabs, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).areas(area);

    let mut spans = Vec::new();
    for t in ZoneTab::ALL {
        let n = match t {
            ZoneTab::Temp => a.temp.len(),
            ZoneTab::Home => a.home.len(),
            ZoneTab::Nix => usize::from(a.nix.is_some()),
        };
        let style = if t == s.zones.tab {
            Style::new()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        spans.push(Span::styled(format!(" {} ({n}) ", t.title()), style));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled("← → switch", fmt::dim()));
    f.render_widget(Paragraph::new(Line::from(spans)), tabs);

    match s.zones.tab {
        ZoneTab::Temp => {
            if a.temp.is_empty() {
                empty(
                    f,
                    body,
                    "Temporary data",
                    "No temporary zone (/tmp, /var/tmp) is inside this scan. They are analysed when the scan root contains them.",
                );
                return;
            }
            let sel = s.zones.temp_sel.min(a.temp.len() - 1);
            let items: Vec<(String, u64)> =
                a.temp.iter().map(|t| (t.label.clone(), t.bytes)).collect();
            let (list_area, detail) = split(body);
            list(f, list_area, "Zones", &items, sel);
            let lines = temp_lines(&a.temp[sel], detail.width as usize);
            detail_scroll(f, detail, "Temporary data", lines, &mut s.zones.scroll);
        }
        ZoneTab::Home => {
            if a.home.is_empty() {
                empty(
                    f,
                    body,
                    "Home",
                    "No home directory (/home/*, /root) is inside this scan. Scan / or the home directory itself.",
                );
                return;
            }
            let sel = s.zones.home_sel.min(a.home.len() - 1);
            let items: Vec<(String, u64)> =
                a.home.iter().map(|h| (h.label.clone(), h.bytes)).collect();
            let (list_area, detail) = split(body);
            list(f, list_area, "Homes", &items, sel);
            let lines = home_lines(&a.home[sel], detail.width as usize);
            detail_scroll(f, detail, "Home", lines, &mut s.zones.scroll);
        }
        ZoneTab::Nix => match &a.nix {
            None => empty(
                f,
                body,
                "Nix",
                "No Nix store found in this scan (scan / with the filesystem holding /nix, or use --scope all).",
            ),
            Some(n) => {
                let lines = nix_lines(n, body.width.saturating_sub(2) as usize);
                detail_scroll(f, body, "Nix", lines, &mut s.zones.scroll);
            }
        },
    }
}

fn split(body: Rect) -> (Rect, Rect) {
    let [l, d] = Layout::horizontal([Constraint::Length(28), Constraint::Min(30)]).areas(body);
    (l, d)
}

fn empty(f: &mut Frame, area: Rect, title: &str, msg: &str) {
    let b = panel(title);
    let i = b.inner(area);
    f.render_widget(b, area);
    let lines: Vec<Line> = wrap(msg, i.width as usize)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, fmt::dim())))
        .collect();
    f.render_widget(Paragraph::new(lines), i);
}

fn list(f: &mut Frame, area: Rect, title: &str, items: &[(String, u64)], sel: usize) {
    let b = panel(title);
    let i = b.inner(area);
    f.render_widget(b, area);
    let w = i.width as usize;
    let li: Vec<ListItem> = items
        .iter()
        .map(|(label, bytes)| {
            let size = fmt::bytes(*bytes);
            let lw = w.saturating_sub(size.chars().count() + 1);
            ListItem::new(format!("{:<lw$} {size}", fmt::truncate_left(label, lw)))
        })
        .collect();
    let mut st = ListState::default().with_selected(Some(sel));
    f.render_stateful_widget(
        List::new(li).highlight_style(fmt::selected_row()),
        i,
        &mut st,
    );
}

fn detail_scroll(
    f: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    scroll: &mut u16,
) {
    let b = panel(title);
    let i = b.inner(area);
    f.render_widget(b, area);
    let max = lines.len().saturating_sub(i.height as usize) as u16;
    *scroll = (*scroll).min(max);
    f.render_widget(Paragraph::new(lines).scroll((*scroll, 0)), i);
}

fn age_rows(age: &[u64; AGE_BUCKETS], total: u64) -> Vec<Line<'static>> {
    let t = total.max(1);
    (0..AGE_BUCKETS)
        .map(|i| {
            Line::from(vec![
                Span::styled(format!("{:<8}", AGE_LABELS[i]), fmt::dim()),
                Span::styled(
                    fmt::bar(age[i] as f64 / t as f64, 14),
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw(format!(
                    " {:>10} {:>5}",
                    fmt::bytes(age[i]),
                    fmt::percent(fmt::ratio_percent(age[i], t))
                )),
            ])
        })
        .collect()
}

pub fn temp_lines(t: &TempReport, width: usize) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    let (verdict, color) = match t.assessment {
        TempAssessment::Normal => ("normal", Color::Green),
        TempAssessment::Large => ("unusually large", Color::Yellow),
        TempAssessment::Stale => ("stale data", Color::LightRed),
        TempAssessment::LargeAndStale => ("unusually large and stale", Color::Red),
    };
    l.push(kv(
        "Assessment",
        vec![Span::styled(
            verdict,
            Style::new().fg(color).add_modifier(Modifier::BOLD),
        )],
    ));
    l.push(kv_plain(
        "Filesystem",
        format!(
            "{}{}",
            t.fstype,
            if t.ram_backed {
                " (RAM-backed: uses memory, cleared on reboot)"
            } else {
                ""
            }
        ),
    ));
    l.push(kv_plain(
        "Size",
        format!(
            "{} ({} of fs used)",
            fmt::bytes(t.bytes),
            fmt::percent(t.percent_of_fs_used)
        ),
    ));
    l.push(kv_plain(
        "Contents",
        format!("{} files, {} dirs", fmt::count(t.files), fmt::count(t.dirs)),
    ));
    l.push(kv_plain("Newest", fmt::age_label(t.newest_age_days)));
    l.push(kv_plain(
        "Stale",
        format!(
            "{} ({:.0}%) untouched for {}+ days",
            fmt::bytes(t.stale_bytes),
            t.stale_percent,
            t.stale_after_days
        ),
    ));
    l.push(Line::raw(""));
    l.push(section("By age"));
    l.extend(age_rows(&t.age, t.bytes));
    l.push(Line::raw(""));
    l.push(section("Owners"));
    for o in &t.owners {
        l.push(Line::from(format!(
            "{:<14}{:>10} {:>5}",
            fmt::truncate_right(&o.name, 13),
            fmt::bytes(o.bytes),
            fmt::percent(o.percent)
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Largest children"));
    for c in &t.top_children {
        l.push(Line::from(format!(
            "{:>10}  {}  (owner {}, changed {})",
            fmt::bytes(c.bytes),
            fmt::truncate_left(
                &c.path.display().to_string(),
                width.saturating_sub(40).max(10)
            ),
            c.owner,
            fmt::age_label(c.newest_age_days)
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Largest files"));
    for fr in t.top_files.iter().take(5) {
        l.push(Line::from(format!(
            "{:>10}  {}",
            fmt::bytes(fr.allocated_bytes),
            fmt::truncate_left(
                &fr.path.display().to_string(),
                width.saturating_sub(14).max(10)
            )
        )));
    }
    l
}

pub fn home_lines(h: &HomeReport, width: usize) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    l.push(kv_plain("Owner", h.owner_name.clone()));
    l.push(kv_plain(
        "Size",
        format!(
            "{} ({} of fs used)",
            fmt::bytes(h.bytes),
            fmt::percent(h.percent_of_fs_used)
        ),
    ));
    l.push(kv_plain(
        "Ownership",
        format!(
            "{} by {}, {} root-owned, {} other users",
            fmt::bytes(h.owned_by_user_bytes),
            h.owner_name,
            fmt::bytes(h.root_owned_bytes),
            fmt::bytes(h.other_owned_bytes)
        ),
    ));
    l.push(kv_plain("Loose files", fmt::bytes(h.loose_bytes)));
    l.push(Line::raw(""));
    l.push(section("By age"));
    l.extend(age_rows(&h.age, h.bytes));
    l.push(Line::raw(""));
    l.push(section("Where the space is"));
    for b in &h.buckets {
        l.push(Line::from(format!(
            "{:>10} {:>5}  {}  (stale >90d: {})",
            fmt::bytes(b.bytes),
            fmt::percent(b.percent_of_home),
            b.bucket.label(),
            fmt::bytes(b.stale_bytes)
        )));
        for (p, bytes) in b.top_children.iter().take(2) {
            l.push(Line::from(Span::styled(
                format!(
                    "    {:>10}  {}",
                    fmt::bytes(*bytes),
                    fmt::truncate_left(&p.display().to_string(), width.saturating_sub(18).max(10))
                ),
                fmt::dim(),
            )));
        }
    }
    l.push(Line::raw(""));
    l.push(section(&format!(
        "Projects ({} total, {} regenerable artifacts)",
        fmt::bytes(h.project_total_bytes),
        fmt::bytes(h.artifact_total_bytes)
    )));
    if h.projects.is_empty() {
        l.push(Line::from(Span::styled("none detected", fmt::dim())));
    }
    for p in &h.projects {
        let arts = if p.artifacts.is_empty() {
            String::new()
        } else {
            format!(
                " [{}]",
                p.artifacts
                    .iter()
                    .map(|(n, b)| format!("{} {}", fmt::safe_text(n), fmt::bytes(*b)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        l.push(Line::from(format!(
            "{:>10}  {} ({}){arts}",
            fmt::bytes(p.bytes),
            fmt::truncate_left(
                &p.path.display().to_string(),
                width.saturating_sub(34).max(10)
            ),
            p.kind.label()
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Largest files"));
    for fr in h.large_files.iter().take(5) {
        l.push(Line::from(format!(
            "{:>10}  {}",
            fmt::bytes(fr.allocated_bytes),
            fmt::truncate_left(
                &fr.path.display().to_string(),
                width.saturating_sub(14).max(10)
            )
        )));
    }
    l
}

pub fn nix_lines(n: &NixReport, width: usize) -> Vec<Line<'static>> {
    let mut l: Vec<Line> = Vec::new();
    l.push(kv_plain(
        "Store",
        format!(
            "{} in {} paths ({} of fs used)",
            fmt::bytes(n.store_bytes),
            fmt::count(n.store_paths as u64),
            fmt::percent(n.percent_of_fs_used)
        ),
    ));
    l.push(kv_plain(
        "Loose files",
        format!(
            "{} files, {}",
            fmt::count(n.loose_files),
            fmt::bytes(n.loose_bytes)
        ),
    ));
    l.push(kv_plain(
        "Database",
        n.db_bytes.map_or("not in scan".into(), fmt::bytes),
    ));
    l.push(kv_plain(
        "Profiles",
        n.profiles_bytes.map_or("not in scan".into(), fmt::bytes),
    ));

    // The three states must never be confused.
    let (gc_text, gc_style) = match &n.gc {
        GcEstimate::NotRequested => (
            "NOT QUERIED: start with --nix-gc to measure".to_string(),
            Style::new().fg(Color::Yellow),
        ),
        GcEstimate::Unavailable(why) => (
            format!("UNAVAILABLE: {why}"),
            Style::new().fg(Color::LightRed),
        ),
        GcEstimate::Estimated {
            bytes, dead_paths, ..
        } => (
            format!(
                "QUERIED: {} reclaimable ({} dead paths)",
                fmt::bytes(*bytes),
                fmt::count(*dead_paths as u64)
            ),
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
    };
    l.push(kv("GC estimate", vec![Span::styled(gc_text, gc_style)]));

    l.push(Line::raw(""));
    l.push(section("Generations"));
    if n.generations.is_empty() {
        l.push(Line::from(Span::styled(
            "no profile links found",
            fmt::dim(),
        )));
    }
    for g in &n.generations {
        l.push(Line::from(format!(
            "{:<18} {:>4} generations{}",
            fmt::safe_text(&g.profile),
            g.count,
            g.current
                .map_or(String::new(), |c| format!(", current #{c}"))
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Largest store paths"));
    for p in n.top_paths.iter().take(8) {
        l.push(Line::from(format!(
            "{:>10}  {}",
            fmt::bytes(p.bytes),
            fmt::truncate_right(&p.name, width.saturating_sub(13).max(10))
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Largest packages (all versions)"));
    for p in n.top_packages.iter().take(8) {
        l.push(Line::from(format!(
            "{:>10}  {} ({} path{})",
            fmt::bytes(p.bytes),
            fmt::safe_text(&p.name),
            p.versions,
            if p.versions == 1 { "" } else { "s" }
        )));
    }
    l.push(Line::raw(""));
    l.push(section("Why is it large?"));
    for e in &n.explanation {
        l.extend(bullet(e, width, Style::new()));
    }
    for sgst in &n.suggestions {
        l.extend(bullet(sgst, width, fmt::dim()));
    }
    l
}
