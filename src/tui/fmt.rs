// SPDX-License-Identifier: GPL-3.0-only
//
// Shared formatting and styling, so a value looks the same in every view.

use crate::analysis::{FindingKind, Severity, fmt_bytes};
use crate::coverage::{Completeness, ScanConfidence};
use crate::model::{FilesystemScan, StoragePool, flags};
use crate::terminal;
use ratatui::style::{Color, Modifier, Style};
use std::path::Path;

pub fn bytes(b: u64) -> String {
    fmt_bytes(b)
}

pub fn percent(p: f64) -> String {
    if p >= 100.0 {
        "100%".to_string()
    } else if p >= 10.0 {
        format!("{p:.0}%")
    } else {
        format!("{p:.1}%")
    }
}

pub fn ratio_percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

/// 284192 -> "284,192"
pub fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn duration_secs(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0} ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.1} s")
    } else {
        format!("{}m {:02}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    }
}

pub fn age_label(days: Option<u64>) -> String {
    match days {
        Some(0) => "today".into(),
        Some(1) => "1 day".into(),
        Some(d) if d < 365 => format!("{d} days"),
        Some(d) => format!("{:.1} yr", d as f64 / 365.0),
        None => "n/a".into(),
    }
}

/// "today", "3 days ago", "1.4 yr ago" (reads naturally inside a sentence).
pub fn ago(days: Option<u64>) -> String {
    match days {
        Some(0) => "today".into(),
        Some(1) => "1 day ago".into(),
        Some(d) if d < 365 => format!("{d} days ago"),
        Some(d) => format!("{:.1} yr ago", d as f64 / 365.0),
        None => "n/a".into(),
    }
}

pub fn age_days(now: i64, mtime: i64) -> Option<u64> {
    (mtime > 0).then(|| ((now - mtime).max(0) / 86_400) as u64)
}

/// Unix seconds -> "YYYY-MM-DD" (UTC), without a date library.
pub fn date(unix: i64) -> String {
    if unix <= 0 {
        return "n/a".into();
    }
    let days = unix.div_euclid(86_400);
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn kind_label(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Directory => "directory",
        FindingKind::Temporary => "temporary",
        FindingKind::Home => "home",
        FindingKind::Nix => "nix",
    }
}

pub fn safe_text(s: &str) -> String {
    terminal::safe_text(s)
}

pub fn safe_path(path: &Path) -> String {
    terminal::safe_path(path)
}

pub fn fs_name(fs: &FilesystemScan) -> String {
    format!("{} ({})", safe_path(&fs.mountpoint), safe_text(&fs.fstype))
}

pub fn pool_name(pool: &StoragePool) -> String {
    format!("{} ({})", safe_text(&pool.label), safe_text(&pool.fstype))
}

/// Keep the *end* of a path, which is the informative part.
pub fn truncate_left(s: &str, width: usize) -> String {
    let safe = safe_text(s);
    let n = safe.chars().count();
    if n <= width {
        safe
    } else if width <= 1 {
        "…".chars().take(width).collect()
    } else {
        let tail: String = safe.chars().skip(n - (width - 1)).collect();
        format!("…{tail}")
    }
}

pub fn truncate_right(s: &str, width: usize) -> String {
    let safe = safe_text(s);
    let n = safe.chars().count();
    if n <= width {
        safe
    } else if width <= 1 {
        "…".chars().take(width).collect()
    } else {
        let head: String = safe.chars().take(width - 1).collect();
        format!("{head}…")
    }
}

/// A fixed-width text bar, e.g. "██████░░░░".
pub fn bar(ratio: f64, width: usize) -> String {
    let filled = ((ratio.clamp(0.0, 1.0) * width as f64).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// Compact markers for a tree row: ! denied, ? unreadable, M mount root,
/// S skipped mount, x pruned, P project, b self-bind.
pub fn node_badges(node_flags: u16) -> String {
    let mut s = String::new();
    let table = [
        (flags::DENIED, '!'),
        (flags::UNREADABLE, '?'),
        (flags::MOUNT_ROOT, 'M'),
        (flags::SKIPPED_MOUNT, 'S'),
        (flags::EXCLUDED, 'x'),
        (flags::PROJECT, 'P'),
        (flags::SELF_BIND, 'b'),
    ];
    for (bit, ch) in table {
        if node_flags & bit != 0 {
            s.push(ch);
        }
    }
    s
}

pub fn flag_names(node_flags: u16) -> Vec<&'static str> {
    let table = [
        (flags::DENIED, "permission denied"),
        (flags::UNREADABLE, "unreadable (I/O error)"),
        (flags::MOUNT_ROOT, "mount root (filesystem entered)"),
        (flags::SKIPPED_MOUNT, "mount not scanned"),
        (flags::EXCLUDED, "pruned by rule"),
        (flags::PROJECT, "project root"),
        (flags::SELF_BIND, "self bind mount"),
    ];
    table
        .iter()
        .filter(|(bit, _)| node_flags & bit != 0)
        .map(|&(_, n)| n)
        .collect()
}

// ---- styles ----

pub fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new()
            .fg(Color::White)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD),
        Severity::High => Style::new()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
        Severity::Medium => Style::new().fg(Color::Yellow),
        Severity::Low => Style::new().fg(Color::Green),
    }
}

pub fn confidence_style(c: ScanConfidence) -> Style {
    match c {
        ScanConfidence::High => Style::new().fg(Color::Green),
        ScanConfidence::Medium => Style::new().fg(Color::Yellow),
        ScanConfidence::Low => Style::new()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn completeness_style(c: Completeness) -> Style {
    match c {
        Completeness::Complete => Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        Completeness::Substantial => Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        Completeness::Partial => Style::new()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
        Completeness::Minimal => Style::new()
            .fg(Color::White)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD),
    }
}

pub fn pressure_color(used_percent: f64) -> Color {
    if used_percent >= 95.0 {
        Color::Red
    } else if used_percent >= 90.0 {
        Color::LightRed
    } else if used_percent >= 80.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

pub fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

pub fn heading() -> Style {
    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

pub fn selected_row() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_get_thousands_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(284_192), "284,192");
        assert_eq!(count(1_234_567_890), "1,234,567,890");
    }

    #[test]
    fn dates_are_correct_utc() {
        assert_eq!(date(0), "n/a");
        assert_eq!(date(86_400), "1970-01-02");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_800_000_000), "2027-01-15");
    }

    #[test]
    fn truncation_keeps_the_informative_end() {
        assert_eq!(
            truncate_left("/home/kay/projects/rootwatch", 12),
            "…s/rootwatch"
        );
        assert_eq!(truncate_right("a\x1b[31msecret", 20), "a\\x1b[31msecret");
        assert!(!truncate_left("bad\npath", 20).contains('\n'));

        assert_eq!(
            truncate_left("/home/kay/projects/rootwatch", 12)
                .chars()
                .count(),
            12
        );
        assert_eq!(truncate_left("short", 12), "short");
        assert_eq!(truncate_right("abcdefghij", 5), "abcd…");
        assert_eq!(truncate_left("abc", 1), "…");
        assert_eq!(truncate_left("abc", 0), "");
    }

    #[test]
    fn bars_and_percent() {
        assert_eq!(bar(0.5, 10), "█████░░░░░");
        assert_eq!(bar(2.0, 4), "████");
        assert_eq!(bar(-1.0, 4), "░░░░");
        assert_eq!(percent(100.0), "100%");
        assert_eq!(percent(73.4), "73%");
        assert_eq!(percent(4.26), "4.3%");
    }

    #[test]
    fn badges_cover_mount_and_permission_states() {
        assert_eq!(node_badges(flags::DENIED | flags::PROJECT), "!P");
        assert_eq!(node_badges(0), "");
        assert!(flag_names(flags::SKIPPED_MOUNT).contains(&"mount not scanned"));
    }

    #[test]
    fn ago_reads_naturally_in_a_sentence() {
        assert_eq!(ago(Some(0)), "today");
        assert_eq!(ago(Some(1)), "1 day ago");
        assert_eq!(ago(Some(30)), "30 days ago");
        assert_eq!(ago(Some(730)), "2.0 yr ago");
        assert_eq!(ago(None), "n/a");
        // regression: "(today ago)"
        assert!(!format!("({})", ago(Some(0))).contains("today ago"));
    }

    #[test]
    fn durations() {
        assert_eq!(duration_secs(0.25), "250 ms");
        assert_eq!(duration_secs(2.34), "2.3 s");
        assert_eq!(duration_secs(125.0), "2m 05s");
    }
}
