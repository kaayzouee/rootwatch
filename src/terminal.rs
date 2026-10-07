// SPDX-License-Identifier: GPL-3.0-only

use std::path::Path;

/// Escape terminal-control characters so untrusted text cannot inject terminal
/// control sequences when rendered in a CLI or TUI.
pub fn safe_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\x1b' => out.push_str("\\x1b"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:04x}}}", c as u32);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn safe_path(path: &Path) -> String {
    safe_text(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_controls() {
        assert_eq!(
            safe_text("ok\tesc\x1b[2J\nnext\r"),
            "ok\\tesc\\x1b[2J\\nnext\\r"
        );
        assert_eq!(safe_text("\u{0085}"), "\\u{0085}");
    }

    #[test]
    fn leaves_printable_text_unchanged() {
        assert_eq!(safe_text("/home/user/file.txt"), "/home/user/file.txt");
    }
}
