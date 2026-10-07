// SPDX-License-Identifier: GPL-3.0-only
//
// Semantic commands. Raw key events are interpreted here and nowhere else:
// widgets and view logic only ever see a `Command`, so key bindings can change
// without touching a single widget.

use super::state::View;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tui_input::InputRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Quit,
    NextTab,
    PreviousTab,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Enter,
    Back,
    Search,
    /// Redraw (Ctrl-L). Never touches the filesystem.
    Refresh,
    Top,
    Bottom,
    Expand,
    Collapse,
    Rescan,
    Help,
    /// Cycle the sort order of the current view.
    Sort,
    GoTo(View),
    None,
}

/// Which component currently owns the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    /// The `/` prompt is open: printable keys edit the query.
    Search,
}

pub fn map_key(key: KeyEvent, mode: InputMode) -> Command {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    // Ctrl-C always quits, in every mode: raw mode swallows SIGINT.
    if ctrl && key.code == KeyCode::Char('c') {
        return Command::Quit;
    }

    if mode == InputMode::Search {
        return match key.code {
            KeyCode::Esc => Command::Back,
            KeyCode::Enter => Command::Enter,
            // Cursor keys the prompt does not use stay navigable.
            KeyCode::Up => Command::Up,
            KeyCode::Down => Command::Down,
            KeyCode::PageUp => Command::PageUp,
            KeyCode::PageDown => Command::PageDown,
            KeyCode::Tab => Command::NextTab,
            KeyCode::BackTab => Command::PreviousTab,
            _ => Command::None,
        };
    }

    if alt {
        return Command::None;
    }
    if ctrl {
        return match key.code {
            KeyCode::Char('l') => Command::Refresh,
            KeyCode::Char('d') => Command::PageDown,
            KeyCode::Char('u') => Command::PageUp,
            _ => Command::None,
        };
    }

    match key.code {
        KeyCode::Char('q') => Command::Quit,
        KeyCode::Esc => Command::Back,
        KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => Command::PreviousTab,
        KeyCode::Tab => Command::NextTab,
        KeyCode::BackTab => Command::PreviousTab,
        KeyCode::Up | KeyCode::Char('k') => Command::Up,
        KeyCode::Down | KeyCode::Char('j') => Command::Down,
        KeyCode::Left | KeyCode::Char('h') => Command::Left,
        KeyCode::Right | KeyCode::Char('l') => Command::Right,
        KeyCode::PageUp => Command::PageUp,
        KeyCode::PageDown => Command::PageDown,
        KeyCode::Enter => Command::Enter,
        KeyCode::Char('/') => Command::Search,
        KeyCode::Char('r') => Command::Rescan,
        KeyCode::Char('g') | KeyCode::Home => Command::Top,
        KeyCode::Char('G') | KeyCode::End => Command::Bottom,
        KeyCode::Char(' ') | KeyCode::Char('+') | KeyCode::Char('=') => Command::Expand,
        KeyCode::Char('-') => Command::Collapse,
        KeyCode::Char('?') => Command::Help,
        KeyCode::Char('s') => Command::Sort,
        KeyCode::Char(c @ '1'..='7') => Command::GoTo(View::ALL[(c as usize) - ('1' as usize)]),
        _ => Command::None,
    }
}

/// Line-editing requests for the search prompt (used only in search mode).
pub fn input_request(key: KeyEvent) -> Option<InputRequest> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('a') if ctrl => Some(InputRequest::GoToStart),
        KeyCode::Char('e') if ctrl => Some(InputRequest::GoToEnd),
        KeyCode::Char('w') if ctrl => Some(InputRequest::DeletePrevWord),
        KeyCode::Char('u') if ctrl => Some(InputRequest::DeleteLine),
        KeyCode::Char('k') if ctrl => Some(InputRequest::DeleteTillEnd),
        KeyCode::Char('b') if alt => Some(InputRequest::GoToPrevWord),
        KeyCode::Char('f') if alt => Some(InputRequest::GoToNextWord),
        KeyCode::Char(c) if !ctrl && !alt => Some(InputRequest::InsertChar(c)),
        KeyCode::Backspace if ctrl || alt => Some(InputRequest::DeletePrevWord),
        KeyCode::Backspace => Some(InputRequest::DeletePrevChar),
        KeyCode::Delete => Some(InputRequest::DeleteNextChar),
        KeyCode::Left if ctrl || alt => Some(InputRequest::GoToPrevWord),
        KeyCode::Right if ctrl || alt => Some(InputRequest::GoToNextWord),
        KeyCode::Left => Some(InputRequest::GoToPrevChar),
        KeyCode::Right => Some(InputRequest::GoToNextChar),
        KeyCode::Home => Some(InputRequest::GoToStart),
        KeyCode::End => Some(InputRequest::GoToEnd),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn m(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }
    fn n(code: KeyCode) -> Command {
        map_key(k(code), InputMode::Normal)
    }

    #[test]
    fn vim_and_arrow_navigation() {
        assert_eq!(n(KeyCode::Char('j')), Command::Down);
        assert_eq!(n(KeyCode::Down), Command::Down);
        assert_eq!(n(KeyCode::Char('k')), Command::Up);
        assert_eq!(n(KeyCode::Up), Command::Up);
        assert_eq!(n(KeyCode::Char('h')), Command::Left);
        assert_eq!(n(KeyCode::Left), Command::Left);
        assert_eq!(n(KeyCode::Char('l')), Command::Right);
        assert_eq!(n(KeyCode::Right), Command::Right);
        assert_eq!(n(KeyCode::PageUp), Command::PageUp);
        assert_eq!(n(KeyCode::PageDown), Command::PageDown);
    }

    #[test]
    fn jump_open_back_search_rescan_quit() {
        assert_eq!(n(KeyCode::Char('g')), Command::Top);
        assert_eq!(n(KeyCode::Home), Command::Top);
        assert_eq!(n(KeyCode::Char('G')), Command::Bottom);
        assert_eq!(
            map_key(
                m(KeyCode::Char('G'), KeyModifiers::SHIFT),
                InputMode::Normal
            ),
            Command::Bottom
        );
        assert_eq!(n(KeyCode::End), Command::Bottom);
        assert_eq!(n(KeyCode::Enter), Command::Enter);
        assert_eq!(n(KeyCode::Esc), Command::Back);
        assert_eq!(n(KeyCode::Char('/')), Command::Search);
        assert_eq!(n(KeyCode::Char('r')), Command::Rescan);
        assert_eq!(n(KeyCode::Char('q')), Command::Quit);
        assert_eq!(n(KeyCode::Char('?')), Command::Help);
        assert_eq!(n(KeyCode::Char('s')), Command::Sort);
    }

    #[test]
    fn tab_and_shift_tab() {
        assert_eq!(n(KeyCode::Tab), Command::NextTab);
        assert_eq!(n(KeyCode::BackTab), Command::PreviousTab);
        assert_eq!(
            map_key(m(KeyCode::Tab, KeyModifiers::SHIFT), InputMode::Normal),
            Command::PreviousTab
        );
        assert_eq!(
            map_key(m(KeyCode::BackTab, KeyModifiers::SHIFT), InputMode::Normal),
            Command::PreviousTab
        );
    }

    #[test]
    fn expand_collapse_keys() {
        assert_eq!(n(KeyCode::Char(' ')), Command::Expand);
        assert_eq!(n(KeyCode::Char('+')), Command::Expand);
        assert_eq!(n(KeyCode::Char('-')), Command::Collapse);
    }

    #[test]
    fn number_keys_jump_to_views() {
        assert_eq!(n(KeyCode::Char('1')), Command::GoTo(View::Overview));
        assert_eq!(n(KeyCode::Char('3')), Command::GoTo(View::Tree));
        assert_eq!(n(KeyCode::Char('7')), Command::GoTo(View::Zones));
        assert_eq!(n(KeyCode::Char('8')), Command::None);
        assert_eq!(n(KeyCode::Char('0')), Command::None);
    }

    #[test]
    fn ctrl_c_quits_in_every_mode() {
        let cc = m(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map_key(cc, InputMode::Normal), Command::Quit);
        assert_eq!(map_key(cc, InputMode::Search), Command::Quit);
    }

    #[test]
    fn modifiers_do_not_trigger_plain_bindings() {
        // Ctrl-q, Alt-j, Ctrl-r must not act like q, j, r.
        assert_eq!(
            map_key(
                m(KeyCode::Char('q'), KeyModifiers::CONTROL),
                InputMode::Normal
            ),
            Command::None
        );
        assert_eq!(
            map_key(m(KeyCode::Char('j'), KeyModifiers::ALT), InputMode::Normal),
            Command::None
        );
        assert_eq!(
            map_key(
                m(KeyCode::Char('r'), KeyModifiers::CONTROL),
                InputMode::Normal
            ),
            Command::None
        );
        assert_eq!(
            map_key(
                m(KeyCode::Char('l'), KeyModifiers::CONTROL),
                InputMode::Normal
            ),
            Command::Refresh
        );
        assert_eq!(
            map_key(
                m(KeyCode::Char('d'), KeyModifiers::CONTROL),
                InputMode::Normal
            ),
            Command::PageDown
        );
        assert_eq!(
            map_key(
                m(KeyCode::Char('u'), KeyModifiers::CONTROL),
                InputMode::Normal
            ),
            Command::PageUp
        );
    }

    #[test]
    fn search_mode_only_exposes_control_keys() {
        let s = |c| map_key(k(c), InputMode::Search);
        assert_eq!(s(KeyCode::Esc), Command::Back);
        assert_eq!(s(KeyCode::Enter), Command::Enter);
        assert_eq!(s(KeyCode::Down), Command::Down);
        // letters that are commands in normal mode must be typed text here
        for c in ['q', 'j', 'k', 'r', 's', '/', '1', '?', 'g', 'G'] {
            assert_eq!(s(KeyCode::Char(c)), Command::None, "{c}");
            assert_eq!(
                input_request(k(KeyCode::Char(c))),
                Some(InputRequest::InsertChar(c))
            );
        }
    }

    #[test]
    fn prompt_editing_requests() {
        assert_eq!(
            input_request(k(KeyCode::Backspace)),
            Some(InputRequest::DeletePrevChar)
        );
        assert_eq!(
            input_request(k(KeyCode::Delete)),
            Some(InputRequest::DeleteNextChar)
        );
        assert_eq!(
            input_request(k(KeyCode::Left)),
            Some(InputRequest::GoToPrevChar)
        );
        assert_eq!(
            input_request(m(KeyCode::Char('u'), KeyModifiers::CONTROL)),
            Some(InputRequest::DeleteLine)
        );
        assert_eq!(
            input_request(m(KeyCode::Char('w'), KeyModifiers::CONTROL)),
            Some(InputRequest::DeletePrevWord)
        );
        assert_eq!(input_request(k(KeyCode::F(5))), None);
        assert_eq!(
            input_request(m(KeyCode::Char('x'), KeyModifiers::CONTROL)),
            None
        );
    }

    #[test]
    fn unknown_keys_do_nothing() {
        assert_eq!(n(KeyCode::F(1)), Command::None);
        assert_eq!(n(KeyCode::Char('z')), Command::None);
    }
}
