use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};

use crate::inspect::PortCollector;
use crate::model::{PLACEHOLDER, PortRecord, SortMode};

const SHORTCUTS: [(&str, &str); 12] = [
    ("Enter", "details"),
    ("/", "filter"),
    ("g", "jump"),
    ("s", "sort"),
    ("r", "refresh"),
    ("k", "kill"),
    ("b", "browse"),
    ("o", "open"),
    ("x", "curl"),
    ("p", "proto"),
    ("h", "help"),
    ("q", "quit"),
];
const NOTIFICATION_BANNER_REFRESHES: u8 = 3;
const NOTIFICATION_TOAST_HEIGHT: u16 = 3;
const NOTIFICATION_TOAST_MIN_WIDTH: u16 = 24;
const NOTIFICATION_TOAST_MAX_WIDTH: u16 = 56;
const NOTIFICATION_TOAST_MARGIN_X: u16 = 2;
const NOTIFICATION_TOAST_MARGIN_Y: u16 = 1;

pub fn run_app(collector: PortCollector, refresh_interval: Duration) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, collector, refresh_interval);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    collector: PortCollector,
    refresh_interval: Duration,
) -> Result<()> {
    let mut app = App::new(collector, refresh_interval);
    app.refresh()?;

    loop {
        terminal.draw(|frame| app.render(frame))?;

        let timeout = app
            .refresh_interval
            .checked_sub(app.last_refresh.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        if event::poll(timeout.min(Duration::from_millis(250)))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if !app.handle_key(key)? {
                break;
            }
        }

        if app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh()?;
        }
    }

    Ok(())
}

struct App {
    collector: PortCollector,
    rows: Vec<PortRecord>,
    table_state: TableState,
    sort_mode: SortMode,
    filter_input: String,
    filter_mode: bool,
    jump_mode: bool,
    jump_input: String,
    detail_open: bool,
    show_help: bool,
    show_protocol_footer: bool,
    refresh_interval: Duration,
    last_refresh: Instant,
    seen_listener_keys: BTreeSet<(u16, u32)>,
    has_loaded_once: bool,
    notification_banner: Option<NotificationBanner>,
    status: String,
}

struct NotificationBanner {
    message: String,
    refreshes_left: u8,
}

impl NotificationBanner {
    fn new(message: String) -> Self {
        Self {
            message,
            refreshes_left: NOTIFICATION_BANNER_REFRESHES,
        }
    }
}

impl App {
    fn new(collector: PortCollector, refresh_interval: Duration) -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            collector,
            rows: Vec::new(),
            table_state,
            sort_mode: SortMode::Port,
            filter_input: String::new(),
            filter_mode: false,
            jump_mode: false,
            jump_input: String::new(),
            detail_open: false,
            show_help: false,
            show_protocol_footer: true,
            refresh_interval,
            last_refresh: Instant::now(),
            seen_listener_keys: BTreeSet::new(),
            has_loaded_once: false,
            notification_banner: None,
            status: "Loaded. `h` shows shortcuts.".to_string(),
        }
    }

    fn refresh(&mut self) -> Result<()> {
        self.apply_rows(self.collector.collect()?);
        Ok(())
    }

    fn apply_rows(&mut self, mut rows: Vec<PortRecord>) {
        rows.sort_by(|left, right| left.sort_cmp(right, self.sort_mode));
        let listener_keys = listener_keys(&rows);
        let new_listeners = if self.has_loaded_once {
            listener_keys
                .difference(&self.seen_listener_keys)
                .copied()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        self.rows = rows;
        self.last_refresh = Instant::now();
        self.reselect();
        self.seen_listener_keys = listener_keys;
        self.has_loaded_once = true;

        if new_listeners.is_empty() {
            self.advance_notification_banner();
        } else {
            self.notification_banner = Some(NotificationBanner::new(
                self.notification_message(&new_listeners),
            ));
        }

        self.status = format!("Refreshed {} rows.", self.filtered_rows().len());
    }

    fn filtered_rows(&self) -> Vec<&PortRecord> {
        let filter = self.filter_input.trim().to_ascii_lowercase();
        let mut rows = self.rows.iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| left.sort_cmp(right, self.sort_mode));

        if filter.is_empty() {
            return rows;
        }

        rows.into_iter()
            .filter(|record| {
                let haystack = format!(
                    "{} {} {} {} {} {} {}",
                    record.port,
                    record.directory,
                    record.framework,
                    record.pid,
                    record.command,
                    record.language,
                    record.bind_address
                )
                .to_ascii_lowercase();
                haystack.contains(&filter)
            })
            .collect()
    }

    fn selected(&self) -> Option<&PortRecord> {
        let rows = self.filtered_rows();
        self.table_state
            .selected()
            .and_then(|index| rows.get(index).copied())
    }

    fn reselect(&mut self) {
        let len = self.filtered_rows().len();
        match (len, self.table_state.selected()) {
            (0, _) => self.table_state.select(None),
            (_, None) => self.table_state.select(Some(0)),
            (len, Some(index)) if index >= len => {
                self.table_state.select(Some(len.saturating_sub(1)))
            }
            _ => {}
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        if self.filter_mode {
            return Ok(self.handle_filter_key(key));
        }

        if self.jump_mode {
            return Ok(self.handle_jump_key(key));
        }

        match key.code {
            KeyCode::Char('q') => return Ok(false),
            KeyCode::Esc => {
                if self.detail_open {
                    self.detail_open = false;
                    self.status = "Closed details.".to_string();
                } else if self.show_help {
                    self.show_help = false;
                    self.status = "Closed help.".to_string();
                }
            }
            KeyCode::Down => self.move_selection(1),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Enter => self.detail_open = !self.detail_open,
            KeyCode::Char('/') => {
                self.filter_mode = true;
                self.status = "Filter mode. Type to filter rows, Enter to apply.".to_string();
            }
            KeyCode::Char('g') => {
                self.jump_mode = true;
                self.jump_input.clear();
                self.status = "Jump mode. Type a port number and press Enter.".to_string();
            }
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.reselect();
                self.status = format!("Sorting by {}.", self.sort_mode);
            }
            KeyCode::Char('r') => {
                self.refresh()?;
            }
            KeyCode::Char('h') => {
                self.show_help = !self.show_help;
            }
            KeyCode::Char('p') => {
                self.show_protocol_footer = !self.show_protocol_footer;
            }
            KeyCode::Char('k') => self.kill_selected()?,
            KeyCode::Char('o') => self.open_directory()?,
            KeyCode::Char('b') => self.open_browser()?,
            KeyCode::Char('x') => self.emit_snippet(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(false);
            }
            _ => {}
        }

        Ok(true)
    }

    fn handle_filter_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.filter_mode = false;
                self.status = "Filter cancelled.".to_string();
            }
            KeyCode::Enter => {
                self.filter_mode = false;
                self.reselect();
                self.status = format!("Filter applied: {}", self.filter_label());
            }
            KeyCode::Backspace => {
                self.filter_input.pop();
            }
            KeyCode::Char(character) => {
                self.filter_input.push(character);
                self.reselect();
            }
            _ => {}
        }
        true
    }

    fn handle_jump_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.jump_mode = false;
                self.jump_input.clear();
                self.status = "Jump cancelled.".to_string();
            }
            KeyCode::Enter => {
                self.jump_mode = false;
                if let Ok(port) = self.jump_input.parse::<u16>() {
                    if let Some(index) = self
                        .filtered_rows()
                        .iter()
                        .position(|record| record.port == port)
                    {
                        self.table_state.select(Some(index));
                        self.status = format!("Jumped to port {port}.");
                    } else {
                        self.status = format!("Port {port} is not in the current table.");
                    }
                } else {
                    self.status = "Jump expects a valid port number.".to_string();
                }
                self.jump_input.clear();
            }
            KeyCode::Backspace => {
                self.jump_input.pop();
            }
            KeyCode::Char(character) if character.is_ascii_digit() => {
                self.jump_input.push(character);
            }
            _ => {}
        }
        true
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_rows().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }

        let current = self.table_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len.saturating_sub(1) as isize) as usize;
        self.table_state.select(Some(next));
    }

    fn kill_selected(&mut self) -> Result<()> {
        let Some(selected) = self.selected() else {
            self.status = "No row selected.".to_string();
            return Ok(());
        };

        let report = self.collector.kill_port(selected.port)?;
        if let Some(reason) = report.blocked_reason {
            self.status = reason;
            return Ok(());
        }

        let status = if report.outcomes.is_empty() {
            format!("Nothing was listening on port {}.", selected.port)
        } else {
            format!("Kill issued for port {}.", selected.port)
        };
        self.refresh()?;
        self.status = status;
        Ok(())
    }

    fn open_directory(&mut self) -> Result<()> {
        let Some(selected) = self.selected() else {
            self.status = "No row selected.".to_string();
            return Ok(());
        };

        if selected.directory == PLACEHOLDER {
            self.status = "Selected process does not expose a working directory.".to_string();
            return Ok(());
        }

        open::that(&selected.directory)?;
        self.status = format!("Opened {}.", selected.directory);
        Ok(())
    }

    fn open_browser(&mut self) -> Result<()> {
        let Some(selected) = self.selected() else {
            self.status = "No row selected.".to_string();
            return Ok(());
        };

        let url = format!("http://127.0.0.1:{}", selected.port);
        open::that(&url)?;
        self.status = format!("Opened {url}.");
        Ok(())
    }

    fn emit_snippet(&mut self) {
        if let Some(selected) = self.selected() {
            self.status = format!(
                "Snippet: curl -i http://127.0.0.1:{}  # {}",
                selected.port, selected.command
            );
        }
    }

    fn filter_label(&self) -> &str {
        if self.filter_input.trim().is_empty() {
            "none"
        } else {
            self.filter_input.trim()
        }
    }

    fn notification_message(&self, new_listeners: &[(u16, u32)]) -> String {
        let mut matches = self
            .rows
            .iter()
            .filter(|record| new_listeners.contains(&(record.port, record.pid)))
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| left.port.cmp(&right.port).then(left.pid.cmp(&right.pid)));

        match matches.as_slice() {
            [record] => format!(
                "New listener: {} {} (pid {})",
                record.port, record.command, record.pid
            ),
            _ => format!(
                "New listeners: {} processes started listening.",
                matches.len()
            ),
        }
    }

    fn advance_notification_banner(&mut self) {
        let Some(notification) = self.notification_banner.as_mut() else {
            return;
        };

        if notification.refreshes_left > 1 {
            notification.refreshes_left -= 1;
        } else {
            self.notification_banner = None;
        }
    }

    fn notification_banner_message(&self) -> Option<&str> {
        self.notification_banner
            .as_ref()
            .map(|notification| notification.message.as_str())
    }

    fn render(&mut self, frame: &mut Frame) {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_header(frame, areas[0]);
        self.render_table(frame, areas[1]);
        self.render_footer(frame, areas[2]);
        self.render_notification_banner(frame, areas[1]);

        if self.detail_open {
            self.render_detail(frame);
        }
        if self.show_help {
            self.render_help(frame);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let rows = self.filtered_rows().len();
        let refresh_in = self
            .refresh_interval
            .saturating_sub(self.last_refresh.elapsed())
            .as_secs();
        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                "ports",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  live listener monitor"),
            Span::raw(format!("  rows: {rows}")),
            Span::raw(format!("  sort: {}", self.sort_mode)),
            Span::raw(format!("  filter: {}", self.filter_label())),
            Span::raw(format!("  interval: {}s", self.refresh_interval.as_secs())),
            Span::raw(format!("  refresh in: {refresh_in}s")),
        ]))
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, area);
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let rows = self.filtered_rows();
        let display_rows = rows.iter().map(|record| {
            Row::new(vec![
                Cell::from(record.port_label()).style(cell_style(record, false)),
                Cell::from(record.short_dir()).style(cell_style(record, false)),
                Cell::from(record.framework.clone()).style(cell_style(record, false)),
                Cell::from(record.language.clone()).style(cell_style(record, false)),
                Cell::from(record.pid_label()).style(cell_style(record, false)),
                Cell::from(record.memory_human.clone()).style(cell_style(record, true)),
                Cell::from(record.uptime_human.clone()).style(cell_style(record, false)),
                Cell::from(record.command.clone()).style(cell_style(record, true)),
            ])
            .style(row_style(record))
        });

        let table = Table::new(
            display_rows,
            [
                Constraint::Length(8),
                Constraint::Percentage(15),
                Constraint::Percentage(12),
                Constraint::Percentage(16),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Percentage(30),
            ],
        )
        .header(
            Row::new([
                "Port",
                "Dir",
                "Framework",
                "Language",
                "PID",
                "Mem",
                "Uptime",
                "Command",
            ])
            .style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .block(
            Block::default()
                .title("Listening Ports")
                .borders(Borders::ALL),
        );

        frame.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let footer_areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Length(1)])
            .split(area);
        let mut footer = self.status.clone();
        if self.show_protocol_footer
            && let Some(selected) = self.selected()
        {
            footer.push_str(&format!(
                "  [{} {} {}]",
                selected.protocol, selected.bind_address, selected.language
            ));
        }

        let paragraph = Paragraph::new(footer)
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(paragraph, footer_areas[0]);

        let shortcuts = Paragraph::new(shortcuts_text(footer_areas[1].width as usize))
            .alignment(Alignment::Left)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(shortcuts, footer_areas[1]);
    }

    fn render_notification_banner(&self, frame: &mut Frame, area: Rect) {
        let Some(message) = self.notification_banner_message() else {
            return;
        };
        let Some(rect) = notification_toast_rect(area, message) else {
            return;
        };

        frame.render_widget(Clear, rect);
        let banner = Paragraph::new(message)
            .alignment(Alignment::Left)
            .style(Style::default().fg(Color::White).bg(Color::Black))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::White)),
            );
        frame.render_widget(banner, rect);
    }

    fn render_detail(&self, frame: &mut Frame) {
        let area = centered_rect(70, 55, frame.area());
        frame.render_widget(Clear, area);
        let content = if let Some(selected) = self.selected() {
            vec![
                Line::from(vec![
                    Span::styled("Port ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{}", selected.port)),
                    Span::raw(format!(" ({})", selected.protocol)),
                ]),
                Line::from(format!("PID        {}", selected.pid_label())),
                Line::from(format!("Directory  {}", selected.directory)),
                Line::from(format!("Framework  {}", selected.framework)),
                Line::from(format!("Language   {}", selected.language)),
                Line::from(format!("Memory     {}", selected.memory_human)),
                Line::from(format!("Uptime     {}", selected.uptime_human)),
                Line::from(format!("Command    {}", selected.command)),
                Line::from(format!("Cmdline    {}", selected.command_line)),
                Line::from(format!("Address    {}", selected.bind_address)),
                Line::from(format!("Executable {}", selected.exe_path)),
                Line::from(""),
                Line::from(
                    "Actions: k kill, b open browser, o open directory, x show curl snippet",
                ),
            ]
        } else {
            vec![Line::from("No row selected.")]
        };

        let paragraph = Paragraph::new(content)
            .wrap(Wrap { trim: false })
            .block(Block::default().title("Port Details").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
    }

    fn render_help(&self, frame: &mut Frame) {
        let area = centered_rect(72, 65, frame.area());
        frame.render_widget(Clear, area);
        let help = Paragraph::new(vec![
            Line::from("Arrows      Move selection"),
            Line::from("Enter       Toggle detail view"),
            Line::from("/           Filter rows"),
            Line::from("g           Jump to a port"),
            Line::from("s           Cycle sort mode"),
            Line::from("r           Refresh now"),
            Line::from("k           Kill selected port"),
            Line::from("b           Open http://127.0.0.1:<port>"),
            Line::from("o           Open selected working directory"),
            Line::from("x           Show a curl snippet in the status bar"),
            Line::from("p           Toggle protocol/address footer"),
            Line::from("h           Toggle this help"),
            Line::from("Esc         Close overlays only"),
            Line::from("q / Ctrl-C  Quit"),
        ])
        .block(Block::default().title("Shortcuts").borders(Borders::ALL));
        frame.render_widget(help, area);
    }
}

fn centered_rect(horizontal: u16, vertical: u16, area: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - vertical) / 2),
            Constraint::Percentage(vertical),
            Constraint::Percentage((100 - vertical) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - horizontal) / 2),
            Constraint::Percentage(horizontal),
            Constraint::Percentage((100 - horizontal) / 2),
        ])
        .split(popup[1])[1]
}

fn shortcuts_text(width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let mut line = String::new();
    for (key, usage) in SHORTCUTS {
        let item = format!("{key} {usage}");
        let candidate = if line.is_empty() {
            item.clone()
        } else {
            format!("{line}  {item}")
        };

        if candidate.chars().count() <= width {
            line = candidate;
            continue;
        }

        if line.is_empty() {
            return truncate_text(&item, width);
        }

        return truncate_text(&line, width);
    }

    line
}

fn truncate_text(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".to_string();
    }

    let mut truncated = value.chars().take(width - 1).collect::<String>();
    truncated.push('…');
    truncated
}

fn notification_toast_rect(area: Rect, message: &str) -> Option<Rect> {
    if area.width <= NOTIFICATION_TOAST_MARGIN_X * 2
        || area.height <= NOTIFICATION_TOAST_MARGIN_Y + NOTIFICATION_TOAST_HEIGHT
    {
        return None;
    }

    let available_width = area.width.saturating_sub(NOTIFICATION_TOAST_MARGIN_X * 2);
    if available_width < NOTIFICATION_TOAST_MIN_WIDTH {
        return None;
    }

    let message_width = message.chars().count().saturating_add(4) as u16;
    let width = message_width
        .clamp(NOTIFICATION_TOAST_MIN_WIDTH, NOTIFICATION_TOAST_MAX_WIDTH)
        .min(available_width);
    let x = area.x + area.width - width - NOTIFICATION_TOAST_MARGIN_X;
    let y = area.y + area.height - NOTIFICATION_TOAST_HEIGHT - NOTIFICATION_TOAST_MARGIN_Y;

    Some(Rect::new(x, y, width, NOTIFICATION_TOAST_HEIGHT))
}

fn listener_keys(rows: &[PortRecord]) -> BTreeSet<(u16, u32)> {
    rows.iter()
        .filter(|record| record.pid != 0)
        .map(|record| (record.port, record.pid))
        .collect()
}

fn row_style(record: &PortRecord) -> Style {
    if record.is_system_process() {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default()
    }
}

fn cell_style(record: &PortRecord, emphasize_high_memory: bool) -> Style {
    if emphasize_high_memory && record.is_high_memory() {
        return Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    }

    if record.is_system_process() {
        return Style::default().add_modifier(Modifier::DIM);
    }

    Style::default()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::layout::Rect;

    use crate::cli::DEFAULT_INTERVAL_SECS;
    use crate::inspect::PortCollector;
    use crate::model::{PLACEHOLDER, PortOwnerKind};

    use super::{App, notification_toast_rect, shortcuts_text};

    #[test]
    fn filter_matches_rows() {
        let mut app = App::new(
            PortCollector::new(),
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
        );
        app.filter_input = "vite".to_string();
        app.rows = vec![crate::model::PortRecord {
            port: 3000,
            protocol: crate::model::PortProtocol::Tcp,
            pid: 1,
            owner_kind: PortOwnerKind::Process,
            directory: "/tmp/app".to_string(),
            framework: "Vite".to_string(),
            language: "JavaScript/TypeScript".to_string(),
            memory_human: "10MB".to_string(),
            memory_bytes: 10,
            uptime_human: "5m".to_string(),
            uptime_seconds: 300,
            command: "node server.js".to_string(),
            command_line: "node server.js".to_string(),
            process_name: "node".to_string(),
            exe_path: "/usr/bin/node".to_string(),
            bind_address: "127.0.0.1:3000".to_string(),
            system_owned: false,
        }];

        assert_eq!(app.filtered_rows().len(), 1);
    }

    #[test]
    fn filter_matches_language_column() {
        let mut app = App::new(
            PortCollector::new(),
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
        );
        app.filter_input = "python".to_string();
        app.rows = vec![crate::model::PortRecord {
            port: 8000,
            protocol: crate::model::PortProtocol::Tcp,
            pid: 1,
            owner_kind: PortOwnerKind::Process,
            directory: "/tmp/api".to_string(),
            framework: "FastAPI".to_string(),
            language: "Python".to_string(),
            memory_human: "10MB".to_string(),
            memory_bytes: 10,
            uptime_human: "5m".to_string(),
            uptime_seconds: 300,
            command: "uvicorn app.main:app".to_string(),
            command_line: "uvicorn app.main:app".to_string(),
            process_name: "uvicorn".to_string(),
            exe_path: "/usr/bin/python".to_string(),
            bind_address: "127.0.0.1:8000".to_string(),
            system_owned: false,
        }];

        assert_eq!(app.filtered_rows().len(), 1);
    }

    #[test]
    fn shortcuts_line_contains_key_word_pairs() {
        let line = shortcuts_text(200);
        assert!(line.contains("Enter details"));
        assert!(line.contains("/ filter"));
        assert!(line.contains("q quit"));
    }

    #[test]
    fn shortcuts_line_truncates_narrow_widths() {
        let line = shortcuts_text(18);
        assert!(!line.is_empty());
        assert!(line.chars().count() <= 18);
    }

    #[test]
    fn notification_toast_rect_anchors_to_lower_right() {
        let rect = notification_toast_rect(Rect::new(0, 3, 100, 20), "New listener: 1234 nc")
            .expect("toast rect");

        assert_eq!(rect.height, 3);
        assert_eq!(rect.y, 19);
        assert_eq!(rect.x + rect.width, 98);
    }

    #[test]
    fn notification_toast_rect_returns_none_for_narrow_areas() {
        assert_eq!(
            notification_toast_rect(Rect::new(0, 0, 10, 10), "New listener"),
            None
        );
    }

    #[test]
    fn esc_does_not_exit_main_table() {
        let mut app = App::new(
            PortCollector::new(),
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
        );
        let should_continue = app
            .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("esc should be handled");
        assert!(should_continue);
    }

    #[test]
    fn first_refresh_does_not_notify() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        assert_eq!(app.status, "Refreshed 1 rows.");
        assert_eq!(app.notification_banner_message(), None);
    }

    #[test]
    fn second_refresh_notifies_on_new_listener() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
        ]);

        assert_eq!(
            app.notification_banner_message(),
            Some("New listener: 8083 docker:live-chat-app (pid 222)")
        );
        assert_eq!(app.status, "Refreshed 2 rows.");
    }

    #[test]
    fn banner_persists_for_two_additional_refreshes() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        let rows = vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
        ];

        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(rows.clone());
        app.apply_rows(rows.clone());
        assert_eq!(
            app.notification_banner_message(),
            Some("New listener: 8083 docker:live-chat-app (pid 222)")
        );

        app.apply_rows(rows);
        assert_eq!(
            app.notification_banner_message(),
            Some("New listener: 8083 docker:live-chat-app (pid 222)")
        );
    }

    #[test]
    fn banner_clears_after_third_unchanged_refresh() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        let rows = vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
        ];

        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(rows.clone());
        app.apply_rows(rows.clone());
        app.apply_rows(rows.clone());
        app.apply_rows(rows);

        assert_eq!(app.notification_banner_message(), None);
        assert_eq!(app.status, "Refreshed 2 rows.");
    }

    #[test]
    fn unknown_owner_rows_do_not_notify() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            crate::model::PortRecord {
                port: 8083,
                protocol: crate::model::PortProtocol::Tcp,
                pid: 0,
                owner_kind: PortOwnerKind::HostUnknown,
                directory: PLACEHOLDER.to_string(),
                framework: PLACEHOLDER.to_string(),
                language: PLACEHOLDER.to_string(),
                memory_human: PLACEHOLDER.to_string(),
                memory_bytes: 0,
                uptime_human: PLACEHOLDER.to_string(),
                uptime_seconds: 0,
                command: "host-listener".to_string(),
                command_line: "ss".to_string(),
                process_name: "host-listener".to_string(),
                exe_path: PLACEHOLDER.to_string(),
                bind_address: "0.0.0.0:8083".to_string(),
                system_owned: false,
            },
        ]);

        assert_eq!(app.status, "Refreshed 2 rows.");
        assert_eq!(app.notification_banner_message(), None);
    }

    #[test]
    fn multiple_new_listeners_are_summarized() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
            sample_record(5432, 333, "/tmp/live-chat", "postgres"),
        ]);

        assert_eq!(
            app.notification_banner_message(),
            Some("New listeners: 2 processes started listening.")
        );
        assert_eq!(app.status, "Refreshed 3 rows.");
    }

    #[test]
    fn later_new_listener_replaces_existing_banner() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
        ]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
            sample_record(5432, 333, "/tmp/live-chat", "postgres"),
        ]);

        assert_eq!(
            app.notification_banner_message(),
            Some("New listener: 5432 postgres (pid 333)")
        );
    }

    #[test]
    fn status_updates_do_not_clear_active_banner() {
        let mut app = App::new(PortCollector::new(), Duration::from_secs(3));
        app.apply_rows(vec![sample_record(3000, 111, "/tmp/app", "node")]);
        app.apply_rows(vec![
            sample_record(3000, 111, "/tmp/app", "node"),
            sample_record(8083, 222, "/tmp/live-chat", "docker:live-chat-app"),
        ]);

        app.emit_snippet();

        assert!(
            app.status
                .starts_with("Snippet: curl -i http://127.0.0.1:3000")
        );
        assert_eq!(
            app.notification_banner_message(),
            Some("New listener: 8083 docker:live-chat-app (pid 222)")
        );
    }

    fn sample_record(
        port: u16,
        pid: u32,
        directory: &str,
        command: &str,
    ) -> crate::model::PortRecord {
        crate::model::PortRecord {
            port,
            protocol: crate::model::PortProtocol::Tcp,
            pid,
            owner_kind: PortOwnerKind::Process,
            directory: directory.to_string(),
            framework: "Vite".to_string(),
            language: "JavaScript/TypeScript".to_string(),
            memory_human: "10MB".to_string(),
            memory_bytes: 10,
            uptime_human: "5m".to_string(),
            uptime_seconds: 300,
            command: command.to_string(),
            command_line: command.to_string(),
            process_name: command.to_string(),
            exe_path: "/usr/bin/node".to_string(),
            bind_address: format!("127.0.0.1:{port}"),
            system_owned: false,
        }
    }
}
