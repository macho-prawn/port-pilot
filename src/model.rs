use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::path::Path;

pub const PLACEHOLDER: &str = "------";
pub const HIGH_MEMORY_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl Display for PortProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortOwnerKind {
    Process,
    HostUnknown,
    DockerPublished,
}

impl PortOwnerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::HostUnknown => "host_unknown",
            Self::DockerPublished => "docker_published",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRecord {
    pub port: u16,
    pub protocol: PortProtocol,
    pub pid: u32,
    pub owner_kind: PortOwnerKind,
    pub directory: String,
    pub framework: String,
    pub language: String,
    pub memory_human: String,
    pub memory_bytes: u64,
    pub uptime_human: String,
    pub uptime_seconds: u64,
    pub command: String,
    pub command_line: String,
    pub process_name: String,
    pub exe_path: String,
    pub bind_address: String,
    pub system_owned: bool,
}

impl PortRecord {
    pub fn sort_cmp(&self, other: &Self, sort: SortMode) -> Ordering {
        match sort {
            SortMode::Port => self
                .port
                .cmp(&other.port)
                .then(self.protocol.to_string().cmp(&other.protocol.to_string()))
                .then(self.pid.cmp(&other.pid)),
            SortMode::Memory => other
                .memory_bytes
                .cmp(&self.memory_bytes)
                .then(self.port.cmp(&other.port)),
            SortMode::Uptime => other
                .uptime_seconds
                .cmp(&self.uptime_seconds)
                .then(self.port.cmp(&other.port)),
            SortMode::Dir => self
                .dir_sort_key()
                .cmp(&other.dir_sort_key())
                .then(self.port.cmp(&other.port)),
        }
    }

    pub fn short_dir(&self) -> String {
        if self.directory == PLACEHOLDER {
            return PLACEHOLDER.to_string();
        }

        let path = Path::new(&self.directory);
        path.file_name()
            .and_then(|segment| segment.to_str())
            .filter(|segment| !segment.is_empty())
            .unwrap_or(&self.directory)
            .to_string()
    }

    pub fn port_label(&self) -> String {
        format!("{}", self.port)
    }

    pub fn dir_name(&self) -> String {
        self.short_dir()
    }

    pub fn dir_sort_key(&self) -> (bool, String) {
        let dir = self.dir_name();
        (dir == PLACEHOLDER, dir.to_ascii_lowercase())
    }

    pub fn pid_label(&self) -> String {
        if self.pid != 0 {
            self.pid.to_string()
        } else {
            PLACEHOLDER.to_string()
        }
    }

    pub fn is_killable(&self) -> bool {
        self.owner_kind == PortOwnerKind::Process && self.pid != 0
    }

    pub fn is_high_memory(&self) -> bool {
        self.memory_bytes >= HIGH_MEMORY_BYTES
    }

    pub fn is_system_process(&self) -> bool {
        self.system_owned
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortDetails {
    pub record: PortRecord,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillOutcome {
    pub pid: u32,
    pub port: u16,
    pub command: String,
    pub result: KillResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillResult {
    TerminatedGracefully,
    TerminatedForcefully,
    SignalNotSupported,
    PermissionDenied,
    NotFound,
    Failed(String),
}

impl Display for KillResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminatedGracefully => write!(f, "terminated"),
            Self::TerminatedForcefully => write!(f, "force-killed"),
            Self::SignalNotSupported => write!(f, "signal unsupported"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::NotFound => write!(f, "no longer running"),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillReport {
    pub outcomes: Vec<KillOutcome>,
    pub blocked_reason: Option<String>,
}

impl KillReport {
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    Port,
    Memory,
    Uptime,
    Dir,
}

impl SortMode {
    pub const ALL: [Self; 4] = [Self::Port, Self::Memory, Self::Uptime, Self::Dir];

    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }
}

impl Display for SortMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Port => write!(f, "port"),
            Self::Memory => write!(f, "memory"),
            Self::Uptime => write!(f, "uptime"),
            Self::Dir => write!(f, "dir"),
        }
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return PLACEHOLDER.to_string();
    }

    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx < UNITS.len() - 1 {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{value:.0}{}", UNITS[idx])
    } else {
        format!("{value:.1}{}", UNITS[idx])
    }
}

pub fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return PLACEHOLDER.to_string();
    }

    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

pub fn placeholder_if_empty(value: String) -> String {
    if value.trim().is_empty() {
        PLACEHOLDER.to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PLACEHOLDER, PortOwnerKind, PortProtocol, PortRecord, SortMode, format_bytes,
        format_duration,
    };

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), PLACEHOLDER);
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0MB");
    }

    #[test]
    fn formats_duration() {
        assert_eq!(format_duration(0), PLACEHOLDER);
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3_700), "1h 1m");
    }

    #[test]
    fn cycles_sort_modes() {
        assert_eq!(SortMode::Port.next(), SortMode::Memory);
        assert_eq!(SortMode::Dir.next(), SortMode::Port);
    }

    #[test]
    fn pid_label_hides_unknown_owner_rows() {
        let process = PortRecord {
            port: 3000,
            protocol: PortProtocol::Tcp,
            pid: 123,
            owner_kind: PortOwnerKind::Process,
            directory: PLACEHOLDER.to_string(),
            framework: PLACEHOLDER.to_string(),
            language: PLACEHOLDER.to_string(),
            memory_human: PLACEHOLDER.to_string(),
            memory_bytes: 0,
            uptime_human: PLACEHOLDER.to_string(),
            uptime_seconds: 0,
            command: "node".to_string(),
            command_line: "node".to_string(),
            process_name: "node".to_string(),
            exe_path: PLACEHOLDER.to_string(),
            bind_address: "127.0.0.1:3000".to_string(),
            system_owned: false,
        };
        let host_unknown = PortRecord {
            owner_kind: PortOwnerKind::HostUnknown,
            pid: 0,
            ..process.clone()
        };

        assert_eq!(process.pid_label(), "123");
        assert_eq!(host_unknown.pid_label(), PLACEHOLDER);
        assert!(process.is_killable());
        assert!(!host_unknown.is_killable());
    }

    #[test]
    fn dir_sort_key_places_placeholders_last() {
        let named = PortRecord {
            port: 3000,
            protocol: PortProtocol::Tcp,
            pid: 123,
            owner_kind: PortOwnerKind::Process,
            directory: "/tmp/live-chat".to_string(),
            framework: PLACEHOLDER.to_string(),
            language: PLACEHOLDER.to_string(),
            memory_human: PLACEHOLDER.to_string(),
            memory_bytes: 0,
            uptime_human: PLACEHOLDER.to_string(),
            uptime_seconds: 0,
            command: "node".to_string(),
            command_line: "node".to_string(),
            process_name: "node".to_string(),
            exe_path: PLACEHOLDER.to_string(),
            bind_address: "127.0.0.1:3000".to_string(),
            system_owned: false,
        };
        let placeholder = PortRecord {
            directory: PLACEHOLDER.to_string(),
            ..named.clone()
        };

        assert!(named.dir_sort_key() < placeholder.dir_sort_key());
        assert_eq!(named.dir_name(), "live-chat");
    }
}
