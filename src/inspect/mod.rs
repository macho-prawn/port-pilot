use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde_json::Value;
use sysinfo::{Pid, Signal, System};

use crate::model::{
    KillOutcome, KillReport, KillResult, PLACEHOLDER, PortDetails, PortOwnerKind, PortProtocol,
    PortRecord, format_bytes, format_duration, placeholder_if_empty,
};

pub struct PortCollector;

impl PortCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self) -> Result<Vec<PortRecord>> {
        Ok(self
            .collect_details()?
            .into_iter()
            .map(|detail| detail.record)
            .collect())
    }

    pub fn collect_port(&self, port: u16) -> Result<Vec<PortDetails>> {
        let mut details = self.collect_details()?;
        details.retain(|detail| detail.record.port == port);
        details.sort_by(|left, right| {
            left.record
                .port
                .cmp(&right.record.port)
                .then(left.record.pid.cmp(&right.record.pid))
        });
        Ok(details)
    }

    pub fn kill_port(&self, port: u16) -> Result<KillReport> {
        let details = self.collect_port(port)?;
        let targets = details
            .iter()
            .filter(|detail| detail.record.is_killable())
            .map(|detail| (detail.record.pid, detail.record.command.clone()))
            .collect::<BTreeSet<_>>();

        if targets.is_empty() {
            let blocked_reason = (!details.is_empty()).then(|| {
                format!("Port {port} is in use but is not tied to a killable local process.")
            });
            return Ok(KillReport {
                outcomes: Vec::new(),
                blocked_reason,
            });
        }

        let mut outcomes = Vec::new();
        for (pid_raw, command) in targets {
            outcomes.push(KillOutcome {
                pid: pid_raw,
                port,
                command,
                result: terminate_process(pid_raw),
            });
        }

        Ok(KillReport {
            outcomes,
            blocked_reason: None,
        })
    }

    fn collect_details(&self) -> Result<Vec<PortDetails>> {
        let listeners = discover_listeners()?;
        let mut system = System::new_all();
        system.refresh_all();

        let mut grouped: BTreeMap<
            (u16, PortProtocol, u32, PortOwnerKind, String, String),
            AggregateRecord,
        > = BTreeMap::new();

        for listener in listeners {
            let address = listener.address;
            let port = listener.port;
            let pid = listener.pid;
            let protocol = listener.protocol;
            let owner_kind = listener.owner_kind;
            let process_name = listener.process_name;
            let command = listener.command;
            let command_line = listener.command_line;
            let directory = listener.directory;
            let framework = listener.framework;
            let language = listener.language;
            let exe_path = listener.exe_path;
            let key = (
                port,
                protocol,
                pid,
                owner_kind,
                process_name.clone(),
                command.clone(),
            );

            grouped
                .entry(key)
                .and_modify(|entry| entry.addresses.push(address.clone()))
                .or_insert_with(|| AggregateRecord {
                    port,
                    protocol,
                    pid,
                    owner_kind,
                    process_name,
                    command,
                    command_line,
                    directory,
                    framework,
                    language,
                    exe_path,
                    addresses: vec![address],
                });
        }

        let mut details = grouped
            .into_values()
            .map(|aggregate| build_details(aggregate, &system))
            .collect::<Vec<_>>();
        details.sort_by(|left, right| {
            left.record
                .port
                .cmp(&right.record.port)
                .then(left.record.pid.cmp(&right.record.pid))
                .then(left.record.command.cmp(&right.record.command))
        });

        Ok(details)
    }
}

#[derive(Debug)]
struct AggregateRecord {
    port: u16,
    protocol: PortProtocol,
    pid: u32,
    owner_kind: PortOwnerKind,
    process_name: String,
    command: String,
    command_line: String,
    directory: String,
    framework: String,
    language: String,
    exe_path: String,
    addresses: Vec<String>,
}

#[derive(Debug, Clone)]
struct DiscoveredListener {
    pid: u32,
    owner_kind: PortOwnerKind,
    process_name: String,
    command: String,
    command_line: String,
    directory: String,
    framework: String,
    language: String,
    exe_path: String,
    address: String,
    port: u16,
    protocol: PortProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerPublishedPort {
    container_name: String,
    host_ip: String,
    host_port: u16,
    container_port: u16,
    protocol: PortProtocol,
    pid: u32,
    process_name: String,
    command: String,
    command_line: String,
    directory: String,
    framework: String,
    language: String,
    exe_path: String,
}

#[derive(Debug, Clone)]
struct RuntimeMetadata {
    process_name: String,
    command: String,
    command_line: String,
    directory: String,
    framework: String,
    language: String,
    exe_path: String,
}

fn build_details(aggregate: AggregateRecord, system: &System) -> PortDetails {
    let bind_address = join_addresses(&aggregate.addresses, aggregate.port);
    let pid = Pid::from_u32(aggregate.pid);
    let process = (aggregate.pid != 0).then(|| system.process(pid)).flatten();
    let (
        directory,
        framework,
        language,
        memory_human,
        memory_bytes,
        uptime_human,
        uptime_seconds,
        command,
        command_line,
        exe_path,
    ) = if aggregate.owner_kind == PortOwnerKind::Process {
        let cwd = resolve_cwd(process);
        let exe_path = process
            .and_then(|proc_| proc_.exe())
            .map(path_to_string)
            .unwrap_or_else(|| PLACEHOLDER.to_string());
        let command_line = process
            .map(command_line)
            .unwrap_or_else(|| aggregate.command_line.clone());
        let command = process
            .map(command_summary)
            .filter(|summary| summary != PLACEHOLDER)
            .unwrap_or_else(|| placeholder_if_empty(aggregate.command.clone()));
        let memory_bytes = process.map(|proc_| proc_.memory()).unwrap_or(0);
        let uptime_seconds = process.map(|proc_| proc_.run_time()).unwrap_or(0);
        let identity = detect_identity(
            cwd.as_deref(),
            exe_path.as_str(),
            command_line.as_str(),
            aggregate.process_name.as_str(),
        );

        (
            cwd.unwrap_or_else(|| PLACEHOLDER.to_string()),
            identity.framework,
            identity.language,
            format_bytes(memory_bytes),
            memory_bytes,
            format_duration(uptime_seconds),
            uptime_seconds,
            command,
            command_line,
            exe_path,
        )
    } else {
        let runtime_directory = resolve_cwd(process);
        let runtime_exe_path = process
            .and_then(|proc_| proc_.exe())
            .map(path_to_string)
            .unwrap_or_else(|| PLACEHOLDER.to_string());
        let runtime_command_line = process
            .map(command_line)
            .unwrap_or_else(|| PLACEHOLDER.to_string());
        let runtime_command = process
            .map(command_summary)
            .filter(|summary| summary != PLACEHOLDER)
            .unwrap_or_else(|| PLACEHOLDER.to_string());
        let runtime_memory_bytes = process.map(|proc_| proc_.memory()).unwrap_or(0);
        let runtime_uptime_seconds = process.map(|proc_| proc_.run_time()).unwrap_or(0);
        let detection_directory = if aggregate.directory == PLACEHOLDER {
            runtime_directory.as_deref()
        } else {
            Some(aggregate.directory.as_str())
        };
        let detection_exe = if aggregate.exe_path == PLACEHOLDER {
            runtime_exe_path.as_str()
        } else {
            aggregate.exe_path.as_str()
        };
        let detection_command_line = if matches!(
            aggregate.command_line.as_str(),
            PLACEHOLDER | "ss" | "netstat"
        ) {
            runtime_command_line.as_str()
        } else {
            aggregate.command_line.as_str()
        };
        let detection_process_name = if matches!(
            aggregate.process_name.as_str(),
            PLACEHOLDER | "host-listener"
        ) {
            runtime_command.as_str()
        } else {
            aggregate.process_name.as_str()
        };
        let identity = detect_identity(
            detection_directory,
            detection_exe,
            detection_command_line,
            detection_process_name,
        );

        (
            if aggregate.directory == PLACEHOLDER {
                runtime_directory.unwrap_or_else(|| PLACEHOLDER.to_string())
            } else {
                placeholder_if_empty(aggregate.directory.clone())
            },
            if aggregate.framework == PLACEHOLDER {
                identity.framework
            } else {
                placeholder_if_empty(aggregate.framework.clone())
            },
            if aggregate.language == PLACEHOLDER {
                identity.language
            } else {
                placeholder_if_empty(aggregate.language.clone())
            },
            format_bytes(runtime_memory_bytes),
            runtime_memory_bytes,
            format_duration(runtime_uptime_seconds),
            runtime_uptime_seconds,
            if matches!(aggregate.command.as_str(), PLACEHOLDER | "host-listener") {
                placeholder_if_empty(runtime_command)
            } else {
                placeholder_if_empty(aggregate.command.clone())
            },
            if matches!(
                aggregate.command_line.as_str(),
                PLACEHOLDER | "ss" | "netstat"
            ) {
                placeholder_if_empty(runtime_command_line)
            } else {
                placeholder_if_empty(aggregate.command_line.clone())
            },
            if aggregate.exe_path == PLACEHOLDER {
                placeholder_if_empty(runtime_exe_path)
            } else {
                placeholder_if_empty(aggregate.exe_path.clone())
            },
        )
    };

    PortDetails {
        record: PortRecord {
            port: aggregate.port,
            protocol: aggregate.protocol,
            pid: aggregate.pid,
            owner_kind: aggregate.owner_kind,
            directory,
            framework,
            language,
            memory_human,
            memory_bytes,
            uptime_human,
            uptime_seconds,
            command,
            command_line,
            process_name: placeholder_if_empty(aggregate.process_name),
            exe_path,
            bind_address,
            system_owned: is_system_owned(aggregate.pid, process),
        },
        addresses: aggregate.addresses,
    }
}

fn resolve_cwd(process: Option<&sysinfo::Process>) -> Option<String> {
    let cwd = process
        .and_then(|proc_| proc_.cwd())
        .map(path_to_string)
        .filter(|value| value != PLACEHOLDER);
    if cwd.is_some() {
        return cwd;
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(proc_) = process {
            if let Some(path) = linux_proc_cwd(proc_.pid().as_u32()) {
                return Some(path);
            }
        }
    }

    process
        .and_then(|proc_| proc_.exe())
        .and_then(Path::parent)
        .map(path_to_string)
}

fn is_system_owned(_pid: u32, process: Option<&sysinfo::Process>) -> bool {
    #[cfg(unix)]
    {
        return process
            .and_then(|proc_| proc_.effective_user_id().or_else(|| proc_.user_id()))
            .map(|uid| uid.to_string() == "0")
            .unwrap_or(false);
    }

    #[cfg(windows)]
    {
        let _ = process;
        return matches!(_pid, 0 | 4);
    }

    #[allow(unreachable_code)]
    {
        let _ = _pid;
        let _ = process;
        false
    }
}

fn command_summary(process: &sysinfo::Process) -> String {
    let exe_name = process
        .exe()
        .and_then(Path::file_name)
        .and_then(|segment| segment.to_str())
        .map(str::to_owned);
    let argv = process
        .cmd()
        .iter()
        .map(os_to_string)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if !argv.is_empty() {
        let mut summary = argv.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
        if summary.len() > 48 {
            summary.truncate(45);
            summary.push_str("...");
        }
        return placeholder_if_empty(summary);
    }

    if let Some(exe_name) = exe_name {
        return exe_name;
    }

    placeholder_if_empty(process.name().to_string_lossy().into_owned())
}

fn command_line(process: &sysinfo::Process) -> String {
    let joined = process
        .cmd()
        .iter()
        .map(os_to_string)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !joined.is_empty() {
        return joined;
    }

    process
        .exe()
        .map(path_to_string)
        .unwrap_or_else(|| PLACEHOLDER.to_string())
}

fn os_to_string(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn join_addresses(addresses: &[String], port: u16) -> String {
    if addresses.is_empty() {
        return PLACEHOLDER.to_string();
    }

    let mut unique = addresses
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    unique.sort();

    match unique.as_slice() {
        [single] => format!("{single}:{port}"),
        [first, rest @ ..] => format!("{first}:{port} (+{})", rest.len()),
        [] => PLACEHOLDER.to_string(),
    }
}

fn parse_socket(socket: &str) -> Option<(String, u16)> {
    let trimmed = socket.trim();
    let (address, port) = trimmed.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let address = address
        .split("->")
        .next()
        .unwrap_or(address)
        .trim_matches(['[', ']'])
        .to_string();
    Some((address, port))
}

fn discover_listeners() -> Result<Vec<DiscoveredListener>> {
    let process_result = discover_process_listeners();
    let fallback_result = discover_host_fallback_listeners();

    let primary = process_result.as_ref().ok().cloned().unwrap_or_default();
    let mut fallback = fallback_result.as_ref().ok().cloned().unwrap_or_default();
    enrich_docker_fallback_listeners(&mut fallback);

    let listeners = merge_discovered_listeners(primary, fallback);
    if !listeners.is_empty() {
        return Ok(listeners);
    }

    match (process_result, fallback_result) {
        (Err(process_err), Err(fallback_err)) => Err(anyhow!(
            "failed to enumerate listening sockets: {process_err}; fallback failed: {fallback_err}"
        )),
        _ => Ok(Vec::new()),
    }
}

fn discover_process_listeners() -> Result<Vec<DiscoveredListener>> {
    match listeners::get_all() {
        Ok(found) => Ok(found
            .into_iter()
            .map(|listener| {
                let process_name = placeholder_if_empty(listener.process.name);
                DiscoveredListener {
                    pid: listener.process.pid,
                    owner_kind: PortOwnerKind::Process,
                    process_name: process_name.clone(),
                    command: process_name.clone(),
                    command_line: process_name,
                    directory: PLACEHOLDER.to_string(),
                    framework: PLACEHOLDER.to_string(),
                    language: PLACEHOLDER.to_string(),
                    exe_path: PLACEHOLDER.to_string(),
                    address: listener.socket.ip().to_string(),
                    port: listener.socket.port(),
                    protocol: PortProtocol::Tcp,
                }
            })
            .collect()),
        #[cfg(unix)]
        Err(_err) => discover_with_lsof(),
        #[cfg(not(unix))]
        Err(err) => Err(anyhow!("listeners backend failed: {err}")),
    }
}

fn merge_discovered_listeners(
    primary: Vec<DiscoveredListener>,
    fallback: Vec<DiscoveredListener>,
) -> Vec<DiscoveredListener> {
    let mut merged = primary.clone();
    let mut deduped_fallback: BTreeMap<(u16, PortProtocol, String), DiscoveredListener> =
        BTreeMap::new();

    for listener in fallback {
        let key = (
            listener.port,
            listener.protocol,
            listener_merge_address_key(&listener.address),
        );
        if primary.iter().any(|candidate| {
            candidate.port == listener.port
                && candidate.protocol == listener.protocol
                && candidate.pid == listener.pid
                && listener_addresses_match(&candidate.address, &listener.address)
        }) {
            continue;
        }

        match deduped_fallback.get(&key) {
            Some(existing) if listener_precedence(existing) >= listener_precedence(&listener) => {}
            _ => {
                deduped_fallback.insert(key, listener);
            }
        }
    }

    merged.extend(deduped_fallback.into_values());
    merged
}

fn listener_precedence(listener: &DiscoveredListener) -> u8 {
    match listener.owner_kind {
        PortOwnerKind::Process => 3,
        PortOwnerKind::DockerPublished => 2,
        PortOwnerKind::HostUnknown => 1,
    }
}

fn listener_addresses_match(left: &str, right: &str) -> bool {
    listener_merge_address_key(left) == listener_merge_address_key(right)
}

fn listener_merge_address_key(address: &str) -> String {
    let normalized = normalize_host_address(address);
    if is_wildcard_address(&normalized) {
        "*".to_string()
    } else {
        normalized
    }
}

#[cfg(unix)]
fn discover_with_lsof() -> Result<Vec<DiscoveredListener>> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"])
        .output()
        .map_err(|err| anyhow!("failed to run lsof fallback: {err}"))?;

    if !output.status.success() && !output.stdout.is_empty() {
        return Err(anyhow!(
            "lsof fallback exited with status {}",
            output.status
        ));
    }

    Ok(parse_lsof_output(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(unix)]
fn parse_lsof_output(stdout: &str) -> Vec<DiscoveredListener> {
    let mut listeners = Vec::new();
    let mut current_pid = None;
    let mut current_command = None;

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }

        let (field, value) = line.split_at(1);
        match field {
            "p" => current_pid = value.parse::<u32>().ok(),
            "c" => current_command = Some(placeholder_if_empty(value.to_string())),
            "n" => {
                if let (Some(pid), Some(process_name)) = (current_pid, current_command.clone())
                    && let Some((address, port)) = parse_socket(value)
                {
                    listeners.push(DiscoveredListener {
                        pid,
                        owner_kind: PortOwnerKind::Process,
                        process_name: process_name.clone(),
                        command: process_name.clone(),
                        command_line: process_name,
                        directory: PLACEHOLDER.to_string(),
                        framework: PLACEHOLDER.to_string(),
                        language: PLACEHOLDER.to_string(),
                        exe_path: PLACEHOLDER.to_string(),
                        address,
                        port,
                        protocol: PortProtocol::Tcp,
                    });
                }
            }
            _ => {}
        }
    }

    listeners
}

fn discover_host_fallback_listeners() -> Result<Vec<DiscoveredListener>> {
    #[cfg(unix)]
    {
        return discover_with_ss();
    }

    #[cfg(windows)]
    {
        return discover_with_netstat();
    }

    #[allow(unreachable_code)]
    Ok(Vec::new())
}

#[cfg(unix)]
fn discover_with_ss() -> Result<Vec<DiscoveredListener>> {
    let output = Command::new("ss")
        .args(["-ltnp"])
        .output()
        .map_err(|err| anyhow!("failed to run ss fallback: {err}"))?;

    if !output.status.success() {
        return Err(anyhow!("ss fallback exited with status {}", output.status));
    }

    Ok(parse_ss_output(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(windows)]
fn discover_with_netstat() -> Result<Vec<DiscoveredListener>> {
    let output = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .map_err(|err| anyhow!("failed to run netstat fallback: {err}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "netstat fallback exited with status {}",
            output.status
        ));
    }

    Ok(parse_netstat_output(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg_attr(not(unix), allow(dead_code))]
fn parse_ss_output(stdout: &str) -> Vec<DiscoveredListener> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("State") {
                return None;
            }

            let columns = trimmed.split_whitespace().collect::<Vec<_>>();
            let local_socket = columns.get(3)?;
            let (address, port) = parse_socket(local_socket)?;
            let process_field = columns.get(5).copied().unwrap_or_default();
            let pid = parse_ss_pid(process_field).unwrap_or(0);
            let process_name = parse_ss_process_name(process_field)
                .unwrap_or("host-listener")
                .to_string();
            let command_line = if process_name == "host-listener" {
                "ss".to_string()
            } else {
                process_name.clone()
            };

            Some(DiscoveredListener {
                pid,
                owner_kind: PortOwnerKind::HostUnknown,
                process_name: process_name.clone(),
                command: process_name,
                command_line,
                directory: PLACEHOLDER.to_string(),
                framework: PLACEHOLDER.to_string(),
                language: PLACEHOLDER.to_string(),
                exe_path: PLACEHOLDER.to_string(),
                address,
                port,
                protocol: PortProtocol::Tcp,
            })
        })
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_netstat_output(stdout: &str) -> Vec<DiscoveredListener> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.starts_with("TCP") {
                return None;
            }

            let columns = trimmed.split_whitespace().collect::<Vec<_>>();
            if columns.get(3).copied() != Some("LISTENING") {
                return None;
            }

            let local_socket = columns.get(1)?;
            let (address, port) = parse_socket(local_socket)?;
            let pid = columns
                .get(4)
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0);

            Some(DiscoveredListener {
                pid,
                owner_kind: PortOwnerKind::HostUnknown,
                process_name: "host-listener".to_string(),
                command: "host-listener".to_string(),
                command_line: "netstat".to_string(),
                directory: PLACEHOLDER.to_string(),
                framework: PLACEHOLDER.to_string(),
                language: PLACEHOLDER.to_string(),
                exe_path: PLACEHOLDER.to_string(),
                address,
                port,
                protocol: PortProtocol::Tcp,
            })
        })
        .collect()
}

fn enrich_docker_fallback_listeners(listeners: &mut [DiscoveredListener]) {
    if listeners.is_empty() {
        return;
    }

    let published_ports = match discover_docker_published_ports() {
        Ok(published_ports) => published_ports,
        Err(_) => return,
    };

    apply_docker_publish_matches(listeners, &published_ports);
    enrich_containerd_listeners(listeners);
}

fn apply_docker_publish_matches(
    listeners: &mut [DiscoveredListener],
    published_ports: &[DockerPublishedPort],
) {
    for listener in listeners.iter_mut() {
        if listener.owner_kind != PortOwnerKind::HostUnknown {
            continue;
        }

        let Some(published) = published_ports.iter().find(|published| {
            published.protocol == listener.protocol
                && published.host_port == listener.port
                && docker_host_matches(&published.host_ip, &listener.address)
        }) else {
            continue;
        };

        listener.owner_kind = PortOwnerKind::DockerPublished;
        listener.pid = published.pid;
        listener.process_name = published.process_name.clone();
        listener.command = published.command.clone();
        listener.command_line = published.command_line.clone();
        listener.directory = published.directory.clone();
        listener.framework = published.framework.clone();
        listener.language = published.language.clone();
        listener.exe_path = published.exe_path.clone();
    }
}

fn enrich_containerd_listeners(listeners: &mut [DiscoveredListener]) {
    let runtime_by_pid = match discover_containerd_runtime_by_pid() {
        Ok(runtime_by_pid) => runtime_by_pid,
        Err(_) => return,
    };

    for listener in listeners.iter_mut() {
        let Some(runtime) = runtime_by_pid.get(&listener.pid) else {
            continue;
        };

        if matches!(listener.command.as_str(), PLACEHOLDER | "host-listener") {
            listener.command = runtime.command.clone();
        }
        if matches!(
            listener.command_line.as_str(),
            PLACEHOLDER | "ss" | "netstat"
        ) {
            listener.command_line = runtime.command_line.clone();
        }
        if matches!(
            listener.process_name.as_str(),
            PLACEHOLDER | "host-listener"
        ) {
            listener.process_name = runtime.process_name.clone();
        }
        if listener.directory == PLACEHOLDER {
            listener.directory = runtime.directory.clone();
        }
        if listener.framework == PLACEHOLDER {
            listener.framework = runtime.framework.clone();
        }
        if listener.language == PLACEHOLDER {
            listener.language = runtime.language.clone();
        }
        if listener.exe_path == PLACEHOLDER {
            listener.exe_path = runtime.exe_path.clone();
        }
    }
}

fn discover_docker_published_ports() -> Result<Vec<DockerPublishedPort>> {
    let output = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
        .map_err(|err| anyhow!("failed to run docker ps: {err}"))?;

    if !output.status.success() {
        return Err(anyhow!("docker ps exited with status {}", output.status));
    }

    let names = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(Vec::new());
    }

    let mut args = vec!["inspect".to_string()];
    args.extend(names);

    let output = Command::new("docker")
        .args(args.iter().map(String::as_str))
        .output()
        .map_err(|err| anyhow!("failed to run docker inspect: {err}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "docker inspect exited with status {}",
            output.status
        ));
    }

    parse_docker_inspect_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_docker_inspect_output(stdout: &str) -> Result<Vec<DockerPublishedPort>> {
    let parsed = serde_json::from_str::<Value>(stdout)
        .map_err(|err| anyhow!("failed to parse docker inspect output: {err}"))?;

    Ok(parsed
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(parse_docker_inspect_container)
        .collect())
}

fn parse_docker_inspect_container(container: &Value) -> Vec<DockerPublishedPort> {
    let container_name = json_str(container, &["Name"])
        .unwrap_or(PLACEHOLDER)
        .trim_start_matches('/')
        .to_string();
    let labels = container
        .get("Config")
        .and_then(|config| config.get("Labels"))
        .and_then(Value::as_object);
    let compose_project = labels
        .and_then(|labels| labels.get("com.docker.compose.project"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let compose_service = labels
        .and_then(|labels| labels.get("com.docker.compose.service"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let kubernetes_pod = labels
        .and_then(|labels| labels.get("io.kubernetes.pod.name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let kubernetes_namespace = labels
        .and_then(|labels| labels.get("io.kubernetes.pod.namespace"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let kubernetes_container = labels
        .and_then(|labels| labels.get("io.kubernetes.container.name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let project_directory = labels
        .and_then(|labels| labels.get("com.docker.compose.project.working_dir"))
        .and_then(Value::as_str)
        .filter(|path| Path::new(path).exists())
        .map(str::to_string);
    let image = json_str(container, &["Config", "Image"])
        .unwrap_or(PLACEHOLDER)
        .to_string();
    let pid = container
        .get("State")
        .and_then(|state| state.get("Pid"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let working_dir = json_str(container, &["Config", "WorkingDir"])
        .unwrap_or_default()
        .to_string();
    let command_parts = docker_command_parts(container);
    let command_text = placeholder_if_empty(command_parts.join(" "));
    let command_summary = summarize_command_parts(&command_parts);
    let docker_process_name = if let Some(container_name) = kubernetes_container.as_deref() {
        container_name.to_string()
    } else if let Some(service) = compose_service.as_deref() {
        service.to_string()
    } else {
        container_name.clone()
    };
    let detection_command_line = if working_dir.trim().is_empty() {
        command_text.clone()
    } else if command_text == PLACEHOLDER {
        working_dir.clone()
    } else {
        format!("{command_text} {}", working_dir.trim())
    };
    let identity = detect_identity(
        project_directory.as_deref(),
        image.as_str(),
        detection_command_line.as_str(),
        docker_process_name.as_str(),
    );
    let command = if let Some(container_name) = kubernetes_container.as_deref() {
        let pod = kubernetes_pod.as_deref().unwrap_or("pod");
        let namespace = kubernetes_namespace.as_deref().unwrap_or("default");
        format!("k8s:{namespace}/{pod}/{container_name}")
    } else if let Some(service) = compose_service.as_deref() {
        format!("docker:{service}")
    } else if command_summary != PLACEHOLDER {
        command_summary
    } else if image != PLACEHOLDER {
        format!("docker:{image}")
    } else {
        format!("docker:{container_name}")
    };
    let command_line = if let Some(container_name) = kubernetes_container.as_deref() {
        let pod = kubernetes_pod.as_deref().unwrap_or("pod");
        let namespace = kubernetes_namespace.as_deref().unwrap_or("default");
        if command_text != PLACEHOLDER && !working_dir.trim().is_empty() {
            format!(
                "kubernetes {namespace}/{pod}/{container_name}: {command_text} [wd: {}]",
                working_dir.trim()
            )
        } else if command_text != PLACEHOLDER {
            format!("kubernetes {namespace}/{pod}/{container_name}: {command_text}")
        } else {
            format!("kubernetes {namespace}/{pod}/{container_name}")
        }
    } else if let Some(service) = compose_service.as_deref() {
        let compose_target = compose_project
            .as_deref()
            .map(|project| format!("{project}/{service}"))
            .unwrap_or_else(|| service.to_string());
        if command_text != PLACEHOLDER && !working_dir.trim().is_empty() {
            format!(
                "docker compose {compose_target}: {command_text} [wd: {}]",
                working_dir.trim()
            )
        } else if command_text != PLACEHOLDER {
            format!("docker compose {compose_target}: {command_text}")
        } else {
            format!("docker compose {compose_target}")
        }
    } else if command_text != PLACEHOLDER && !working_dir.trim().is_empty() {
        format!(
            "docker run {image}: {command_text} [wd: {}]",
            working_dir.trim()
        )
    } else if command_text != PLACEHOLDER {
        format!("docker run {image}: {command_text}")
    } else {
        format!("docker image {image}")
    };
    let directory = project_directory.unwrap_or_else(|| PLACEHOLDER.to_string());
    let framework = identity.framework;
    let language = identity.language;
    let exe_path = placeholder_if_empty(image.clone());

    container
        .get("NetworkSettings")
        .and_then(|settings| settings.get("Ports"))
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|ports| ports.iter())
        .filter_map(|(port_spec, bindings)| {
            let (container_port, protocol) = parse_port_spec(port_spec)?;
            Some((container_port, protocol, bindings.as_array()?))
        })
        .flat_map(|(container_port, protocol, bindings)| {
            bindings.iter().filter_map({
                let container_name = container_name.clone();
                let process_name = docker_process_name.clone();
                let command = command.clone();
                let command_line = command_line.clone();
                let directory = directory.clone();
                let framework = framework.clone();
                let language = language.clone();
                let exe_path = exe_path.clone();
                move |binding| {
                    let host_ip = binding
                        .get("HostIp")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let host_port = binding
                        .get("HostPort")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse::<u16>().ok())?;

                    Some(DockerPublishedPort {
                        container_name: container_name.clone(),
                        host_ip,
                        host_port,
                        container_port,
                        protocol,
                        pid,
                        process_name: process_name.clone(),
                        command: command.clone(),
                        command_line: command_line.clone(),
                        directory: directory.clone(),
                        framework: framework.clone(),
                        language: language.clone(),
                        exe_path: exe_path.clone(),
                    })
                }
            })
        })
        .collect()
}

fn docker_command_parts(container: &Value) -> Vec<String> {
    let mut parts = Vec::new();

    if let Some(path) = json_str(container, &["Path"]).filter(|value| !value.is_empty()) {
        parts.push(path.to_string());
    }
    parts.extend(json_string_array(container.get("Args")));

    if !parts.is_empty() {
        return parts;
    }

    parts.extend(json_string_array(
        container
            .get("Config")
            .and_then(|config| config.get("Entrypoint")),
    ));
    parts.extend(json_string_array(
        container.get("Config").and_then(|config| config.get("Cmd")),
    ));

    parts
}

fn json_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|segment| !segment.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn json_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn parse_ss_pid(process_field: &str) -> Option<u32> {
    process_field
        .split("pid=")
        .nth(1)?
        .split(|character: char| !character.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()
}

fn parse_ss_process_name(process_field: &str) -> Option<&str> {
    let start = process_field.find("((")? + 2;
    let rest = process_field[start..].trim_start_matches('"');
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn summarize_command_parts(parts: &[String]) -> String {
    if parts.is_empty() {
        return PLACEHOLDER.to_string();
    }

    let mut summary = parts.iter().take(4).cloned().collect::<Vec<_>>().join(" ");
    if summary.len() > 48 {
        summary.truncate(45);
        summary.push_str("...");
    }

    placeholder_if_empty(summary)
}

fn parse_port_spec(port_spec: &str) -> Option<(u16, PortProtocol)> {
    let (port, protocol) = port_spec.split_once('/')?;
    let port = port.parse::<u16>().ok()?;
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => PortProtocol::Tcp,
        "udp" => PortProtocol::Udp,
        _ => return None,
    };

    Some((port, protocol))
}

fn discover_containerd_runtime_by_pid() -> Result<BTreeMap<u32, RuntimeMetadata>> {
    let mut runtime_by_pid = BTreeMap::new();

    for namespace in ["default", "k8s.io"] {
        let tasks_output = Command::new("ctr")
            .args(["--namespace", namespace, "tasks", "list"])
            .output();
        let Ok(tasks_output) = tasks_output else {
            continue;
        };
        if !tasks_output.status.success() {
            continue;
        }

        for (container_id, pid) in
            parse_ctr_tasks_list(&String::from_utf8_lossy(&tasks_output.stdout))
        {
            if runtime_by_pid.contains_key(&pid) {
                continue;
            }
            if let Ok(metadata) =
                discover_containerd_runtime_for_container(namespace, &container_id)
            {
                runtime_by_pid.insert(pid, metadata);
            }
        }
    }

    if runtime_by_pid.is_empty() {
        Err(anyhow!("no containerd runtime metadata available"))
    } else {
        Ok(runtime_by_pid)
    }
}

fn discover_containerd_runtime_for_container(
    namespace: &str,
    container_id: &str,
) -> Result<RuntimeMetadata> {
    let output = Command::new("ctr")
        .args(["--namespace", namespace, "containers", "info", container_id])
        .output()
        .map_err(|err| anyhow!("failed to run ctr containers info: {err}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "ctr containers info exited with status {}",
            output.status
        ));
    }

    parse_ctr_container_info(&String::from_utf8_lossy(&output.stdout), container_id)
}

fn parse_ctr_tasks_list(stdout: &str) -> Vec<(String, u32)> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("TASK") {
                return None;
            }

            let columns = trimmed.split_whitespace().collect::<Vec<_>>();
            let container_id = columns.first()?.to_string();
            let pid = columns.get(1)?.parse::<u32>().ok()?;
            Some((container_id, pid))
        })
        .collect()
}

fn parse_ctr_container_info(stdout: &str, container_id: &str) -> Result<RuntimeMetadata> {
    let info = serde_json::from_str::<Value>(stdout)
        .map_err(|err| anyhow!("failed to parse ctr container info: {err}"))?;
    let labels = info.get("Labels").and_then(Value::as_object);
    let image = json_str(&info, &["Image"])
        .unwrap_or(PLACEHOLDER)
        .to_string();
    let kubernetes_pod = labels
        .and_then(|labels| labels.get("io.kubernetes.pod.name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let kubernetes_namespace = labels
        .and_then(|labels| labels.get("io.kubernetes.pod.namespace"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let kubernetes_container = labels
        .and_then(|labels| labels.get("io.kubernetes.container.name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let working_dir = json_str(&info, &["Spec", "process", "cwd"])
        .unwrap_or_default()
        .to_string();
    let command_parts = json_string_array(
        info.get("Spec")
            .and_then(|spec| spec.get("process"))
            .and_then(|process| process.get("args")),
    );
    let command_text = placeholder_if_empty(command_parts.join(" "));
    let command_summary = summarize_command_parts(&command_parts);
    let process_name = if let Some(container_name) = kubernetes_container.as_deref() {
        container_name.to_string()
    } else if command_summary != PLACEHOLDER {
        command_summary.clone()
    } else {
        container_id.to_string()
    };
    let detection_command_line = if working_dir.trim().is_empty() {
        command_text.clone()
    } else if command_text == PLACEHOLDER {
        working_dir.clone()
    } else {
        format!("{command_text} {}", working_dir.trim())
    };
    let identity = detect_identity(
        None,
        image.as_str(),
        detection_command_line.as_str(),
        process_name.as_str(),
    );
    let command = if let Some(container_name) = kubernetes_container.as_deref() {
        let pod = kubernetes_pod.as_deref().unwrap_or("pod");
        let namespace = kubernetes_namespace.as_deref().unwrap_or("default");
        format!("k8s:{namespace}/{pod}/{container_name}")
    } else if command_summary != PLACEHOLDER {
        command_summary
    } else if image != PLACEHOLDER {
        format!("containerd:{image}")
    } else {
        format!("containerd:{container_id}")
    };
    let command_line = if let Some(container_name) = kubernetes_container.as_deref() {
        let pod = kubernetes_pod.as_deref().unwrap_or("pod");
        let namespace = kubernetes_namespace.as_deref().unwrap_or("default");
        if command_text != PLACEHOLDER && !working_dir.trim().is_empty() {
            format!(
                "kubernetes {namespace}/{pod}/{container_name}: {command_text} [wd: {}]",
                working_dir.trim()
            )
        } else if command_text != PLACEHOLDER {
            format!("kubernetes {namespace}/{pod}/{container_name}: {command_text}")
        } else {
            format!("kubernetes {namespace}/{pod}/{container_name}")
        }
    } else if command_text != PLACEHOLDER && !working_dir.trim().is_empty() {
        format!(
            "containerd {container_id}: {command_text} [wd: {}]",
            working_dir.trim()
        )
    } else if command_text != PLACEHOLDER {
        format!("containerd {container_id}: {command_text}")
    } else {
        format!("containerd image {image}")
    };

    Ok(RuntimeMetadata {
        process_name,
        command,
        command_line,
        directory: PLACEHOLDER.to_string(),
        framework: identity.framework,
        language: identity.language,
        exe_path: placeholder_if_empty(image),
    })
}

fn docker_host_matches(host_ip: &str, listener_address: &str) -> bool {
    let host_ip = normalize_host_address(host_ip);
    let listener_address = normalize_host_address(listener_address);
    host_ip == listener_address
        || is_wildcard_address(&host_ip)
        || is_wildcard_address(&listener_address)
}

fn normalize_host_address(address: &str) -> String {
    address.trim().trim_matches(['[', ']']).to_ascii_lowercase()
}

fn is_wildcard_address(address: &str) -> bool {
    matches!(address, "" | "*" | "0.0.0.0" | "::")
}

fn terminate_process(pid_raw: u32) -> KillResult {
    #[cfg(unix)]
    {
        return terminate_process_unix(pid_raw);
    }

    #[cfg(windows)]
    {
        return terminate_process_windows(pid_raw);
    }

    #[allow(unreachable_code)]
    {
        terminate_process_sysinfo(pid_raw)
    }
}

#[cfg(unix)]
fn terminate_process_unix(pid_raw: u32) -> KillResult {
    let term_status = Command::new("kill")
        .args(["-TERM", &pid_raw.to_string()])
        .status();

    match term_status {
        Ok(status) if status.success() => {
            if wait_for_exit(Pid::from_u32(pid_raw)) {
                return KillResult::TerminatedGracefully;
            }
        }
        Ok(_) => return KillResult::PermissionDenied,
        Err(err) => return KillResult::Failed(format!("kill failed: {err}")),
    }

    let kill_status = Command::new("kill")
        .args(["-KILL", &pid_raw.to_string()])
        .status();

    match kill_status {
        Ok(status) if status.success() => KillResult::TerminatedForcefully,
        Ok(status) if !status.success() => KillResult::PermissionDenied,
        Ok(_) => KillResult::Failed("process stayed alive".to_string()),
        Err(err) => KillResult::Failed(format!("kill failed: {err}")),
    }
}

#[cfg(windows)]
fn terminate_process_windows(pid_raw: u32) -> KillResult {
    let term_status = Command::new("taskkill")
        .args(["/PID", &pid_raw.to_string()])
        .status();

    match term_status {
        Ok(status) if status.success() => {
            if wait_for_exit(Pid::from_u32(pid_raw)) {
                return KillResult::TerminatedGracefully;
            }
        }
        Ok(_) => {}
        Err(err) => return KillResult::Failed(format!("taskkill failed: {err}")),
    }

    let force_status = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid_raw.to_string()])
        .status();

    match force_status {
        Ok(status) if status.success() => KillResult::TerminatedForcefully,
        Ok(status) if !status.success() => KillResult::PermissionDenied,
        Ok(_) => KillResult::Failed("process stayed alive".to_string()),
        Err(err) => KillResult::Failed(format!("taskkill failed: {err}")),
    }
}

fn terminate_process_sysinfo(pid_raw: u32) -> KillResult {
    let pid = Pid::from_u32(pid_raw);
    let mut system = System::new_all();
    system.refresh_all();

    let Some(process) = system.process(pid) else {
        return KillResult::NotFound;
    };

    if let Some(sent) = process.kill_with(Signal::Term) {
        if !sent {
            return KillResult::PermissionDenied;
        }

        if wait_for_exit(pid) {
            return KillResult::TerminatedGracefully;
        }
    } else if !process.kill() {
        return KillResult::SignalNotSupported;
    }

    let mut retry_system = System::new_all();
    retry_system.refresh_all();
    let Some(process) = retry_system.process(pid) else {
        return KillResult::TerminatedGracefully;
    };

    if process.kill() && wait_for_exit(pid) {
        KillResult::TerminatedForcefully
    } else {
        KillResult::Failed("process stayed alive".to_string())
    }
}

fn wait_for_exit(pid: Pid) -> bool {
    for _ in 0..10 {
        thread::sleep(Duration::from_millis(200));
        let mut probe = System::new_all();
        probe.refresh_all();
        if probe.process(pid).is_none() {
            return true;
        }
    }
    false
}

struct DetectedIdentity {
    framework: String,
    language: String,
}

fn detect_identity(
    cwd: Option<&str>,
    exe_path: &str,
    command_line: &str,
    process_name: &str,
) -> DetectedIdentity {
    let mut haystack = String::new();
    haystack.push_str(&command_line.to_ascii_lowercase());
    haystack.push(' ');
    haystack.push_str(&exe_path.to_ascii_lowercase());
    haystack.push(' ');
    haystack.push_str(&process_name.to_ascii_lowercase());

    let framework_name = detect_framework(&haystack, cwd);
    let language = detect_language(&haystack, cwd, framework_name.as_str());
    let framework =
        match detect_framework_version(cwd, framework_name.as_str(), &haystack, exe_path) {
            Some(version) => format!("{framework_name} {version}"),
            None => framework_name,
        };

    DetectedIdentity {
        framework,
        language,
    }
}

fn detect_framework(haystack: &str, cwd: Option<&str>) -> String {
    let checks: &[(&[&str], &str)] = &[
        (&["next dev", "next start", "/next"], "Next.js"),
        (&["vite", "vitest"], "Vite"),
        (&["nuxt"], "Nuxt"),
        (&["astro"], "Astro"),
        (&["svelte-kit", "sveltekit"], "SvelteKit"),
        (&["react-scripts", "create-react-app"], "React"),
        (&["nestjs", "@nestjs"], "NestJS"),
        (&["express"], "Express"),
        (&["uvicorn", "fastapi"], "FastAPI"),
        (&["gunicorn", "django"], "Django"),
        (&["flask"], "Flask"),
        (&["rails", "puma"], "Rails"),
        (&["sinatra"], "Sinatra"),
        (&["laravel", "artisan serve"], "Laravel"),
        (&["spring"], "Spring Boot"),
        (&["dotnet watch", "aspnet"], "ASP.NET"),
        (&["axum"], "Axum"),
        (&["actix"], "Actix"),
        (&["rocket"], "Rocket"),
    ];

    for (patterns, label) in checks {
        if patterns.iter().any(|pattern| haystack.contains(pattern)) {
            return label.to_string();
        }
    }

    if let Some(cwd) = cwd {
        if has_any_marker(
            cwd,
            &["next.config.js", "next.config.mjs", "next.config.ts"],
        ) {
            return "Next.js".to_string();
        }
        if has_any_marker(cwd, &["vite.config.ts", "vite.config.js"]) {
            return "Vite".to_string();
        }
        if has_any_marker(cwd, &["nuxt.config.ts", "nuxt.config.js"]) {
            return "Nuxt".to_string();
        }
        if has_any_marker(cwd, &["astro.config.mjs", "astro.config.ts"]) {
            return "Astro".to_string();
        }
        if has_any_marker(cwd, &["svelte.config.js", "svelte.config.ts"]) {
            return "SvelteKit".to_string();
        }
        if has_any_marker(cwd, &["manage.py"]) {
            return "Django".to_string();
        }
        if has_any_marker(cwd, &["config.ru"]) {
            return "Rails".to_string();
        }
        if has_any_marker(cwd, &["Cargo.toml"]) {
            return "Custom".to_string();
        }
    }

    PLACEHOLDER.to_string()
}

fn detect_framework_version(
    cwd: Option<&str>,
    framework: &str,
    haystack: &str,
    exe_path: &str,
) -> Option<String> {
    if framework == PLACEHOLDER {
        return None;
    }

    if let Some(cwd) = cwd {
        let version = match framework {
            "Next.js" => package_json_dependency_version(cwd, &["next"]),
            "Vite" => package_json_dependency_version(cwd, &["vite"]),
            "Nuxt" => package_json_dependency_version(cwd, &["nuxt"]),
            "Astro" => package_json_dependency_version(cwd, &["astro"]),
            "SvelteKit" => package_json_dependency_version(cwd, &["@sveltejs/kit"]),
            "React" => package_json_dependency_version(cwd, &["react-scripts", "react"]),
            "NestJS" => package_json_dependency_version(cwd, &["@nestjs/core"]),
            "Express" => package_json_dependency_version(cwd, &["express"]),
            "FastAPI" => python_dependency_version(cwd, &["fastapi"]),
            "Django" => python_dependency_version(cwd, &["django"]),
            "Flask" => python_dependency_version(cwd, &["flask"]),
            "Rails" => ruby_dependency_version(cwd, &["rails"]),
            "Sinatra" => ruby_dependency_version(cwd, &["sinatra"]),
            "Laravel" => composer_dependency_version(cwd, &["laravel/framework"]),
            "Spring Boot" => spring_boot_version(cwd),
            "Axum" => cargo_dependency_version(cwd, &["axum"]),
            "Actix" => cargo_dependency_version(cwd, &["actix-web", "actix"]),
            "Rocket" => cargo_dependency_version(cwd, &["rocket"]),
            _ => None,
        };

        if version.is_some() {
            return version;
        }
    }

    let _ = haystack;
    version_from_text(framework, exe_path)
}

fn package_json_dependency_version(cwd: &str, package_names: &[&str]) -> Option<String> {
    let manifest = read_manifest_nearby(cwd, &["package.json"])?;
    let parsed = serde_json::from_str::<Value>(&manifest).ok()?;
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(dependencies) = parsed.get(section).and_then(Value::as_object) else {
            continue;
        };
        for package_name in package_names {
            if let Some(version) = dependencies.get(*package_name).and_then(Value::as_str)
                && let Some(version) = sanitize_version(version)
            {
                return Some(version);
            }
        }
    }
    None
}

fn cargo_dependency_version(cwd: &str, crate_names: &[&str]) -> Option<String> {
    let manifest = read_manifest_nearby(cwd, &["Cargo.toml"])?;
    for line in manifest.lines().map(str::trim) {
        for crate_name in crate_names {
            if let Some(remainder) = line.strip_prefix(crate_name) {
                if let Some(version) = extract_inline_version(remainder) {
                    return Some(version);
                }
            }
        }
    }
    None
}

fn python_dependency_version(cwd: &str, package_names: &[&str]) -> Option<String> {
    if let Some(manifest) = read_manifest_nearby(cwd, &["pyproject.toml"]) {
        for line in manifest.lines().map(str::trim) {
            for package_name in package_names {
                if line.to_ascii_lowercase().contains(package_name)
                    && let Some(version) = extract_requirement_version(line)
                {
                    return Some(version);
                }
            }
        }
    }

    if let Some(requirements) = read_manifest_nearby(cwd, &["requirements.txt"]) {
        for line in requirements.lines().map(str::trim) {
            for package_name in package_names {
                if line.to_ascii_lowercase().starts_with(package_name)
                    && let Some(version) = extract_requirement_version(line)
                {
                    return Some(version);
                }
            }
        }
    }

    None
}

fn ruby_dependency_version(cwd: &str, gem_names: &[&str]) -> Option<String> {
    let manifest = read_manifest_nearby(cwd, &["Gemfile.lock", "Gemfile"])?;
    for line in manifest.lines().map(str::trim) {
        for gem_name in gem_names {
            if line.starts_with(gem_name)
                && let Some(version) = extract_parenthesized_version(line)
            {
                return Some(version);
            }
        }
    }
    None
}

fn composer_dependency_version(cwd: &str, package_names: &[&str]) -> Option<String> {
    let manifest = read_manifest_nearby(cwd, &["composer.json"])?;
    let parsed = serde_json::from_str::<Value>(&manifest).ok()?;
    for section in ["require", "require-dev"] {
        let Some(dependencies) = parsed.get(section).and_then(Value::as_object) else {
            continue;
        };
        for package_name in package_names {
            if let Some(version) = dependencies.get(*package_name).and_then(Value::as_str)
                && let Some(version) = sanitize_version(version)
            {
                return Some(version);
            }
        }
    }
    None
}

fn spring_boot_version(cwd: &str) -> Option<String> {
    if let Some(manifest) = read_manifest_nearby(cwd, &["pom.xml"]) {
        for line in manifest.lines().map(str::trim) {
            if line.contains("<version>")
                && let Some(version) = extract_xml_version(line)
            {
                return Some(version);
            }
        }
    }

    if let Some(manifest) = read_manifest_nearby(cwd, &["build.gradle", "build.gradle.kts"]) {
        for line in manifest.lines().map(str::trim) {
            if line.contains("spring-boot")
                && let Some(version) = extract_quoted_version(line)
            {
                return Some(version);
            }
        }
    }

    None
}

fn version_from_text(framework: &str, text: &str) -> Option<String> {
    let lowered = framework.to_ascii_lowercase();
    let text_lowered = text.to_ascii_lowercase();

    for separator in ['@', ':', '-', ' '] {
        let needle = format!("{lowered}{separator}");
        if let Some(index) = text_lowered.find(&needle) {
            let suffix = &text[index + needle.len()..];
            if let Some(version) = sanitize_version(suffix) {
                return Some(version);
            }
        }
    }

    None
}

fn read_manifest_nearby(cwd: &str, names: &[&str]) -> Option<String> {
    let current = Path::new(cwd);
    let parent = current.parent();

    names
        .iter()
        .flat_map(|name| {
            [
                Some(current.join(name)),
                parent.map(|parent| parent.join(name)),
            ]
        })
        .flatten()
        .find_map(|path| std::fs::read_to_string(path).ok())
}

fn sanitize_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let start = trimmed
        .find(|character: char| character.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if start == trimmed.len() {
        return None;
    }

    let version = trimmed[start..]
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
        .collect::<String>();

    (!version.is_empty()
        && version
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit()))
    .then_some(version)
}

fn extract_inline_version(line: &str) -> Option<String> {
    if let Some(version) = line.split('"').nth(1).and_then(sanitize_version) {
        return Some(version);
    }

    line.split("version")
        .nth(1)
        .and_then(extract_quoted_version)
        .and_then(|version| sanitize_version(&version))
}

fn extract_requirement_version(line: &str) -> Option<String> {
    for separator in ["==", ">=", "~=", "="] {
        if let Some(version) = line.split(separator).nth(1).and_then(sanitize_version) {
            return Some(version);
        }
    }
    None
}

fn extract_parenthesized_version(line: &str) -> Option<String> {
    line.split('(')
        .nth(1)
        .and_then(|segment| segment.split(')').next())
        .and_then(sanitize_version)
}

fn extract_xml_version(line: &str) -> Option<String> {
    line.split("<version>")
        .nth(1)
        .and_then(|segment| segment.split("</version>").next())
        .and_then(sanitize_version)
}

fn extract_quoted_version(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(version) = line.split(quote).nth(1).and_then(sanitize_version) {
            return Some(version);
        }
    }
    None
}

fn detect_language(haystack: &str, cwd: Option<&str>, framework: &str) -> String {
    let checks: &[(&[&str], &str)] = &[
        (
            &["node", "npm", "pnpm", "yarn", "bun", "deno"],
            "JavaScript/TypeScript",
        ),
        (&["python", "uvicorn", "gunicorn"], "Python"),
        (&["ruby", "bundle", "rails"], "Ruby"),
        (&["php", "artisan"], "PHP"),
        (&["java", "spring"], "Java"),
        (&["go run", "/go"], "Go"),
        (&["cargo run", "rustc", "/target/debug"], "Rust"),
        (&["dotnet", "aspnet"], ".NET"),
        (&["pwsh", "powershell"], "PowerShell"),
    ];

    for (patterns, label) in checks {
        if patterns.iter().any(|pattern| haystack.contains(pattern)) {
            return label.to_string();
        }
    }

    let inferred = match framework {
        "Next.js" | "Vite" | "Nuxt" | "Astro" | "SvelteKit" | "React" | "NestJS" | "Express" => {
            Some("JavaScript/TypeScript")
        }
        "FastAPI" | "Django" | "Flask" => Some("Python"),
        "Rails" | "Sinatra" => Some("Ruby"),
        "Laravel" => Some("PHP"),
        "Spring Boot" => Some("Java"),
        "ASP.NET" => Some(".NET"),
        "Axum" | "Actix" | "Rocket" => Some("Rust"),
        _ => None,
    };
    if let Some(language) = inferred {
        return language.to_string();
    }

    if let Some(cwd) = cwd {
        if has_any_marker(cwd, &["package.json", "bun.lockb", "pnpm-lock.yaml"]) {
            return "JavaScript/TypeScript".to_string();
        }
        if has_any_marker(cwd, &["pyproject.toml", "requirements.txt"]) {
            return "Python".to_string();
        }
        if has_any_marker(cwd, &["Gemfile"]) {
            return "Ruby".to_string();
        }
        if has_any_marker(cwd, &["go.mod"]) {
            return "Go".to_string();
        }
        if has_any_marker(cwd, &["Cargo.toml"]) {
            return "Rust".to_string();
        }
        if has_any_marker(cwd, &["pom.xml", "build.gradle"]) {
            return "Java".to_string();
        }
        if has_any_marker(cwd, &["composer.json"]) {
            return "PHP".to_string();
        }
        if has_any_marker(cwd, &["global.json"]) {
            return ".NET".to_string();
        }
    }

    PLACEHOLDER.to_string()
}

fn has_any_marker(cwd: &str, markers: &[&str]) -> bool {
    let current = Path::new(cwd);
    let parent = current.parent();

    markers.iter().any(|marker| {
        current.join(marker).exists() || parent.is_some_and(|parent| parent.join(marker).exists())
    })
}

fn path_to_string(path: &Path) -> String {
    placeholder_if_empty(path.display().to_string())
}

#[cfg(target_os = "linux")]
fn linux_proc_cwd(pid: u32) -> Option<String> {
    procfs::process::Process::new(pid as i32)
        .ok()
        .and_then(|process| process.cwd().ok())
        .map(|path| path.display().to_string())
}

#[cfg(not(target_os = "linux"))]
#[cfg_attr(not(test), allow(dead_code))]
fn linux_proc_cwd(_pid: u32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        DiscoveredListener, DockerPublishedPort, cargo_dependency_version, detect_framework,
        detect_framework_version, detect_language, docker_host_matches, merge_discovered_listeners,
        package_json_dependency_version, parse_ctr_container_info, parse_ctr_tasks_list,
        parse_docker_inspect_output, parse_netstat_output, parse_ss_output,
    };
    use crate::model::{PLACEHOLDER, PortOwnerKind, PortProtocol};
    use tempfile::tempdir;

    #[test]
    fn detects_framework_from_command() {
        assert_eq!(detect_framework("next dev", None), "Next.js");
        assert_eq!(detect_framework("uvicorn api:app", None), "FastAPI");
    }

    #[test]
    fn detects_language_from_framework() {
        assert_eq!(detect_language("", None, "Axum"), "Rust");
        assert_eq!(detect_language("", None, PLACEHOLDER), PLACEHOLDER);
    }

    #[test]
    fn detects_framework_version_from_package_json() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"devDependencies":{"vite":"^5.4.2"}}"#,
        )
        .expect("package.json");

        assert_eq!(
            package_json_dependency_version(
                temp_dir.path().to_str().expect("temp dir path"),
                &["vite"],
            ),
            Some("5.4.2".to_string())
        );
        assert_eq!(
            detect_framework_version(
                Some(temp_dir.path().to_str().expect("temp dir path")),
                "Vite",
                "",
                "",
            ),
            Some("5.4.2".to_string())
        );
    }

    #[test]
    fn detects_framework_version_from_cargo_toml() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("Cargo.toml"),
            "[dependencies]\naxum = \"0.7.5\"\n",
        )
        .expect("cargo toml");

        assert_eq!(
            cargo_dependency_version(temp_dir.path().to_str().expect("temp dir path"), &["axum"]),
            Some("0.7.5".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn parses_lsof_output() {
        let parsed = super::parse_lsof_output("p123\ncnode\nn127.0.0.1:3000\nn*:5173\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].pid, 123);
        assert_eq!(parsed[0].port, 3000);
        assert_eq!(parsed[1].address, "*");
    }

    #[test]
    fn parses_ss_output_into_host_fallback_rows() {
        let parsed = parse_ss_output(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 0.0.0.0:8083 0.0.0.0:* users:((\"docker-proxy\",pid=321,fd=4))\nLISTEN 0 4096 [::]:5432 [::]:*\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 8083);
        assert_eq!(parsed[0].owner_kind, PortOwnerKind::HostUnknown);
        assert_eq!(parsed[0].pid, 321);
        assert_eq!(parsed[0].command, "docker-proxy");
        assert_eq!(parsed[1].address, "::");
    }

    #[test]
    fn parses_windows_netstat_output_into_host_fallback_rows() {
        let parsed = parse_netstat_output(
            "  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       999\n  TCP    [::]:8083              [::]:0                 LISTENING       777\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 3000);
        assert_eq!(parsed[0].pid, 999);
        assert_eq!(parsed[0].command_line, "netstat");
        assert_eq!(parsed[1].address, "::");
    }

    #[test]
    fn process_rows_win_over_wildcard_star_fallback_rows_for_same_pid() {
        let merged = merge_discovered_listeners(
            vec![process_listener(8083, "0.0.0.0", 42, "node")],
            vec![host_listener_with_pid(8083, "*", 42)],
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].owner_kind, PortOwnerKind::Process);
        assert_eq!(merged[0].pid, 42);
    }

    #[test]
    fn process_rows_win_over_ipv6_wildcard_fallback_rows_for_same_pid() {
        let merged = merge_discovered_listeners(
            vec![process_listener(8083, "0.0.0.0", 42, "node")],
            vec![host_listener_with_pid(8083, "::", 42)],
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].owner_kind, PortOwnerKind::Process);
        assert_eq!(merged[0].pid, 42);
    }

    #[test]
    fn fallback_rows_with_different_pid_are_retained_for_same_wildcard_socket() {
        let merged = merge_discovered_listeners(
            vec![process_listener(8083, "0.0.0.0", 42, "node")],
            vec![host_listener_with_pid(8083, "*", 7)],
        );

        assert_eq!(merged.len(), 2);
        assert!(
            merged
                .iter()
                .any(|listener| listener.owner_kind == PortOwnerKind::Process && listener.pid == 42)
        );
        assert!(merged.iter().any(|listener| {
            listener.owner_kind == PortOwnerKind::HostUnknown && listener.pid == 7
        }));
    }

    #[test]
    fn fallback_rows_with_pid_zero_are_retained_for_same_wildcard_socket() {
        let merged = merge_discovered_listeners(
            vec![process_listener(8083, "0.0.0.0", 42, "node")],
            vec![host_listener(8083, "*")],
        );

        assert_eq!(merged.len(), 2);
        assert!(
            merged
                .iter()
                .any(|listener| listener.owner_kind == PortOwnerKind::Process && listener.pid == 42)
        );
        assert!(merged.iter().any(|listener| {
            listener.owner_kind == PortOwnerKind::HostUnknown && listener.pid == 0
        }));
    }

    #[test]
    fn wildcard_equivalent_fallback_rows_share_a_merge_key() {
        let merged = merge_discovered_listeners(
            Vec::new(),
            vec![
                host_listener(8083, "*"),
                docker_published_listener(8083, "0.0.0.0", 321, "docker:web"),
            ],
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].owner_kind, PortOwnerKind::DockerPublished);
        assert_eq!(merged[0].pid, 321);
    }

    #[test]
    fn parses_docker_inspect_output() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"devDependencies":{"vite":"^5.4.2"}}"#,
        )
        .expect("package.json");
        fs::write(
            temp_dir.path().join("vite.config.ts"),
            "export default {};\n",
        )
        .expect("vite config");
        let inspect = format!(
            r#"[{{
                "Name":"/live-chat-app",
                "Path":"docker-entrypoint.sh",
                "Args":["npm","run","docker:start"],
                "Config":{{
                    "Image":"live-chat-app:latest",
                    "WorkingDir":"/app",
                    "Labels":{{
                        "com.docker.compose.project":"live-chat",
                        "com.docker.compose.service":"web",
                        "com.docker.compose.project.working_dir":"{}"
                    }}
                }},
                "NetworkSettings":{{
                    "Ports":{{
                        "8083/tcp":[{{"HostIp":"0.0.0.0","HostPort":"8083"}}]
                    }}
                }}
            }}]"#,
            temp_dir.path().display()
        );
        let parsed = parse_docker_inspect_output(&inspect).expect("parse docker inspect");

        assert_eq!(
            parsed,
            vec![DockerPublishedPort {
                container_name: "live-chat-app".to_string(),
                host_ip: "0.0.0.0".to_string(),
                host_port: 8083,
                container_port: 8083,
                protocol: PortProtocol::Tcp,
                pid: 0,
                process_name: "web".to_string(),
                command: "docker:web".to_string(),
                command_line: "docker compose live-chat/web: docker-entrypoint.sh npm run docker:start [wd: /app]".to_string(),
                directory: temp_dir.path().display().to_string(),
                framework: "Vite 5.4.2".to_string(),
                language: "JavaScript/TypeScript".to_string(),
                exe_path: "live-chat-app:latest".to_string(),
            }]
        );
    }

    #[test]
    fn docker_enrichment_relabels_matching_fallback_rows() {
        let mut listeners = vec![host_listener(8083, "0.0.0.0")];
        super::apply_docker_publish_matches(&mut listeners, &[docker_published_port()]);

        assert_eq!(listeners[0].owner_kind, PortOwnerKind::DockerPublished);
        assert_eq!(listeners[0].command, "docker:web");
        assert!(listeners[0].command_line.contains("docker compose"));
        assert_eq!(listeners[0].framework, "Vite");
    }

    #[test]
    fn standalone_container_uses_image_and_command_metadata() {
        let inspect = r#"[{
            "Name":"/api",
            "Path":"uvicorn",
            "Args":["app.main:app","--host","0.0.0.0","--port","8000"],
            "Config":{
                "Image":"my-fastapi:latest",
                "WorkingDir":"/srv/app",
                "Labels":null
            },
            "NetworkSettings":{
                "Ports":{
                    "8000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8000"}]
                }
            }
        }]"#;
        let parsed = parse_docker_inspect_output(inspect).expect("parse docker inspect");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].framework, "FastAPI");
        assert_eq!(parsed[0].language, "Python");
        assert_eq!(parsed[0].directory, PLACEHOLDER);
        assert!(parsed[0].command.starts_with("uvicorn app.main:app"));
        assert!(
            parsed[0]
                .command_line
                .contains("docker run my-fastapi:latest")
        );
    }

    #[test]
    fn docker_host_matching_treats_wildcards_as_compatible() {
        assert!(docker_host_matches("", "0.0.0.0"));
        assert!(docker_host_matches("0.0.0.0", "*"));
        assert!(docker_host_matches("::", "0.0.0.0"));
    }

    #[test]
    fn parses_ctr_task_list_output() {
        let parsed = parse_ctr_tasks_list(
            "TASK                            PID     STATUS\n9f8e7d6c5b4a                    4321    RUNNING\n",
        );

        assert_eq!(parsed, vec![("9f8e7d6c5b4a".to_string(), 4321)]);
    }

    #[test]
    fn parses_containerd_info_for_standalone_container() {
        let info = r#"{
            "Image":"docker.io/library/my-fastapi:latest",
            "Labels":{},
            "Spec":{
                "process":{
                    "cwd":"/srv/app",
                    "args":["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
                }
            }
        }"#;

        let parsed = parse_ctr_container_info(info, "fastapi-container").expect("containerd info");

        assert_eq!(parsed.framework, "FastAPI");
        assert_eq!(parsed.language, "Python");
        assert!(parsed.command.starts_with("uvicorn app.main:app"));
        assert!(parsed.command_line.contains("containerd fastapi-container"));
        assert_eq!(parsed.exe_path, "docker.io/library/my-fastapi:latest");
    }

    #[test]
    fn parses_containerd_info_for_kubernetes_container() {
        let info = r#"{
            "Image":"registry.k8s.io/app:1.0",
            "Labels":{
                "io.kubernetes.pod.name":"api-6dbf6d9d5b-abcde",
                "io.kubernetes.pod.namespace":"prod",
                "io.kubernetes.container.name":"api"
            },
            "Spec":{
                "process":{
                    "cwd":"/workspace",
                    "args":["node","server.js"]
                }
            }
        }"#;

        let parsed = parse_ctr_container_info(info, "k8s-container").expect("containerd info");

        assert_eq!(parsed.command, "k8s:prod/api-6dbf6d9d5b-abcde/api");
        assert!(
            parsed
                .command_line
                .contains("kubernetes prod/api-6dbf6d9d5b-abcde/api")
        );
        assert_eq!(parsed.language, "JavaScript/TypeScript");
    }

    fn process_listener(port: u16, address: &str, pid: u32, command: &str) -> DiscoveredListener {
        DiscoveredListener {
            pid,
            owner_kind: PortOwnerKind::Process,
            process_name: command.to_string(),
            command: command.to_string(),
            command_line: command.to_string(),
            directory: PLACEHOLDER.to_string(),
            framework: PLACEHOLDER.to_string(),
            language: PLACEHOLDER.to_string(),
            exe_path: PLACEHOLDER.to_string(),
            address: address.to_string(),
            port,
            protocol: PortProtocol::Tcp,
        }
    }

    fn host_listener(port: u16, address: &str) -> DiscoveredListener {
        host_listener_with_pid(port, address, 0)
    }

    fn host_listener_with_pid(port: u16, address: &str, pid: u32) -> DiscoveredListener {
        DiscoveredListener {
            pid,
            owner_kind: PortOwnerKind::HostUnknown,
            process_name: "host-listener".to_string(),
            command: "host-listener".to_string(),
            command_line: "ss".to_string(),
            directory: PLACEHOLDER.to_string(),
            framework: PLACEHOLDER.to_string(),
            language: PLACEHOLDER.to_string(),
            exe_path: PLACEHOLDER.to_string(),
            address: address.to_string(),
            port,
            protocol: PortProtocol::Tcp,
        }
    }

    fn docker_published_listener(
        port: u16,
        address: &str,
        pid: u32,
        command: &str,
    ) -> DiscoveredListener {
        DiscoveredListener {
            pid,
            owner_kind: PortOwnerKind::DockerPublished,
            process_name: command.to_string(),
            command: command.to_string(),
            command_line: command.to_string(),
            directory: PLACEHOLDER.to_string(),
            framework: PLACEHOLDER.to_string(),
            language: PLACEHOLDER.to_string(),
            exe_path: PLACEHOLDER.to_string(),
            address: address.to_string(),
            port,
            protocol: PortProtocol::Tcp,
        }
    }

    fn docker_published_port() -> DockerPublishedPort {
        DockerPublishedPort {
            container_name: "live-chat-app".to_string(),
            host_ip: "0.0.0.0".to_string(),
            host_port: 8083,
            container_port: 8083,
            protocol: PortProtocol::Tcp,
            pid: 0,
            process_name: "web".to_string(),
            command: "docker:web".to_string(),
            command_line:
                "docker compose live-chat/web: docker-entrypoint.sh npm run docker:start [wd: /app]"
                    .to_string(),
            directory: "/tmp/live-chat".to_string(),
            framework: "Vite".to_string(),
            language: "JavaScript/TypeScript".to_string(),
            exe_path: "live-chat-app:latest".to_string(),
        }
    }
}
