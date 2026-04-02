use std::fmt::Write as _;

use anyhow::{Result, bail};
use owo_colors::OwoColorize;
use serde_json::{Value, json};

use crate::model::{KillReport, KillResult, PLACEHOLDER, PortDetails, PortRecord};

const HEADERS: [&str; 8] = [
    "Port",
    "Directory",
    "Framework",
    "Programming Language",
    "PID",
    "Memory",
    "Uptime",
    "Command",
];

pub fn print_table(records: &[PortRecord]) -> Result<()> {
    println!("{}", render_table(records));
    Ok(())
}

pub fn print_table_json(records: &[PortRecord]) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&list_json_payload(records))?
    );
    Ok(())
}

pub fn print_check_result(details: &[PortDetails], port: u16) -> Result<()> {
    if details.is_empty() {
        println!("{}", format!("Port {port} is free.").green().bold());
        return Ok(());
    }

    for (index, detail) in details.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!(
            "{}",
            format!("Port {} ({})", detail.record.port, detail.record.protocol)
                .bold()
                .blue()
        );
        println!("PID        {}", detail.record.pid_label().cyan());
        println!("Directory  {}", colorize_value(&detail.record.directory));
        println!("Framework  {}", colorize_value(&detail.record.framework));
        println!("Language   {}", colorize_value(&detail.record.language));
        println!("Memory     {}", colorize_value(&detail.record.memory_human));
        println!("Uptime     {}", colorize_value(&detail.record.uptime_human));
        println!("Command    {}", colorize_value(&detail.record.command));
        println!("Cmdline    {}", colorize_value(&detail.record.command_line));
        println!(
            "Addresses  {}",
            colorize_value(&detail.addresses.join(", "))
        );
        println!("Executable {}", colorize_value(&detail.record.exe_path));
    }

    Ok(())
}

pub fn print_check_result_json(details: &[PortDetails], port: u16) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&check_json_payload(details, port))?
    );
    Ok(())
}

pub fn print_kill_result(report: &KillReport, port: u16) -> Result<()> {
    if report.is_empty() {
        if let Some(reason) = &report.blocked_reason {
            bail!("{reason}");
        }
        bail!("Nothing is listening on port {port}");
    }

    let mut had_success = false;
    for outcome in &report.outcomes {
        let line = format!(
            "PID {} on port {} ({}) -> {}",
            outcome.pid, outcome.port, outcome.command, outcome.result
        );
        match outcome.result {
            KillResult::TerminatedGracefully | KillResult::TerminatedForcefully => {
                had_success = true;
                println!("{}", line.green().bold());
            }
            _ => println!("{}", line.yellow()),
        }
    }

    if had_success {
        Ok(())
    } else {
        bail!("Failed to stop any process bound to port {port}")
    }
}

pub fn render_table(records: &[PortRecord]) -> String {
    let rows = records.iter().collect::<Vec<_>>();
    let widths = compute_widths(&rows);
    let mut output = String::new();

    writeln!(
        output,
        "{}  {}  {}  {}  {}  {}  {}  {}",
        pad(HEADERS[0], widths[0]).bold(),
        pad(HEADERS[1], widths[1]).bold(),
        pad(HEADERS[2], widths[2]).bold(),
        pad(HEADERS[3], widths[3]).bold(),
        pad(HEADERS[4], widths[4]).bold(),
        pad(HEADERS[5], widths[5]).bold(),
        pad(HEADERS[6], widths[6]).bold(),
        pad(HEADERS[7], widths[7]).bold(),
    )
    .ok();

    for record in rows {
        let port_label = pad(&record.port_label(), widths[0]);
        let dir = pad(&record.short_dir(), widths[1]);
        let framework = pad(&record.framework, widths[2]);
        let language = pad(&record.language, widths[3]);
        let pid_label = pad(&record.pid_label(), widths[4]);
        let memory = pad(&record.memory_human, widths[5]);
        let uptime = pad(&record.uptime_human, widths[6]);
        let command = pad(&record.command, widths[7]);

        writeln!(
            output,
            "{}  {}  {}  {}  {}  {}  {}  {}",
            style_port_cell(&port_label, record),
            colorize_cell(dir, record, false),
            colorize_cell(framework, record, false),
            colorize_cell(language, record, false),
            style_pid_cell(&pid_label, record),
            colorize_cell(memory, record, true),
            colorize_cell(uptime, record, false),
            colorize_cell(command, record, true),
        )
        .ok();
    }

    if records.is_empty() {
        writeln!(output, "{}", "No listening ports found.".yellow().bold()).ok();
    }

    output
}

fn compute_widths(records: &[&PortRecord]) -> [usize; 8] {
    let mut widths = HEADERS.map(str::len);

    for record in records {
        widths[0] = widths[0].max(record.port_label().len());
        widths[1] = widths[1].max(record.short_dir().len());
        widths[2] = widths[2].max(record.framework.len());
        widths[3] = widths[3].max(record.language.len());
        widths[4] = widths[4].max(record.pid_label().len());
        widths[5] = widths[5].max(record.memory_human.len());
        widths[6] = widths[6].max(record.uptime_human.len());
        widths[7] = widths[7].max(record.command.len());
    }

    widths
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn list_json_payload(records: &[PortRecord]) -> Value {
    Value::Array(records.iter().map(record_json_value).collect())
}

fn check_json_payload(details: &[PortDetails], port: u16) -> Value {
    json!({
        "port": port,
        "is_free": details.is_empty(),
        "details": details.iter().map(detail_json_value).collect::<Vec<_>>(),
    })
}

fn record_json_value(record: &PortRecord) -> Value {
    json!({
        "port": record.port,
        "protocol": record.protocol.to_string(),
        "directory": record.directory,
        "dir_name": record.dir_name(),
        "framework": record.framework,
        "language": record.language,
        "pid": record.pid,
        "owner_kind": record.owner_kind.as_str(),
        "memory_bytes": record.memory_bytes,
        "memory_human": record.memory_human,
        "uptime_seconds": record.uptime_seconds,
        "uptime_human": record.uptime_human,
        "command": record.command,
        "command_line": record.command_line,
        "process_name": record.process_name,
        "executable": record.exe_path,
        "bind_address": record.bind_address,
        "is_system_process": record.is_system_process(),
        "is_high_memory": record.is_high_memory(),
    })
}

fn detail_json_value(detail: &PortDetails) -> Value {
    let mut record = record_json_value(&detail.record);
    if let Some(object) = record.as_object_mut() {
        object.insert(
            "addresses".to_string(),
            Value::Array(
                detail
                    .addresses
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    record
}

fn style_port_cell(value: &str, record: &PortRecord) -> String {
    if record.is_system_process() {
        value.blue().bold().dimmed().to_string()
    } else {
        value.blue().bold().to_string()
    }
}

fn style_pid_cell(value: &str, record: &PortRecord) -> String {
    if record.is_system_process() {
        value.cyan().dimmed().to_string()
    } else {
        value.cyan().to_string()
    }
}

fn colorize_cell(value: String, record: &PortRecord, emphasize_high_memory: bool) -> String {
    let trimmed = value.trim();

    if trimmed == PLACEHOLDER {
        if record.is_system_process() {
            return value.yellow().dimmed().to_string();
        }
        return value.yellow().to_string();
    }

    if emphasize_high_memory && record.is_high_memory() {
        return value.red().bold().to_string();
    }

    if record.is_system_process() {
        return value.dimmed().to_string();
    }

    value
}

fn colorize_value(value: &str) -> String {
    if value.trim().is_empty() || value.trim() == PLACEHOLDER {
        PLACEHOLDER.yellow().to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{PLACEHOLDER, PortOwnerKind, PortProtocol, PortRecord};

    use super::{check_json_payload, list_json_payload, render_table};

    #[test]
    fn renders_static_table() {
        let rendered = render_table(&[PortRecord {
            port: 3000,
            protocol: PortProtocol::Tcp,
            pid: 123,
            owner_kind: PortOwnerKind::Process,
            directory: "/tmp/app".to_string(),
            framework: "Vite".to_string(),
            language: "JavaScript/TypeScript".to_string(),
            memory_human: "12.0MB".to_string(),
            memory_bytes: 12_000_000,
            uptime_human: "5m 0s".to_string(),
            uptime_seconds: 300,
            command: "node server.js".to_string(),
            command_line: "node server.js".to_string(),
            process_name: "node".to_string(),
            exe_path: "/usr/bin/node".to_string(),
            bind_address: "127.0.0.1:3000".to_string(),
            system_owned: false,
        }]);

        assert!(rendered.contains("3000"));
        assert!(rendered.contains("Vite"));
        assert!(rendered.contains("Programming Language"));
        assert!(rendered.contains("JavaScript/TypeScript"));
    }

    #[test]
    fn renders_placeholder_pid_for_host_listener() {
        let rendered = render_table(&[PortRecord {
            port: 8083,
            protocol: PortProtocol::Tcp,
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
        }]);

        assert!(rendered.contains(PLACEHOLDER));
        assert!(!rendered.contains(" 0 "));
    }

    #[test]
    fn renders_list_json_payload() {
        let payload = list_json_payload(&[PortRecord {
            port: 3000,
            protocol: PortProtocol::Tcp,
            pid: 123,
            owner_kind: PortOwnerKind::Process,
            directory: "/tmp/app".to_string(),
            framework: "Vite 5.4.0".to_string(),
            language: "JavaScript/TypeScript".to_string(),
            memory_human: "12.0MB".to_string(),
            memory_bytes: 12_000_000,
            uptime_human: "5m 0s".to_string(),
            uptime_seconds: 300,
            command: "node server.js".to_string(),
            command_line: "node server.js".to_string(),
            process_name: "node".to_string(),
            exe_path: "/usr/bin/node".to_string(),
            bind_address: "127.0.0.1:3000".to_string(),
            system_owned: false,
        }]);

        assert_eq!(payload[0]["framework"], "Vite 5.4.0");
        assert_eq!(payload[0]["dir_name"], "app");
        assert_eq!(payload[0]["owner_kind"], "process");
    }

    #[test]
    fn renders_check_json_payload_for_free_port() {
        let payload = check_json_payload(&[], 9999);
        assert_eq!(payload["port"], 9999);
        assert_eq!(payload["is_free"], true);
        assert!(
            payload["details"]
                .as_array()
                .is_some_and(|items| items.is_empty())
        );
    }
}
