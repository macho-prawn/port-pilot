use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser, Subcommand};

pub const DEFAULT_INTERVAL_SECS: u64 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "ports",
    version,
    about = "Inspect, monitor, and manage listening ports on your machine",
    long_about = "Inspect, monitor, and manage listening ports on your machine.\n\nRun `ports` with no arguments to open the live TUI.",
    arg_required_else_help = false,
    disable_help_subcommand = true,
    after_help = "Examples:\n  ports\n  ports --interval 5\n  ports ls\n  ports --json ls\n  ports check 3000\n  ports --json check 3000\n  ports kill 3000\n  ports help kill"
)]
pub struct Cli {
    /// Emit machine-readable JSON output for list/check commands
    #[arg(long, global = true)]
    pub json: bool,
    /// Refresh interval in seconds for the live TUI
    #[arg(long, global = true, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    pub interval: Option<u64>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print a static table of all listening ports
    #[command(alias = "ls")]
    List,
    /// Show detailed info for a port, or say that it is free
    Check {
        /// Port number to inspect
        port: u16,
    },
    /// Kill the process or processes listening on a port
    Kill {
        /// Port number to terminate
        port: u16,
    },
    /// Show help for a specific switch or command
    Help {
        /// Topic name such as list, ls, check, kill, -h, or --help
        topic: Option<String>,
    },
    #[command(hide = true)]
    InternalHoldPort {
        #[arg(hide = true)]
        port: u16,
    },
}

impl Cli {
    pub fn validate(&self) -> Result<()> {
        if self.json && !matches!(self.command, Some(Commands::List | Commands::Check { .. })) {
            bail!("`--json` is only supported with `list` and `check`");
        }

        if self.interval.is_some() && self.command.is_some() {
            bail!("`--interval` is only supported when launching the TUI with no subcommand");
        }

        Ok(())
    }

    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs(self.interval.unwrap_or(DEFAULT_INTERVAL_SECS))
    }
}

pub fn print_help(topic: Option<String>) -> Result<()> {
    let normalized = topic
        .as_deref()
        .unwrap_or("--help")
        .trim()
        .trim_start_matches('-')
        .to_ascii_lowercase();

    let mut command = Cli::command();

    if normalized.is_empty() || normalized == "h" || normalized == "help" {
        command.print_long_help()?;
        println!();
        return Ok(());
    }

    let target = match normalized.as_str() {
        "ls" => "list",
        other => other,
    };

    if let Some(subcommand) = command.find_subcommand_mut(target) {
        subcommand.print_long_help()?;
        println!();
        return Ok(());
    }

    bail!("Unknown help topic `{}`", topic.unwrap_or_default())
}

pub fn run_hold_port(port: u16) -> Result<()> {
    let _listener = TcpListener::bind(("127.0.0.1", port))?;
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn rejects_json_without_supported_subcommand() {
        let cli = Cli::parse_from(["ports", "--json", "kill", "3000"]);
        let error = cli.validate().expect_err("json should be rejected");
        assert!(error.to_string().contains("`--json`"));
    }

    #[test]
    fn rejects_interval_for_subcommands() {
        let cli = Cli::parse_from(["ports", "--interval", "5", "list"]);
        let error = cli.validate().expect_err("interval should be rejected");
        assert!(error.to_string().contains("`--interval`"));
    }

    #[test]
    fn accepts_json_for_check() {
        let cli = Cli::parse_from(["ports", "--json", "check", "3000"]);
        cli.validate().expect("json should be accepted for check");
    }
}
