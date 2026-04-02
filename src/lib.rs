pub mod cli;
pub mod inspect;
pub mod model;
pub mod output;
pub mod tui;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use inspect::PortCollector;

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    cli.validate()?;
    let collector = PortCollector::new();

    match cli.command {
        None => tui::run_app(collector, cli.refresh_interval()),
        Some(Commands::List) if cli.json => output::print_table_json(&collector.collect()?),
        Some(Commands::List) => output::print_table(&collector.collect()?),
        Some(Commands::Check { port }) if cli.json => {
            output::print_check_result_json(&collector.collect_port(port)?, port)
        }
        Some(Commands::Check { port }) => {
            output::print_check_result(&collector.collect_port(port)?, port)
        }
        Some(Commands::Kill { port }) => {
            output::print_kill_result(&collector.kill_port(port)?, port)
        }
        Some(Commands::Help { topic }) => cli::print_help(topic),
        Some(Commands::InternalHoldPort { port }) => cli::run_hold_port(port),
    }
}
