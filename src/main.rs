mod cli;
mod cmd;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Prepare { cc, file } => cmd::prepare::run(cc, file),
        Command::Apply { file } => cmd::apply::run(file),
    }
}