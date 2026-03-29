use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Prepare {
        #[arg(short, long, default_value = "gcc")]
        cc: String,

        file: Vec<String>
    },
    Apply { file: String },
}