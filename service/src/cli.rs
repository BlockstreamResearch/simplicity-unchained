use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "service")]
#[command(about = "Simplicity Unchained Service", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the service
    Start {
        /// Path to the configuration file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
}
