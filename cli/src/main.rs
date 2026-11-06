mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "simplicity-unchained")]
#[command(about = "Profile-bound policy signing utilities for Simplicity Unchained")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Confidential multi-asset liquid-policy-v1 utilities (not legacy tx)
    LiquidPolicy {
        #[command(subcommand)]
        command: Box<commands::liquid_policy::Command>,
    },
    /// Bitcoin policy-profile funding, evaluation and signing
    Policy {
        #[command(subcommand)]
        command: Box<commands::policy::PolicyCommand>,
    },
    /// Keypair operations
    Keypair {
        #[command(subcommand)]
        command: KeypairCommands,
    },
}

#[derive(Subcommand)]
enum KeypairCommands {
    /// Generate a new keypair
    Generate,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::LiquidPolicy { command } => commands::liquid_policy::execute(*command),
        Commands::Policy { command } => commands::policy::execute(*command),
        Commands::Keypair {
            command: KeypairCommands::Generate,
        } => commands::keypair::generate::execute(),
    }
}
