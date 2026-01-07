mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "simplicity-unchained")]
#[command(about = "A CLI tool for Simplicity Unchained utilities", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Address operations
    Address {
        #[command(subcommand)]
        command: AddressCommands,
    },

    /// Keypair operations
    Keypair {
        #[command(subcommand)]
        command: KeypairCommands,
    },

    /// Transaction operations
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },
}

#[derive(Subcommand)]
enum AddressCommands {
    /// Generate a 2-of-2 multisig address from two public keys
    Multisig {
        /// First public key in hex format
        #[arg(short = '1', long)]
        pubkey1: String,

        /// Second public key in hex format
        #[arg(short = '2', long)]
        pubkey2: String,

        /// Network (elements, liquid, liquid_testnet)
        #[arg(short, long, default_value = "elements")]
        network: String,
    },
}

#[derive(Subcommand)]
enum KeypairCommands {
    /// Generate a new keypair
    Generate,
}

#[derive(Subcommand)]
enum TxCommands {
    /// Create a PSET (PartiallySignedTransaction) from UTXOs
    Create {
        /// Transaction input in format: txid:vout
        #[arg(short = 'i', long = "input", num_args = 1.., required = true)]
        inputs: Vec<String>,

        /// Transaction output in format: address:value
        #[arg(short = 'o', long = "output", num_args = 1.., required = true)]
        outputs: Vec<String>,

        /// Asset ID (defaults to L-BTC on Liquid/Elements)
        #[arg(short, long)]
        asset: Option<String>,

        /// Network (elements, liquid, liquid_testnet)
        #[arg(short, long, default_value = "elements")]
        network: String,
    },

    /// Sign a PSET with one secret key (for co-signing)
    Sign {
        /// PSET in hex format
        #[arg(short, long)]
        pset: String,

        /// Secret key in hex format
        #[arg(short = 'k', long)]
        secret_key: String,

        /// Input index to sign
        #[arg(short, long)]
        input_index: usize,

        /// Redeem script in hex format
        #[arg(short, long)]
        redeem_script: String,
    },

    /// Finalize a PSET into a broadcastable transaction
    Finalize {
        /// PSET in hex format
        #[arg(short, long)]
        pset: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Address { command } => match command {
            AddressCommands::Multisig {
                pubkey1,
                pubkey2,
                network,
            } => {
                commands::address::multisig::execute(&pubkey1, &pubkey2, &network)?;
            }
        },

        Commands::Keypair { command } => match command {
            KeypairCommands::Generate => {
                commands::keypair::generate::execute()?;
            }
        },

        Commands::Tx { command } => match command {
            TxCommands::Create {
                inputs,
                outputs,
                asset,
                network,
            } => {
                commands::tx::create::execute(&inputs, &outputs, asset.as_deref(), &network)?;
            }

            TxCommands::Sign {
                pset,
                secret_key,
                input_index,
                redeem_script,
            } => {
                commands::tx::sign::execute(&pset, &secret_key, input_index, &redeem_script)?;
            }

            TxCommands::Finalize { pset } => {
                commands::tx::finalize::execute(&pset)?;
            }
        },
    }

    Ok(())
}
