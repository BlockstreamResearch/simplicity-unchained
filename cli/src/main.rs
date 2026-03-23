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

    /// Transaction operations (Elements/Liquid)
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },

    /// Bitcoin transaction operations
    BtcTx {
        #[command(subcommand)]
        command: BtcTxCommands,
    },
}

#[derive(Subcommand)]
enum AddressCommands {
    /// Generate a 2-of-2 multisig address from two public keys.
    /// Use --type to select p2sh (legacy) or p2wsh (segwit v0). Defaults to p2wsh.
    Multisig {
        /// First public key in hex format
        #[arg(short = '1', long)]
        pubkey1: String,

        /// Second public key in hex format
        #[arg(short = '2', long)]
        pubkey2: String,

        /// Network (elements, liquid, liquid_testnet, bitcoin, testnet, testnet4)
        #[arg(short, long, default_value = "elements")]
        network: String,

        /// Script type: p2wsh (default) or p2sh
        #[arg(short, long, default_value = "p2wsh")]
        type_: String,
    },

    /// Generate a P2TR (Taproot) address from a single public key.
    /// The key is used as the internal key and tweaked with the Simplicity CMR.
    P2tr {
        /// Public key in hex format (the tweaked co-signer key)
        #[arg(short, long)]
        pubkey: String,

        /// Public key in hex format (the tweaked co-signer key)
        #[arg(short, long)]
        cmr: String,

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
enum BtcTxCommands {
    /// Create a PSBT (PartiallySignedTransaction) from UTXOs
    Create {
        /// Transaction input in format: txid:vout
        #[arg(short = 'i', long = "input", num_args = 1.., required = true)]
        inputs: Vec<String>,

        /// Transaction output in format: address:value
        #[arg(short = 'o', long = "output", num_args = 1.., required = true)]
        outputs: Vec<String>,

        /// Network (bitcoin, testnet)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },

    /// Sign a PSBT with one secret key (for co-signing)
    Sign {
        /// PSBT in hex format
        #[arg(short, long)]
        psbt: String,

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

    /// Finalize a PSBT into a broadcastable transaction
    Finalize {
        /// PSBT in hex format
        #[arg(short, long)]
        psbt: String,
    },
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
                type_,
            } => {
                commands::address::multisig::execute(&pubkey1, &pubkey2, &network, &type_)?;
            }
            AddressCommands::P2tr {
                pubkey,
                cmr,
                network,
            } => {
                commands::address::p2tr::execute(&pubkey, &cmr, &network)?;
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

        Commands::BtcTx { command } => match command {
            BtcTxCommands::Create {
                inputs,
                outputs,
                network,
            } => {
                commands::btc_tx::create::execute(&inputs, &outputs, &network)?;
            }

            BtcTxCommands::Sign {
                psbt,
                secret_key,
                input_index,
                redeem_script,
            } => {
                commands::btc_tx::sign::execute(&psbt, &secret_key, input_index, &redeem_script)?;
            }

            BtcTxCommands::Finalize { psbt } => {
                commands::btc_tx::finalize::execute(&psbt)?;
            }
        },
    }

    Ok(())
}
