mod commands;
mod demo_script;

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

        /// User leaf hash in hex format
        #[arg(long)]
        user_leaf_hash: String,

        /// Network (elements, liquid, liquid_testnet, bitcoin, testnet, testnet4)
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

        /// Relative timelock in blocks for recovery path
        #[arg(long)]
        sequence: Option<u16>,
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

        #[arg(short, long)]
        cosigner_pubkey: Option<String>,

        /// User leaf script in hex format
        #[arg(long)]
        user_leaf_hash: String,
    },

    /// Finalize a PSBT into a broadcastable transaction
    Finalize {
        /// PSBT in hex format
        #[arg(short, long)]
        psbt: String,
    },

    /// Spend the user leaf (Leaf 1) of a P2TR output independently
    SpendUserLeaf {
        /// PSBT in hex format
        #[arg(short, long)]
        psbt: String,

        /// User secret key in hex format
        #[arg(short = 'k', long)]
        secret_key: String,

        /// User leaf script in hex format
        #[arg(long)]
        user_leaf_script: String,

        /// Cosigner public key in hex format
        #[arg(long)]
        cosigner_pubkey: String,

        /// Input index to sign
        #[arg(short, long, default_value_t = 0)]
        input_index: usize,

        /// Network (bitcoin, testnet)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },

    /// Build a CSV recovery leaf script from a user pubkey and timelock
    BuildCsvLeaf {
        /// User public key in hex format
        #[arg(long)]
        user_pubkey: String,

        /// Timelock in blocks
        #[arg(long)]
        timelock: u16,
    },

    /// Finalize a user leaf (Leaf 1) PSBT into a broadcastable transaction
    FinalizeUserLeaf {
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

        /// Relative timelock in blocks for recovery path
        #[arg(long)]
        sequence: Option<u16>,
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

        #[arg(short, long)]
        cosigner_pubkey: String,

        /// User leaf script in hex format
        #[arg(long)]
        user_leaf_hash: String,

        /// Network (elements, liquid, liquid_testnet)
        #[arg(short, long, default_value = "liquid_testnet")]
        network: String,
    },

    /// Finalize a PSET into a broadcastable transaction
    Finalize {
        /// PSET in hex format
        #[arg(short, long)]
        pset: String,
    },

    /// Spend the user leaf (Leaf 1) of a P2TR output independently
    SpendUserLeaf {
        /// PSET in hex format
        #[arg(short, long)]
        psbt: String,

        /// User secret key in hex format
        #[arg(short = 'k', long)]
        secret_key: String,

        /// User leaf script in hex format
        #[arg(long)]
        user_leaf_script: String,

        /// Cosigner public key in hex format
        #[arg(long)]
        cosigner_pubkey: String,

        /// Input index to sign
        #[arg(short, long, default_value_t = 0)]
        input_index: usize,

        /// Network (elements, liquid, liquid_testnet)
        #[arg(short, long, default_value = "liquid_testnet")]
        network: String,
    },

    /// Build a CSV recovery leaf script from a user pubkey and timelock
    BuildCsvLeaf {
        /// User public key in hex format
        #[arg(long)]
        user_pubkey: String,

        /// Timelock in blocks
        #[arg(long)]
        timelock: u16,
    },

    /// Finalize a user leaf (Leaf 1) PSBT into a broadcastable transaction
    FinalizeUserLeaf {
        /// PSET in hex format
        #[arg(short, long)]
        psbt: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Address { command } => match command {
            AddressCommands::Multisig {
                pubkey1,
                pubkey2,
                user_leaf_hash,
                network,
            } => {
                commands::address::multisig::execute(&pubkey1, &pubkey2, &user_leaf_hash, &network)?
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
                sequence,
            } => {
                commands::tx::create::execute(
                    &inputs,
                    &outputs,
                    asset.as_deref(),
                    &network,
                    sequence,
                )?;
            }

            TxCommands::Sign {
                pset,
                secret_key,
                input_index,
                cosigner_pubkey,
                user_leaf_hash,
                network,
            } => {
                commands::tx::sign::execute(
                    &pset,
                    &secret_key,
                    input_index,
                    &cosigner_pubkey,
                    &user_leaf_hash,
                    &network,
                )?;
            }

            TxCommands::Finalize { pset } => {
                commands::tx::finalize::execute(&pset)?;
            }
            TxCommands::SpendUserLeaf {
                psbt: pset,
                secret_key,
                user_leaf_script,
                cosigner_pubkey,
                input_index,
                network,
            } => {
                commands::tx::spend_user_leaf::execute(
                    &pset,
                    &secret_key,
                    &user_leaf_script,
                    &cosigner_pubkey,
                    input_index,
                    &network,
                )?;
            }

            TxCommands::BuildCsvLeaf {
                user_pubkey,
                timelock,
            } => {
                demo_script::csv_leaf_elements::build_csv_script(&user_pubkey, timelock)?;
            }

            TxCommands::FinalizeUserLeaf { psbt: pset } => {
                demo_script::csv_leaf_elements::finalize_user_leaf(&pset)?;
            }
        },

        Commands::BtcTx { command } => match command {
            BtcTxCommands::Create {
                inputs,
                outputs,
                network,
                sequence,
            } => {
                commands::btc_tx::create::execute(&inputs, &outputs, &network, sequence)?;
            }

            BtcTxCommands::Sign {
                psbt,
                secret_key,
                input_index,
                cosigner_pubkey,
                user_leaf_hash,
            } => {
                commands::btc_tx::sign::execute(
                    &psbt,
                    &secret_key,
                    input_index,
                    cosigner_pubkey.as_deref(),
                    &user_leaf_hash,
                )?;
            }

            BtcTxCommands::Finalize { psbt } => {
                commands::btc_tx::finalize::execute(&psbt)?;
            }

            BtcTxCommands::SpendUserLeaf {
                psbt,
                secret_key,
                user_leaf_script,
                cosigner_pubkey,
                input_index,
                network,
            } => {
                commands::btc_tx::spend_user_leaf::execute(
                    &psbt,
                    &secret_key,
                    &user_leaf_script,
                    &cosigner_pubkey,
                    input_index,
                    &network,
                )?;
            }

            BtcTxCommands::BuildCsvLeaf {
                user_pubkey,
                timelock,
            } => {
                demo_script::csv_leaf_btc::build_csv_script(&user_pubkey, timelock)?;
            }

            BtcTxCommands::FinalizeUserLeaf { psbt } => {
                demo_script::csv_leaf_btc::finalize_user_leaf(&psbt)?;
            }
        },
    }

    Ok(())
}
