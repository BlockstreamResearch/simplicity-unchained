mod cli;
mod config;
mod handlers;
mod validation;
mod work;

use cli::{Cli, Commands};
use config::Config;

use simplicity_unchained_core::{BitcoinNetwork, ElementsNetwork};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use axum::Router;
use clap::Parser;
use log::{error, info};
use tokio::net::TcpListener;

use crate::handlers::SignerState;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Start { config } => start(config).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{}", e);
            ExitCode::FAILURE
        }
    }
}

async fn start(config_path: PathBuf) -> Result<(), String> {
    let config =
        Config::from_file(config_path).map_err(|e| format!("Failed to load config: {}", e))?;

    let elements_network = ElementsNetwork::from_str(&config.service.elements_network)
        .map_err(|e| format!("Failed to parse Elements network: {}", e))?;

    let bitcoin_network = BitcoinNetwork::from_str(&config.service.bitcoin_network)
        .map_err(|e| format!("Failed to parse Bitcoin network: {}", e))?;

    let signer_state = SignerState::new(
        &config.service.private_key,
        elements_network,
        bitcoin_network,
    )
    .map_err(|e| format!("Failed to initialize signer state: {}", e))?;

    let app = Router::new().merge(handlers::routes(signer_state));

    let bind_addr = format!("0.0.0.0:{}", config.service.port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;
    info!("Starting service on {}...", bind_addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {}", e))
}
