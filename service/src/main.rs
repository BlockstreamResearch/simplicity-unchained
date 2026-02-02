mod cli;
mod config;
mod handlers;
mod validation;

use cli::{Cli, Commands};
use config::Config;

use simplicity_unchained_core::{BitcoinNetwork, ElementsNetwork};
use std::path::PathBuf;
use std::str::FromStr;

use axum::Router;
use clap::Parser;
use log::{error, info};
use tokio::net::TcpListener;

use crate::handlers::SignerState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => {
            start(config).await;
        }
    }
}

async fn start(config_path: PathBuf) {
    let config = match Config::from_file(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load config: {}", e);
            return;
        }
    };

    let elements_network = match ElementsNetwork::from_str(&config.service.elements_network) {
        Ok(network) => network,
        Err(e) => {
            error!("Failed to parse network: {}", e);
            return;
        }
    };

    let bitcoin_network = match BitcoinNetwork::from_str(&config.service.bitcoin_network) {
        Ok(network) => network,
        Err(e) => {
            error!("Failed to parse bitcoin network: {}", e);
            return;
        }
    };

    // Initialize signer state from config
    let signer_state = match SignerState::new(
        &config.service.private_key,
        elements_network,
        bitcoin_network,
    ) {
        Ok(state) => state,
        Err(e) => {
            error!("Failed to initialize signer state: {}", e);
            return;
        }
    };

    let app = Router::new().merge(handlers::routes(signer_state));

    let bind_addr = format!("0.0.0.0:{}", config.service.port);
    info!("Starting service on {}...", bind_addr);

    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", bind_addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
    }
}
