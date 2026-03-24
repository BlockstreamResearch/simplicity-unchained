pub mod sign_psbt;
pub mod sign_pset;
pub mod tweak;

use std::sync::Arc;

use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};

use serde::Serialize;

use serde_json::json;

use hal_simplicity::simplicity::elements::secp256k1_zkp::{All, Secp256k1, SecretKey};

use simplicity_unchained_core::{BitcoinNetwork, ElementsNetwork};

async fn version() -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub fn routes(signer_state: SignerState) -> Router {
    Router::new()
        .route("/simplicity-unchained/version", get(version))
        .route(
            "/simplicity-unchained/sign/psbt",
            post(sign_psbt::sign_psbt),
        )
        .route(
            "/simplicity-unchained/sign/pset",
            post(sign_pset::sign_pset),
        )
        .route("/simplicity-unchained/tweak", post(tweak::get_tweaked_key))
        .with_state(signer_state)
}

#[derive(Clone, Debug)]
pub struct SignerState {
    pub secret_key: SecretKey,
    pub secp: Arc<Secp256k1<All>>,
    pub elements_network: ElementsNetwork,
    pub bitcoin_network: BitcoinNetwork,
    pub has_custom_jets: bool,
}

impl SignerState {
    pub fn new(
        secret_key_hex: &str,
        elements_network: ElementsNetwork,
        bitcoin_network: BitcoinNetwork,
    ) -> Result<Self, String> {
        let secret_key_bytes =
            hex::decode(secret_key_hex).map_err(|e| format!("Invalid private key hex: {}", e))?;

        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;

        let has_custom_jets = std::env::var("JET_DLL_PATH").is_ok();

        Ok(Self {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network,
            bitcoin_network,
            has_custom_jets,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
