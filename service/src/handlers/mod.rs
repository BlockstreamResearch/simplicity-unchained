pub mod liquid_policy;
pub mod policy;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use serde_json::json;
use simplicity::elements::secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey};
use simplicity_unchained_core::BitcoinNetwork;
use tokio::sync::Semaphore;

use crate::work::{MAX_BLOCKING_JOBS, MAX_BODY_BYTES};

async fn version() -> impl IntoResponse {
    Json(json!({ "version": env!("CARGO_PKG_VERSION") }))
}

pub fn routes(signer_state: SignerState) -> Router {
    Router::new()
        .route(
            "/simplicity-unchained/policy/liquid/capabilities",
            get(liquid_policy::capabilities),
        )
        .route(
            "/simplicity-unchained/policy/liquid/tweak",
            post(liquid_policy::tweak),
        )
        .route(
            "/simplicity-unchained/policy/liquid/prepare",
            post(liquid_policy::prepare),
        )
        .route(
            "/simplicity-unchained/policy/liquid/evaluate",
            post(liquid_policy::evaluate),
        )
        .route(
            "/simplicity-unchained/policy/liquid/sign",
            post(liquid_policy::sign),
        )
        .route("/simplicity-unchained/version", get(version))
        .route(
            "/simplicity-unchained/policy/bitcoin/capabilities",
            get(policy::capabilities),
        )
        .route(
            "/simplicity-unchained/policy/bitcoin/tweak",
            post(policy::tweak),
        )
        .route(
            "/simplicity-unchained/policy/bitcoin/prepare",
            post(policy::prepare),
        )
        .route(
            "/simplicity-unchained/policy/bitcoin/evaluate",
            post(policy::evaluate),
        )
        .route(
            "/simplicity-unchained/policy/bitcoin/sign",
            post(policy::sign),
        )
        .route_layer(middleware::from_fn(crate::work::request_deadline))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(signer_state)
}

#[derive(Clone, Debug)]
pub struct SignerState {
    pub secret_key: SecretKey,
    pub secp: Arc<Secp256k1<All>>,
    pub bitcoin_network: BitcoinNetwork,
    pub liquid_network: simplicity_unchained_policy::liquid::Network,
    pub work_slots: Arc<Semaphore>,
}

impl SignerState {
    pub fn new(secret_key_hex: &str, bitcoin_network: BitcoinNetwork) -> Result<Self, String> {
        let secret_key_bytes =
            hex::decode(secret_key_hex).map_err(|e| format!("Invalid private key hex: {}", e))?;
        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        let secp = Secp256k1::new();
        Ok(Self {
            secret_key,
            secp: Arc::new(secp),
            bitcoin_network,
            liquid_network: Default::default(),
            work_slots: Arc::new(Semaphore::new(MAX_BLOCKING_JOBS)),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests;
