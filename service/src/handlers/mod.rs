pub mod sign;

use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};

use serde::Serialize;

use serde_json::json;

async fn version() -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub fn routes(signer_state: sign::SignerState) -> Router {
    Router::new()
        .route("/version", get(version))
        .route("/sign/pset", post(sign::sign_pset))
        .with_state(signer_state)
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
