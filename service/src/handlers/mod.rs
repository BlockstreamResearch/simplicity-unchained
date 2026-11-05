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

use simplicity::elements::secp256k1_zkp::{All, Secp256k1, SecretKey};

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

        Ok(Self {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network,
            bitcoin_network,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use axum::extract::State;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use simplicity::{
        ConstructNode, Word,
        bitcoin::PublicKey,
        elements::secp256k1_zkp::{Keypair, Message},
        jet::Jet,
        node::{CoreConstructible, WitnessConstructible},
        types,
    };

    pub(super) fn script_key_program<J: Jet>(
        get_pubkey: J,
        verify: J,
        secret_key: &SecretKey,
    ) -> (String, String) {
        let program = types::Context::with_context(|ctx| {
            let index = Arc::<ConstructNode>::const_word(&ctx, Word::u8(1));
            let key_jet = Arc::<ConstructNode>::jet(&ctx, &get_pubkey);
            let key = Arc::<ConstructNode>::comp(&index, &key_jet).unwrap();
            let msg = Arc::<ConstructNode>::const_word(&ctx, Word::u256([0x42; 32]));
            let key_msg = Arc::<ConstructNode>::pair(&key, &msg).unwrap();
            let signature = Arc::<ConstructNode>::witness(&ctx, None);
            let args = Arc::<ConstructNode>::pair(&key_msg, &signature).unwrap();
            let verify_jet = Arc::<ConstructNode>::jet(&ctx, &verify);
            Arc::<ConstructNode>::comp(&args, &verify_jet)
                .unwrap()
                .finalize_types()
                .unwrap()
                .to_vec_without_witness()
        });
        let secp = Secp256k1::new();
        let signature = secp.sign_schnorr(
            &Message::from_digest([0x42; 32]),
            &Keypair::from_secret_key(&secp, secret_key),
        );
        (
            STANDARD.encode(program),
            STANDARD.encode(signature.as_ref()),
        )
    }

    pub(super) fn key_script(state: &SignerState, secret_key: &SecretKey) -> String {
        let key =
            simplicity::bitcoin::secp256k1::PublicKey::from_secret_key(&*state.secp, secret_key);
        format!("5221{}", hex::encode(key.serialize()))
    }

    pub(super) async fn tweaked_public_key(
        state: &SignerState,
        program: &str,
        script: Option<&str>,
        jet_env: tweak::JetEnvKind,
    ) -> PublicKey {
        let response = tweak::get_tweaked_key(
            State(state.clone()),
            Json(tweak::TweakRequest {
                program: program.to_string(),
                jet_env: Some(jet_env),
                redeem_script_hex: script.map(str::to_string),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        PublicKey::from_str(result["tweaked_public_key_hex"].as_str().unwrap()).unwrap()
    }
}
