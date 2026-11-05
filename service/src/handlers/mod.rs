pub mod sign_psbt;
pub mod sign_pset;
pub mod tweak;

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

use simplicity::elements::secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::work::{MAX_BLOCKING_JOBS, MAX_BODY_BYTES};
use simplicity_unchained_core::{BitcoinNetwork, ElementsNetwork};
use tokio::sync::Semaphore;

// Public identity of the disclosed demo key; also reject its negation (same Taproot identity).
const DISCLOSED_DEMO_KEY: &str = "3523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf";

fn validate_signing_identity(public_key: XOnlyPublicKey) -> Result<(), String> {
    if public_key.to_string() == DISCLOSED_DEMO_KEY {
        return Err(
            "The publicly disclosed demo signing key is not allowed; provision a new private key"
                .to_string(),
        );
    }
    Ok(())
}

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
        .route_layer(middleware::from_fn(crate::work::request_deadline))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(signer_state)
}

#[derive(Clone, Debug)]
pub struct SignerState {
    pub secret_key: SecretKey,
    pub secp: Arc<Secp256k1<All>>,
    pub elements_network: ElementsNetwork,
    pub bitcoin_network: BitcoinNetwork,
    pub work_slots: Arc<Semaphore>,
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

        let secp = Secp256k1::new();
        validate_signing_identity(
            PublicKey::from_secret_key(&secp, &secret_key)
                .x_only_public_key()
                .0,
        )?;

        Ok(Self {
            secret_key,
            secp: Arc::new(secp),
            elements_network,
            bitcoin_network,
            work_slots: Arc::new(Semaphore::new(MAX_BLOCKING_JOBS)),
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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use simplicity::{
        ConstructNode, Word,
        bitcoin::PublicKey,
        elements::secp256k1_zkp::{Keypair, Message},
        jet::Jet,
        node::{CoreConstructible, WitnessConstructible},
        types,
    };
    use tower::ServiceExt;

    fn test_state() -> SignerState {
        SignerState::new(
            &hex::encode([0xcd; 32]),
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        )
        .unwrap()
    }

    #[test]
    fn disclosed_demo_identity_is_rejected_for_both_parities() {
        for prefix in ["02", "03"] {
            let public_key = simplicity::elements::secp256k1_zkp::PublicKey::from_str(&format!(
                "{}{}",
                prefix, DISCLOSED_DEMO_KEY
            ))
            .unwrap();
            let result = validate_signing_identity(public_key.x_only_public_key().0);
            assert!(
                result
                    .unwrap_err()
                    .contains("publicly disclosed demo signing key")
            );
        }
        assert!(
            SignerState::new("", ElementsNetwork::LiquidTestnet, BitcoinNetwork::Testnet,).is_err()
        );
        assert!(
            SignerState::new(
                &hex::encode([0; 32]),
                ElementsNetwork::LiquidTestnet,
                BitcoinNetwork::Testnet,
            )
            .is_err()
        );
    }

    pub(super) async fn post_json(
        state: &SignerState,
        path: &str,
        body: serde_json::Value,
    ) -> Response {
        routes(state.clone())
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub(super) fn expensive_program() -> String {
        let bytes = types::Context::with_context(|ctx| {
            let mut node = Arc::<ConstructNode>::unit(&ctx);
            for _ in 0..20 {
                node = Arc::<ConstructNode>::comp(&node, &node).unwrap();
            }
            node.finalize_types().unwrap().to_vec_without_witness()
        });
        assert!(bytes.len() < 256);
        STANDARD.encode(bytes)
    }

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
        let response = post_json(
            state,
            "/simplicity-unchained/tweak",
            json!({
                "program": program,
                "jet_env": match jet_env {
                    tweak::JetEnvKind::Bitcoin => "bitcoin",
                    tweak::JetEnvKind::Elements => "elements",
                },
                "redeem_script_hex": script,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        PublicKey::from_str(result["tweaked_public_key_hex"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn cpu_admission_is_shared_and_precedes_json_extraction() {
        let state = test_state();
        let slots = [
            Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
            Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
        ];
        let app = routes(state.clone());
        for path in [
            "/simplicity-unchained/sign/psbt",
            "/simplicity-unchained/sign/pset",
            "/simplicity-unchained/tweak",
        ] {
            let response = app
                .clone()
                .oneshot(Request::post(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let response = app
            .oneshot(
                Request::get("/simplicity-unchained/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(slots);
        let response = post_json(
            &state,
            "/simplicity-unchained/tweak",
            json!({
                "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.work_slots.available_permits(), MAX_BLOCKING_JOBS);
    }

    #[tokio::test]
    async fn request_body_limit_has_exact_boundary() {
        let state = test_state();
        let mut body = json!({
            "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
        })
        .to_string();
        body.extend(std::iter::repeat_n(' ', MAX_BODY_BYTES - body.len()));
        for (extra, status) in [(0, StatusCode::OK), (1, StatusCode::PAYLOAD_TOO_LARGE)] {
            let response = routes(state.clone())
                .oneshot(
                    Request::post("/simplicity-unchained/tweak")
                        .header("content-type", "application/json")
                        .body(Body::from(format!("{}{}", body, " ".repeat(extra))))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(state.work_slots.available_permits(), MAX_BLOCKING_JOBS);
        }
    }

    #[tokio::test]
    async fn malformed_requests_release_admission_slots() {
        let state = test_state();
        for path in [
            "/simplicity-unchained/sign/psbt",
            "/simplicity-unchained/sign/pset",
            "/simplicity-unchained/tweak",
        ] {
            let response = post_json(&state, path, json!({})).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(state.work_slots.available_permits(), MAX_BLOCKING_JOBS);
        }
    }

    #[tokio::test]
    async fn stalled_body_hits_request_deadline_and_releases_slot() {
        use axum::body::{Bytes, HttpBody};
        use std::{
            convert::Infallible,
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        };

        struct StalledBody;
        impl HttpBody for StalledBody {
            type Data = Bytes;
            type Error = Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Poll::Pending
            }
        }

        let state = test_state();
        let response = tokio::time::timeout(
            Duration::from_secs(6),
            routes(state.clone()).oneshot(
                Request::post("/simplicity-unchained/tweak")
                    .header("content-type", "application/json")
                    .body(Body::new(StalledBody))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(state.work_slots.available_permits(), MAX_BLOCKING_JOBS);
    }
}
