use std::str::FromStr;

use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use simplicity::{ConstructNode, node::CoreConstructible, types};
use tower::ServiceExt;

fn test_state() -> SignerState {
    SignerState::new(&hex::encode([0xcd; 32]), BitcoinNetwork::Testnet4).unwrap()
}

#[test]
fn disclosed_demo_identity_is_rejected_for_both_parities() {
    for prefix in ["02", "03"] {
        let public_key = PublicKey::from_str(&format!("{prefix}{DISCLOSED_DEMO_KEY}")).unwrap();
        assert!(
            validate_signing_identity(public_key.x_only_public_key().0)
                .unwrap_err()
                .contains("publicly disclosed demo signing key")
        );
    }
    assert!(SignerState::new("", BitcoinNetwork::Testnet4).is_err());
    assert!(SignerState::new(&hex::encode([0; 32]), BitcoinNetwork::Testnet4).is_err());
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

const POLICY_POST_PATHS: [&str; 4] = [
    "/simplicity-unchained/policy/bitcoin/tweak",
    "/simplicity-unchained/policy/bitcoin/prepare",
    "/simplicity-unchained/policy/bitcoin/evaluate",
    "/simplicity-unchained/policy/bitcoin/sign",
];

#[tokio::test]
async fn legacy_routes_are_not_available_even_when_workers_are_busy() {
    let state = test_state();
    let slots = [
        Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
        Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
    ];
    for path in [
        "/simplicity-unchained/tweak",
        "/simplicity-unchained/sign/psbt",
        "/simplicity-unchained/sign/pset",
    ] {
        for method in ["GET", "POST"] {
            let response = routes(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    drop(slots);
}

#[tokio::test]
async fn cpu_admission_is_shared_and_precedes_json_extraction() {
    let state = test_state();
    let slots = [
        Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
        Arc::clone(&state.work_slots).acquire_owned().await.unwrap(),
    ];
    for path in POLICY_POST_PATHS {
        let response = routes(state.clone())
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    for (path, expected) in [
        (
            "/simplicity-unchained/policy/bitcoin/capabilities",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        ("/simplicity-unchained/version", StatusCode::OK),
    ] {
        let response = routes(state.clone())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    drop(slots);
    let response = routes(state.clone())
        .oneshot(
            Request::get("/simplicity-unchained/policy/bitcoin/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.work_slots.available_permits(), MAX_BLOCKING_JOBS);
}

#[tokio::test]
async fn malformed_requests_release_admission_slots() {
    let state = test_state();
    for path in POLICY_POST_PATHS {
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
            Request::post("/simplicity-unchained/policy/bitcoin/tweak")
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
