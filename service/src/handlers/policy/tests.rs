use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use serde_json::{Value, json};
use simplicity::{
    ConstructNode, Word,
    bitcoin::{
        Amount, OutPoint, Sequence, TapNodeHash, Transaction, TxIn, TxOut,
        absolute::LockTime,
        key::UntweakedKeypair,
        psbt::Psbt,
        script::ScriptBuf,
        secp256k1::{Message, Secp256k1, SecretKey},
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
    },
    node::{CoreConstructible, WitnessConstructible},
    types,
};
use simplicity_unchained_core::{
    BitcoinNetwork,
    jets::bitcoin::CoreExtension,
    jets::policy::PolicyJet,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc},
};
use tower::ServiceExt;

use super::*;
use crate::handlers::routes;

const PREFIX: &str = "/simplicity-unchained/policy/bitcoin";

fn state() -> SignerState {
    SignerState::new(&hex::encode([0xcd; 32]), BitcoinNetwork::Testnet).unwrap()
}

fn unit_program() -> String {
    let bytes = types::Context::with_context(|ctx| {
        Arc::<ConstructNode>::unit(&ctx)
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    STANDARD.encode(bytes)
}

fn approval_program() -> (String, UntweakedKeypair) {
    let secp = Secp256k1::new();
    let key =
        UntweakedKeypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x44; 32]).unwrap());
    let bytes = types::Context::with_context(|ctx| {
        let public_key = Arc::<ConstructNode>::const_word(
            &ctx,
            Word::u256(key.x_only_public_key().0.serialize()),
        );
        let hash = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Builtin(policy::Builtin::PolicyTransactionApprovalHash),
        );
        let key_msg = Arc::<ConstructNode>::pair(&public_key, &hash).unwrap();
        let signature = Arc::<ConstructNode>::witness(&ctx, None);
        let args = Arc::<ConstructNode>::pair(&key_msg, &signature).unwrap();
        let verify = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Legacy(CoreExtension::Core(simplicity::jet::Core::Bip0340Verify)),
        );
        Arc::<ConstructNode>::comp(&args, &verify)
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    (STANDARD.encode(bytes), key)
}

async fn request(state: &SignerState, method: &str, operation: &str, body: Value) -> Response {
    routes(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("{PREFIX}/{operation}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn capabilities_body(state: &SignerState) -> Value {
    let response = request(state, "GET", "capabilities", Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

async fn fixture(state: &SignerState, program: &str) -> (Psbt, Value) {
    let capabilities = capabilities_body(state).await;
    let binding = json!({
        "profile_hash": capabilities["profile_hash"],
        "network": "testnet",
        "program": program,
        "redeem_script_hex": "",
    });
    let response = request(state, "POST", "tweak", binding.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tweak = body(response).await;
    let service_key = XOnlyPublicKey::from_str(tweak["public_key_hex"].as_str().unwrap()).unwrap();
    let secp = Secp256k1::new();
    let user =
        UntweakedKeypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x33; 32]).unwrap());
    let user_key = user.public_key();
    let recovery_hash = TapNodeHash::from_byte_array([0x42; 32]);
    let leaf = p2tr_multisig_leaf_btc(
        &service_key
            .public_key(bitcoin::secp256k1::Parity::Even)
            .into(),
        &user_key.into(),
    );
    let spend = TaprootBuilder::new()
        .add_leaf(1, leaf)
        .unwrap()
        .add_hidden_node(1, recovery_hash)
        .unwrap()
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .unwrap();
    // This parent is content evidence only, deliberately not a mined transaction.
    let parent = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        }],
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent.compute_txid(), 0),
            sequence: Sequence::from_height(144),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, user.x_only_public_key().0, None),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(parent.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(parent);
    let mut payload = binding;
    payload["psbt_hex"] = json!(hex::encode(psbt.serialize()));
    payload["input_index"] = json!(0);
    payload["user_pubkey"] = json!(user_key.to_string());
    payload["user_leaf_hash_hex"] = json!(hex::encode(recovery_hash.to_byte_array()));
    payload["witness"] = json!("");
    (psbt, payload)
}

#[tokio::test]
async fn capabilities_are_profile_and_network_specific() {
    let capabilities = capabilities_body(&state()).await;
    assert_eq!(capabilities["profile"], "bitcoin-policy-v1");
    assert_eq!(capabilities["network"], "testnet");
    assert_eq!(capabilities["profile_hash"].as_str().unwrap().len(), 64);
    assert_eq!(
        capabilities["base_public_key_hex"].as_str().unwrap().len(),
        64
    );
    assert_eq!(capabilities["provenance"], "parent-txid-verified");
    assert_eq!(
        capabilities["genesis_hash"],
        hex::encode(
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet)
                .block_hash()
                .to_byte_array()
        )
    );
}

#[tokio::test]
async fn prepare_evaluate_and_sign_use_the_exact_same_context() {
    let state = state();
    let (original, payload) = fixture(&state, &unit_program()).await;
    let response = request(&state, "POST", "prepare", payload.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let prepared = body(response).await;
    assert_eq!(prepared["context"]["fee"], 10_000);
    assert_eq!(prepared["context"]["debit"], 100_000);
    assert_eq!(prepared["context"]["chain_status_verified"], false);
    assert_eq!(prepared["context"]["provenance"], "parent-txid-verified");
    let response = request(&state, "POST", "evaluate", payload.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let evaluation = body(response).await;
    assert_eq!(evaluation["accepted"], true);
    assert_eq!(evaluation["context"], prepared["context"]);
    let response = request(&state, "POST", "sign", payload).await;
    assert_eq!(response.status(), StatusCode::OK);
    let signed = body(response).await;
    assert_eq!(signed["context"], prepared["context"]);
    let result =
        Psbt::deserialize(&hex::decode(signed["psbt_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(result.unsigned_tx, original.unsigned_tx);
    assert_eq!(
        result.inputs[0].witness_utxo,
        original.inputs[0].witness_utxo
    );
    assert_eq!(
        result.inputs[0].non_witness_utxo,
        original.inputs[0].non_witness_utxo
    );
    let key = XOnlyPublicKey::from_str(signed["public_key_hex"].as_str().unwrap()).unwrap();
    let digest: [u8; 32] = hex::decode(
        signed["context"]["cooperative_sighash_default"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(
        &hex::decode(signed["signature_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    state
        .secp
        .verify_schnorr(&signature, &Message::from_digest(digest), &key)
        .unwrap();
    assert_eq!(result.inputs[0].tap_script_sigs.len(), 1);
    assert_eq!(
        result.inputs[0]
            .tap_script_sigs
            .values()
            .next()
            .unwrap()
            .signature,
        signature
    );
    let (control, (script, version)) = result.inputs[0].tap_scripts.iter().next().unwrap();
    assert_eq!(*version, LeafVersion::TapScript);
    assert_eq!(
        hex::encode(
            bitcoin::sighash::ScriptPath::with_defaults(script)
                .leaf_hash()
                .to_byte_array()
        ),
        signed["context"]["cooperative_leaf_hash"]
    );
    let output_key = XOnlyPublicKey::from_slice(
        &original.inputs[0]
            .witness_utxo
            .as_ref()
            .unwrap()
            .script_pubkey
            .as_bytes()[2..],
    )
    .unwrap();
    assert!(control.verify_taproot_commitment(&*state.secp, output_key, script));
}

#[tokio::test]
async fn missing_or_inconsistent_parent_evidence_never_signs() {
    let state = state();
    let (mut psbt, mut payload) = fixture(&state, &unit_program()).await;
    psbt.inputs[0].non_witness_utxo = None;
    payload["psbt_hex"] = json!(hex::encode(psbt.serialize()));
    let response = request(&state, "POST", "sign", payload.clone()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error = body(response).await;
    assert_eq!(error["code"], "invalid_context");
    assert!(error.get("signature_hex").is_none());
    let (mut psbt, _) = fixture(&state, &unit_program()).await;
    psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(100_001);
    payload["psbt_hex"] = json!(hex::encode(psbt.serialize()));
    let response = request(&state, "POST", "sign", payload).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body(response).await.get("signature_hex").is_none());
}

#[tokio::test]
async fn mismatched_profile_and_network_reject_before_execution() {
    let state = state();
    let (_, payload) = fixture(&state, &unit_program()).await;
    for (field, value) in [
        ("profile_hash", json!(hex::encode([0u8; 32]))),
        ("network", json!("testnet4")),
    ] {
        let mut modified = payload.clone();
        modified[field] = value;
        modified["program"] = json!("invalid-base64");
        for operation in ["prepare", "evaluate", "sign"] {
            let response = request(&state, "POST", operation, modified.clone()).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let error = body(response).await;
            assert!(error["error"].as_str().unwrap().contains(field));
            assert!(error.get("signature_hex").is_none());
        }
    }
}

#[tokio::test]
async fn profile_key_is_isolated_even_for_a_jet_free_program() {
    let state = state();
    let capabilities = capabilities_body(&state).await;
    let program = unit_program();
    let new_response = request(
        &state,
        "POST",
        "tweak",
        json!({
            "profile_hash": capabilities["profile_hash"],
            "network": "testnet",
            "program": program,
            "redeem_script_hex": "",
        }),
    )
    .await;
    assert_eq!(new_response.status(), StatusCode::OK);
    let policy_key = body(new_response).await;
    let bytes = STANDARD.decode(program).unwrap();
    let cmr = simplicity_unchained_core::policy::policy_cmr(&bytes).unwrap();
    let key = UntweakedKeypair::from_secret_key(&state.secp, &state.secret_key)
        .tap_tweak(
            &state.secp,
            Some(TapNodeHash::from_byte_array(
                simplicity_unchained_core::utils::signing_commitment(cmr, &[]),
            )),
        )
        .to_keypair();
    assert_ne!(
        policy_key["public_key_hex"],
        key.x_only_public_key().0.to_string()
    );
}

#[tokio::test]
async fn policy_requests_have_the_same_exact_body_limit() {
    let state = state();
    let capabilities = capabilities_body(&state).await;
    let mut payload = json!({
        "profile_hash": capabilities["profile_hash"],
        "network": "testnet",
        "program": unit_program(),
        "redeem_script_hex": "",
    })
    .to_string();
    payload.extend(std::iter::repeat_n(' ', MAX_BODY_BYTES - payload.len()));
    for (extra, expected) in [(0, StatusCode::OK), (1, StatusCode::PAYLOAD_TOO_LARGE)] {
        let response = routes(state.clone())
            .oneshot(
                Request::post(format!("{PREFIX}/tweak"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!("{payload}{}", " ".repeat(extra))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn transaction_approval_prepares_without_a_signature_and_rejects_mutation() {
    let state = state();
    let (program, approver) = approval_program();
    let (mut psbt, mut payload) = fixture(&state, &program).await;
    payload.as_object_mut().unwrap().remove("witness");
    let response = request(&state, "POST", "prepare", payload.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let prepared = body(response).await;
    let digest: [u8; 32] = hex::decode(
        prepared["context"]["policy_transaction_approval_hash"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let approval = state
        .secp
        .sign_schnorr(&Message::from_digest(digest), &approver);
    payload["witness"] = json!(STANDARD.encode(approval.as_ref()));
    let response = request(&state, "POST", "sign", payload.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["context"], prepared["context"]);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(89_999);
    payload["psbt_hex"] = json!(hex::encode(psbt.serialize()));
    for operation in ["evaluate", "sign"] {
        let response = request(&state, "POST", operation, payload.clone()).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let error = body(response).await;
        assert_eq!(error["code"], "policy_rejected");
        assert!(error.get("signature_hex").is_none());
    }
}

#[tokio::test]
async fn removed_legacy_signing_endpoint_cannot_sign_new_profile_outputs() {
    let state = state();
    let (_, payload) = fixture(&state, &unit_program()).await;
    let response =
        crate::handlers::tests::post_json(&state, "/simplicity-unchained/sign/psbt", payload).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn over_cost_policy_rejects_without_a_success_shaped_signature() {
    let state = state();
    let program = crate::handlers::tests::expensive_program();
    let (_, payload) = fixture(&state, &program).await;
    let response = request(&state, "POST", "sign", payload).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error = body(response).await;
    assert_eq!(error["code"], "execution_limit");
    assert!(error.get("signature_hex").is_none());
    assert_eq!(
        state.work_slots.available_permits(),
        crate::work::MAX_BLOCKING_JOBS
    );
}
