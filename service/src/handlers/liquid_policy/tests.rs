#[allow(dead_code)]
mod common {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../policy/tests/common/liquid.rs"
    ));
}
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use policy::elements::{
    encode::{deserialize, serialize},
    pset::PartiallySignedTransaction,
};
use tower::ServiceExt;

fn state(f: &Fixture) -> SignerState {
    SignerState::new(
        &hex::encode(f.base_secret.secret_bytes()),
        simplicity_unchained_core::BitcoinNetwork::Testnet4,
    )
    .unwrap()
}
fn transaction(f: &Fixture, index: usize) -> Value {
    json!({"profile_hash":hex::encode(policy::profile_hash()),"network":f.network.name(),"program":STANDARD.encode(&f.program),"redeem_script_hex":hex::encode(&f.data),"pset_hex":hex::encode(serialize(&f.pset)),"input_index":index,"user_pubkey":f.user.to_string(),"user_leaf_hash_hex":hex::encode(f.recovery.to_byte_array()),"witness":""})
}
async fn request(state: &SignerState, method: &str, op: &str, body: Value) -> (StatusCode, Value) {
    let response = super::super::routes(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("/simplicity-unchained/policy/liquid/{op}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn confidential_multi_asset_http_prepare_evaluate_sign_user_finalize_roundtrip() {
    let mut f = Fixture::new();
    let s = state(&f);
    let (status, caps) = request(&s, "GET", "capabilities", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps["network"], "liquidtestnet");
    assert_eq!(caps["manifest"], policy::manifest());
    let binding = json!({"profile_hash":hex::encode(policy::profile_hash()),"network":"liquidtestnet","program":STANDARD.encode(&f.program),"redeem_script_hex":hex::encode(&f.data)});
    let (status, tweak) = request(&s, "POST", "tweak", binding).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        tweak["public_key_hex"],
        f.context(0)
            .unwrap()
            .cooperative()
            .service_pubkey
            .to_string()
    );
    for index in 0..2 {
        let local = f.context(index).unwrap();
        let expected = serde_json::to_value(local.summary()).unwrap();
        let (status, prepared) = request(&s, "POST", "prepare", transaction(&f, index)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(prepared["context"], expected);
        let (status, evaluated) = request(&s, "POST", "evaluate", transaction(&f, index)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(evaluated["context"], expected);
        assert_eq!(evaluated["accepted"], true);
        let (status, signed) = request(&s, "POST", "sign", transaction(&f, index)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(signed["context"], expected);
        let mut pset: PartiallySignedTransaction =
            deserialize(&hex::decode(signed["pset_hex"].as_str().unwrap()).unwrap()).unwrap();
        local.revalidate(&pset).unwrap();
        let actual = pset.inputs()[index]
            .tap_script_sigs
            .get(&(
                local.cooperative().service_pubkey,
                local.cooperative().leaf_hash,
            ))
            .unwrap();
        assert_eq!(signed["signature_hex"], hex::encode(actual.sig.as_ref()));
        policy::add_signature(&local, &mut pset, f.user_secret, false).unwrap();
        f.pset = pset;
    }
    let context = f.context(0).unwrap();
    let tx = policy::finalize(&context, &f.pset).unwrap();
    assert!(tx.input.iter().all(|i| i.witness.script_witness.len() == 4));
    tx.verify_tx_amt_proofs(&Secp256k1::new(), context.prevouts())
        .unwrap();
}
#[tokio::test]
async fn http_sign_rejects_tampered_labels_missing_proofs_evidence_and_replays() {
    let f = Fixture::new();
    let s = state(&f);
    for mutation in 0..9 {
        let mut pset = f.pset.clone();
        match mutation {
            0 => pset.inputs_mut()[0].amount = Some(99_999),
            1 => pset.inputs_mut()[0].asset = Some(f.other_asset),
            2 => pset.inputs_mut()[0].blind_value_proof = None,
            3 => pset.outputs_mut()[0].blind_asset_proof = None,
            4 => pset.inputs_mut()[0].non_witness_utxo = None,
            5 => pset.outputs_mut()[0].amount = Some(20_001),
            6 => pset.outputs_mut()[0].value_rangeproof = None,
            7 => pset.outputs_mut()[0].asset_surjection_proof = None,
            _ => {
                pset.inputs_mut()[0].blind_asset_proof =
                    f.pset.inputs()[1].blind_asset_proof.clone()
            }
        }
        let mut body = transaction(&f, 0);
        body["pset_hex"] = hex::encode(serialize(&pset)).into();
        let (status, body) = request(&s, "POST", "sign", body).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "mutation {mutation}: {body}"
        );
        assert!(body.get("signature_hex").is_none());
    }
    for (field, bad) in [
        ("network", json!("liquid")),
        (
            "profile_hash",
            json!(hex::encode(simplicity_unchained_policy::profile_hash())),
        ),
        ("witness", Value::Null),
    ] {
        let mut body = transaction(&f, 0);
        body[field] = bad;
        assert_eq!(
            request(&s, "POST", "sign", body).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let mut body = transaction(&f, 0);
    body["blinding_secret_key_hex"] = json!("forbidden");
    let response = super::super::routes(s)
        .oneshot(
            Request::post("/simplicity-unchained/policy/liquid/sign")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
