//! Strict new Liquid profile endpoints. Never accept local unblinding secrets.
use super::SignerState;
use crate::work::{MAX_BODY_BYTES, WorkPermit};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use simplicity_unchained_policy::liquid::{
    self as policy,
    elements::{
        encode::{deserialize, serialize},
        pset::PartiallySignedTransaction as Pset,
        secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
        taproot::TapNodeHash,
    },
};
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TweakRequest {
    pub profile_hash: String,
    pub network: String,
    pub program: String,
    pub redeem_script_hex: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionRequest {
    pub profile_hash: String,
    pub network: String,
    pub program: String,
    pub redeem_script_hex: String,
    pub pset_hex: String,
    pub input_index: usize,
    pub user_pubkey: String,
    pub user_leaf_hash_hex: String,
    pub witness: Option<String>,
}
type Result<T> = std::result::Result<T, String>;
fn bounded(value: &str) -> Result<()> {
    if value.len() <= MAX_BODY_BYTES {
        Ok(())
    } else {
        Err("encoded field exceeds request limit".into())
    }
}
fn hex_bytes(value: &str) -> Result<Vec<u8>> {
    bounded(value)?;
    hex::decode(value).map_err(|e| e.to_string())
}
fn base64(value: &str) -> Result<Vec<u8>> {
    bounded(value)?;
    STANDARD.decode(value).map_err(|e| e.to_string())
}
fn key(value: &str) -> Result<XOnlyPublicKey> {
    match value.len() {
        64 => XOnlyPublicKey::from_str(value).map_err(|e| e.to_string()),
        66 => PublicKey::from_str(value)
            .map(|k| k.x_only_public_key().0)
            .map_err(|e| e.to_string()),
        _ => Err("expected compressed/x-only public key".into()),
    }
}
fn base_key(state: &SignerState) -> XOnlyPublicKey {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&state.secret_key.secret_bytes()).expect("valid secret"),
    )
    .x_only_public_key()
    .0
}
fn binding(
    state: &SignerState,
    fingerprint: &str,
    network: &str,
    program: &str,
    data: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if fingerprint != hex::encode(policy::profile_hash()) {
        return Err("liquid-policy-v1 fingerprint mismatch".into());
    }
    if network != state.liquid_network.name() {
        return Err("configured Liquid network mismatch".into());
    }
    Ok((base64(program)?, hex_bytes(data)?))
}
fn prepare_request(
    state: &SignerState,
    r: &TransactionRequest,
) -> Result<(Pset, policy::PreparedPolicy)> {
    let (program, data) = binding(
        state,
        &r.profile_hash,
        &r.network,
        &r.program,
        &r.redeem_script_hex,
    )?;
    let pset: Pset = deserialize(&hex_bytes(&r.pset_hex)?).map_err(|e| e.to_string())?;
    let recovery: [u8; 32] = hex_bytes(&r.user_leaf_hash_hex)?
        .try_into()
        .map_err(|_| "recovery hash must be 32 bytes")?;
    let prepared = policy::PreparedPolicy::new(
        &program,
        &pset,
        r.input_index,
        &data,
        state.liquid_network,
        base_key(state),
        key(&r.user_pubkey)?,
        TapNodeHash::from_byte_array(recovery),
    )
    .map_err(|e| e.to_string())?;
    Ok((pset, prepared))
}
pub(crate) fn execute(
    state: &SignerState,
    r: &TransactionRequest,
    operation: &str,
) -> Result<Value> {
    let (mut pset, prepared) = prepare_request(state, r)?;
    if operation == "prepare" {
        return Ok(json!({"context":prepared.summary()}));
    }
    let witness = base64(
        r.witness
            .as_ref()
            .ok_or("witness is required; use empty string for unit witness")?,
    )?;
    let cost = prepared
        .evaluate_default(&witness)
        .map_err(|e| e.to_string())?;
    if operation == "evaluate" {
        return Ok(
            json!({"accepted":true,"context":prepared.summary(),"execution_cost_milliweight":cost}),
        );
    }
    if operation != "sign" {
        return Err("unsupported Liquid policy operation".into());
    }
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&state.secret_key.secret_bytes()).expect("valid secret"),
    );
    let tweak = policy::service_tweak(
        pair.x_only_public_key().0,
        prepared.cmr().to_byte_array(),
        prepared.context().script_data(),
        state.liquid_network,
    )
    .map_err(|e| e.to_string())?;
    let pair = pair
        .add_xonly_tweak(&secp, &tweak)
        .map_err(|e| e.to_string())?;
    let sig = policy::add_signature(prepared.context(), &mut pset, pair.secret_key(), true)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"pset_hex":hex::encode(serialize(&pset)),"signature_hex":hex::encode(sig.sig.as_ref()),"public_key_hex":prepared.context().cooperative().service_pubkey.to_string(),"input_index":r.input_index,"context":prepared.summary(),"execution_cost_milliweight":cost}),
    )
}
async fn work(
    permit: WorkPermit,
    job: impl FnOnce() -> Result<Value> + Send + 'static,
) -> Response {
    match permit.run(job).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":e,"code":"invalid_liquid_policy"})),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}
pub async fn capabilities(State(state): State<SignerState>, permit: WorkPermit) -> Response {
    work(permit,move || Ok(json!({"profile":policy::PROFILE_NAME,"profile_hash":hex::encode(policy::profile_hash()),"network":state.liquid_network.name(),"genesis_hash":hex::encode(state.liquid_network.genesis_hash().to_byte_array()),"base_public_key_hex":base_key(&state).to_string(),"manifest":policy::manifest(),"limits":{"max_body_bytes":MAX_BODY_BYTES,"max_blocking_jobs":crate::work::MAX_BLOCKING_JOBS},"provenance":"verified PSET exact asset/value disclosure proofs; parent content, NOT chain state"}))).await
}
pub async fn tweak(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(r): Json<TweakRequest>,
) -> Response {
    work(permit,move || {
        let (program,data) = binding(&state,&r.profile_hash,&r.network,&r.program,&r.redeem_script_hex)?;
        let cmr = policy::policy_cmr(&program).map_err(|e| e.to_string())?.to_byte_array();
        let base = base_key(&state);
        Ok(json!({"profile":policy::PROFILE_NAME,"profile_hash":hex::encode(policy::profile_hash()),"network":state.liquid_network.name(),"genesis_hash":hex::encode(state.liquid_network.genesis_hash().to_byte_array()),"cmr":hex::encode(cmr),"signing_commitment":hex::encode(policy::signing_commitment(cmr,&data,state.liquid_network).map_err(|e| e.to_string())?),"public_key_hex":policy::tweak_public_key(base,cmr,&data,state.liquid_network).map_err(|e| e.to_string())?.to_string(),"base_public_key_hex":base.to_string()}))
    }).await
}
pub async fn prepare(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(r): Json<TransactionRequest>,
) -> Response {
    work(permit, move || execute(&state, &r, "prepare")).await
}
pub async fn evaluate(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(r): Json<TransactionRequest>,
) -> Response {
    work(permit, move || execute(&state, &r, "evaluate")).await
}
pub async fn sign(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(r): Json<TransactionRequest>,
) -> Response {
    work(permit, move || execute(&state, &r, "sign")).await
}
#[cfg(test)]
mod tests;
