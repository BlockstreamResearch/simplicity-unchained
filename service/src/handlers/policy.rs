use std::str::FromStr;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use simplicity::bitcoin::{
    self,
    hashes::Hash,
    key::{TapTweak, UntweakedKeypair},
    psbt::Psbt,
    secp256k1::{Message, XOnlyPublicKey},
    taproot::{LeafVersion, TapNodeHash},
};
use simplicity_unchained_core::policy::{PolicyError, PreparedPolicy, policy_cmr, prepare_policy};
use simplicity_unchained_policy::{self as policy, ContextSummary, Limits, Manifest, PROFILE_NAME};

use super::SignerState;
use crate::work::{MAX_BLOCKING_JOBS, MAX_BODY_BYTES, WorkPermit};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TweakRequest {
    pub profile_hash: String,
    pub network: String,
    pub program: String,
    pub redeem_script_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionRequest {
    pub profile_hash: String,
    pub network: String,
    pub program: String,
    pub redeem_script_hex: String,
    pub psbt_hex: String,
    pub input_index: usize,
    pub user_pubkey: String,
    pub user_leaf_hash_hex: String,
    pub witness: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TweakResponse {
    pub profile: &'static str,
    pub profile_hash: String,
    pub network: &'static str,
    pub genesis_hash: String,
    pub cmr: String,
    pub signing_commitment: String,
    pub public_key_hex: String,
    pub base_public_key_hex: String,
}

#[derive(Debug, Serialize)]
struct CapabilitiesResponse {
    profile: &'static str,
    profile_hash: String,
    network: &'static str,
    genesis_hash: String,
    base_public_key_hex: String,
    manifest: Manifest,
    limits: ServiceLimits,
    provenance: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceLimits {
    #[serde(flatten)]
    profile: Limits,
    max_body_bytes: usize,
    max_blocking_jobs: usize,
}

#[derive(Debug, Serialize)]
struct PrepareResponse {
    context: ContextSummary,
}

#[derive(Debug, Serialize)]
struct EvaluateResponse {
    accepted: bool,
    context: ContextSummary,
    execution_cost_milliweight: u32,
}

#[derive(Debug, Serialize)]
struct SignResponse {
    psbt_hex: String,
    signature_hex: String,
    public_key_hex: String,
    input_index: usize,
    context: ContextSummary,
    execution_cost_milliweight: u32,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn invalid(field: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: format!("{field}: {error}"),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        log::error!("Policy operation failed: {error}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "Policy operation failed".to_owned(),
        }
    }

    fn context(error: policy::Error) -> Self {
        let limited = matches!(
            error,
            policy::Error::EvidenceTooLarge
                | policy::Error::ScriptDataTooLarge
                | policy::Error::OutputScriptTooLarge(_)
        );
        Self {
            status: if limited {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            code: if limited {
                "profile_limit"
            } else {
                "invalid_context"
            },
            message: error.to_string(),
        }
    }

    fn execution(error: PolicyError) -> Self {
        let (status, code) = match &error {
            PolicyError::Decode(_) => (StatusCode::BAD_REQUEST, "invalid_program_or_witness"),
            PolicyError::Context(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_context"),
            PolicyError::CommitmentMismatch => (StatusCode::BAD_REQUEST, "commitment_mismatch"),
            PolicyError::PolicyRejected(_) => (StatusCode::UNPROCESSABLE_ENTITY, "policy_rejected"),
            PolicyError::ExecutionCostExceeded { .. } | PolicyError::MemoryLimit(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "execution_limit")
            }
            PolicyError::Vm(_) => return Self::internal(error),
        };
        if let PolicyError::Context(error) = error {
            return Self::context(error);
        }
        Self {
            status,
            code,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            error: String,
            code: &'static str,
        }
        log::warn!("[{}] Policy {}: {}", self.status, self.code, self.message);
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
                code: self.code,
            }),
        )
            .into_response()
    }
}

fn configured_network(state: &SignerState) -> (bitcoin::Network, &'static str) {
    match state.bitcoin_network {
        simplicity_unchained_core::BitcoinNetwork::Mainnet => {
            (bitcoin::Network::Bitcoin, "bitcoin")
        }
        simplicity_unchained_core::BitcoinNetwork::Testnet => {
            (bitcoin::Network::Testnet, "testnet")
        }
        simplicity_unchained_core::BitcoinNetwork::Testnet4 => {
            (bitcoin::Network::Testnet4, "testnet4")
        }
    }
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() > MAX_BODY_BYTES {
        return Err(ApiError::invalid(
            field,
            "encoded data exceeds request limit",
        ));
    }
    hex::decode(value).map_err(|error| ApiError::invalid(field, error))
}

fn decode_base64(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() > MAX_BODY_BYTES {
        return Err(ApiError::invalid(
            field,
            "encoded data exceeds request limit",
        ));
    }
    STANDARD
        .decode(value)
        .map_err(|error| ApiError::invalid(field, error))
}

fn decode_user_key(value: &str) -> Result<XOnlyPublicKey, ApiError> {
    if value.len() == 64 {
        XOnlyPublicKey::from_str(value).map_err(|error| ApiError::invalid("user_pubkey", error))
    } else {
        bitcoin::secp256k1::PublicKey::from_str(value)
            .map(|key| key.x_only_public_key().0)
            .map_err(|error| ApiError::invalid("user_pubkey", error))
    }
}

fn decode_recovery_hash(value: &str) -> Result<bitcoin::TapNodeHash, ApiError> {
    let bytes = decode_hex("user_leaf_hash_hex", value)?;
    bitcoin::TapNodeHash::from_slice(&bytes)
        .map_err(|error| ApiError::invalid("user_leaf_hash_hex", error))
}

struct Binding {
    program: Vec<u8>,
    script: Vec<u8>,
    network: bitcoin::Network,
}

fn decode_binding(
    state: &SignerState,
    profile_hash: &str,
    network: &str,
    program: &str,
    script: &str,
) -> Result<Binding, ApiError> {
    if decode_hex("profile_hash", profile_hash)? != policy::profile_hash() {
        return Err(ApiError::invalid(
            "profile_hash",
            "unsupported profile fingerprint",
        ));
    }
    let (configured, name) = configured_network(state);
    if network != name {
        return Err(ApiError::invalid(
            "network",
            format!("service is configured for {name}"),
        ));
    }
    let program = decode_base64("program", program)?;
    if program.is_empty() {
        return Err(ApiError::invalid("program", "empty program"));
    }
    let script = decode_hex("redeem_script_hex", script)?;
    if script.len() > policy::MAX_SCRIPT_BYTES {
        return Err(ApiError::context(policy::Error::ScriptDataTooLarge));
    }
    Ok(Binding {
        program,
        script,
        network: configured,
    })
}

fn base_public_key(state: &SignerState) -> XOnlyPublicKey {
    UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key)
        .x_only_public_key()
        .0
}

fn prepare_request(
    state: &SignerState,
    request: &TransactionRequest,
) -> Result<(Psbt, PreparedPolicy), ApiError> {
    let binding = decode_binding(
        state,
        &request.profile_hash,
        &request.network,
        &request.program,
        &request.redeem_script_hex,
    )?;
    let bytes = decode_hex("psbt_hex", &request.psbt_hex)?;
    let psbt = Psbt::deserialize(&bytes).map_err(|error| ApiError::invalid("psbt_hex", error))?;
    let prepared = prepare_policy(
        &binding.program,
        &psbt,
        request.input_index,
        &binding.script,
        binding.network,
        base_public_key(state),
        decode_user_key(&request.user_pubkey)?,
        decode_recovery_hash(&request.user_leaf_hash_hex)?,
    )
    .map_err(ApiError::execution)?;
    Ok((psbt, prepared))
}

fn witness(request: &TransactionRequest) -> Result<Vec<u8>, ApiError> {
    let value = request.witness.as_deref().ok_or_else(|| {
        ApiError::invalid("witness", "required; use an empty string for zero bits")
    })?;
    decode_base64("witness", value)
}

fn capabilities_internal(state: &SignerState) -> Result<CapabilitiesResponse, ApiError> {
    let (network, name) = configured_network(state);
    let manifest = policy::manifest();
    Ok(CapabilitiesResponse {
        profile: PROFILE_NAME,
        profile_hash: hex::encode(policy::profile_hash()),
        network: name,
        genesis_hash: hex::encode(policy::genesis_hash(network).map_err(ApiError::context)?),
        base_public_key_hex: base_public_key(state).to_string(),
        limits: ServiceLimits {
            profile: manifest.limits.clone(),
            max_body_bytes: MAX_BODY_BYTES,
            max_blocking_jobs: MAX_BLOCKING_JOBS,
        },
        manifest,
        provenance: "parent-txid-verified",
    })
}

fn tweak_internal(state: &SignerState, request: TweakRequest) -> Result<TweakResponse, ApiError> {
    let binding = decode_binding(
        state,
        &request.profile_hash,
        &request.network,
        &request.program,
        &request.redeem_script_hex,
    )?;
    let cmr = policy_cmr(&binding.program).map_err(ApiError::execution)?;
    let key = base_public_key(state);
    Ok(TweakResponse {
        profile: PROFILE_NAME,
        profile_hash: hex::encode(policy::profile_hash()),
        network: configured_network(state).1,
        genesis_hash: hex::encode(
            policy::genesis_hash(binding.network).map_err(ApiError::context)?,
        ),
        cmr: hex::encode(cmr.to_byte_array()),
        signing_commitment: hex::encode(
            policy::signing_commitment(cmr.to_byte_array(), &binding.script, binding.network)
                .map_err(ApiError::context)?,
        ),
        public_key_hex: policy::tweak_public_key(
            key,
            cmr.to_byte_array(),
            &binding.script,
            binding.network,
        )
        .map_err(ApiError::context)?
        .to_string(),
        base_public_key_hex: key.to_string(),
    })
}

fn prepare_internal(
    state: &SignerState,
    request: TransactionRequest,
) -> Result<PrepareResponse, ApiError> {
    let (_, prepared) = prepare_request(state, &request)?;
    Ok(PrepareResponse {
        context: prepared.summary(),
    })
}

fn evaluate_internal(
    state: &SignerState,
    request: TransactionRequest,
) -> Result<EvaluateResponse, ApiError> {
    let (_, prepared) = prepare_request(state, &request)?;
    let evaluation = prepared
        .evaluate_default(&witness(&request)?)
        .map_err(ApiError::execution)?;
    Ok(EvaluateResponse {
        accepted: true,
        context: evaluation.context,
        execution_cost_milliweight: evaluation.cost_milliweight,
    })
}

fn sign_internal(
    state: &SignerState,
    request: TransactionRequest,
) -> Result<SignResponse, ApiError> {
    let (mut psbt, prepared) = prepare_request(state, &request)?;
    let evaluation = prepared
        .evaluate_default(&witness(&request)?)
        .map_err(ApiError::execution)?;
    let context = prepared.context();
    let keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key).tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(context.signing_commitment())),
    );
    let (public_key, _) = keypair.public_parts();
    let public_key = public_key.to_x_only_public_key();
    if public_key != context.service_pubkey() {
        return Err(ApiError::internal("policy public/private tweak mismatch"));
    }
    let message = Message::from_digest(context.sighash());
    let signature = state.secp.sign_schnorr(&message, &keypair.to_keypair());
    state
        .secp
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(ApiError::internal)?;
    let input = &mut psbt.inputs[request.input_index];
    input.tap_script_sigs.insert(
        (public_key, context.cooperative_leaf_hash()),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: bitcoin::TapSighashType::Default,
        },
    );
    input.tap_scripts.insert(
        context.control_block().clone(),
        (context.cooperative_script().clone(), LeafVersion::TapScript),
    );
    Ok(SignResponse {
        psbt_hex: hex::encode(psbt.serialize()),
        signature_hex: hex::encode(signature.as_ref()),
        public_key_hex: public_key.to_string(),
        input_index: request.input_index,
        context: evaluation.context,
        execution_cost_milliweight: evaluation.cost_milliweight,
    })
}

async fn work_response<T: Serialize + Send + 'static>(
    permit: WorkPermit,
    operation: &'static str,
    job: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Response {
    match permit.run(job).await {
        Ok(Ok(response)) => {
            log::info!("[200] Policy {operation} successful");
            Json(response).into_response()
        }
        Ok(Err(error)) => error.into_response(),
        Err(error) => error.into_response(),
    }
}

pub async fn capabilities(State(state): State<SignerState>, permit: WorkPermit) -> Response {
    work_response(permit, "capabilities", move || {
        capabilities_internal(&state)
    })
    .await
}

pub async fn tweak(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(request): Json<TweakRequest>,
) -> Response {
    work_response(permit, "tweak", move || tweak_internal(&state, request)).await
}

pub async fn prepare(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(request): Json<TransactionRequest>,
) -> Response {
    work_response(permit, "prepare", move || prepare_internal(&state, request)).await
}

pub async fn evaluate(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(request): Json<TransactionRequest>,
) -> Response {
    work_response(permit, "evaluate", move || {
        evaluate_internal(&state, request)
    })
    .await
}

pub async fn sign(
    State(state): State<SignerState>,
    permit: WorkPermit,
    Json(request): Json<TransactionRequest>,
) -> Response {
    work_response(permit, "sign", move || sign_internal(&state, request)).await
}

#[cfg(test)]
mod tests;
