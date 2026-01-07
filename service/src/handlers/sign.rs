use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::simplicity::elements;

use elements::{
    EcdsaSighashType,
    bitcoin::PublicKey,
    encode::{deserialize, serialize},
    hashes::Hash,
    pset::PartiallySignedTransaction,
    script::Script,
    secp256k1_zkp::{All, Message, Secp256k1, SecretKey},
    sighash::SighashCache,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

use simplicity_unchained_core::{Network, runner::SimplicityRunner};

use crate::handlers::ErrorResponse;
use crate::validation;

#[derive(Clone, Debug)]
pub struct SignerState {
    pub secret_key: SecretKey,
    pub secp: Arc<Secp256k1<All>>,
    pub network: Network,
}

impl SignerState {
    pub fn new(secret_key_hex: &str, network: Network) -> Result<Self, String> {
        let secret_key_bytes =
            hex::decode(secret_key_hex).map_err(|e| format!("Invalid private key hex: {}", e))?;

        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|e| format!("Invalid private key: {}", e))?;

        Ok(Self {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            network,
        })
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct SignPsetRequest {
    #[validate(length(min = 1), custom(function = "validation::validate_hex"))]
    pub pset_hex: String,

    // TODO(ivanlele): it looks bad, but cargo check yells warning which we can't silence with #[allow], so leave it as is for now
    #[validate(range(min = 0, max = {
        u16::MAX as usize
    }))]
    pub input_index: usize,

    #[validate(custom(function = "validation::validate_redeem_script"))]
    pub redeem_script_hex: String,

    #[validate(length(min = 1))]
    pub program: String,

    pub witness: String,
}

#[derive(Debug, Serialize)]
pub struct SignPsetResponse {
    pub pset_hex: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub input_index: usize,
    pub partial_sigs_count: usize,
}

pub async fn sign_pset(
    State(state): State<SignerState>,
    Json(request): Json<SignPsetRequest>,
) -> impl IntoResponse {
    // Validate request using validator
    if let Err(errors) = request.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Validation failed: {}", errors),
            }),
        )
            .into_response();
    }

    match sign_pset_internal(&state, request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response(),
    }
}

fn sign_pset_internal(
    state: &SignerState,
    request: SignPsetRequest,
) -> Result<SignPsetResponse, String> {
    let pset_bytes =
        hex::decode(&request.pset_hex).map_err(|e| format!("Failed to decode PSET hex: {}", e))?;

    let mut pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).map_err(|e| format!("Failed to deserialize PSET: {}", e))?;

    if request.input_index >= pset.inputs().len() {
        return Err(format!(
            "Input index {} out of bounds (PSET has {} inputs)",
            request.input_index,
            pset.inputs().len()
        ));
    }

    // Validate with Simplicity runner before signing
    SimplicityRunner::execute(
        &request.program,
        &request.witness,
        request.input_index,
        &pset,
        state.network.clone(),
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let redeem_script_bytes = hex::decode(&request.redeem_script_hex)
        .map_err(|e| format!("Failed to decode redeem script hex: {}", e))?;
    let redeem_script = Script::from(redeem_script_bytes);

    let public_key = PublicKey::from_private_key(
        &*state.secp,
        &elements::bitcoin::PrivateKey {
            compressed: true,
            network: elements::bitcoin::NetworkKind::Main,
            inner: state.secret_key,
        },
    );

    let tx = pset
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    let pset_input = &pset.inputs()[request.input_index];
    let prev_value = pset_input
        .witness_utxo
        .as_ref()
        .ok_or_else(|| format!("Missing witness UTXO for input {}", request.input_index))?
        .value;

    // Compute sighash for P2WSH (SegWit v0)
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.segwitv0_sighash(
        request.input_index,
        &redeem_script,
        prev_value,
        EcdsaSighashType::All,
    );

    // Sign the sighash
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = state.secp.sign_ecdsa(&msg, &state.secret_key);

    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.as_u32() as u8);

    let input = &mut pset.inputs_mut()[request.input_index];
    input.partial_sigs.insert(public_key, sig_bytes.clone());

    if input.witness_script.is_none() {
        input.witness_script = Some(redeem_script.clone());
    }

    let partial_sigs_count = pset.inputs()[request.input_index].partial_sigs.len();

    Ok(SignPsetResponse {
        pset_hex: hex::encode(serialize(&pset)),
        signature_hex: hex::encode(&sig_bytes),
        public_key_hex: hex::encode(public_key.to_bytes()),
        input_index: request.input_index,
        partial_sigs_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{
        OutPoint, Transaction, TxIn, TxInWitness, TxOut, Txid,
        confidential::{Asset, Value},
        opcodes::all::OP_CHECKMULTISIG,
        pset::PartiallySignedTransaction,
        script::Builder as ScriptBuilder,
        secp256k1_zkp::Secp256k1,
    };
    use std::str::FromStr;

    use simplicity_unchained_core::Network;

    fn create_test_signer_state() -> SignerState {
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        SignerState {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            network: simplicity_unchained_core::Network::LiquidTestnet,
        }
    }

    fn create_2of2_multisig_script(state: &SignerState, key2: &SecretKey) -> Script {
        let pubkey1 = PublicKey::from_private_key(
            &*state.secp,
            &elements::bitcoin::PrivateKey {
                compressed: true,
                network: elements::bitcoin::NetworkKind::Main,
                inner: state.secret_key,
            },
        );
        let pubkey2 = PublicKey::from_private_key(
            &*state.secp,
            &elements::bitcoin::PrivateKey {
                compressed: true,
                network: elements::bitcoin::NetworkKind::Main,
                inner: *key2,
            },
        );

        ScriptBuilder::new()
            .push_int(2)
            .push_key(&pubkey1)
            .push_key(&pubkey2)
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn create_test_transaction() -> Transaction {
        let prev_txid =
            Txid::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .expect("valid txid");

        Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                is_pegin: false,
                script_sig: Script::new(),
                sequence: elements::Sequence::MAX,
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![TxOut {
                asset: Asset::Explicit(elements::AssetId::from_slice(&[0; 32]).unwrap()),
                value: Value::Explicit(100_000),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: Script::new(),
                witness: Default::default(),
            }],
        }
    }

    fn create_test_pset(tx: Transaction) -> PartiallySignedTransaction {
        let mut pset = PartiallySignedTransaction::from_tx(tx);

        // Add witness_utxo to the first input (required for SegWit v0)
        pset.inputs_mut()[0].witness_utxo = Some(TxOut {
            asset: Asset::Explicit(elements::AssetId::from_slice(&[0; 32]).unwrap()),
            value: Value::Explicit(100_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: Script::new(),
            witness: Default::default(),
        });

        pset
    }

    #[test]
    fn test_sign_pset_internal_success() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();
        let pset = create_test_pset(tx);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: hex::encode(redeem_script.as_bytes()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.pset_hex.is_empty());
        assert!(!response.signature_hex.is_empty());
        assert!(!response.public_key_hex.is_empty());
        assert_eq!(response.input_index, 0);
        assert_eq!(response.partial_sigs_count, 1);

        // Verify the signature has the correct format (DER + sighash type)
        let sig_bytes = hex::decode(&response.signature_hex).unwrap();
        assert!(sig_bytes.len() > 0);
        assert_eq!(
            *sig_bytes.last().unwrap(),
            EcdsaSighashType::All.as_u32() as u8
        );

        // Verify we can decode the signed PSET
        let signed_pset_bytes = hex::decode(&response.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        // Verify the signature was added to the PSET
        assert!(!signed_pset.inputs()[0].partial_sigs.is_empty());

        // Verify the witness_script was added
        assert!(signed_pset.inputs()[0].witness_script.is_some());
    }

    #[test]
    fn test_sign_pset_internal_invalid_hex() {
        let state = create_test_signer_state();

        let request = SignPsetRequest {
            pset_hex: "invalid_hex!!!".to_string(),
            input_index: 0,
            redeem_script_hex: "".to_string(),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode PSET hex"));
    }

    #[test]
    fn test_sign_pset_internal_invalid_pset_data() {
        let state = create_test_signer_state();

        // Valid hex but invalid PSET data
        let invalid_data = hex::encode(b"not a valid pset");

        let request = SignPsetRequest {
            pset_hex: invalid_data,
            input_index: 0,
            redeem_script_hex: "".to_string(),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to deserialize PSET"));
    }

    #[test]
    fn test_sign_pset_internal_input_index_out_of_bounds() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();
        let pset = create_test_pset(tx);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 999, // Out of bounds
            redeem_script_hex: hex::encode(redeem_script.as_bytes()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Input index 999 out of bounds")
        );
    }

    #[test]
    fn test_sign_pset_internal_invalid_redeem_script() {
        let state = create_test_signer_state();

        let tx = create_test_transaction();
        let pset = create_test_pset(tx);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: "invalid_hex!!!".to_string(),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Failed to decode redeem script")
        );
    }

    #[test]
    fn test_sign_pset_internal_signature_verification() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();
        let pset = create_test_pset(tx.clone());

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: hex::encode(redeem_script.as_bytes()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };

        let result = sign_pset_internal(&state, request).unwrap();

        // Decode the signed PSET
        let signed_pset_bytes = hex::decode(&result.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        // Get the signature from the PSET
        let public_key = PublicKey::from_private_key(
            &*state.secp,
            &elements::bitcoin::PrivateKey {
                compressed: true,
                network: elements::bitcoin::NetworkKind::Main,
                inner: state.secret_key,
            },
        );

        let sig_bytes = signed_pset.inputs()[0]
            .partial_sigs
            .get(&public_key)
            .expect("signature should be present");

        // Verify signature format
        assert!(sig_bytes.len() > 1);
        assert_eq!(
            *sig_bytes.last().unwrap(),
            EcdsaSighashType::All.as_u32() as u8
        );

        // Compute the expected sighash for SegWit v0
        let pset_input = &signed_pset.inputs()[0];
        let prev_value = pset_input.witness_utxo.as_ref().unwrap().value;

        let mut sighash_cache = SighashCache::new(&tx);
        let sighash =
            sighash_cache.segwitv0_sighash(0, &redeem_script, prev_value, EcdsaSighashType::All);

        // Verify the signature is valid for the sighash
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig_without_sighash_type = &sig_bytes[..sig_bytes.len() - 1];
        let signature =
            elements::secp256k1_zkp::ecdsa::Signature::from_der(sig_without_sighash_type)
                .expect("valid DER signature");

        let verification =
            state
                .secp
                .verify_ecdsa(&msg, &signature, &state.secret_key.public_key(&*state.secp));

        assert!(verification.is_ok());
    }

    #[test]
    fn test_signer_state_new_valid_key() {
        let secret_key_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let result = SignerState::new(secret_key_hex, Network::LiquidTestnet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signer_state_new_invalid_hex() {
        let secret_key_hex = "not_valid_hex";
        let result = SignerState::new(secret_key_hex, Network::LiquidTestnet);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key hex"));
    }

    #[test]
    fn test_signer_state_new_invalid_key_length() {
        let secret_key_hex = "cdcdcd"; // Too short
        let result = SignerState::new(secret_key_hex, Network::LiquidTestnet);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key"));
    }

    #[test]
    fn test_sign_pset_request_validation() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        // Valid request
        let valid_request = SignPsetRequest {
            pset_hex: "0000000000".to_string(),
            input_index: 0,
            redeem_script_hex: hex::encode(redeem_script.as_bytes()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };
        assert!(valid_request.validate().is_ok());

        // Empty pset_hex should fail
        let invalid_request = SignPsetRequest {
            pset_hex: "".to_string(),
            input_index: 0,
            redeem_script_hex: hex::encode(redeem_script.as_bytes()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: "".to_string(),
        };
        assert!(invalid_request.validate().is_err());
    }
}
