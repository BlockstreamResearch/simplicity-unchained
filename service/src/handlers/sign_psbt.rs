use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::bitcoin::key::{TapTweak, TweakedKeypair, UntweakedKeypair};
use hal_simplicity::bitcoin::{self, secp256k1};
use hal_simplicity::bitcoin::{TapNodeHash, Transaction, TxOut};

use hal_simplicity::simplicity::bitcoin::{
    EcdsaSighashType, hashes::Hash, psbt::Psbt, script::Script, sighash::SighashCache,
};

use hal_simplicity::simplicity::elements::secp256k1_zkp::Message;

use serde::{Deserialize, Serialize};

use validator::Validate;

use simplicity_unchained_core::{runner::SimplicityRunner, utils::TransactionType};

use crate::handlers::ErrorResponse;
use crate::validation;

use super::SignerState;

#[derive(Debug, Deserialize, Validate)]
pub struct SignPsbtRequest {
    #[validate(length(min = 1), custom(function = "validation::validate_hex"))]
    pub psbt_hex: String,

    #[validate(range(min = 0, max = {
        u16::MAX as usize
    }))]
    pub input_index: usize,

    #[validate(custom(function = "validation::validate_redeem_script"))]
    pub redeem_script_hex: Option<String>,

    #[validate(length(min = 1))]
    pub program: String,

    pub witness: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignPsbtResponse {
    pub psbt_hex: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub input_index: usize,
    pub partial_sigs_count: usize,
}

pub async fn sign_psbt(
    State(state): State<SignerState>,
    Json(request): Json<SignPsbtRequest>,
) -> impl IntoResponse {
    // Validate request using validator
    if let Err(errors) = request.validate() {
        let error_msg = format!("Validation failed: {}", errors);
        log::error!("[400] Sign PSBT validation error: {}", error_msg);

        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: error_msg }),
        )
            .into_response();
    }

    match sign_psbt_internal(&state, request) {
        Ok(response) => {
            log::info!(
                "[200] Sign PSBT successful: Tweaked Public Key {}, custom jets used: {}",
                response.public_key_hex,
                state.has_custom_jets
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            log::error!("[400] Sign PSBT error: {}", e);

            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response()
        }
    }
}

fn sign_psbt_internal(
    state: &SignerState,
    request: SignPsbtRequest,
) -> Result<SignPsbtResponse, String> {
    let psbt_bytes =
        hex::decode(&request.psbt_hex).map_err(|e| format!("Failed to decode PSBT hex: {}", e))?;

    let mut psbt: Psbt =
        Psbt::deserialize(&psbt_bytes).map_err(|e| format!("Failed to deserialize PSBT: {}", e))?;

    if request.input_index >= psbt.inputs.len() {
        return Err(format!(
            "Input index {} out of bounds (PSBT has {} inputs)",
            request.input_index,
            psbt.inputs.len()
        ));
    }

    let redeem_script = match request.redeem_script_hex {
        Some(str) => {
            let bytes = hex::decode(str)
                .map_err(|e| format!("Failed to decode redeem script hex: {}", e))?;
            hal_simplicity::simplicity::elements::Script::from(bytes)
        }
        None => hal_simplicity::simplicity::elements::Script::new(),
    };

    let cmr = SimplicityRunner::execute_bitcoin(
        &request.program,
        request.witness.as_deref(),
        request.input_index,
        &psbt,
        redeem_script.clone(),
        state.bitcoin_network,
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
    );

    let script_pubkey = psbt.inputs[request.input_index]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| format!("Missing witness_utxo for input {}", request.input_index))?
        .script_pubkey
        .clone();

    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    let tx_ty = TransactionType::from(script_pubkey.as_script());
    let (sig_bytes, partial_sigs_count) = match tx_ty {
        TransactionType::P2SH | TransactionType::P2WSH => {
            let sig = sign_p2wsh_p2sh(
                state,
                &mut psbt,
                &tx,
                hal_simplicity::bitcoin::Script::from_bytes(redeem_script.as_bytes()),
                &tweaked_keypair,
                request.input_index,
                tx_ty,
            )?;

            let count = psbt.inputs[request.input_index].partial_sigs.len();
            (sig, count)
        }
        TransactionType::P2TR => {
            let sig = sign_p2tr(state, &mut psbt, &tx, &tweaked_keypair, request.input_index)?;
            let count = psbt.inputs[request.input_index].partial_sigs.len();
            (sig, count)
        }
    };

    let public_key_hex = match tx_ty {
        TransactionType::P2SH | TransactionType::P2WSH => {
            let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();
            let public_key = bitcoin::PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
                tweaked_public_key.to_x_only_public_key(),
                tweaked_parity,
            ));
            hex::encode(public_key.to_bytes())
        }
        TransactionType::P2TR => String::new(),
    };

    Ok(SignPsbtResponse {
        psbt_hex: hex::encode(psbt.serialize()),
        // NOTE: For P2TR, sig_bytes is 64 bytes
        // For P2SH/P2WSH it is DER-encoded ECDSA + 1 sighash byte.
        signature_hex: hex::encode(&sig_bytes),
        public_key_hex,
        input_index: request.input_index,
        partial_sigs_count,
    })
}

fn sign_p2wsh_p2sh(
    state: &SignerState,
    psbt: &mut Psbt,
    tx: &Transaction,
    redeem_script: &Script,
    tweaked_keypair: &TweakedKeypair,
    input_index: usize,
    tx_type: TransactionType,
) -> Result<Vec<u8>, String> {
    //let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();
    //let public_key = bitcoin::PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
    //    tweaked_public_key.to_x_only_public_key(),
    //    tweaked_parity,
    //));

    let tweaked_private_key = bitcoin::key::PrivateKey::new(
        tweaked_keypair.to_keypair().secret_key(),
        state.bitcoin_network,
    );
    let public_key = bitcoin::PublicKey::from_private_key(&state.secp, &tweaked_private_key);

    let sighash = match tx_type {
        TransactionType::P2SH => {
            let sighash_cache = SighashCache::new(tx);
            *sighash_cache
                .legacy_signature_hash(input_index, redeem_script, EcdsaSighashType::All.to_u32())
                .map_err(|e| e.to_string())?
                .as_byte_array()
        }
        TransactionType::P2WSH => {
            let prev_value = psbt.inputs[input_index]
                .witness_utxo
                .as_ref()
                .ok_or_else(|| format!("Missing witness UTXO for input {}", input_index))?
                .value;

            let mut sighash_cache = SighashCache::new(tx);
            *sighash_cache
                .p2wsh_signature_hash(
                    input_index,
                    redeem_script,
                    prev_value,
                    EcdsaSighashType::All,
                )
                .map_err(|e| e.to_string())?
                .as_byte_array()
        }
        _ => unreachable!("Other types handled separately"),
    };

    let msg = Message::from_digest(sighash);
    let signature = hal_simplicity::bitcoin::ecdsa::Signature::sighash_all(
        state
            .secp
            .sign_ecdsa(&msg, &tweaked_keypair.to_keypair().secret_key()),
    );

    let input = &mut psbt.inputs[input_index];
    input.partial_sigs.insert(public_key, signature);

    let input_script = match tx_type {
        TransactionType::P2SH => &mut input.redeem_script,
        TransactionType::P2WSH => &mut input.witness_script,
        _ => unreachable!("Other types handled separately"),
    };

    if input_script.is_none() {
        *input_script = Some(redeem_script.to_owned());
    }

    Ok(signature.to_vec())
}

fn sign_p2tr(
    state: &SignerState,
    psbt: &mut Psbt,
    tx: &Transaction,
    tweaked_keypair: &TweakedKeypair,
    input_index: usize,
) -> Result<Vec<u8>, String> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| "Missing witness_utxo for taproot input".to_string())
        })
        .collect::<Result<_, _>>()?;

    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            input_index,
            &hal_simplicity::bitcoin::sighash::Prevouts::All(&prevouts),
            hal_simplicity::bitcoin::TapSighashType::Default,
        )
        .map_err(|e| format!("Failed to compute taproot sighash: {}", e))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = state.secp.sign_schnorr(&msg, &tweaked_keypair.to_keypair());

    // 64-byte raw Schnorr signature
    let sig_bytes = signature.as_ref().to_vec();

    psbt.inputs[input_index].tap_key_sig = Some(hal_simplicity::bitcoin::taproot::Signature {
        signature,
        sighash_type: hal_simplicity::bitcoin::TapSighashType::Default,
    });

    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use hal_simplicity::bitcoin::{self, WScriptHash};
    use hal_simplicity::hal_simplicity::Program;
    use hal_simplicity::simplicity::bitcoin::{
        NetworkKind, OutPoint, PrivateKey, Transaction, TxIn, TxOut, Txid,
        opcodes::all::OP_CHECKMULTISIG,
        psbt::Psbt,
        script::{Builder as ScriptBuilder, ScriptBuf},
    };
    use hal_simplicity::simplicity::elements::{
        secp256k1_zkp::Secp256k1, secp256k1_zkp::SecretKey,
    };
    use simplicity_unchained_core::BitcoinNetwork;
    use std::str::FromStr;

    use simplicity_unchained_core::{ElementsNetwork, jets::bitcoin::CoreExtension};

    fn create_test_signer_state() -> SignerState {
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        SignerState {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network: simplicity_unchained_core::ElementsNetwork::LiquidTestnet,
            bitcoin_network: simplicity_unchained_core::BitcoinNetwork::Testnet,
            has_custom_jets: false,
        }
    }

    fn create_2of2_multisig_script(state: &SignerState, key2: &SecretKey) -> ScriptBuf {
        let pubkey1 = bitcoin::PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
                inner: state.secret_key,
            },
        );
        let pubkey2 = bitcoin::PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
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
                .unwrap();

        Transaction {
            version: hal_simplicity::simplicity::bitcoin::transaction::Version::TWO,
            lock_time: hal_simplicity::simplicity::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: hal_simplicity::simplicity::bitcoin::Sequence::MAX,
                witness: Default::default(),
            }],
            output: vec![TxOut {
                value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn create_test_psbt(tx: Transaction, script_pubkey: ScriptBuf) -> Psbt {
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Add witness_utxo to the first input (required for SegWit v0)
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(100_000),
            script_pubkey,
        });

        psbt
    }

    #[test]
    fn test_sign_psbt_internal_success() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();

        let script_pubkey = bitcoin::ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());
        let psbt = create_test_psbt(tx, script_pubkey);

        let psbt_bytes = psbt.serialize();
        let psbt_hex = hex::encode(&psbt_bytes);

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.psbt_hex.is_empty());
        assert!(!response.signature_hex.is_empty());
        assert!(!response.public_key_hex.is_empty());
        assert_eq!(response.input_index, 0);
        assert_eq!(response.partial_sigs_count, 1);

        // Verify the signature has the correct format (DER + sighash type)
        let sig_bytes = hex::decode(&response.signature_hex).unwrap();
        assert!(sig_bytes.len() > 0);
        assert_eq!(
            *sig_bytes.last().unwrap(),
            EcdsaSighashType::All.to_u32() as u8
        );

        // Verify we can decode the signed PSBT
        let signed_psbt_bytes = hex::decode(&response.psbt_hex).unwrap();
        let signed_psbt: Psbt = Psbt::deserialize(&signed_psbt_bytes).unwrap();

        // Verify the signature was added to the PSBT
        assert!(!signed_psbt.inputs[0].partial_sigs.is_empty());

        // Verify the witness_script was added
        assert!(signed_psbt.inputs[0].witness_script.is_some());
    }

    #[test]
    fn test_sign_psbt_internal_invalid_hex() {
        let state = create_test_signer_state();

        let request = SignPsbtRequest {
            psbt_hex: "invalid_hex!!!".to_string(),
            input_index: 0,
            redeem_script_hex: Some("".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode PSBT hex"));
    }

    #[test]
    fn test_sign_psbt_internal_invalid_psbt_data() {
        let state = create_test_signer_state();

        // Valid hex but invalid PSBT data
        let invalid_data = hex::encode(b"not a valid psbt");

        let request = SignPsbtRequest {
            psbt_hex: invalid_data,
            input_index: 0,
            redeem_script_hex: Some("".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to deserialize PSBT"));
    }

    #[test]
    fn test_sign_psbt_internal_input_index_out_of_bounds() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();

        let script_pubkey = bitcoin::ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());
        let psbt = create_test_psbt(tx, script_pubkey);

        let psbt_bytes = psbt.serialize();
        let psbt_hex = hex::encode(&psbt_bytes);

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 99, // Out of bounds
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Input index 99 out of bounds"));
    }

    #[test]
    fn test_sign_psbt_internal_invalid_redeem_script() {
        let state = create_test_signer_state();

        let tx = create_test_transaction();

        let script_pubkey = bitcoin::ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0; 32]));
        let psbt = create_test_psbt(tx, script_pubkey);

        let psbt_bytes = psbt.serialize();
        let psbt_hex = hex::encode(&psbt_bytes);

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 0,
            redeem_script_hex: Some("invalid!!!".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Failed to decode redeem script hex")
        );
    }

    #[test]
    fn test_sign_psbt_internal_signature_verification() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();

        let script_pubkey = bitcoin::ScriptBuf::new_p2wsh(&redeem_script.wscript_hash());
        let psbt = create_test_psbt(tx.clone(), script_pubkey);

        let psbt_bytes = psbt.serialize();
        let psbt_hex = hex::encode(&psbt_bytes);

        let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string();

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: program.clone(),
            witness: Some("".to_string()),
        };

        let result = sign_psbt_internal(&state, request).unwrap();

        // Decode the signed PSBT
        let signed_psbt_bytes = hex::decode(&result.psbt_hex).unwrap();
        let signed_psbt: Psbt = Psbt::deserialize(&signed_psbt_bytes).unwrap();

        let program = Program::<CoreExtension>::from_str(&program, Some("")).unwrap();

        let cmr = program.commit_prog().cmr();

        let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
        let tweaked_keypair = untweaked_keypair.tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );

        let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();

        let public_key = bitcoin::PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
            tweaked_public_key.to_x_only_public_key(),
            tweaked_parity,
        ));

        let sig_bytes = signed_psbt.inputs[0].partial_sigs.get(&public_key).unwrap();

        // Verify signature format
        assert_eq!(sig_bytes.sighash_type, EcdsaSighashType::All);

        // Compute the expected sighash for SegWit v0
        let psbt_input = &signed_psbt.inputs[0];
        let prev_value = psbt_input.witness_utxo.as_ref().unwrap().value;

        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(0, &redeem_script, prev_value, EcdsaSighashType::All)
            .unwrap();

        // Verify the signature is valid for the sighash
        let msg = Message::from_digest(sighash.to_byte_array());
        let verification = state
            .secp
            .verify_ecdsa(&msg, &sig_bytes.signature, &public_key.inner);
        assert!(verification.is_ok());
    }

    #[test]
    fn test_signer_state_new_valid_key() {
        let secret_key_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let result = SignerState::new(
            secret_key_hex,
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_signer_state_new_invalid_hex() {
        let secret_key_hex = "not_valid_hex";
        let result = SignerState::new(
            secret_key_hex,
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key hex"));
    }

    #[test]
    fn test_signer_state_new_invalid_key_length() {
        let secret_key_hex = "cdcdcd"; // Too short
        let result = SignerState::new(
            secret_key_hex,
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key"));
    }

    #[test]
    fn test_sign_psbt_request_validation() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        // Valid request
        let valid_request = SignPsbtRequest {
            psbt_hex: "70736574ff".to_string(), // Some valid hex
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };
        assert!(valid_request.validate().is_ok());

        // Empty psbt_hex should fail
        let invalid_request = SignPsbtRequest {
            psbt_hex: "".to_string(),
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };
        assert!(invalid_request.validate().is_err());
    }
}
