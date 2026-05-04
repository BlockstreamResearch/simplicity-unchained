use std::str::FromStr;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::bitcoin::key::{TapTweak, TweakedKeypair, UntweakedKeypair};
use hal_simplicity::bitcoin::sighash::{Prevouts, ScriptPath};
use hal_simplicity::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use hal_simplicity::bitcoin::{self, TapSighashType};
use hal_simplicity::bitcoin::{TapNodeHash, Transaction, TxOut};

use hal_simplicity::simplicity::bitcoin::{hashes::Hash, psbt::Psbt, sighash::SighashCache};

use hal_simplicity::simplicity::elements::secp256k1_zkp::Message;

use serde::{Deserialize, Serialize};

use simplicity_unchained_core::utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc};
use validator::Validate;

use simplicity_unchained_core::runner::SimplicityRunner;

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

    #[validate(length(min = 1))]
    pub program: String,

    pub witness: Option<String>,

    #[validate(custom(function = "validation::validate_redeem_script"))]
    pub redeem_script_hex: Option<String>,

    #[validate(length(min = 1), custom(function = "validation::validate_hex"))]
    pub user_pubkey: String,

    #[validate(length(min = 1), custom(function = "validation::validate_hex"))]
    pub user_leaf_hash_hex: String,
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

    let user_pk = bitcoin::secp256k1::PublicKey::from_str(&request.user_pubkey)
        .map_err(|e| format!("Failed to deserialize user pubkey: {}", e))?;

    let user_leaf_hash = {
        let bytes = hex::decode(&request.user_leaf_hash_hex)
            .map_err(|e| format!("Failed to decode user leaf hash hex: {}", e))?;

        TapNodeHash::from_slice(&bytes).map_err(|e| e.to_string())?
    };

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
        redeem_script,
        state.bitcoin_network,
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
    );

    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    let (sig_bytes, partial_sigs_count) = {
        let sig = sign_p2tr(
            state,
            &mut psbt,
            &tx,
            &tweaked_keypair,
            &user_pk,
            user_leaf_hash,
            request.input_index,
        )?;
        let count = psbt.inputs[request.input_index].partial_sigs.len();
        (sig, count)
    };

    let public_key_hex = String::new();

    Ok(SignPsbtResponse {
        psbt_hex: hex::encode(psbt.serialize()),
        signature_hex: hex::encode(&sig_bytes),
        public_key_hex,
        input_index: request.input_index,
        partial_sigs_count,
    })
}

fn sign_p2tr(
    state: &SignerState,
    psbt: &mut Psbt,
    tx: &Transaction,
    cosigner_tweaked: &TweakedKeypair,
    user_pubkey: &bitcoin::secp256k1::PublicKey,
    user_leaf_hash: TapNodeHash,
    input_index: usize,
) -> Result<Vec<u8>, String> {
    let secp = &*state.secp;

    let (cosigner_tweaked_xonly, parity) = cosigner_tweaked.public_parts();
    let cosigner_full_pk = cosigner_tweaked_xonly
        .as_x_only_public_key()
        .public_key(parity)
        .into();
    let user_full_pk = (*user_pubkey).into();

    let multisig_leaf = p2tr_multisig_leaf_btc(&cosigner_full_pk, &user_full_pk);

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf.clone())
        .map_err(|e| format!("Failed to add multisig leaf: {}", e))?
        .add_hidden_node(1, user_leaf_hash)
        .map_err(|e| format!("Failed to add recovery leaf: {}", e))?
        .finalize(secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| "Failed to finalize taproot".to_string())?;

    let control_block = spend_info
        .control_block(&(multisig_leaf.clone(), LeafVersion::TapScript))
        .ok_or_else(|| "Failed to get control block".to_string())?;

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| "Missing witness_utxo".to_string())
        })
        .collect::<Result<_, _>>()?;

    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            ScriptPath::with_defaults(&multisig_leaf),
            TapSighashType::Default,
        )
        .map_err(|e| format!("Failed to compute script-path sighash: {}", e))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &cosigner_tweaked.to_keypair());

    let tap_sig = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };

    let leaf_hash = ScriptPath::with_defaults(&multisig_leaf).leaf_hash();
    psbt.inputs[input_index].tap_script_sigs.insert(
        (cosigner_tweaked_xonly.to_x_only_public_key(), leaf_hash),
        tap_sig,
    );

    psbt.inputs[input_index]
        .tap_scripts
        .insert(control_block, (multisig_leaf, LeafVersion::TapScript));

    Ok(signature.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use hal_simplicity::bitcoin::{self};
    use hal_simplicity::hal_simplicity::Program;
    use hal_simplicity::simplicity::bitcoin::{
        NetworkKind, OutPoint, PrivateKey, Transaction, TxIn, TxOut, Txid, psbt::Psbt,
        script::ScriptBuf, taproot::LeafVersion,
    };
    use hal_simplicity::simplicity::elements::{
        secp256k1_zkp::Secp256k1, secp256k1_zkp::SecretKey,
    };
    use simplicity_unchained_core::BitcoinNetwork;
    use std::str::FromStr;

    use simplicity_unchained_core::utils::generate_p2tr_address_btc;
    use simplicity_unchained_core::{ElementsNetwork, jets::bitcoin::CoreExtension};

    const PROGRAM: &str = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA";

    fn create_test_signer_state() -> SignerState {
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        SignerState {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network: ElementsNetwork::LiquidTestnet,
            bitcoin_network: BitcoinNetwork::Testnet,
            has_custom_jets: false,
        }
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
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt
    }

    /// Build a P2TR address + user leaf hash for use in tests.
    fn create_test_p2tr_setup(
        state: &SignerState,
        user_secret_key: &SecretKey,
    ) -> (bitcoin::Address, TapNodeHash, bitcoin::PublicKey) {
        let cosigner_pubkey = bitcoin::PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
                inner: state.secret_key,
            },
        );
        let user_pubkey = bitcoin::PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
                inner: *user_secret_key,
            },
        );

        let user_leaf_script = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::OP_TRUE)
            .into_script();
        let user_leaf_hash = TapNodeHash::from_script(&user_leaf_script, LeafVersion::TapScript);

        let (address, _) = generate_p2tr_address_btc(
            &cosigner_pubkey,
            &user_pubkey,
            user_leaf_hash,
            bitcoin::Network::Testnet,
        )
        .expect("failed to generate p2tr address");

        (address, user_leaf_hash, user_pubkey)
    }

    fn create_test_sign_request(
        psbt_hex: String,
        user_pubkey: &bitcoin::PublicKey,
        user_leaf_hash: TapNodeHash,
    ) -> SignPsbtRequest {
        SignPsbtRequest {
            psbt_hex,
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        }
    }

    #[test]
    fn test_sign_psbt_internal_success() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, user_leaf_hash, user_pubkey) =
            create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let psbt = create_test_psbt(tx, address.script_pubkey());
        let psbt_hex = hex::encode(psbt.serialize());

        let request = create_test_sign_request(psbt_hex, &user_pubkey, user_leaf_hash);
        let result = sign_psbt_internal(&state, request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.psbt_hex.is_empty());
        assert!(!response.signature_hex.is_empty());
        assert_eq!(response.input_index, 0);

        // Schnorr sig is always 64 bytes
        let sig_bytes = hex::decode(&response.signature_hex).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let signed_psbt = Psbt::deserialize(&hex::decode(&response.psbt_hex).unwrap()).unwrap();
        assert!(!signed_psbt.inputs[0].tap_script_sigs.is_empty());
    }

    #[test]
    fn test_sign_psbt_internal_invalid_hex() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (_, user_leaf_hash, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let request = SignPsbtRequest {
            psbt_hex: "invalid_hex!!!".to_string(),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: None,
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode PSBT hex"));
    }

    #[test]
    fn test_sign_psbt_internal_invalid_psbt_data() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (_, user_leaf_hash, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let request = SignPsbtRequest {
            psbt_hex: hex::encode(b"not a valid psbt"),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: None,
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to deserialize PSBT"));
    }

    #[test]
    fn test_sign_psbt_internal_input_index_out_of_bounds() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, user_leaf_hash, user_pubkey) =
            create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let psbt = create_test_psbt(tx, address.script_pubkey());
        let psbt_hex = hex::encode(psbt.serialize());

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 99,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Input index 99 out of bounds"));
    }

    #[test]
    fn test_sign_psbt_internal_invalid_leaf_hash() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, _, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let psbt = create_test_psbt(tx, address.script_pubkey());
        let psbt_hex = hex::encode(psbt.serialize());

        let request = SignPsbtRequest {
            psbt_hex,
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: "deadbeef".to_string(), // wrong length
        };

        let result = sign_psbt_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid slice length"));
    }

    #[test]
    fn test_sign_psbt_internal_signature_verification() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, user_leaf_hash, user_pubkey) =
            create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let psbt = create_test_psbt(tx.clone(), address.script_pubkey());
        let psbt_hex = hex::encode(psbt.serialize());

        let request = create_test_sign_request(psbt_hex, &user_pubkey, user_leaf_hash);
        let result = sign_psbt_internal(&state, request).unwrap();

        let signed_psbt = Psbt::deserialize(&hex::decode(&result.psbt_hex).unwrap()).unwrap();

        // Exactly one tap_script_sig added
        assert_eq!(signed_psbt.inputs[0].tap_script_sigs.len(), 1);

        // Derive the expected cosigner xonly pubkey
        let program = Program::<CoreExtension>::from_str(PROGRAM, Some("")).unwrap();
        let cmr = program.commit_prog().cmr();
        let untweaked = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
        let tweaked = untweaked.tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );
        let (cosigner_xonly, _) = tweaked.public_parts();

        // Verify the sig is keyed to the cosigner xonly pubkey
        let has_cosigner_sig = signed_psbt.inputs[0]
            .tap_script_sigs
            .keys()
            .any(|(xonly, _)| xonly == &cosigner_xonly.to_x_only_public_key());
        assert!(has_cosigner_sig);
    }

    #[test]
    fn test_sign_psbt_request_validation() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (_, user_leaf_hash, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let leaf_hash_hex = hex::encode(user_leaf_hash.to_byte_array());
        let user_pubkey_hex = hex::encode(user_pubkey.to_bytes());

        // Valid request
        let valid_request = SignPsbtRequest {
            psbt_hex: "70736274ff".to_string(),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: user_pubkey_hex.clone(),
            redeem_script_hex: None,
            user_leaf_hash_hex: leaf_hash_hex.clone(),
        };
        assert!(valid_request.validate().is_ok());

        // Empty psbt_hex should fail
        let invalid_request = SignPsbtRequest {
            psbt_hex: "".to_string(),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: user_pubkey_hex,
            redeem_script_hex: None,
            user_leaf_hash_hex: leaf_hash_hex,
        };
        assert!(invalid_request.validate().is_err());
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
        let result = SignerState::new(
            "not_valid_hex",
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key hex"));
    }

    #[test]
    fn test_signer_state_new_invalid_key_length() {
        let result = SignerState::new(
            "cdcdcd",
            ElementsNetwork::LiquidTestnet,
            BitcoinNetwork::Testnet,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key"));
    }
}
