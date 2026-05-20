use std::str::FromStr;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::{
    bitcoin::{self},
    simplicity::elements::{
        self, SchnorrSig, SchnorrSighashType, Transaction, TxOut,
        encode::Encodable,
        schnorr::{TapTweak, TweakedKeypair, UntweakedKeypair},
        sighash::{Prevouts, ScriptPath},
        taproot::{LeafVersion, TapNodeHash, TaprootBuilder},
    },
};

use elements::{
    encode::deserialize, hashes::Hash, pset::PartiallySignedTransaction, secp256k1_zkp::Message,
    sighash::SighashCache,
};
use serde::{Deserialize, Serialize};

use simplicity_unchained_core::{
    runner::SimplicityRunner,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_elements},
};
use validator::Validate;

use crate::handlers::ErrorResponse;
use crate::validation;

use super::SignerState;

#[derive(Debug, Deserialize, Validate)]
pub struct SignPsetRequest {
    #[validate(length(min = 1), custom(function = "validation::validate_hex"))]
    pub pset_hex: String,

    // TODO(ivanlele): it looks bad, but cargo check yells warning which we can't silence with #[allow], so leave it as is for now
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
        let error_msg = format!("Validation failed: {}", errors);
        log::error!("[400] Sign PSET validation error: {}", error_msg);

        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: error_msg }),
        )
            .into_response();
    }

    match sign_pset_internal(&state, request) {
        Ok(response) => {
            log::info!(
                "[200] Sign PSET successful: Tweaked Public Key {}, custom jets used: {}",
                response.public_key_hex,
                state.has_custom_jets
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            log::error!("[400] Sign PSET error: {}", e);

            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response()
        }
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

    let user_pk = bitcoin::secp256k1::PublicKey::from_str(&request.user_pubkey)
        .map_err(|e| format!("Failed to deserialize user pubkey: {}", e))?;

    let user_leaf_hash = {
        let bytes = hex::decode(&request.user_leaf_hash_hex)
            .map_err(|e| format!("Failed to decode user leaf hash hex: {}", e))?;

        elements::hashes::sha256::Hash::from_slice(&bytes).map_err(|e| e.to_string())?
    };

    let redeem_script = match request.redeem_script_hex {
        Some(str) => {
            let bytes = hex::decode(str)
                .map_err(|e| format!("Failed to decode redeem script hex: {}", e))?;
            hal_simplicity::simplicity::elements::Script::from(bytes)
        }
        None => hal_simplicity::simplicity::elements::Script::new(),
    };

    let cmr = SimplicityRunner::execute_elements(
        &request.program,
        request.witness.as_deref(),
        request.input_index,
        &pset,
        redeem_script,
        state.elements_network,
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
    );

    let tx = pset
        .clone()
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    let (sig_bytes, partial_sigs_count) = {
        let sig = sign_p2tr(
            state,
            &mut pset,
            &tx,
            &tweaked_keypair,
            &user_pk,
            user_leaf_hash,
            request.input_index,
        )?;
        let count = pset.inputs()[request.input_index].partial_sigs.len();
        (sig, count)
    };

    let public_key_hex = String::new();

    let mut pset_bytes = Vec::new();
    pset.consensus_encode(&mut pset_bytes)
        .map_err(|e| format!("Failed to encode PSET: {}", e))?;

    Ok(SignPsetResponse {
        pset_hex: hex::encode(pset_bytes),
        signature_hex: hex::encode(&sig_bytes),
        public_key_hex,
        input_index: request.input_index,
        partial_sigs_count,
    })
}

fn sign_p2tr(
    state: &SignerState,
    pset: &mut PartiallySignedTransaction,
    tx: &Transaction,
    cosigner_tweaked: &TweakedKeypair,
    user_pubkey: &bitcoin::secp256k1::PublicKey,
    user_leaf_hash: elements::hashes::sha256::Hash,
    input_index: usize,
) -> Result<Vec<u8>, String> {
    let secp = &*state.secp;

    let (cosigner_tweaked_xonly, parity) = cosigner_tweaked.public_parts();
    let cosigner_full_pk = cosigner_tweaked_xonly.as_inner().public_key(parity).into();
    let user_full_pk = (*user_pubkey).into();

    let multisig_leaf = p2tr_multisig_leaf_elements(&cosigner_full_pk, &user_full_pk);

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf.clone())
        .map_err(|e| format!("Failed to add multisig leaf: {}", e))?
        .add_hidden(1, user_leaf_hash)
        .map_err(|e| format!("Failed to add recovery leaf: {}", e))?
        .finalize(secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| "Failed to finalize taproot".to_string())?;

    let control_block = spend_info
        .control_block(&(multisig_leaf.clone(), LeafVersion::default())) // TAPROOT_LEAF_TAPSCRIPT
        .ok_or_else(|| "Failed to get control block".to_string())?;

    let prevouts: Vec<TxOut> = pset
        .inputs()
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
            SchnorrSighashType::Default,
            state.elements_network.genesis_hash(),
        )
        .map_err(|e| format!("Failed to compute script-path sighash: {}", e))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &cosigner_tweaked.to_inner());

    let tap_sig = SchnorrSig {
        sig: signature,
        hash_ty: SchnorrSighashType::Default,
    };

    let leaf_hash = ScriptPath::with_defaults(&multisig_leaf).leaf_hash();
    pset.inputs_mut()[input_index]
        .tap_script_sigs
        .insert((cosigner_tweaked_xonly.into_inner(), leaf_hash), tap_sig);

    pset.inputs_mut()[input_index]
        .tap_scripts
        .insert(control_block, (multisig_leaf, LeafVersion::default())); // TAPROOT_LEAF_TAPSCRIPT

    Ok(signature.as_ref().to_vec())
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use bitcoin::PublicKey;
    use hal_simplicity::{
        bitcoin::{NetworkKind, PrivateKey},
        simplicity::elements::{
            OutPoint, Transaction, TxIn, TxOut, Txid,
            pset::PartiallySignedTransaction as Pset,
            secp256k1_zkp::{Secp256k1, SecretKey},
            taproot::LeafVersion,
        },
    };
    use simplicity_unchained_core::{
        BitcoinNetwork, ElementsNetwork, utils::generate_p2tr_address_elements,
    };
    use std::str::FromStr;

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
                .expect("valid txid");

        Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: elements::script::Script::new(),
                sequence: elements::Sequence::MAX,
                witness: Default::default(),
                is_pegin: false,
                asset_issuance: Default::default(),
            }],
            output: vec![TxOut::default()],
        }
    }

    fn create_test_pset(
        tx: Transaction,
        script_pubkey: elements::script::Script,
        value: elements::confidential::Value,
    ) -> Pset {
        let mut pset = Pset::from_tx(tx);
        pset.inputs_mut()[0].witness_utxo = Some(TxOut {
            asset: elements::confidential::Asset::Explicit(elements::issuance::AssetId::default()),
            value,
            nonce: elements::confidential::Nonce::Null,
            script_pubkey,
            witness: Default::default(),
        });
        for output in pset.outputs_mut() {
            if output.amount.is_none() {
                output.amount = Some(90_000);
            }
            if output.asset.is_none() {
                output.asset = Some(elements::issuance::AssetId::default());
            }
        }
        pset
    }

    fn create_test_p2tr_setup(
        state: &SignerState,
        user_secret_key: &SecretKey,
    ) -> (
        elements::Address,
        elements::hashes::sha256::Hash,
        bitcoin::PublicKey,
    ) {
        let cosigner_pubkey = PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
                inner: state.secret_key,
            },
        );
        let user_pubkey = PublicKey::from_private_key(
            &*state.secp,
            &PrivateKey {
                compressed: true,
                network: NetworkKind::Test,
                inner: *user_secret_key,
            },
        );

        let user_leaf_script = elements::script::Builder::new()
            .push_opcode(elements::opcodes::OP_TRUE)
            .into_script();

        let user_leaf_hash = elements::hashes::sha256::Hash::from_byte_array(
            elements::taproot::TapLeafHash::from_script(&user_leaf_script, LeafVersion::default())
                .to_byte_array(),
        );

        let (address, _) = generate_p2tr_address_elements(
            &cosigner_pubkey,
            &user_pubkey,
            user_leaf_hash,
            &elements::AddressParams::LIQUID_TESTNET,
        )
        .expect("failed to generate p2tr address");

        (address, user_leaf_hash, user_pubkey)
    }

    fn create_test_sign_request(
        pset_hex: String,
        user_pubkey: &PublicKey,
        user_leaf_hash: elements::hashes::sha256::Hash,
    ) -> SignPsetRequest {
        SignPsetRequest {
            pset_hex,
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        }
    }

    #[test]
    fn test_sign_pset_internal_success() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, user_leaf_hash, user_pubkey) =
            create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let value = elements::confidential::Value::Explicit(100_000);
        let pset = create_test_pset(tx, address.script_pubkey(), value);

        let mut pset_bytes = Vec::new();
        elements::encode::Encodable::consensus_encode(&pset, &mut pset_bytes).unwrap();
        let pset_hex = hex::encode(pset_bytes);

        let request = create_test_sign_request(pset_hex, &user_pubkey, user_leaf_hash);
        let result = sign_pset_internal(&state, request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.pset_hex.is_empty());
        assert!(!response.signature_hex.is_empty());
        assert_eq!(response.input_index, 0);

        let sig_bytes = hex::decode(&response.signature_hex).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_sign_pset_internal_invalid_hex() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (_, user_leaf_hash, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let request = SignPsetRequest {
            pset_hex: "invalid_hex!!!".to_string(),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: None,
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode PSET hex"));
    }

    #[test]
    fn test_sign_pset_internal_invalid_pset_data() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (_, user_leaf_hash, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let request = SignPsetRequest {
            pset_hex: hex::encode(b"not a valid pset"),
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: None,
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to deserialize PSET"));
    }

    #[test]
    fn test_sign_pset_internal_input_index_out_of_bounds() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, user_leaf_hash, user_pubkey) =
            create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let value = elements::confidential::Value::Explicit(100_000);
        let pset = create_test_pset(tx, address.script_pubkey(), value);

        let mut pset_bytes = Vec::new();
        elements::encode::Encodable::consensus_encode(&pset, &mut pset_bytes).unwrap();
        let pset_hex = hex::encode(pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 99,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: hex::encode(user_leaf_hash.to_byte_array()),
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }

    #[test]
    fn test_sign_pset_internal_invalid_leaf_hash() {
        let state = create_test_signer_state();
        let user_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let (address, _, user_pubkey) = create_test_p2tr_setup(&state, &user_secret_key);

        let tx = create_test_transaction();
        let value = elements::confidential::Value::Explicit(100_000);
        let pset = create_test_pset(tx, address.script_pubkey(), value);

        let mut pset_bytes = Vec::new();
        elements::encode::Encodable::consensus_encode(&pset, &mut pset_bytes).unwrap();
        let pset_hex = hex::encode(pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            program: PROGRAM.to_string(),
            witness: Some("".to_string()),
            user_pubkey: hex::encode(user_pubkey.to_bytes()),
            redeem_script_hex: None,
            user_leaf_hash_hex: "deadbeef".to_string(), // wrong length
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid slice length"));
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
