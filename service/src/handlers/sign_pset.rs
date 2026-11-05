use std::str::FromStr;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use simplicity::{
    bitcoin::{self},
    elements::{
        self, SchnorrSig, SchnorrSighashType, Transaction, TxOut,
        encode::Encodable,
        schnorr::{TapTweak, TweakedKeypair, UntweakedKeypair},
        sighash::{Prevouts, ScriptPath},
        taproot::{LeafVersion, TapNodeHash, TaprootBuilder},
    },
};

use elements::{
    encode::deserialize, pset::PartiallySignedTransaction, secp256k1_zkp::Message,
    sighash::SighashCache,
};
use serde::{Deserialize, Serialize};

use simplicity_unchained_core::{
    runner::SimplicityRunner,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_elements, signing_commitment},
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
                "[200] Sign PSET successful: Tweaked Public Key {}",
                response.public_key_hex
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

        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("invalid slice length {} (expected 32)", bytes.len()))?;
        elements::hashes::sha256::Hash::from_byte_array(bytes)
    };

    let redeem_script = validation::decode_redeem_script(request.redeem_script_hex.as_deref())?;

    let cmr = SimplicityRunner::execute_elements(
        &request.program,
        request.witness.as_deref(),
        request.input_index,
        &pset,
        redeem_script.clone(),
        state.elements_network,
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(signing_commitment(
            cmr,
            redeem_script.as_bytes(),
        ))),
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
        .add_hidden(
            1,
            TapNodeHash::from_byte_array(user_leaf_hash.to_byte_array()),
        )
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

    if prevouts[input_index].script_pubkey
        != elements::Script::new_v1_p2tr_tweaked(spend_info.output_key())
    {
        return Err(
            "Spent output does not match the program, redeem script, user key and recovery leaf"
                .to_string(),
        );
    }

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
    use simplicity::{
        bitcoin::{NetworkKind, PrivateKey},
        elements::{
            OutPoint, Transaction, TxIn, TxOut, Txid,
            pset::PartiallySignedTransaction as Pset,
            secp256k1_zkp::{Secp256k1, SecretKey},
            taproot::LeafVersion,
        },
    };
    use simplicity_unchained_core::{
        BitcoinNetwork, ElementsNetwork, jets::elements::ElementsExtension, program::Program,
        utils::generate_p2tr_address_elements,
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
        let cmr = Program::<ElementsExtension>::from_str(PROGRAM, None)
            .unwrap()
            .cmr();
        let tweaked = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key).tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(signing_commitment(cmr, &[]))),
        );
        let (key, parity) = tweaked.public_parts();
        let cosigner_pubkey = PublicKey::new(key.into_inner().public_key(parity));
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

    #[tokio::test]
    async fn test_script_key_substitution_is_rejected() {
        use super::super::tests::{key_script, script_key_program, tweaked_public_key};
        use super::super::tweak::JetEnvKind;
        use simplicity::jet::Elements;

        let state = create_test_signer_state();
        let guardian = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let attacker = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (program, witness) = script_key_program(
            ElementsExtension::GetPubkeyFromScript,
            ElementsExtension::Elements(Elements::Bip0340Verify),
            &guardian,
        );
        let (attacker_program, attacker_witness) = script_key_program(
            ElementsExtension::GetPubkeyFromScript,
            ElementsExtension::Elements(Elements::Bip0340Verify),
            &attacker,
        );
        assert_eq!(program, attacker_program);
        let script = key_script(&state, &guardian);
        let attacker_script = key_script(&state, &attacker);
        let cosigner =
            tweaked_public_key(&state, &program, Some(&script), JetEnvKind::Elements).await;
        let (_, recovery, user) = create_test_p2tr_setup(&state, &attacker);
        let (address, spend_info) = generate_p2tr_address_elements(
            &cosigner,
            &user,
            recovery,
            &elements::AddressParams::LIQUID_TESTNET,
        )
        .unwrap();
        let tx = create_test_transaction();
        let pset = create_test_pset(
            tx,
            address.script_pubkey(),
            elements::confidential::Value::Explicit(100_000),
        );
        let request = |script: Option<&str>, witness: &str| {
            let mut request = create_test_sign_request(
                hex::encode(elements::encode::serialize(&pset)),
                &user,
                recovery,
            );
            request.program = program.clone();
            request.witness = Some(witness.to_string());
            request.redeem_script_hex = script.map(str::to_string);
            request
        };
        let result = sign_pset_internal(&state, request(Some(&script), &witness)).unwrap();
        let signed: Pset = deserialize(&hex::decode(result.pset_hex).unwrap()).unwrap();
        let ((signing_key, _), signature) = signed.inputs()[0]
            .tap_script_sigs
            .first_key_value()
            .unwrap();
        assert_eq!(*signing_key, cosigner.inner.x_only_public_key().0);
        let (control, (leaf, _)) = signed.inputs()[0].tap_scripts.first_key_value().unwrap();
        assert!(control.verify_taproot_commitment(&*state.secp, &spend_info.output_key(), leaf,));
        let tx = pset.extract_tx().unwrap();
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[pset.inputs()[0].witness_utxo.clone().unwrap()]),
                ScriptPath::with_defaults(leaf),
                SchnorrSighashType::Default,
                state.elements_network.genesis_hash(),
            )
            .unwrap();
        state
            .secp
            .verify_schnorr(
                &signature.sig,
                &Message::from_digest(sighash.to_byte_array()),
                signing_key,
            )
            .unwrap();
        assert!(
            sign_pset_internal(&state, request(Some(&script), &attacker_witness))
                .unwrap_err()
                .contains("Simplicity execution failed")
        );
        assert!(
            sign_pset_internal(&state, request(Some(&attacker_script), &attacker_witness))
                .unwrap_err()
                .contains("Spent output does not match")
        );
        let changed_opcode = format!("51{}", &script[2..]);
        assert!(
            sign_pset_internal(&state, request(Some(&changed_opcode), &witness))
                .unwrap_err()
                .contains("Spent output does not match")
        );
        assert!(sign_pset_internal(&state, request(None, &attacker_witness)).is_err());
    }

    #[test]
    fn test_legacy_cmr_only_output_is_rejected() {
        let state = create_test_signer_state();
        let user_secret = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (_, recovery, user) = create_test_p2tr_setup(&state, &user_secret);
        let cmr = Program::<ElementsExtension>::from_str(PROGRAM, None)
            .unwrap()
            .cmr();
        let legacy = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key).tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );
        let (key, parity) = legacy.public_parts();
        let cosigner = PublicKey::new(key.into_inner().public_key(parity));
        let (address, _) = generate_p2tr_address_elements(
            &cosigner,
            &user,
            recovery,
            &elements::AddressParams::LIQUID_TESTNET,
        )
        .unwrap();
        let pset = create_test_pset(
            create_test_transaction(),
            address.script_pubkey(),
            elements::confidential::Value::Explicit(100_000),
        );
        let request = create_test_sign_request(
            hex::encode(elements::encode::serialize(&pset)),
            &user,
            recovery,
        );
        assert!(
            sign_pset_internal(&state, request)
                .unwrap_err()
                .contains("Spent output does not match")
        );
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
