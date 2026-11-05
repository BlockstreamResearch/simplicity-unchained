use std::str::FromStr;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use simplicity::bitcoin::key::{TapTweak, TweakedKeypair, UntweakedKeypair};
use simplicity::bitcoin::sighash::{Prevouts, ScriptPath};
use simplicity::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use simplicity::bitcoin::{self, TapSighashType};
use simplicity::bitcoin::{TapNodeHash, Transaction, TxOut};

use simplicity::bitcoin::{hashes::Hash, psbt::Psbt, sighash::SighashCache};

use simplicity::elements::secp256k1_zkp::Message;

use serde::{Deserialize, Serialize};

use simplicity_unchained_core::utils::{
    UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc, signing_commitment,
};
use validator::Validate;

use simplicity_unchained_core::runner::SimplicityRunner;

use crate::handlers::ErrorResponse;
use crate::validation;
use crate::work::WorkPermit;

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
    permit: WorkPermit,
    Json(request): Json<SignPsbtRequest>,
) -> impl IntoResponse {
    let result = permit
        .run(move || {
            request
                .validate()
                .map_err(|e| format!("Validation failed: {}", e))?;
            sign_psbt_internal(&state, request)
        })
        .await;
    match result {
        Ok(Ok(response)) => {
            log::info!(
                "[200] Sign PSBT successful: Tweaked Public Key {}",
                response.public_key_hex
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(Err(e)) => {
            log::error!("[400] Sign PSBT error: {}", e);

            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response()
        }
        Err(e) => e.into_response(),
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

    let redeem_script = validation::decode_redeem_script(request.redeem_script_hex.as_deref())?;

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
        Some(TapNodeHash::from_byte_array(signing_commitment(
            cmr,
            redeem_script.as_bytes(),
        ))),
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

    if prevouts[input_index].script_pubkey
        != bitcoin::ScriptBuf::new_p2tr_tweaked(spend_info.output_key())
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
    use simplicity::bitcoin::{self};
    use simplicity::bitcoin::{
        NetworkKind, OutPoint, PrivateKey, Transaction, TxIn, TxOut, Txid, psbt::Psbt,
        script::ScriptBuf, taproot::LeafVersion,
    };
    use simplicity::elements::{secp256k1_zkp::Secp256k1, secp256k1_zkp::SecretKey};
    use simplicity_unchained_core::BitcoinNetwork;
    use simplicity_unchained_core::program::Program;
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
            work_slots: Arc::new(tokio::sync::Semaphore::new(crate::work::MAX_BLOCKING_JOBS)),
        }
    }

    fn create_test_transaction() -> Transaction {
        let prev_txid =
            Txid::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();

        Transaction {
            version: simplicity::bitcoin::transaction::Version::TWO,
            lock_time: simplicity::bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: simplicity::bitcoin::Sequence::MAX,
                witness: Default::default(),
            }],
            output: vec![TxOut {
                value: simplicity::bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn create_test_psbt(tx: Transaction, script_pubkey: ScriptBuf) -> Psbt {
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: simplicity::bitcoin::Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt
    }

    /// Build a P2TR address + user leaf hash for use in tests.
    fn create_test_p2tr_setup(
        state: &SignerState,
        user_secret_key: &SecretKey,
    ) -> (bitcoin::Address, TapNodeHash, bitcoin::PublicKey) {
        let cmr = Program::<CoreExtension>::from_str(PROGRAM, None)
            .unwrap()
            .cmr();
        let tweaked = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key).tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(signing_commitment(cmr, &[]))),
        );
        let (key, parity) = tweaked.public_parts();
        let cosigner_pubkey =
            bitcoin::PublicKey::new(key.to_x_only_public_key().public_key(parity));
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

    #[tokio::test]
    async fn high_cost_program_is_rejected_by_signing_endpoint() {
        use super::super::tests::{expensive_program, post_json};
        let state = create_test_signer_state();
        let user_secret = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (address, recovery, user) = create_test_p2tr_setup(&state, &user_secret);
        let psbt = create_test_psbt(create_test_transaction(), address.script_pubkey());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            post_json(
                &state,
                "/simplicity-unchained/sign/psbt",
                serde_json::json!({
                    "psbt_hex": hex::encode(psbt.serialize()),
                    "input_index": 0,
                    "program": expensive_program(),
                    "witness": "",
                    "user_pubkey": hex::encode(user.to_bytes()),
                    "user_leaf_hash_hex": hex::encode(recovery.to_byte_array()),
                }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("exceeds maximum 10000000 milliweight")
        );
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
            Some(TapNodeHash::from_byte_array(signing_commitment(cmr, &[]))),
        );
        let (cosigner_xonly, _) = tweaked.public_parts();

        // Verify the sig is keyed to the cosigner xonly pubkey
        let has_cosigner_sig = signed_psbt.inputs[0]
            .tap_script_sigs
            .keys()
            .any(|(xonly, _)| xonly == &cosigner_xonly.to_x_only_public_key());
        assert!(has_cosigner_sig);
    }

    #[tokio::test]
    async fn test_script_key_substitution_is_rejected() {
        use super::super::tests::{key_script, script_key_program, tweaked_public_key};
        use super::super::tweak::JetEnvKind;
        use simplicity::jet::Core;

        let state = create_test_signer_state();
        let guardian = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let attacker = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (program, witness) = script_key_program(
            CoreExtension::GetPubkeyFromScript,
            CoreExtension::Core(Core::Bip0340Verify),
            &guardian,
        );
        let (attacker_program, attacker_witness) = script_key_program(
            CoreExtension::GetPubkeyFromScript,
            CoreExtension::Core(Core::Bip0340Verify),
            &attacker,
        );
        assert_eq!(program, attacker_program);
        let script = key_script(&state, &guardian);
        let attacker_script = key_script(&state, &attacker);
        let cosigner =
            tweaked_public_key(&state, &program, Some(&script), JetEnvKind::Bitcoin).await;
        let (_, recovery, user) = create_test_p2tr_setup(&state, &attacker);
        let (address, spend_info) =
            generate_p2tr_address_btc(&cosigner, &user, recovery, bitcoin::Network::Testnet)
                .unwrap();
        let tx = create_test_transaction();
        let psbt = create_test_psbt(tx.clone(), address.script_pubkey());
        let request = |script: Option<&str>, witness: &str| {
            let mut request =
                create_test_sign_request(hex::encode(psbt.serialize()), &user, recovery);
            request.program = program.clone();
            request.witness = Some(witness.to_string());
            request.redeem_script_hex = script.map(str::to_string);
            request
        };
        let result = sign_psbt_internal(&state, request(Some(&script), &witness)).unwrap();
        let signed = Psbt::deserialize(&hex::decode(result.psbt_hex).unwrap()).unwrap();
        let ((signing_key, _), signature) =
            signed.inputs[0].tap_script_sigs.first_key_value().unwrap();
        assert_eq!(*signing_key, cosigner.inner.x_only_public_key().0);
        let (control, (leaf, _)) = signed.inputs[0].tap_scripts.first_key_value().unwrap();
        assert!(control.verify_taproot_commitment(
            &*state.secp,
            spend_info.output_key().to_x_only_public_key(),
            leaf,
        ));
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[psbt.inputs[0].witness_utxo.clone().unwrap()]),
                ScriptPath::with_defaults(leaf),
                TapSighashType::Default,
            )
            .unwrap();
        state
            .secp
            .verify_schnorr(
                &signature.signature,
                &Message::from_digest(sighash.to_byte_array()),
                signing_key,
            )
            .unwrap();
        assert!(
            sign_psbt_internal(&state, request(Some(&script), &attacker_witness))
                .unwrap_err()
                .contains("Simplicity execution failed")
        );
        assert!(
            sign_psbt_internal(&state, request(Some(&attacker_script), &attacker_witness))
                .unwrap_err()
                .contains("Spent output does not match")
        );
        let changed_opcode = format!("51{}", &script[2..]);
        assert!(
            sign_psbt_internal(&state, request(Some(&changed_opcode), &witness))
                .unwrap_err()
                .contains("Spent output does not match")
        );
        assert!(sign_psbt_internal(&state, request(None, &attacker_witness)).is_err());
        // A signature over a fixed message remains a reusable policy, by design.
        let mut changed_tx = psbt.clone();
        changed_tx.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(40_000);
        let mut static_replay = request(Some(&script), &witness);
        static_replay.psbt_hex = hex::encode(changed_tx.serialize());
        assert!(sign_psbt_internal(&state, static_replay).is_ok());
    }

    #[tokio::test]
    async fn transaction_approval_cannot_be_replayed_for_a_different_spend() {
        use super::super::tests::{post_json, tweaked_public_key};
        use super::super::tweak::JetEnvKind;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use simplicity::{
            ConstructNode, Word,
            jet::Core,
            node::{CoreConstructible, WitnessConstructible},
            types,
        };
        use simplicity_unchained_core::runner::bitcoin_execution_environment;

        let state = create_test_signer_state();
        let guardian = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let guardian_pair = UntweakedKeypair::from_secret_key(&*state.secp, &guardian);
        let guardian_key = guardian_pair.x_only_public_key().0;
        let program = types::Context::with_context(|ctx| {
            let key = Arc::<ConstructNode>::const_word(&ctx, Word::u256(guardian_key.serialize()));
            let hash = Arc::<ConstructNode>::jet(&ctx, &CoreExtension::TxApprovalHash);
            let key_msg = Arc::<ConstructNode>::pair(&key, &hash).unwrap();
            let signature = Arc::<ConstructNode>::witness(&ctx, None);
            let args = Arc::<ConstructNode>::pair(&key_msg, &signature).unwrap();
            let verify = Arc::<ConstructNode>::jet(&ctx, &CoreExtension::Core(Core::Bip0340Verify));
            STANDARD.encode(
                Arc::<ConstructNode>::comp(&args, &verify)
                    .unwrap()
                    .finalize_types()
                    .unwrap()
                    .to_vec_without_witness(),
            )
        });
        let cmr = Program::<CoreExtension>::from_str(&program, None)
            .unwrap()
            .cmr();
        let user_secret = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (_, recovery, user) = create_test_p2tr_setup(&state, &user_secret);
        let cosigner = tweaked_public_key(&state, &program, None, JetEnvKind::Bitcoin).await;
        let (address, spend_info) =
            generate_p2tr_address_btc(&cosigner, &user, recovery, bitcoin::Network::Testnet)
                .unwrap();
        let psbt = create_test_psbt(create_test_transaction(), address.script_pubkey());
        let approval = |psbt: &Psbt| {
            let digest = bitcoin_execution_environment(
                psbt,
                0,
                cmr,
                &simplicity::elements::Script::new(),
                state.bitcoin_network,
            )
            .unwrap()
            .approval_hash;
            STANDARD.encode(
                state
                    .secp
                    .sign_schnorr(&Message::from_digest(digest), &guardian_pair)
                    .as_ref(),
            )
        };
        let witness = approval(&psbt);
        let body = |psbt: &Psbt, witness: &str| {
            serde_json::json!({
                "psbt_hex": hex::encode(psbt.serialize()),
                "input_index": 0,
                "program": program,
                "witness": witness,
                "user_pubkey": hex::encode(user.to_bytes()),
                "user_leaf_hash_hex": hex::encode(recovery.to_byte_array()),
            })
        };
        let response = post_json(
            &state,
            "/simplicity-unchained/sign/psbt",
            body(&psbt, &witness),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let signed =
            Psbt::deserialize(&hex::decode(result["psbt_hex"].as_str().unwrap()).unwrap()).unwrap();
        let ((signing_key, _), signature) =
            signed.inputs[0].tap_script_sigs.first_key_value().unwrap();
        let (control, (leaf, _)) = signed.inputs[0].tap_scripts.first_key_value().unwrap();
        assert!(control.verify_taproot_commitment(
            &*state.secp,
            spend_info.output_key().to_x_only_public_key(),
            leaf,
        ));
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[psbt.inputs[0].witness_utxo.clone().unwrap()]),
                ScriptPath::with_defaults(leaf),
                TapSighashType::Default,
            )
            .unwrap();
        state
            .secp
            .verify_schnorr(
                &signature.signature,
                &Message::from_digest(sighash.to_byte_array()),
                signing_key,
            )
            .unwrap();

        let mut changed_output = psbt.clone();
        changed_output.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(40_000);
        let mut changed_locktime = psbt.clone();
        changed_locktime.unsigned_tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let mut changed_prevout = psbt.clone();
        changed_prevout.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .value = bitcoin::Amount::from_sat(99_999);
        for changed in [&changed_output, &changed_locktime, &changed_prevout] {
            let response = post_json(
                &state,
                "/simplicity-unchained/sign/psbt",
                body(changed, &witness),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(
                result["error"]
                    .as_str()
                    .unwrap()
                    .contains("Simplicity execution failed")
            );
        }
        let mut other_network = state.clone();
        other_network.bitcoin_network = BitcoinNetwork::Testnet4;
        let response = post_json(
            &other_network,
            "/simplicity-unchained/sign/psbt",
            body(&psbt, &witness),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let fresh_witness = approval(&changed_output);
        let response = post_json(
            &state,
            "/simplicity-unchained/sign/psbt",
            body(&changed_output, &fresh_witness),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_legacy_cmr_only_output_is_rejected() {
        let state = create_test_signer_state();
        let user_secret = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let (_, recovery, user) = create_test_p2tr_setup(&state, &user_secret);
        let cmr = Program::<CoreExtension>::from_str(PROGRAM, None)
            .unwrap()
            .cmr();
        let legacy = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key).tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );
        let (key, parity) = legacy.public_parts();
        let cosigner = bitcoin::PublicKey::new(key.to_x_only_public_key().public_key(parity));
        let (address, _) =
            generate_p2tr_address_btc(&cosigner, &user, recovery, bitcoin::Network::Testnet)
                .unwrap();
        let psbt = create_test_psbt(create_test_transaction(), address.script_pubkey());
        let request = create_test_sign_request(hex::encode(psbt.serialize()), &user, recovery);
        assert!(
            sign_psbt_internal(&state, request)
                .unwrap_err()
                .contains("Spent output does not match")
        );
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
