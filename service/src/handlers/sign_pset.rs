use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::{
    bitcoin::secp256k1,
    simplicity::elements::{
        self, SchnorrSighashType, Transaction, TxOut,
        schnorr::{TapTweak, TweakedKeypair, UntweakedKeypair},
        taproot::TapNodeHash,
    },
};

use elements::{
    EcdsaSighashType,
    bitcoin::PublicKey,
    encode::{deserialize, serialize},
    hashes::Hash,
    pset::PartiallySignedTransaction,
    script::Script,
    secp256k1_zkp::Message,
    sighash::SighashCache,
};
use serde::{Deserialize, Serialize};

use validator::Validate;

use simplicity_unchained_core::{runner::SimplicityRunner, utils::TransactionType};

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

    #[validate(custom(function = "validation::validate_redeem_script"))]
    pub redeem_script_hex: Option<String>,

    #[validate(length(min = 1))]
    pub program: String,

    pub witness: Option<String>,
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

    let redeem_script_bytes = match request.redeem_script_hex {
        Some(str) => {
            let bytes = hex::decode(str)
                .map_err(|e| format!("Failed to decode redeem script hex: {}", e))?;
            Script::from(bytes)
        }
        None => Script::new(),
    };

    let redeem_script = Script::from(redeem_script_bytes);

    let cmr = SimplicityRunner::execute_elements(
        &request.program,
        request.witness.as_deref(),
        request.input_index,
        &pset,
        redeem_script.clone(),
        state.elements_network.clone(),
    )
    .map_err(|e| format!("Simplicity execution failed: {}", e))?;

    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
    );

    let tx = pset
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;

    let script_pubkey = &pset.inputs()[request.input_index]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| format!("Missing witness_utxo for input {}", request.input_index))?
        .script_pubkey;

    let tx_ty = TransactionType::from(script_pubkey);
    let (sig_bytes, partial_sigs_count) = match tx_ty {
        TransactionType::P2SH | TransactionType::P2WSH => {
            let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();
            let public_key = PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
                tweaked_public_key.into_inner(),
                tweaked_parity,
            ));

            let sig = sign_p2wsh_p2sh(
                state,
                &mut pset,
                &tx,
                &redeem_script,
                public_key,
                &tweaked_keypair,
                request.input_index,
                tx_ty,
            )?;

            let count = pset.inputs()[request.input_index].partial_sigs.len();
            (sig, count)
        }
        TransactionType::P2TR => {
            let sig = sign_p2tr(state, &mut pset, &tx, &tweaked_keypair, request.input_index)?;
            let count = pset.inputs()[request.input_index].partial_sigs.len();
            (sig, count)
        }
    };

    let public_key_hex = match tx_ty {
        TransactionType::P2SH | TransactionType::P2WSH => {
            let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();
            let public_key = PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
                tweaked_public_key.into_inner(),
                tweaked_parity,
            ));
            hex::encode(public_key.to_bytes())
        }
        TransactionType::P2TR => String::new(),
    };

    Ok(SignPsetResponse {
        pset_hex: hex::encode(serialize(&pset)),
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
    pset: &mut PartiallySignedTransaction,
    tx: &Transaction,
    redeem_script: &Script,
    public_key: PublicKey,
    tweaked_keypair: &TweakedKeypair,
    input_index: usize,
    tx_type: TransactionType,
) -> Result<Vec<u8>, String> {
    let sighash = match tx_type {
        TransactionType::P2SH => {
            let sighash_cache = SighashCache::new(tx);
            sighash_cache.legacy_sighash(input_index, redeem_script, EcdsaSighashType::All)
        }
        TransactionType::P2WSH => {
            let prev_value = pset.inputs()[input_index]
                .witness_utxo
                .as_ref()
                .ok_or_else(|| format!("Missing witness UTXO for input {}", input_index))?
                .value;

            let mut sighash_cache = SighashCache::new(tx);
            sighash_cache.segwitv0_sighash(
                input_index,
                redeem_script,
                prev_value,
                EcdsaSighashType::All,
            )
        }
        _ => unreachable!("Other types handled separately"),
    };

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = state
        .secp
        .sign_ecdsa(&msg, &tweaked_keypair.to_inner().secret_key());

    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.as_u32() as u8);

    let input = &mut pset.inputs_mut()[input_index];
    input.partial_sigs.insert(public_key, sig_bytes.clone());

    let input_script = match tx_type {
        TransactionType::P2SH => &mut input.redeem_script,
        TransactionType::P2WSH => &mut input.witness_script,
        _ => unreachable!("Other types handled separately"),
    };

    if input_script.is_none() {
        *input_script = Some(redeem_script.clone());
    }

    Ok(sig_bytes)
}

fn sign_p2tr(
    state: &SignerState,
    pset: &mut PartiallySignedTransaction,
    tx: &Transaction,
    tweaked_keypair: &TweakedKeypair,
    input_index: usize,
) -> Result<Vec<u8>, String> {
    let prevouts: Vec<TxOut> = pset
        .inputs()
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
            &elements::sighash::Prevouts::All(&prevouts),
            SchnorrSighashType::Default,
            state.elements_network.genesis_hash(),
        )
        .map_err(|e| format!("Failed to compute taproot sighash: {}", e))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = state.secp.sign_schnorr(&msg, &tweaked_keypair.to_inner());

    // 64-byte raw Schnorr signature
    let sig_bytes = signature.as_ref().to_vec();

    pset.inputs_mut()[input_index].tap_key_sig = Some(elements::SchnorrSig {
        sig: signature,
        hash_ty: SchnorrSighashType::Default,
    });

    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use elements::{
        OutPoint, Transaction, TxIn, TxInWitness, TxOut, Txid,
        confidential::{Asset, Value},
        opcodes::all::OP_CHECKMULTISIG,
        pset::PartiallySignedTransaction,
        script::Builder as ScriptBuilder,
        secp256k1_zkp::Secp256k1,
    };
    use hal_simplicity::{bitcoin::hashes::Hash, hal_simplicity::Program};
    use std::str::FromStr;

    use hal_simplicity::simplicity::elements::secp256k1_zkp::SecretKey;

    use simplicity_unchained_core::{
        BitcoinNetwork, ElementsNetwork, jets::elements::ElementsExtension,
    };

    fn create_test_signer_state() -> SignerState {
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        SignerState {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network: simplicity_unchained_core::ElementsNetwork::LiquidTestnet,
            bitcoin_network: simplicity_unchained_core::BitcoinNetwork::Testnet,
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

    fn create_test_pset(tx: Transaction, script_pubkey: Script) -> PartiallySignedTransaction {
        let mut pset = PartiallySignedTransaction::from_tx(tx);

        // Add witness_utxo to the first input (required for SegWit v0)
        pset.inputs_mut()[0].witness_utxo = Some(TxOut {
            asset: Asset::Explicit(elements::AssetId::from_slice(&[0; 32]).unwrap()),
            value: Value::Explicit(100_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey,
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
        let script_pubkey = Script::new_v0_wsh(&redeem_script.to_v0_p2wsh().wscript_hash());
        let pset = create_test_pset(tx, script_pubkey);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
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
    fn test_sign_p2sh_success() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();
        let script_pubkey = Script::new_p2sh(&redeem_script.script_hash());
        let pset = create_test_pset(tx, script_pubkey);
        let pset_hex = hex::encode(serialize(&pset));

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };

        let result = sign_pset_internal(&state, request).unwrap();

        // DER + sighash byte
        let sig_bytes = hex::decode(&result.signature_hex).unwrap();
        assert_eq!(
            *sig_bytes.last().unwrap(),
            EcdsaSighashType::All.as_u32() as u8
        );
        assert!(!result.public_key_hex.is_empty());

        let signed_pset_bytes = hex::decode(&result.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        // P2SH: redeem_script set, witness_script NOT set
        assert!(signed_pset.inputs()[0].redeem_script.is_some());
        assert!(signed_pset.inputs()[0].witness_script.is_none());
        assert!(!signed_pset.inputs()[0].partial_sigs.is_empty());
    }

    #[test]
    fn test_sign_p2tr_success() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();

        let secret_key = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        let script_pubkey = Script::new_v1_p2tr(&secp, xonly, None);

        let pset = create_test_pset(tx, script_pubkey);
        let pset_hex = hex::encode(serialize(&pset));

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            // redeem_script is only used for Simplicity validation, not the spending script
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: Some("".to_string()),
        };

        let result = sign_pset_internal(&state, request).unwrap();

        // P2TR returns 64-byte Schnorr sig, no sighash byte
        let sig_bytes = hex::decode(&result.signature_hex).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        assert!(result.public_key_hex.is_empty());

        let signed_pset_bytes = hex::decode(&result.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        // tap_key_sig set, partial_sigs empty
        let tap_sig = signed_pset.inputs()[0]
            .tap_key_sig
            .expect("tap_key_sig should be present");
        assert_eq!(tap_sig.hash_ty, SchnorrSighashType::Default);
        assert!(signed_pset.inputs()[0].partial_sigs.is_empty());
    }

    #[test]
    fn test_sign_pset_internal_invalid_hex() {
        let state = create_test_signer_state();

        let request = SignPsetRequest {
            pset_hex: "invalid_hex!!!".to_string(),
            input_index: 0,
            redeem_script_hex: Some("".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
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
            redeem_script_hex: Some("".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
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

        let script_pubkey = Script::new_v0_wsh(&redeem_script.to_v0_p2wsh().wscript_hash());
        let pset = create_test_pset(tx, script_pubkey);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 999, // Out of bounds
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
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

        let script_pubkey = Script::new_v0_wsh(&Script::default().to_v0_p2wsh().wscript_hash());
        let pset = create_test_pset(tx, script_pubkey);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some("invalid_hex!!!".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
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
        let script_pubkey = Script::new_v0_wsh(&redeem_script.to_v0_p2wsh().wscript_hash());
        let pset = create_test_pset(tx.clone(), script_pubkey);

        let pset_bytes = serialize(&pset);
        let pset_hex = hex::encode(&pset_bytes);

        let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string();

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: program.clone(),
            witness: Some("".to_string()),
        };

        let result = sign_pset_internal(&state, request).unwrap();

        // Decode the signed PSET
        let signed_pset_bytes = hex::decode(&result.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        let program =
            Program::<ElementsExtension>::from_str(&program, Some("")).expect("valid program");

        let cmr = program.commit_prog().cmr();

        let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
        let tweaked_keypair = untweaked_keypair.tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );

        let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();

        let public_key = PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
            tweaked_public_key.into_inner(),
            tweaked_parity,
        ));

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
                .verify_ecdsa(&msg, &signature, &tweaked_keypair.to_inner().public_key());

        assert!(verification.is_ok());
    }
    #[test]
    fn test_sign_p2tr_signature_verification() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        let tx = create_test_transaction();

        let secret_key = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        let script_pubkey = Script::new_v1_p2tr(&secp, xonly, None);

        let pset = create_test_pset(tx.clone(), script_pubkey);
        let pset_hex = hex::encode(serialize(&pset));

        let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string();

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: program.clone(),
            witness: Some("".to_string()),
        };

        let result = sign_pset_internal(&state, request).unwrap();

        let signed_pset_bytes = hex::decode(&result.pset_hex).unwrap();
        let signed_pset: PartiallySignedTransaction = deserialize(&signed_pset_bytes).unwrap();

        let tap_sig = signed_pset.inputs()[0].tap_key_sig.unwrap();

        // Reconstruct tweaked keypair the same way sign_pset_internal does
        let program = Program::<ElementsExtension>::from_str(&program, Some("")).unwrap();
        let cmr = program.commit_prog().cmr();

        let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);
        let tweaked_keypair = untweaked_keypair.tap_tweak(
            &*state.secp,
            Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
        );

        // Recompute sighash
        let prevouts = vec![signed_pset.inputs()[0].witness_utxo.clone().unwrap()];
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(
                0,
                &elements::sighash::Prevouts::All(&prevouts),
                SchnorrSighashType::Default,
                state.elements_network.genesis_hash(),
            )
            .unwrap();

        let msg = Message::from_digest(sighash.to_byte_array());

        // Verify with x-only pubkey — parity is stripped for P2TR
        let (tweaked_xonly, _parity) = tweaked_keypair.public_parts();
        state
            .secp
            .verify_schnorr(&tap_sig.sig, &msg, &tweaked_xonly.into_inner())
            .expect("schnorr signature should be valid");
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
    fn test_sign_pset_request_validation() {
        let state = create_test_signer_state();
        let key2 = SecretKey::from_slice(&[0xab; 32]).expect("valid secret key");
        let redeem_script = create_2of2_multisig_script(&state, &key2);

        // Valid request
        let valid_request = SignPsetRequest {
            pset_hex: "0000000000".to_string(),
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
        };
        assert!(valid_request.validate().is_ok());

        // Empty pset_hex should fail
        let invalid_request = SignPsetRequest {
            pset_hex: "".to_string(),
            input_index: 0,
            redeem_script_hex: Some(hex::encode(redeem_script.as_bytes())),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
        };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_sign_pset_invalid_spend_type() {
        let state = create_test_signer_state();
        let tx = create_test_transaction();
        let script_pubkey =
            Script::new_p2pkh(&hal_simplicity::simplicity::elements::PubkeyHash::all_zeros());
        let pset = create_test_pset(tx, script_pubkey);
        let pset_hex = hex::encode(serialize(&pset));

        let request = SignPsetRequest {
            pset_hex,
            input_index: 0,
            redeem_script_hex: Some("abcd".to_string()),
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            witness: None,
        };

        let result = sign_pset_internal(&state, request);
        assert!(result.is_err());
    }
}
