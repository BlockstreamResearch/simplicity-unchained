use anyhow::{Context, Result};
use hal_simplicity::bitcoin::ScriptBuf;
use hal_simplicity::simplicity::bitcoin::{
    EcdsaSighashType, PublicKey, hashes::Hash, psbt::Psbt, sighash::SighashCache,
};
use hal_simplicity::simplicity::elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use serde_json::json;
use simplicity_unchained_core::utils::TransactionType;

pub fn execute(
    psbt_hex: &str,
    secret_key_hex: &str,
    input_index: usize,
    redeem_script_hex: &str,
) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    if input_index >= psbt.inputs.len() {
        return Err(anyhow::anyhow!(
            "Input index {} out of bounds (PSBT has {} inputs)",
            input_index,
            psbt.inputs.len()
        ));
    }

    let secret_key_bytes =
        hex::decode(secret_key_hex).context("Failed to decode secret key hex")?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).context("Invalid secret key")?;

    let redeem_script_bytes =
        hex::decode(redeem_script_hex).context("Failed to decode redeem script hex")?;
    let redeem_script = ScriptBuf::from(redeem_script_bytes);

    let secp = Secp256k1::new();

    let public_key = PublicKey::from_private_key(
        &secp,
        &hal_simplicity::simplicity::elements::bitcoin::PrivateKey {
            compressed: true,
            network: hal_simplicity::simplicity::elements::bitcoin::NetworkKind::Main,
            inner: secret_key,
        },
    );

    let tx = psbt.clone().extract_tx()?;

    let psbt_input = &psbt.inputs[input_index];

    let script_pubkey = &psbt_input
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing witness UTXO for input {}", input_index))?
        .script_pubkey
        .clone();
    let tx_ty = TransactionType::from(script_pubkey.as_script());

    let prev_value = psbt_input.witness_utxo.as_ref().unwrap().value;

    let mut sighash_cache = SighashCache::new(&tx);

    let sighash = match tx_ty {
        TransactionType::P2SH => *sighash_cache
            .legacy_signature_hash(input_index, &redeem_script, EcdsaSighashType::All.to_u32())?
            .as_byte_array(),
        TransactionType::P2WSH => *sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &redeem_script,
                prev_value,
                EcdsaSighashType::All,
            )?
            .as_byte_array(),
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported script type for tx sign: {}",
                hex::encode(script_pubkey.as_bytes())
            ));
        }
    };

    let msg = Message::from_digest(sighash);

    let signature =
        hal_simplicity::bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&msg, &secret_key));
    let sig_bytes = signature.to_vec();

    // Add signature to PSBT
    let input = &mut psbt.inputs[input_index];
    input.partial_sigs.insert(public_key, signature);

    if script_pubkey.is_p2sh() {
        if input.redeem_script.is_none() {
            input.redeem_script = Some(redeem_script.clone());
        }
    } else if script_pubkey.is_p2wsh() && input.witness_script.is_none() {
        input.witness_script = Some(redeem_script.clone());
    }

    let partial_sigs_count = psbt.inputs[input_index].partial_sigs.len();

    let output = json!({
        "psbt": hex::encode(psbt.serialize()),
        "signature_hex": hex::encode(sig_bytes),
        "public_key_hex": hex::encode(public_key.to_bytes()),
        "input_index": input_index,
        "partial_sigs_count": partial_sigs_count,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
