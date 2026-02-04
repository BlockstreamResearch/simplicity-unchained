use anyhow::{Context, Result};
use hal_simplicity::simplicity::bitcoin::{
    EcdsaSighashType, NetworkKind, PrivateKey, PublicKey, hashes::Hash, psbt::Psbt, script::Script,
    sighash::SighashCache,
};
use hal_simplicity::simplicity::elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use serde_json::json;

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
    let redeem_script = Script::from_bytes(&redeem_script_bytes).to_owned();

    let secp = Secp256k1::new();

    let public_key = PublicKey::from_private_key(
        &secp,
        &PrivateKey {
            compressed: true,
            network: NetworkKind::Main,
            inner: secret_key,
        },
    );

    let psbt_input = &psbt.inputs[input_index];
    let prev_value = psbt_input
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing witness UTXO for input {}", input_index))?
        .value;

    // Clone psbt to extract transaction, since extract_tx consumes it
    let tx = psbt.clone().extract_tx_unchecked_fee_rate();

    // Compute sighash for P2WSH (SegWit v0)
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .p2wsh_signature_hash(
            input_index,
            &redeem_script,
            prev_value,
            EcdsaSighashType::All,
        )
        .context("Failed to compute sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_ecdsa(&msg, &secret_key);

    // Convert to bitcoin's Signature type for PSBT
    let bitcoin_sig = hal_simplicity::simplicity::bitcoin::ecdsa::Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };

    // Add signature to PSBT
    let input = &mut psbt.inputs[input_index];
    input.partial_sigs.insert(public_key, bitcoin_sig);

    if input.witness_script.is_none() {
        input.witness_script = Some(redeem_script);
    }

    let partial_sigs_count = psbt.inputs[input_index].partial_sigs.len();

    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

    let output = json!({
        "psbt": hex::encode(psbt.serialize()),
        "signature_hex": hex::encode(&sig_bytes),
        "public_key_hex": hex::encode(public_key.to_bytes()),
        "input_index": input_index,
        "partial_sigs_count": partial_sigs_count,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
