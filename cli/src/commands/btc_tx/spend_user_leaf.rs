use anyhow::{Context, Result};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    TapLeafHash, TapSighashType,
    key::UntweakedKeypair,
    psbt::Psbt,
    script::ScriptBuf,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, Signature as TapSig},
};
use hal_simplicity::bitcoin::base64::Engine;
use hal_simplicity::bitcoin::hashes::Hash;
use hal_simplicity::bitcoin::{self, base64};
use serde_json::json;
use simplicity_unchained_core::utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc};
use std::str::FromStr;

pub fn execute(
    psbt_hex: &str,
    secret_key_hex: &str,
    user_leaf_script_hex: &str,
    cosigner_pubkey_hex: &str,
    input_index: usize,
    _network: &str,
) -> Result<()> {
    let secp = Secp256k1::new();

    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let mut psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let secret_key = SecretKey::from_str(secret_key_hex).context("Failed to parse secret key")?;
    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (user_xonly, _) = keypair.x_only_public_key();

    let user_leaf_bytes =
        hex::decode(user_leaf_script_hex).context("Failed to decode user leaf script hex")?;
    let user_leaf_script = ScriptBuf::from_bytes(user_leaf_bytes);

    let cosigner_pubkey =
        PublicKey::from_str(cosigner_pubkey_hex).context("Failed to parse cosigner pubkey")?;
    let cosigner_full_pk = bitcoin::PublicKey::new(cosigner_pubkey);
    let user_full_pk = bitcoin::PublicKey::new(keypair.public_key());

    let multisig_leaf = p2tr_multisig_leaf_btc(&cosigner_full_pk, &user_full_pk);

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf)
        .context("Failed to add multisig leaf")?
        .add_leaf(1, user_leaf_script.clone())
        .context("Failed to add user leaf")?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot"))?;

    let control_block = spend_info
        .control_block(&(user_leaf_script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to get control block for user leaf"))?;

    let tx = psbt
        .clone()
        .extract_tx()
        .context("Failed to extract transaction")?;

    let prevouts = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            bitcoin::sighash::ScriptPath::with_defaults(&user_leaf_script),
            TapSighashType::Default,
        )
        .context("Failed to compute sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);

    let tap_sig = TapSig {
        signature,
        sighash_type: TapSighashType::Default,
    };
    let leaf_hash = TapLeafHash::from_script(&user_leaf_script, LeafVersion::TapScript);

    psbt.inputs[input_index]
        .tap_script_sigs
        .insert((user_xonly, leaf_hash), tap_sig);

    psbt.inputs[input_index]
        .tap_scripts
        .insert(control_block, (user_leaf_script, LeafVersion::TapScript));

    let enc_engine = base64::engine::general_purpose::STANDARD;
    let output = json!({
        "psbt": hex::encode(psbt.serialize()),
        "psbt_base64": enc_engine.encode(psbt.serialize()),
        "signature": hex::encode(signature.as_ref()),
        "input_index": input_index,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
