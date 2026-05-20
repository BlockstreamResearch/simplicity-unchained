//! Timelocked user script for demo purposes
use anyhow::{Context, Result, anyhow};
use hal_simplicity::{
    bitcoin::{
        self, Psbt, TapLeafHash, Transaction, Witness, consensus::serialize, hashes::Hash, psbt,
        taproot::LeafVersion,
    },
    simplicity::{ToXOnlyPubkey, bitcoin::PublicKey},
};
use serde_json::json;
use std::str::FromStr;

pub fn build_csv_script(user_pubkey_hex: &str, timelock: u16) -> Result<()> {
    let user_pubkey =
        PublicKey::from_str(user_pubkey_hex).context("Failed to parse user pubkey")?;

    let script = p2tr_recovery_leaf_btc(&user_pubkey, timelock as i64);

    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);

    let output = json!({
        "script": hex::encode(script.as_bytes()),
        "leaf_hash": hex::encode(leaf_hash.to_byte_array()),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

pub fn finalize_user_leaf(psbt_hex: &str) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let mut tx = psbt
        .clone()
        .extract_tx()
        .context("Failed to extract transaction")?;

    for (i, input) in psbt.inputs.iter().enumerate() {
        finalize_internal(&mut tx, i, input)?;
    }

    let output = json!({
        "transaction_hex": hex::encode(serialize(&tx)),
        "txid": tx.compute_txid().to_string(),
        "inputs": tx.input.len(),
        "outputs": tx.output.len(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

fn finalize_internal(tx: &mut Transaction, i: usize, input: &psbt::Input) -> Result<()> {
    let (control_block, (leaf_script, _)) = input
        .tap_scripts
        .iter()
        .next()
        .map(|(cb, s)| (cb.clone(), s.clone()))
        .ok_or_else(|| anyhow!("Input {} missing tap_scripts", i))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let sig = input
        .tap_script_sigs
        .iter()
        .find(|((_, lh), _)| lh == &leaf_hash)
        .map(|(_, sig)| sig)
        .ok_or_else(|| anyhow!("Input {} missing tap_script_sig", i))?;

    let mut witness = Witness::new();
    witness.push(sig.serialize());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[i].witness = witness;

    Ok(())
}

/// Builds the P2TR recovery leaf script for the unilateral user recovery path.
///
/// Allows the user to spend without the cosigner after the timelock expires.
///
/// Script structure:
/// ```text
/// <timelock> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG
fn p2tr_recovery_leaf_btc(user_pk: &PublicKey, timelock: i64) -> bitcoin::script::ScriptBuf {
    bitcoin::script::Builder::new()
        .push_int(timelock)
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_x_only_key(&user_pk.to_x_only_pubkey())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script()
}
