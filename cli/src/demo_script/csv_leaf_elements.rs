//! Timelocked user script for demo purposes
use anyhow::{Context, Result, anyhow};
use hal_simplicity::{
    bitcoin::PublicKey,
    simplicity::{
        ToXOnlyPubkey,
        elements::{
            self,
            encode::{deserialize, serialize},
            hashes::Hash,
            pset::{self, PartiallySignedTransaction},
            taproot::{LeafVersion, TapLeafHash},
        },
    },
};
use serde_json::json;

pub fn build_csv_script(user_pubkey_hex: &str, timelock: u16) -> Result<()> {
    let user_pubkey_bytes =
        hex::decode(user_pubkey_hex).context("Failed to decode user pubkey hex")?;
    let user_pubkey =
        PublicKey::from_slice(&user_pubkey_bytes).context("Failed to parse user pubkey")?;

    let script = p2tr_recovery_leaf_elements(&user_pubkey, timelock as i64);
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::default());

    let output = json!({
        "script": hex::encode(script.to_bytes()),
        "leaf_hash": hex::encode(leaf_hash.to_byte_array()),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

pub fn finalize_user_leaf(pset_hex: &str) -> Result<()> {
    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    let mut tx = pset.extract_tx().context("Failed to extract transaction")?;

    for (i, input) in pset.inputs().iter().enumerate() {
        finalize_internal(&mut tx, i, input)?;
    }

    let output = json!({
        "transaction_hex": hex::encode(serialize(&tx)),
        "txid": tx.txid().to_string(),
        "inputs": tx.input.len(),
        "outputs": tx.output.len(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

fn finalize_internal(tx: &mut elements::Transaction, i: usize, input: &pset::Input) -> Result<()> {
    let (control_block, (leaf_script, leaf_version)) = input
        .tap_scripts
        .iter()
        .next()
        .map(|(cb, s)| (cb.clone(), s.clone()))
        .ok_or_else(|| anyhow!("Input {} missing tap_scripts", i))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, leaf_version);

    let sig = input
        .tap_script_sigs
        .iter()
        .find(|((_, lh), _)| lh == &leaf_hash)
        .map(|(_, sig)| sig)
        .ok_or_else(|| anyhow!("Input {} missing tap_script_sig", i))?;

    tx.input[i].witness.script_witness = vec![
        sig.to_vec(),
        leaf_script.to_bytes(),
        control_block.serialize(),
    ];

    Ok(())
}

/// Builds the P2TR recovery leaf script for the unilateral user recovery path.
///
/// Allows the user to spend without the cosigner after the timelock expires.
///
/// Script structure:
/// ```text
/// <timelock> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG
/// ```
fn p2tr_recovery_leaf_elements(user_pk: &PublicKey, timelock: i64) -> elements::script::Script {
    let user_xonly_bytes = user_pk.to_x_only_pubkey().serialize();

    elements::script::Builder::new()
        .push_int(timelock)
        .push_opcode(elements::opcodes::all::OP_CSV)
        .push_opcode(elements::opcodes::all::OP_DROP)
        .push_slice(&user_xonly_bytes)
        .push_opcode(elements::opcodes::all::OP_CHECKSIG)
        .into_script()
}
