use anyhow::{Context, Result, anyhow};
use hal_simplicity::bitcoin::{
    Psbt, PublicKey, Script, Transaction, Witness,
    consensus::serialize,
    psbt,
    script::{Builder, PushBytesBuf},
};
use serde_json::json;
use simplicity_unchained_core::utils::TransactionType;

pub fn execute(psbt_hex: &str) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let mut tx = psbt
        .clone()
        .extract_tx()
        .context("Failed to extract transaction from PSBT")?;

    // For each input, build the witness from partial signatures
    for (i, input) in psbt.inputs.iter().enumerate() {
        let script_pubkey = &input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| anyhow!("Input {} missing witness_utxo", i))?
            .script_pubkey;
        let tx_ty = TransactionType::from(script_pubkey.as_script());

        match tx_ty {
            TransactionType::P2SH => finalize_p2sh(&mut tx, i, input)?,
            TransactionType::P2WSH => finalize_p2wsh(&mut tx, i, input)?,
            TransactionType::P2TR => finalize_p2tr(&mut tx, i, input)?,
        }
    }

    // Verify all inputs have witnesses
    let all_finalized = tx
        .input
        .iter()
        .all(|input| input.witness.witness_script().is_some() || !input.script_sig.is_empty());

    if !all_finalized {
        return Err(anyhow!(
            "Not all inputs are finalized - transaction may be missing signatures"
        ));
    }

    let witnesses: Vec<_> = tx
        .input
        .iter()
        .enumerate()
        .map(|(idx, input)| {
            json!({
                "input_index": idx,
                "witness_elements": input.witness.witness_script().expect("witness scripts must be non-empty").len()
            })
        })
        .collect();

    let output = json!({
        "transaction_hex": hex::encode(serialize(&tx)),
        "txid": tx.compute_txid().to_string(),
        "inputs": tx.input.len(),
        "outputs": tx.output.len(),
        "finalized": true,
        "witnesses": witnesses
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

// Extracts ordered signatures from partial_sigs according to pubkey order in the multisig script.
// For OP_m <pk1> <pk2> ... OP_n OP_CHECKMULTISIG, signatures must be ordered
fn extract_ordered_sigs(
    script: &Script,
    partial_sigs: &std::collections::BTreeMap<PublicKey, hal_simplicity::bitcoin::ecdsa::Signature>,
    input_index: usize,
) -> Result<Vec<Vec<u8>>> {
    let pubkeys = extract_pubkeys_from_multisig(script, input_index)?;

    if partial_sigs.len() < pubkeys.len() {
        return Err(anyhow!(
            "Input {} requires {} signatures but only has {}",
            input_index,
            pubkeys.len(),
            partial_sigs.len()
        ));
    }

    pubkeys
        .iter()
        .map(|pk| {
            partial_sigs
                .get(pk)
                .map(|pk| pk.to_vec())
                .ok_or_else(|| anyhow!("Input {} missing signature for pubkey {}", input_index, pk))
        })
        .collect()
}

/// Extract public keys from the witness script (2-of-2 multisig format: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG)
fn extract_pubkeys_from_multisig(script: &Script, input_index: usize) -> Result<Vec<PublicKey>> {
    let script_bytes = script.as_bytes();
    let mut pubkeys = Vec::new();
    let mut i = 0;

    while i < script_bytes.len() {
        if script_bytes[i] == 33 && i + 33 < script_bytes.len() {
            let pk_bytes = &script_bytes[i + 1..i + 34];
            if let Ok(pk) = PublicKey::from_slice(pk_bytes) {
                pubkeys.push(pk);
            }
            i += 34;
        } else {
            i += 1;
        }
    }

    if pubkeys.is_empty() {
        return Err(anyhow!(
            "Input {} script contains no recognizable public keys",
            input_index
        ));
    }

    Ok(pubkeys)
}

fn finalize_p2wsh(tx: &mut Transaction, i: usize, input: &psbt::Input) -> Result<()> {
    let witness_script = input
        .witness_script
        .as_ref()
        .ok_or_else(|| anyhow!("Input {} missing witness_script", i))?;

    let sigs = extract_ordered_sigs(witness_script, &input.partial_sigs, i)?;

    let mut witness = vec![vec![]]; // OP_0
    witness.extend(sigs);
    witness.push(witness_script.to_bytes());

    tx.input[i].witness = Witness::from_slice(&witness);

    Ok(())
}

fn finalize_p2sh(tx: &mut Transaction, i: usize, input: &psbt::Input) -> Result<()> {
    let redeem_script = input
        .redeem_script
        .as_ref()
        .ok_or_else(|| anyhow!("Input {} missing redeem_script", i))?;

    let sigs = extract_ordered_sigs(redeem_script, &input.partial_sigs, i)?;

    let mut builder = Builder::new();
    builder = builder.push_opcode(hal_simplicity::bitcoin::opcodes::OP_0);
    for sig in &sigs {
        let push_bytes = PushBytesBuf::try_from(sig.clone())
            .map_err(|_| anyhow!("Input {} signature too large for push", i))?;
        builder = builder.push_slice(&push_bytes);
    }
    let redeem_push = PushBytesBuf::try_from(redeem_script.to_bytes())
        .map_err(|_| anyhow!("Input {} redeem script too large for push", i))?;
    builder = builder.push_slice(&redeem_push);

    tx.input[i].script_sig = builder.into_script();

    Ok(())
}

fn finalize_p2tr(tx: &mut Transaction, i: usize, input: &psbt::Input) -> Result<()> {
    let tap_sig = input
        .tap_key_sig
        .ok_or_else(|| anyhow!("Input {} missing tap_key_sig", i))?;

    tx.input[i].witness = Witness::p2tr_key_spend(&tap_sig);

    Ok(())
}
