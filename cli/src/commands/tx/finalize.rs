use anyhow::{Context, Result, anyhow};
use hal_simplicity::simplicity::elements::{
    self, Transaction,
    bitcoin::PublicKey,
    encode::{deserialize, serialize},
    pset::{self, PartiallySignedTransaction},
    script::{Builder, Script},
};
use serde_json::json;

pub fn execute(pset_hex: &str) -> Result<()> {
    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    let mut tx = pset
        .extract_tx()
        .context("Failed to extract transaction from PSET")?;

    for (i, input) in pset.inputs().iter().enumerate() {
        let (is_p2sh, is_p2wsh, is_p2tr) = {
            let script_pubkey = &input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| anyhow!("Input {} missing witness_utxo", i))?
                .script_pubkey;
            (
                script_pubkey.is_p2sh(),
                script_pubkey.is_v0_p2wsh(),
                script_pubkey.is_v1_p2tr(),
            )
        };
        if is_p2wsh {
            finalize_p2wsh(&mut tx, i, input)?;
        } else if is_p2sh {
            finalize_p2sh(&mut tx, i, input)?;
        } else if is_p2tr {
            finalize_p2tr(&mut tx, i, input)?;
        } else {
            return Err(anyhow!(
                "Input {} has unsupported script type: {}",
                i,
                hex::encode(
                    input
                        .witness_utxo
                        .as_ref()
                        .ok_or_else(|| anyhow!("Input {} missing witness_utxo", i))?
                        .script_pubkey
                        .as_bytes()
                )
            ));
        }
    }

    let all_finalized = tx
        .input
        .iter()
        .all(|input| !input.witness.script_witness.is_empty() || !input.script_sig.is_empty());

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
                "witness_elements": input.witness.script_witness.len()
            })
        })
        .collect();

    let output = json!({
        "transaction_hex": hex::encode(serialize(&tx)),
        "txid": tx.txid().to_string(),
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
    partial_sigs: &std::collections::BTreeMap<PublicKey, Vec<u8>>,
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
                .cloned()
                .ok_or_else(|| anyhow!("Input {} missing signature for pubkey {}", input_index, pk))
        })
        .collect()
}

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

fn finalize_p2wsh(tx: &mut Transaction, i: usize, input: &pset::Input) -> Result<()> {
    let witness_script = input
        .witness_script
        .as_ref()
        .ok_or_else(|| anyhow!("Input {} missing witness_script", i))?;

    let sigs = extract_ordered_sigs(witness_script, &input.partial_sigs, i)?;

    let mut witness = vec![vec![]]; // OP_0
    witness.extend(sigs);
    witness.push(witness_script.to_bytes());

    tx.input[i].witness.script_witness = witness;

    Ok(())
}

fn finalize_p2sh(tx: &mut Transaction, i: usize, input: &pset::Input) -> Result<()> {
    let redeem_script = input
        .redeem_script
        .as_ref()
        .ok_or_else(|| anyhow!("Input {} missing redeem_script", i))?;

    let sigs = extract_ordered_sigs(redeem_script, &input.partial_sigs, i)?;

    eprintln!("sig[0]: {}", hex::encode(&sigs[0]));
    eprintln!("sig[1]: {}", hex::encode(&sigs[1]));
    eprintln!("redeem_script: {}", hex::encode(redeem_script.as_bytes()));

    let mut builder = Builder::new();
    builder = builder.push_opcode(elements::opcodes::all::OP_PUSHBYTES_0);
    for sig in &sigs {
        builder = builder.push_slice(sig);
    }
    builder = builder.push_slice(redeem_script.as_bytes());

    tx.input[i].script_sig = builder.into_script();

    eprintln!(
        "final scriptSig: {}",
        hex::encode(tx.input[i].script_sig.as_bytes())
    );

    Ok(())
}

fn finalize_p2tr(tx: &mut Transaction, i: usize, input: &pset::Input) -> Result<()> {
    let tap_sig = input
        .tap_key_sig
        .ok_or_else(|| anyhow!("Input {} missing tap_key_sig", i))?;

    tx.input[i].witness.script_witness = vec![tap_sig.sig.as_ref().to_vec()];

    Ok(())
}
