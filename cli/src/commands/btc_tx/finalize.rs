use anyhow::{Context, Result, anyhow};
use hal_simplicity::bitcoin::{
    self, Psbt, TapLeafHash, Transaction, Witness, consensus::serialize, psbt, taproot::LeafVersion,
};
use serde_json::json;
use simplicity_unchained_core::utils::extract_pubkeys_from_p2tr_multisig_leaf_btc;

pub fn execute(psbt_hex: &str) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let mut tx = psbt
        .clone()
        .extract_tx()
        .context("Failed to extract transaction from PSBT")?;

    // For each input, build the witness from partial signatures
    for (i, input) in psbt.inputs.iter().enumerate() {
        finalize_p2tr(&mut tx, i, input)?;
    }

    let all_finalized = tx.input.iter().all(|input| !input.witness.is_empty());

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
                "witness_elements": input.witness.len(),
                "script_sig_bytes": input.script_sig.len(),
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

fn finalize_p2tr(tx: &mut Transaction, i: usize, input: &psbt::Input) -> Result<()> {
    let (control_block, (leaf_script, _)) = input
        .tap_scripts
        .iter()
        .next()
        .map(|(cb, s)| (cb.clone(), s.clone()))
        .ok_or_else(|| anyhow!("Input {} missing tap_scripts", i))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let mut witness = Witness::new();

    let pubkeys = extract_pubkeys_from_p2tr_multisig_leaf_btc(&leaf_script, i)
        .map_err(|e| anyhow!("Input {} leaf script is not a multisig leaf: {}", i, e))?;

    let mut sigs: Vec<Option<bitcoin::taproot::Signature>> = vec![None; pubkeys.len()];
    for ((xonly_pk, lh), tap_sig) in &input.tap_script_sigs {
        if *lh != leaf_hash {
            continue;
        }
        for (idx, pk) in pubkeys.iter().enumerate() {
            if xonly_pk == pk {
                sigs[idx] = Some(*tap_sig);
                break;
            }
        }
    }

    let cosigner_sig =
        sigs[0].ok_or_else(|| anyhow!("Input {} missing cosigner tap_script_sig", i))?;
    let user_sig = sigs[1].ok_or_else(|| anyhow!("Input {} missing user tap_script_sig", i))?;

    witness.push(user_sig.serialize());
    witness.push(cosigner_sig.serialize());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[i].witness = witness;

    Ok(())
}
