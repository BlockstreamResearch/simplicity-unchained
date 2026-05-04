use anyhow::{Context, Result, anyhow};
use hal_simplicity::simplicity::elements::taproot::TapLeafHash;
use hal_simplicity::simplicity::elements::{
    Transaction,
    encode::{deserialize, serialize},
    pset::{self, PartiallySignedTransaction},
};
use serde_json::json;
use simplicity_unchained_core::utils::extract_pubkeys_from_p2tr_multisig_leaf_elements;

pub fn execute(pset_hex: &str) -> Result<()> {
    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    let mut tx = pset
        .extract_tx()
        .context("Failed to extract transaction from PSET")?;

    for (i, input) in pset.inputs().iter().enumerate() {
        finalize_p2tr(&mut tx, i, input)?;
    }

    let all_finalized = tx
        .input
        .iter()
        .all(|input| !input.witness.script_witness.is_empty());

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

fn finalize_p2tr(tx: &mut Transaction, i: usize, input: &pset::Input) -> Result<()> {
    let (control_block, (leaf_script, leaf_version)) = input
        .tap_scripts
        .iter()
        .next()
        .map(|(cb, s)| (cb.clone(), s.clone()))
        .ok_or_else(|| anyhow!("Input {} missing tap_scripts", i))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, leaf_version);

    let pubkeys = extract_pubkeys_from_p2tr_multisig_leaf_elements(&leaf_script, i)
        .map_err(|e| anyhow!("Input {} leaf script is not a multisig leaf: {}", i, e))?;

    let mut sigs = vec![None; pubkeys.len()];

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

    tx.input[i].witness.script_witness = vec![
        user_sig.to_vec(),
        cosigner_sig.to_vec(),
        leaf_script.to_bytes(),
        control_block.serialize(),
    ];

    Ok(())
}
