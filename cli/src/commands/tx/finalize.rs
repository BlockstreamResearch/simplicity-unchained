use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use simplicity::elements::taproot::{LeafVersion, TapLeafHash};
use simplicity::elements::{
    BlockHash, Transaction, TxOut,
    encode::{deserialize, serialize},
    pset::{self, PartiallySignedTransaction},
    schnorr::TapTweak,
    secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
};
use simplicity_unchained_core::{
    ElementsNetwork, utils::extract_pubkeys_from_p2tr_multisig_leaf_elements,
};
use std::str::FromStr;

pub fn execute(pset_hex: &str, network: &str) -> Result<()> {
    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    let genesis_hash = ElementsNetwork::from_str(network)
        .map_err(anyhow::Error::msg)?
        .genesis_hash();
    let tx = finalize(&pset, genesis_hash)?;

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

fn finalize(pset: &PartiallySignedTransaction, genesis_hash: BlockHash) -> Result<Transaction> {
    let mut tx = pset
        .extract_tx()
        .context("Failed to extract transaction from PSET")?;
    ensure!(!tx.input.is_empty(), "Transaction has no inputs");
    let prevouts = pset
        .inputs()
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| anyhow!("Input {} missing witness_utxo", i))
        })
        .collect::<Result<Vec<_>>>()?;
    for (i, input) in pset.inputs().iter().enumerate() {
        tx.input[i].witness.script_witness =
            finalize_p2tr(&tx, i, input, &prevouts, genesis_hash)?.into();
    }
    Ok(tx)
}

fn finalize_p2tr(
    tx: &Transaction,
    i: usize,
    input: &pset::Input,
    prevouts: &[TxOut],
    genesis_hash: BlockHash,
) -> Result<Vec<Vec<u8>>> {
    let spent_script = &prevouts[i].script_pubkey;
    ensure!(
        spent_script.is_v1_p2tr(),
        "Input {} spent output is not P2TR",
        i
    );
    ensure!(
        tx.input[i].script_sig.is_empty(),
        "Input {} native P2TR script_sig must be empty",
        i
    );
    // The witness program already contains the tweaked output key.
    let output_key = XOnlyPublicKey::from_slice(&spent_script.as_bytes()[2..])
        .with_context(|| format!("Input {} invalid Taproot output key", i))?
        .dangerous_assume_tweaked();
    let secp = Secp256k1::verification_only();
    let mut candidate = None;
    for (control_block, (leaf_script, leaf_version)) in &input.tap_scripts {
        if *leaf_version != LeafVersion::default()
            || control_block.leaf_version != *leaf_version
            || !control_block.verify_taproot_commitment(&secp, &output_key, leaf_script)
        {
            continue;
        }
        let Ok(pubkeys) = extract_pubkeys_from_p2tr_multisig_leaf_elements(leaf_script, i) else {
            continue;
        };
        ensure!(
            candidate.is_none(),
            "Input {} has ambiguous committed multisig leaves",
            i
        );
        candidate = Some((control_block, leaf_script, pubkeys));
    }
    let (control_block, leaf_script, pubkeys) =
        candidate.ok_or_else(|| anyhow!("Input {} has no committed canonical multisig leaf", i))?;
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::default());

    let signature = |position| {
        input
            .tap_script_sigs
            .get(&(pubkeys[position], leaf_hash))
            .ok_or_else(|| {
                anyhow!(
                    "Input {} missing tap_script_sig for multisig key {}",
                    i,
                    position
                )
            })
    };
    let cosigner_sig = signature(0)?;
    let user_sig = signature(1)?;
    let mut cache = SighashCache::new(tx);
    for (key, signature) in pubkeys.iter().zip([cosigner_sig, user_sig]) {
        let sighash = cache
            .taproot_script_spend_signature_hash(
                i,
                &Prevouts::All(prevouts),
                leaf_hash,
                signature.hash_ty,
                genesis_hash,
            )
            .with_context(|| format!("Input {} failed to compute signature sighash", i))?;
        secp.verify_schnorr(
            &signature.sig,
            &Message::from_digest(sighash.to_byte_array()),
            key,
        )
        .with_context(|| format!("Input {} invalid tap_script_sig for {}", i, key))?;
    }

    Ok(vec![
        user_sig.to_vec(),
        cosigner_sig.to_vec(),
        leaf_script.to_bytes(),
        control_block.serialize(),
    ])
}
