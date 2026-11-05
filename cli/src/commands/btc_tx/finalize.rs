use anyhow::{Context, Result, anyhow, ensure};
use serde_json::json;
use simplicity::bitcoin::{
    Psbt, TapLeafHash, Transaction, TxOut, Witness, XOnlyPublicKey,
    consensus::serialize,
    hashes::Hash,
    psbt,
    secp256k1::{Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
};
use simplicity_unchained_core::utils::extract_pubkeys_from_p2tr_multisig_leaf_btc;

pub fn execute(psbt_hex: &str) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let tx = finalize(&psbt)?;

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

fn finalize(psbt: &Psbt) -> Result<Transaction> {
    let mut tx = psbt.unsigned_tx.clone();
    ensure!(!tx.input.is_empty(), "Transaction has no inputs");
    ensure!(
        tx.input.len() == psbt.inputs.len(),
        "PSBT input count does not match transaction"
    );
    let prevouts = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| anyhow!("Input {} missing witness_utxo", i))
        })
        .collect::<Result<Vec<_>>>()?;
    for (i, input) in psbt.inputs.iter().enumerate() {
        tx.input[i].witness = finalize_p2tr(&tx, i, input, &prevouts)?;
    }
    Ok(tx)
}

fn finalize_p2tr(
    tx: &Transaction,
    i: usize,
    input: &psbt::Input,
    prevouts: &[TxOut],
) -> Result<Witness> {
    let spent_script = &prevouts[i].script_pubkey;
    ensure!(
        spent_script.is_p2tr(),
        "Input {} spent output is not P2TR",
        i
    );
    ensure!(
        tx.input[i].script_sig.is_empty(),
        "Input {} native P2TR script_sig must be empty",
        i
    );
    let output_key = XOnlyPublicKey::from_slice(&spent_script.as_bytes()[2..])
        .with_context(|| format!("Input {} invalid Taproot output key", i))?;
    let secp = Secp256k1::verification_only();
    let mut candidate = None;
    for (control_block, (leaf_script, leaf_version)) in &input.tap_scripts {
        if *leaf_version != LeafVersion::TapScript
            || control_block.leaf_version != *leaf_version
            || !control_block.verify_taproot_commitment(&secp, output_key, leaf_script)
        {
            continue;
        }
        let Ok(pubkeys) = extract_pubkeys_from_p2tr_multisig_leaf_btc(leaf_script, i) else {
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
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);

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
                signature.sighash_type,
            )
            .with_context(|| format!("Input {} failed to compute signature sighash", i))?;
        secp.verify_schnorr(
            &signature.signature,
            &Message::from_digest(sighash.to_byte_array()),
            key,
        )
        .with_context(|| format!("Input {} invalid tap_script_sig for {}", i, key))?;
    }

    let mut witness = Witness::new();
    witness.push(user_sig.serialize());
    witness.push(cosigner_sig.serialize());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    Ok(witness)
}
