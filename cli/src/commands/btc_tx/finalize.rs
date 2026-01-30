use anyhow::{Context, Result};
use hal_simplicity::simplicity::bitcoin::{PublicKey, psbt::Psbt};
use serde_json::json;

pub fn execute(psbt_hex: &str) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    let mut tx = psbt.clone().extract_tx_unchecked_fee_rate();

    // For each input, build the witness from partial signatures
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.partial_sigs.is_empty() {
            return Err(anyhow::anyhow!("Input {} has no partial signatures", i));
        }

        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Input {} missing witness script", i))?;

        // For 2-of-2 multisig, build witness: OP_0 <sig1> <sig2> <redeemScript>
        // We need to order the signatures according to the public keys in the redeem script
        if input.partial_sigs.len() < 2 {
            return Err(anyhow::anyhow!(
                "Input {} requires 2 signatures but only has {}",
                i,
                input.partial_sigs.len()
            ));
        }

        // Extract public keys from the witness script (2-of-2 multisig format: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG)
        let script_bytes = witness_script.as_bytes();
        let mut pubkeys = Vec::new();
        let mut i_byte = 0;
        while i_byte < script_bytes.len() {
            if script_bytes[i_byte] == 33 {
                // Compressed public key length
                if i_byte + 33 < script_bytes.len() {
                    let pk_bytes = &script_bytes[i_byte + 1..i_byte + 34];
                    if let Ok(pk) = PublicKey::from_slice(pk_bytes) {
                        pubkeys.push(pk);
                    }
                    i_byte += 34;
                } else {
                    break;
                }
            } else {
                i_byte += 1;
            }
        }

        if pubkeys.len() != 2 {
            return Err(anyhow::anyhow!(
                "Input {} witness script does not contain exactly 2 public keys",
                i
            ));
        }

        // Order signatures according to the public keys in the redeem script
        let sig1 = input
            .partial_sigs
            .get(&pubkeys[0])
            .ok_or_else(|| anyhow::anyhow!("Missing signature for first public key"))?;
        let sig2 = input
            .partial_sigs
            .get(&pubkeys[1])
            .ok_or_else(|| anyhow::anyhow!("Missing signature for second public key"))?;

        // Serialize signatures with sighash type
        let mut sig1_bytes = sig1.signature.serialize_der().to_vec();
        sig1_bytes.push(sig1.sighash_type.to_u32() as u8);

        let mut sig2_bytes = sig2.signature.serialize_der().to_vec();
        sig2_bytes.push(sig2.sighash_type.to_u32() as u8);

        tx.input[i].witness.push(vec![]); // OP_0 for multisig
        tx.input[i].witness.push(sig1_bytes);
        tx.input[i].witness.push(sig2_bytes);
        tx.input[i].witness.push(witness_script.to_bytes());
    }

    // Verify all inputs have witnesses
    let all_finalized = tx.input.iter().all(|input| !input.witness.is_empty());

    if !all_finalized {
        return Err(anyhow::anyhow!(
            "Not all inputs are finalized - transaction may be missing signatures"
        ));
    }

    let witnesses: Vec<_> = tx
        .input
        .iter()
        .map(|input| {
            input
                .witness
                .iter()
                .map(|w| hex::encode(w))
                .collect::<Vec<_>>()
        })
        .collect();

    let output = json!({
        "transaction_hex": hex::encode(hal_simplicity::simplicity::bitcoin::consensus::serialize(&tx)),
        "txid": tx.compute_txid().to_string(),
        "witnesses": witnesses,
        "finalized": all_finalized,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
