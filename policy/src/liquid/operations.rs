//! Local construction/disclosure generation and cryptographically checked finalization.
use super::{Context, Error, Network, require, verify_disclosure};
use elements::{
    Address, AssetId, OutPoint, Transaction, TxIn, TxOut, TxOutSecrets,
    confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
    encode::{deserialize, serialize},
    pset::PartiallySignedTransaction as Pset,
    secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, rand::rngs::OsRng},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenInput {
    pub txid: String,
    pub vout: u32,
    pub parent_tx_hex: String,
    /// Browser-local receiving key. Never included in a service request/PSET.
    pub blinding_secret_key_hex: Option<String>,
    #[serde(default = "sequence")]
    pub sequence: u32,
}
fn sequence() -> u32 {
    0xffff_fffd
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// `fee` is the sole empty-script output; otherwise a network-checked address.
    pub address: String,
    pub asset_id: String,
    pub value_sat: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub inputs: Vec<ProvenInput>,
    pub outputs: Vec<Output>,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub lock_time: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct DisclosureProofs {
    pub asset_id: String,
    pub value_sat: u64,
    pub blind_asset_proof_hex: Option<String>,
    pub blind_value_proof_hex: Option<String>,
    pub confidential: bool,
}

pub fn unblind_output(out: &TxOut, secret: Option<&str>) -> Result<TxOutSecrets, Error> {
    let secp = Secp256k1::new();
    let secrets = match (out.asset, out.value) {
        (Asset::Explicit(asset), Value::Explicit(value)) => TxOutSecrets::new(asset, AssetBlindingFactor::zero(), value, ValueBlindingFactor::zero()),
        (Asset::Confidential(_), Value::Confidential(_)) => {
            let key = secret.ok_or_else(|| Error::Invalid("confidential input requires a local blinding secret key".into()))?;
            out.unblind(&secp, SecretKey::from_str(key).map_err(|e| Error::Invalid(e.to_string()))?).map_err(|e| Error::Invalid(format!("unblinding failed: {e}")))?
        }
        _ => return Err(Error::Invalid("local unblinding supports fully explicit or fully confidential outputs; mixed commitments require externally generated PSET disclosure proofs".into())),
    };
    let expected_asset = if out.asset.is_confidential() {
        Asset::new_confidential(&secp, secrets.asset, secrets.asset_bf)
    } else {
        Asset::Explicit(secrets.asset)
    };
    let expected_value = if out.value.is_confidential() {
        Value::new_confidential_from_assetid(
            &secp,
            secrets.value,
            secrets.asset,
            secrets.value_bf,
            secrets.asset_bf,
        )
    } else {
        Value::Explicit(secrets.value)
    };
    require(
        out.asset == expected_asset && out.value == expected_value,
        "unblinded openings do not match commitments",
    )?;
    Ok(secrets)
}

pub fn disclosure_proofs(out: &TxOut, secrets: TxOutSecrets) -> Result<DisclosureProofs, Error> {
    disclosure_proofs_with_rng(out, secrets, &mut OsRng)
}
fn disclosure_proofs_with_rng<
    R: elements::secp256k1_zkp::rand::RngCore + elements::secp256k1_zkp::rand::CryptoRng,
>(
    out: &TxOut,
    secrets: TxOutSecrets,
    rng: &mut R,
) -> Result<DisclosureProofs, Error> {
    let secp = Secp256k1::new();
    let asset_proof = if out.asset.is_confidential() {
        Some(
            elements::SurjectionProof::blind_asset_proof(
                rng,
                &secp,
                secrets.asset,
                secrets.asset_bf,
            )
            .map_err(|e| Error::Invalid(e.to_string()))?,
        )
    } else {
        None
    };
    let value_proof = if let Some(commit) = out.value.commitment() {
        let generator = out
            .asset
            .into_asset_gen(&secp)
            .ok_or_else(|| Error::Invalid("null asset".into()))?;
        Some(
            elements::RangeProof::blind_value_proof(
                rng,
                &secp,
                secrets.value,
                commit,
                generator,
                secrets.value_bf,
            )
            .map_err(|e| Error::Invalid(e.to_string()))?,
        )
    } else {
        None
    };
    verify_disclosure(
        out,
        Some(secrets.value),
        Some(secrets.asset),
        value_proof.as_ref(),
        asset_proof.as_ref(),
    )?;
    Ok(DisclosureProofs {
        asset_id: secrets.asset.to_string(),
        value_sat: secrets.value,
        blind_asset_proof_hex: asset_proof.map(|p| hex::encode(p.to_vec())),
        blind_value_proof_hex: value_proof.map(|p| hex::encode(p.to_vec())),
        confidential: out.asset.is_confidential() || out.value.is_confidential(),
    })
}

pub fn create_pset(request: &CreateRequest) -> Result<Pset, Error> {
    create_pset_with_rng(request, &mut OsRng)
}
/// The caller must provide cryptographically secure randomness. Production
/// entry points use OsRng; injection makes public test fixtures reproducible.
pub fn create_pset_with_rng<
    R: elements::secp256k1_zkp::rand::RngCore + elements::secp256k1_zkp::rand::CryptoRng,
>(
    request: &CreateRequest,
    rng: &mut R,
) -> Result<Pset, Error> {
    require(
        (1..=crate::MAX_INPUTS).contains(&request.inputs.len())
            && (1..=crate::MAX_OUTPUTS).contains(&request.outputs.len()),
        "require 1..=8 inputs/outputs",
    )?;
    let size: usize = request.inputs.iter().map(|i| i.parent_tx_hex.len()).sum();
    require(
        size <= crate::MAX_REQUEST_BYTES * 2,
        "parent evidence exceeds 2 MiB",
    )?;
    let mut parents = Vec::new();
    let mut tx_inputs = Vec::new();
    let mut secrets = HashMap::new();
    let mut seen = BTreeSet::new();
    for (index, input) in request.inputs.iter().enumerate() {
        let parent: Transaction = deserialize(
            &hex::decode(&input.parent_tx_hex).map_err(|e| Error::Invalid(e.to_string()))?,
        )
        .map_err(|e| Error::Invalid(e.to_string()))?;
        let txid =
            elements::Txid::from_str(&input.txid).map_err(|e| Error::Invalid(e.to_string()))?;
        require(parent.txid() == txid, "parent txid mismatch")?;
        let out = parent
            .output
            .get(input.vout as usize)
            .ok_or_else(|| Error::Invalid("parent vout out of range".into()))?
            .clone();
        let opening = unblind_output(&out, input.blinding_secret_key_hex.as_deref())?;
        let proof = disclosure_proofs_with_rng(&out, opening, rng)?;
        let outpoint = OutPoint::new(txid, input.vout);
        require(seen.insert(outpoint), "duplicate outpoint")?;
        tx_inputs.push(TxIn {
            previous_output: outpoint,
            sequence: elements::Sequence(input.sequence),
            ..Default::default()
        });
        secrets.insert(index, opening);
        parents.push((parent, out, proof));
    }
    let mut addresses = Vec::new();
    let mut fee_count = 0;
    let mut outputs = Vec::new();
    for output in &request.outputs {
        require(output.value_sat < u64::MAX, "value must be below u64::MAX")?;
        let asset =
            AssetId::from_str(&output.asset_id).map_err(|e| Error::Invalid(e.to_string()))?;
        let address = if output.address == "fee" {
            fee_count += 1;
            require(
                asset == request.network.fee_asset(),
                "fee asset differs from network policy asset",
            )?;
            None
        } else {
            require(output.value_sat > 0, "nonfee output must be positive")?;
            Some(
                Address::parse_with_params(&output.address, request.network.address_params())
                    .map_err(|e| Error::Invalid(e.to_string()))?,
            )
        };
        outputs.push(TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(output.value_sat),
            nonce: Nonce::Null,
            script_pubkey: address
                .as_ref()
                .map(|a| a.script_pubkey())
                .unwrap_or_default(),
            witness: Default::default(),
        });
        addresses.push(address);
    }
    require(fee_count == 1, "exactly one explicit fee output required")?;
    // Check public per-asset conservation before any expensive/randomized blinding.
    let mut totals: BTreeMapCompat = Default::default();
    for s in secrets.values() {
        add(&mut totals, s.asset, s.value as i128)?;
    }
    for out in &outputs {
        add(
            &mut totals,
            out.asset.explicit().expect("explicit"),
            -(out.value.explicit().expect("explicit") as i128),
        )?;
    }
    require(
        totals.values().all(|v| *v == 0),
        "per-asset input/output totals are not conserved",
    )?;
    let tx = Transaction {
        version: 2,
        lock_time: elements::LockTime::from_consensus(request.lock_time),
        input: tx_inputs,
        output: outputs,
    };
    let mut pset = Pset::from_tx(tx);
    for (map, (parent, out, proof)) in pset.inputs_mut().iter_mut().zip(parents) {
        map.non_witness_utxo = Some(parent);
        map.witness_utxo = Some(out.clone());
        map.amount = Some(proof.value_sat);
        map.asset = Some(AssetId::from_str(&proof.asset_id).expect("validated"));
        map.blind_asset_proof = proof.blind_asset_proof_hex.map(|h| {
            elements::SurjectionProof::from_slice(&hex::decode(h).expect("encoded proof"))
                .expect("generated proof")
        });
        map.blind_value_proof = proof.blind_value_proof_hex.map(|h| {
            elements::RangeProof::from_slice(&hex::decode(h).expect("encoded proof"))
                .expect("generated proof")
        });
    }
    let mut blind = false;
    for (map, address) in pset.outputs_mut().iter_mut().zip(addresses) {
        if let Some(key) = address.and_then(|a| a.blinding_pubkey) {
            blind = true;
            map.blinding_key = Some(elements::bitcoin::PublicKey::new(key));
            map.blinder_index = Some(0);
        }
    }
    if blind {
        pset.blind_last(rng, &Secp256k1::new(), &secrets)
            .map_err(|e| Error::Invalid(format!("output blinding failed: {e}")))?;
    }
    let tx = pset
        .extract_tx()
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let prevouts: Vec<_> = pset
        .inputs()
        .iter()
        .map(|i| i.witness_utxo.clone().expect("populated"))
        .collect();
    tx.verify_tx_amt_proofs(&Secp256k1::new(), &prevouts)
        .map_err(|e| {
            Error::Invalid(format!(
                "constructed PSET failed proof/balance verification: {e}"
            ))
        })?;
    require(
        serialize(&pset).len() <= crate::MAX_REQUEST_BYTES,
        "constructed PSET exceeds 2 MiB",
    )?;
    Ok(pset)
}
type BTreeMapCompat = std::collections::BTreeMap<AssetId, i128>;
fn add(totals: &mut BTreeMapCompat, asset: AssetId, value: i128) -> Result<(), Error> {
    let old = totals.entry(asset).or_default();
    *old = old
        .checked_add(value)
        .ok_or_else(|| Error::Invalid("asset total overflow".into()))?;
    Ok(())
}

pub fn add_signature(
    context: &Context,
    pset: &mut Pset,
    secret: SecretKey,
    service: bool,
) -> Result<elements::SchnorrSig, Error> {
    context.revalidate(pset)?;
    if !service {
        require(
            pset.inputs()[context.input_index()]
                .tap_script_sigs
                .contains_key(&(
                    context.cooperative().service_pubkey,
                    context.cooperative().leaf_hash,
                )),
            "user co-signing requires a verified service signature",
        )?;
    }
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, &secret);
    let key = pair.x_only_public_key().0;
    require(
        key == if service {
            context.cooperative().service_pubkey
        } else {
            context.user_pubkey()
        },
        "secret key differs from committed signer",
    )?;
    let sig = elements::SchnorrSig {
        sig: secp.sign_schnorr_no_aux_rand(&Message::from_digest(context.sighash()), &pair),
        hash_ty: elements::SchnorrSighashType::Default,
    };
    let map = &mut pset.inputs_mut()[context.input_index()];
    map.tap_scripts.insert(
        context.cooperative().control_block.clone(),
        (
            context.cooperative().script.clone(),
            elements::taproot::LeafVersion::default(),
        ),
    );
    map.tap_script_sigs
        .insert((key, context.cooperative().leaf_hash), sig);
    context.verify_signatures(pset)?;
    Ok(sig)
}

pub fn finalize(context: &Context, pset: &Pset) -> Result<Transaction, Error> {
    context.revalidate(pset)?;
    require(
        pset.extract_tx()
            .map_err(|e| Error::Invalid(e.to_string()))?
            == *context.tx(),
        "PSET changed after context preparation",
    )?;
    let mut tx = context.tx().clone();
    for (index, input) in pset.inputs().iter().enumerate() {
        let service = input
            .tap_script_sigs
            .get(&(
                context.cooperative().service_pubkey,
                context.cooperative().leaf_hash,
            ))
            .ok_or_else(|| {
                Error::Invalid(format!("missing service signature for input {index}"))
            })?;
        let user = input
            .tap_script_sigs
            .get(&(context.user_pubkey(), context.cooperative().leaf_hash))
            .ok_or_else(|| Error::Invalid(format!("missing user signature for input {index}")))?;
        tx.input[index].witness.script_witness = vec![
            user.to_vec(),
            service.to_vec(),
            context.cooperative().script.to_bytes(),
            context.cooperative().control_block.serialize(),
        ]
        .into();
    }
    Ok(tx)
}
