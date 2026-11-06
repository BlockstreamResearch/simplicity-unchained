use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use elements::{
    AddressParams, AssetId, BlockHash, SchnorrSighashType, Script, Transaction, TxOut,
    confidential::{Asset, Value},
    encode::serialize,
    hashes::sha256,
    pset::PartiallySignedTransaction as Pset,
    secp256k1_zkp::{Message, Scalar, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash, TaprootBuilder},
};
use serde::{Deserialize, Serialize};

use super::{Error, PROFILE_NAME, profile_hash, require};
use crate::{MAX_INPUTS, MAX_OUTPUTS, MAX_REQUEST_BYTES, MAX_SCRIPT_BYTES};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    #[serde(rename = "liquid")]
    Liquid,
    #[default]
    #[serde(rename = "liquidtestnet")]
    LiquidTestnet,
}

impl FromStr for Network {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "liquid" => Ok(Self::Liquid),
            "liquidtestnet" => Ok(Self::LiquidTestnet),
            _ => Err(Error::Invalid(format!(
                "unsupported Liquid policy network: {s}"
            ))),
        }
    }
}

impl Network {
    pub fn name(self) -> &'static str {
        match self {
            Self::Liquid => "liquid",
            Self::LiquidTestnet => "liquidtestnet",
        }
    }
    pub fn address_params(self) -> &'static AddressParams {
        match self {
            Self::Liquid => &AddressParams::LIQUID,
            Self::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
        }
    }
    pub fn genesis_hash(self) -> BlockHash {
        let params = match self {
            Self::Liquid => elements::genesis::NetworkParams::liquidv1(),
            Self::LiquidTestnet => elements::genesis::NetworkParams::liquidtestnet(),
        };
        elements::genesis::genesis_block(&params).block_hash()
    }
    pub fn fee_asset(self) -> AssetId {
        AssetId::from_str(match self {
            Self::Liquid => "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
            Self::LiquidTestnet => {
                "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"
            }
        })
        .expect("fixed network asset")
    }
}

pub fn signing_commitment(
    cmr: [u8; 32],
    script: &[u8],
    network: Network,
) -> Result<[u8; 32], Error> {
    require(
        script.len() <= MAX_SCRIPT_BYTES,
        "script data exceeds 10000 bytes",
    )?;
    Ok(crate::context::tagged_hash(
        "SimplicityUnchained/LiquidPolicySigningCommitment/v1",
        &[
            &profile_hash(),
            network.genesis_hash().as_byte_array(),
            &cmr,
            sha256::Hash::hash(script).as_byte_array(),
        ],
    ))
}

pub fn tweak_public_key(
    base: XOnlyPublicKey,
    cmr: [u8; 32],
    script: &[u8],
    network: Network,
) -> Result<XOnlyPublicKey, Error> {
    let tweak = service_tweak(base, cmr, script, network)?;
    base.add_tweak(&Secp256k1::verification_only(), &tweak)
        .map(|(key, _)| key)
        .map_err(|e| Error::Invalid(e.to_string()))
}

pub fn service_tweak(
    base: XOnlyPublicKey,
    cmr: [u8; 32],
    script: &[u8],
    network: Network,
) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(
        TapTweakHash::from_key_and_tweak(
            base,
            Some(TapNodeHash::from_byte_array(signing_commitment(
                cmr, script, network,
            )?)),
        )
        .to_byte_array(),
    )
    .map_err(|e| Error::Invalid(e.to_string()))
}

#[derive(Clone, Debug)]
pub struct CooperativeOutput {
    pub service_pubkey: XOnlyPublicKey,
    pub script: Script,
    pub script_pubkey: Script,
    pub control_block: ControlBlock,
    pub leaf_hash: TapLeafHash,
}

pub fn cooperative_output(
    base: XOnlyPublicKey,
    cmr: [u8; 32],
    data: &[u8],
    network: Network,
    user: XOnlyPublicKey,
    recovery: TapNodeHash,
) -> Result<CooperativeOutput, Error> {
    let service_pubkey = tweak_public_key(base, cmr, data, network)?;
    let script = elements::script::Builder::new()
        .push_slice(&service_pubkey.serialize())
        .push_opcode(elements::opcodes::all::OP_CHECKSIG)
        .push_slice(&user.serialize())
        .push_opcode(elements::opcodes::all::OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(elements::opcodes::all::OP_EQUAL)
        .into_script();
    let secp = Secp256k1::verification_only();
    let nums = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("fixed NUMS");
    let spend = TaprootBuilder::new()
        .add_leaf(1, script.clone())
        .map_err(|e| Error::Invalid(e.to_string()))?
        .add_hidden(1, recovery)
        .map_err(|e| Error::Invalid(e.to_string()))?
        .finalize(&secp, nums)
        .map_err(|_| Error::Invalid("incomplete cooperative tree".into()))?;
    let control_block = spend
        .control_block(&(script.clone(), LeafVersion::default()))
        .ok_or_else(|| Error::Invalid("missing cooperative control block".into()))?;
    Ok(CooperativeOutput {
        service_pubkey,
        script_pubkey: Script::new_v1_p2tr_tweaked(spend.output_key()),
        leaf_hash: TapLeafHash::from_script(&script, LeafVersion::default()),
        script,
        control_block,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    /// Explorer/display order; jets use the asset ID's raw inner hash bytes.
    pub asset_id: String,
    pub value: u64,
    pub confidential_asset: bool,
    pub confidential_value: bool,
}

impl Disclosure {
    pub fn asset(&self) -> AssetId {
        AssetId::from_str(&self.asset_id).expect("validated asset")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAccounting {
    pub asset_id: String,
    pub total_input_value: u64,
    /// Includes explicit fee outputs. Input and output totals must be exactly equal.
    pub total_output_value: u64,
    pub fee: u64,
    pub returned_value: u64,
    pub debit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSummary {
    pub profile: String,
    pub profile_hash: String,
    pub network: String,
    pub genesis_hash: String,
    pub cmr: String,
    pub signing_commitment: String,
    pub redeem_script_hash: String,
    pub input_index: u32,
    pub input_count: u32,
    pub output_count: u32,
    pub unsigned_tx_hash: String,
    pub prevouts_hash: String,
    pub disclosures_hash: String,
    pub cooperative_leaf_hash: String,
    pub cooperative_sighash_default: String,
    pub policy_approval_hash: String,
    pub policy_transaction_approval_hash: String,
    pub service_pubkey: String,
    pub user_pubkey: String,
    pub recovery_leaf_hash: String,
    pub current_asset_id: String,
    pub fee_asset_id: String,
    pub assets: Vec<AssetAccounting>,
    pub inputs: Vec<Disclosure>,
    pub outputs: Vec<Disclosure>,
    pub output_scripts_hex: Vec<String>,
    pub script_pubkey_hex: String,
    pub vsize_lower_bound: u32,
    pub provenance: String,
    pub chain_status_verified: bool,
}

#[derive(Clone, Debug)]
pub struct Context {
    pub(crate) tx: Transaction,
    pub(crate) prevouts: Vec<TxOut>,
    pub(crate) inputs: Vec<Disclosure>,
    pub(crate) outputs: Vec<Disclosure>,
    pub(crate) accounting: BTreeMap<AssetId, AssetAccounting>,
    pub(crate) index: usize,
    pub(crate) network: Network,
    pub(crate) cmr: [u8; 32],
    pub(crate) data: Vec<u8>,
    pub(crate) cooperative: CooperativeOutput,
    pub(crate) user: XOnlyPublicKey,
    pub(crate) base: XOnlyPublicKey,
    pub(crate) recovery: TapNodeHash,
    pub(crate) sighash: [u8; 32],
    pub(crate) tx_hash: [u8; 32],
    pub(crate) prevouts_hash: [u8; 32],
    pub(crate) disclosures_hash: [u8; 32],
    pub(crate) transaction_approval: [u8; 32],
    pub(crate) approval: [u8; 32],
}

/// Authenticates a disclosure using exact-value and single-asset proof APIs.
/// No blinding factors or receiving private keys enter the signing context.
pub fn verify_disclosure(
    out: &TxOut,
    amount: Option<u64>,
    asset: Option<AssetId>,
    value_proof: Option<&elements::RangeProof>,
    asset_proof: Option<&elements::SurjectionProof>,
) -> Result<Disclosure, Error> {
    let secp = Secp256k1::new();
    let id = match out.asset {
        Asset::Explicit(id) => {
            require(
                asset.is_none_or(|a| a == id),
                "explicit asset label mismatch",
            )?;
            require(
                asset_proof.is_none(),
                "unexpected explicit asset disclosure proof",
            )?;
            id
        }
        Asset::Confidential(generator) => {
            let id = asset
                .ok_or_else(|| Error::Invalid("missing confidential asset disclosure".into()))?;
            require(
                asset_proof
                    .is_some_and(|proof| proof.blind_asset_proof_verify(&secp, id, generator)),
                "invalid or missing confidential asset disclosure proof",
            )?;
            id
        }
        Asset::Null => return Err(Error::Invalid("null asset".into())),
    };
    let generator = match out.asset {
        Asset::Explicit(id) => {
            elements::secp256k1_zkp::Generator::new_unblinded(&secp, id.into_tag())
        }
        Asset::Confidential(generator) => generator,
        Asset::Null => return Err(Error::Invalid("null asset".into())),
    };
    let value = match out.value {
        Value::Explicit(value) => {
            require(
                amount.is_none_or(|a| a == value),
                "explicit amount label mismatch",
            )?;
            require(
                value_proof.is_none(),
                "unexpected explicit value disclosure proof",
            )?;
            value
        }
        Value::Confidential(commit) => {
            let value = amount
                .ok_or_else(|| Error::Invalid("missing confidential value disclosure".into()))?;
            require(value != u64::MAX, "value cannot be u64::MAX")?;
            require(
                value_proof.is_some_and(|proof| {
                    proof.blind_value_proof_verify(&secp, value, generator, commit)
                }),
                "invalid or missing confidential value disclosure proof",
            )?;
            out.witness
                .rangeproof
                .as_ref()
                .ok_or_else(|| Error::Invalid("missing transaction rangeproof".into()))?
                .verify(&secp, commit, out.script_pubkey.as_bytes(), generator)
                .map_err(|e| Error::Invalid(format!("invalid transaction rangeproof: {e}")))?;
            value
        }
        Value::Null => return Err(Error::Invalid("null value".into())),
    };
    require(value < u64::MAX, "value cannot be u64::MAX")?;
    Ok(Disclosure {
        asset_id: id.to_string(),
        value,
        confidential_asset: out.asset.is_confidential(),
        confidential_value: out.value.is_confidential(),
    })
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pset: &Pset,
        index: usize,
        cmr: [u8; 32],
        data: &[u8],
        network: Network,
        base: XOnlyPublicKey,
        user: XOnlyPublicKey,
        recovery: TapNodeHash,
    ) -> Result<Self, Error> {
        require(
            serialize(pset).len() <= MAX_REQUEST_BYTES,
            "PSET/evidence exceeds 2 MiB",
        )?;
        let tx = pset
            .extract_tx()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        require(tx.version == 2, "transaction version must be 2")?;
        require(
            (1..=MAX_INPUTS).contains(&tx.input.len())
                && (1..=MAX_OUTPUTS).contains(&tx.output.len()),
            "transaction requires 1..=8 inputs and outputs",
        )?;
        require(index < tx.input.len(), "input index out of range")?;
        let cooperative = cooperative_output(base, cmr, data, network, user, recovery)?;
        let mut seen = BTreeSet::new();
        let mut prevouts = Vec::new();
        let mut inputs = Vec::new();
        for (i, (input, map)) in tx.input.iter().zip(pset.inputs()).enumerate() {
            require(
                seen.insert(input.previous_output),
                format!("duplicate outpoint at input {i}"),
            )?;
            require(
                !input.is_pegin && !input.has_issuance(),
                "pegins/issuance are unsupported",
            )?;
            require(
                input.script_sig.is_empty() && input.witness.is_empty(),
                "unsigned input has scriptSig/witness",
            )?;
            require(
                map.final_script_sig.as_ref().is_none_or(|s| s.is_empty())
                    && map
                        .final_script_witness
                        .as_ref()
                        .is_none_or(|w| w.is_empty()),
                "finalized input unsupported",
            )?;
            require(
                map.sighash_type.is_none_or(|s| s.to_u32() == 0) && map.tap_key_sig.is_none(),
                "only cooperative SIGHASH_DEFAULT is allowed",
            )?;
            let parent = map.non_witness_utxo.as_ref().ok_or_else(|| {
                Error::Invalid(format!("input {i} missing full parent transaction"))
            })?;
            require(
                parent.txid() == input.previous_output.txid,
                format!("input {i} parent txid mismatch"),
            )?;
            let out = parent
                .output
                .get(input.previous_output.vout as usize)
                .ok_or_else(|| Error::Invalid(format!("input {i} parent vout out of bounds")))?;
            let witness = map
                .witness_utxo
                .as_ref()
                .ok_or_else(|| Error::Invalid(format!("input {i} missing witness_utxo")))?;
            // PSET witness_utxo serialization excludes output witness. Authenticate its base
            // fields against the parent, and use the full parent's rangeproof for verification.
            require(
                serialize(out) == serialize(witness),
                format!("input {i} witness_utxo mismatch"),
            )?;
            require(
                out.script_pubkey == cooperative.script_pubkey,
                format!("input {i} funding script/profile/network mismatch"),
            )?;
            if let Some(proof) = &map.in_utxo_rangeproof {
                require(
                    out.witness.rangeproof.as_ref() == proof.as_ref(),
                    "input UTXO rangeproof differs from parent",
                )?;
            }
            inputs.push(verify_disclosure(
                out,
                map.amount,
                map.asset,
                map.blind_value_proof.as_ref(),
                map.blind_asset_proof.as_ref(),
            )?);
            prevouts.push(out.clone());
        }
        let mut outputs = Vec::new();
        let mut fee_count = 0;
        for (out, map) in tx.output.iter().zip(pset.outputs()) {
            require(
                out.script_pubkey.len() <= MAX_SCRIPT_BYTES,
                "output script exceeds 10000 bytes",
            )?;
            let disclosed = verify_disclosure(
                out,
                map.amount,
                map.asset,
                map.blind_value_proof.as_ref(),
                map.blind_asset_proof.as_ref(),
            )?;
            if out.script_pubkey.is_empty() {
                fee_count += 1;
                require(
                    out.is_fee() && disclosed.asset() == network.fee_asset() && out.nonce.is_null(),
                    "fee must be explicit configured policy asset",
                )?;
            } else {
                require(
                    disclosed.value > 0,
                    "nonfee output must have positive value",
                )?;
            }
            outputs.push(disclosed);
        }
        require(
            fee_count == 1,
            "exactly one explicit policy-asset fee output is required",
        )?;
        tx.verify_tx_amt_proofs(&Secp256k1::new(), &prevouts)
            .map_err(|e| {
                Error::Invalid(format!(
                    "transaction commitment/proof verification failed: {e}"
                ))
            })?;
        let mut accounting: BTreeMap<AssetId, AssetAccounting> = BTreeMap::new();
        for d in &inputs {
            let a = accounting
                .entry(d.asset())
                .or_insert_with(|| AssetAccounting {
                    asset_id: d.asset_id.clone(),
                    ..Default::default()
                });
            a.total_input_value = a
                .total_input_value
                .checked_add(d.value)
                .ok_or_else(|| Error::Invalid("input total overflow".into()))?;
        }
        for (out, d) in tx.output.iter().zip(&outputs) {
            let a = accounting
                .entry(d.asset())
                .or_insert_with(|| AssetAccounting {
                    asset_id: d.asset_id.clone(),
                    ..Default::default()
                });
            a.total_output_value = a
                .total_output_value
                .checked_add(d.value)
                .ok_or_else(|| Error::Invalid("output total overflow".into()))?;
            if out.is_fee() {
                a.fee = d.value;
            }
            if out.script_pubkey == cooperative.script_pubkey {
                a.returned_value = a
                    .returned_value
                    .checked_add(d.value)
                    .ok_or_else(|| Error::Invalid("returned total overflow".into()))?;
            }
        }
        for a in accounting.values_mut() {
            require(
                a.total_input_value == a.total_output_value,
                format!("asset {} is not conserved", a.asset_id),
            )?;
            a.debit = a
                .total_input_value
                .checked_sub(a.returned_value)
                .ok_or_else(|| Error::Invalid("asset debit underflow".into()))?;
        }
        let tx_hash = sha256::Hash::hash(&serialize(&tx)).to_byte_array();
        let prevouts_hash = sha256::Hash::hash(&serialize(&prevouts)).to_byte_array();
        let mut disclosure_bytes = Vec::new();
        for list in [&inputs, &outputs] {
            disclosure_bytes.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for d in list {
                disclosure_bytes.extend_from_slice(&d.asset().to_byte_array());
                disclosure_bytes.extend_from_slice(&d.value.to_be_bytes());
                disclosure_bytes.push(u8::from(d.confidential_asset));
                disclosure_bytes.push(u8::from(d.confidential_value));
            }
        }
        let disclosures_hash = sha256::Hash::hash(&disclosure_bytes).to_byte_array();
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                cooperative.leaf_hash,
                SchnorrSighashType::Default,
                network.genesis_hash(),
            )
            .map_err(|e| Error::Invalid(e.to_string()))?
            .to_byte_array();
        let transaction_approval = crate::context::tagged_hash(
            "SimplicityUnchained/LiquidPolicyTransactionApproval/v1",
            &[
                &profile_hash(),
                network.genesis_hash().as_byte_array(),
                &signing_commitment(cmr, data, network)?,
                &tx_hash,
                &prevouts_hash,
                &disclosures_hash,
                cooperative.leaf_hash.as_byte_array(),
                recovery.as_byte_array(),
            ],
        );
        let approval = crate::context::tagged_hash(
            "SimplicityUnchained/LiquidPolicyInputApproval/v1",
            &[
                &transaction_approval,
                &(index as u32).to_be_bytes(),
                &sighash,
            ],
        );
        let context = Self {
            tx,
            prevouts,
            inputs,
            outputs,
            accounting,
            index,
            network,
            cmr,
            data: data.to_vec(),
            cooperative,
            user,
            base,
            recovery,
            sighash,
            tx_hash,
            prevouts_hash,
            disclosures_hash,
            transaction_approval,
            approval,
        };
        context.verify_signatures(pset)?;
        Ok(context)
    }

    /// Reject every pre-existing signature that is not valid for this exact context.
    pub fn verify_signatures(&self, pset: &Pset) -> Result<(), Error> {
        let secp = Secp256k1::verification_only();
        for (index, input) in pset.inputs().iter().enumerate() {
            require(
                input.partial_sigs.is_empty(),
                "non-Taproot signatures unsupported",
            )?;
            for ((key, leaf), sig) in &input.tap_script_sigs {
                require(
                    (*key == self.cooperative.service_pubkey || *key == self.user)
                        && *leaf == self.cooperative.leaf_hash
                        && sig.hash_ty == SchnorrSighashType::Default,
                    "unrecognized signature key/leaf/sighash",
                )?;
                let digest = SighashCache::new(&self.tx)
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&self.prevouts),
                        self.cooperative.leaf_hash,
                        SchnorrSighashType::Default,
                        self.network.genesis_hash(),
                    )
                    .map_err(|e| Error::Invalid(e.to_string()))?;
                secp.verify_schnorr(&sig.sig, &Message::from_digest(digest.to_byte_array()), key)
                    .map_err(|e| Error::Invalid(format!("invalid input {index} signature: {e}")))?;
            }
            for (control, (script, version)) in &input.tap_scripts {
                require(
                    control == &self.cooperative.control_block
                        && script == &self.cooperative.script
                        && *version == LeafVersion::default(),
                    "unrecognized cooperative leaf/control block",
                )?;
            }
        }
        Ok(())
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }
    pub fn revalidate(&self, pset: &Pset) -> Result<(), Error> {
        let fresh = Self::new(
            pset,
            self.index,
            self.cmr,
            &self.data,
            self.network,
            self.base,
            self.user,
            self.recovery,
        )?;
        require(
            fresh.summary() == self.summary(),
            "PSET changed after preparation",
        )
    }
    pub fn prevouts(&self) -> &[TxOut] {
        &self.prevouts
    }
    pub fn input_index(&self) -> usize {
        self.index
    }
    pub fn cooperative(&self) -> &CooperativeOutput {
        &self.cooperative
    }
    pub fn sighash(&self) -> [u8; 32] {
        self.sighash
    }
    pub fn user_pubkey(&self) -> XOnlyPublicKey {
        self.user
    }
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn cmr(&self) -> [u8; 32] {
        self.cmr
    }
    pub fn script_data(&self) -> &[u8] {
        &self.data
    }

    pub fn summary(&self) -> ContextSummary {
        ContextSummary {
            profile: PROFILE_NAME.into(), profile_hash: hex::encode(profile_hash()), network: self.network.name().into(),
            genesis_hash: hex::encode(self.network.genesis_hash().to_byte_array()), cmr: hex::encode(self.cmr),
            signing_commitment: hex::encode(signing_commitment(self.cmr, &self.data, self.network).expect("validated data")),
            redeem_script_hash: sha256::Hash::hash(&self.data).to_string(), input_index: self.index as u32, input_count: self.inputs.len() as u32, output_count: self.outputs.len() as u32,
            unsigned_tx_hash: hex::encode(self.tx_hash), prevouts_hash: hex::encode(self.prevouts_hash), disclosures_hash: hex::encode(self.disclosures_hash),
            cooperative_leaf_hash: hex::encode(self.cooperative.leaf_hash.to_byte_array()), cooperative_sighash_default: hex::encode(self.sighash),
            policy_approval_hash: hex::encode(self.approval), policy_transaction_approval_hash: hex::encode(self.transaction_approval),
            service_pubkey: self.cooperative.service_pubkey.to_string(), user_pubkey: self.user.to_string(), recovery_leaf_hash: hex::encode(self.recovery.to_byte_array()),
            current_asset_id: self.inputs[self.index].asset_id.clone(), fee_asset_id: self.network.fee_asset().to_string(),
            assets: self.accounting.values().cloned().collect(), inputs: self.inputs.clone(), outputs: self.outputs.clone(),
            output_scripts_hex: self.tx.output.iter().map(|o| hex::encode(o.script_pubkey.as_bytes())).collect(),
            script_pubkey_hex: hex::encode(self.cooperative.script_pubkey.as_bytes()),
            vsize_lower_bound: self.vsize_lower_bound(),
            provenance: "parent-txid/vout + exact witness-utxo; exact-value and single-asset disclosure proofs; transaction range/surjection proofs + Pedersen balance; per-asset checked conservation; existing signatures verified; NOT chain inclusion/confirmation/consensus-validity/unspentness".into(),
            chain_status_verified: false,
        }
    }
}
