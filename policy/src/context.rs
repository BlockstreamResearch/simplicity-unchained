use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use simplicity::bitcoin::{
    self, Network, Script, ScriptBuf, TapSighashType, Transaction, TxOut, XOnlyPublicKey,
    consensus::Encodable,
    hashes::{Hash, HashEngine, sha256},
    psbt::{self, Psbt},
    secp256k1::{Scalar, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash, TaprootBuilder},
};

use crate::{
    Error, MAX_INPUTS, MAX_MONEY, MAX_OUTPUTS, MAX_REQUEST_BYTES, MAX_SCRIPT_BYTES, PROFILE_NAME,
    profile_hash,
};

static NUMS: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("fixed valid NUMS key")
});

pub fn network_name(network: Network) -> Result<&'static str, Error> {
    match network {
        Network::Bitcoin => Ok("bitcoin"),
        Network::Testnet => Ok("testnet"),
        Network::Testnet4 => Ok("testnet4"),
        _ => Err(Error::UnsupportedNetwork),
    }
}

pub fn genesis_hash(network: Network) -> Result<[u8; 32], Error> {
    network_name(network)?;
    Ok(bitcoin::blockdata::constants::genesis_block(network)
        .block_hash()
        .to_byte_array())
}

pub(crate) fn tagged_hash(tag: &str, fields: &[&[u8]]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    for field in fields {
        engine.input(field);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn script_data_check(script: &[u8]) -> Result<(), Error> {
    if script.len() > MAX_SCRIPT_BYTES {
        Err(Error::ScriptDataTooLarge)
    } else {
        Ok(())
    }
}

pub fn signing_commitment(
    cmr: [u8; 32],
    script: &[u8],
    network: Network,
) -> Result<[u8; 32], Error> {
    script_data_check(script)?;
    Ok(tagged_hash(
        "SimplicityUnchained/PolicySigningCommitment/v1",
        &[
            &profile_hash(),
            &genesis_hash(network)?,
            &cmr,
            sha256::Hash::hash(script).as_byte_array(),
        ],
    ))
}

pub fn tweak_public_key(
    base_key: XOnlyPublicKey,
    cmr: [u8; 32],
    script: &[u8],
    network: Network,
) -> Result<XOnlyPublicKey, Error> {
    let commitment = signing_commitment(cmr, script, network)?;
    let tweak =
        TapTweakHash::from_key_and_tweak(base_key, Some(TapNodeHash::from_byte_array(commitment)));
    let scalar = Scalar::from_be_bytes(tweak.to_byte_array()).map_err(|_| Error::Taproot)?;
    let (key, _) = base_key
        .add_tweak(&Secp256k1::verification_only(), &scalar)
        .map_err(|_| Error::Taproot)?;
    Ok(key)
}

/// Public funding reconstruction; contains no secrets or unverified PSBT fields.
#[derive(Clone, Debug)]
pub struct CooperativeOutput {
    pub service_pubkey: XOnlyPublicKey,
    pub script: ScriptBuf,
    pub script_pubkey: ScriptBuf,
    pub control_block: ControlBlock,
    pub leaf_hash: TapLeafHash,
}

pub fn cooperative_output(
    base_key: XOnlyPublicKey,
    cmr: [u8; 32],
    script_data: &[u8],
    network: Network,
    user_pubkey: XOnlyPublicKey,
    recovery_hash: TapNodeHash,
) -> Result<CooperativeOutput, Error> {
    let secp = Secp256k1::verification_only();
    let service_pubkey = tweak_public_key(base_key, cmr, script_data, network)?;
    let script = bitcoin::script::Builder::new()
        .push_x_only_key(&service_pubkey)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .push_x_only_key(&user_pubkey)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(1, script.clone())
        .map_err(|_| Error::Taproot)?
        .add_hidden_node(1, recovery_hash)
        .map_err(|_| Error::Taproot)?
        .finalize(&secp, *NUMS)
        .map_err(|_| Error::Taproot)?;
    let control_block = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or(Error::Taproot)?;
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    Ok(CooperativeOutput {
        service_pubkey,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        script,
        control_block,
        leaf_hash,
    })
}

/// Only this validating module can construct or modify a context.
///
/// Full parent proofs and arbitrary PSBT metadata are deliberately not retained.
#[derive(Clone, Debug)]
pub struct Context {
    tx: Transaction,
    prevouts: Vec<TxOut>,
    input_index: usize,
    network: Network,
    cmr: [u8; 32],
    script_data: Vec<u8>,
    commitment: [u8; 32],
    cooperative: CooperativeOutput,
    user_pubkey: XOnlyPublicKey,
    sighash: [u8; 32],
    approval_hash: [u8; 32],
    transaction_approval_hash: [u8; 32],
    legacy_approval_hash: [u8; 32],
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) script_data_hash: [u8; 32],
    pub(crate) input_script_hashes: Vec<[u8; 32]>,
    pub(crate) output_script_hashes: Vec<[u8; 32]>,
    pub(crate) total_input_value: u64,
    pub(crate) total_output_value: u64,
    pub(crate) fee: u64,
    pub(crate) returned_value: u64,
    pub(crate) debit: u64,
    pub(crate) unsigned_tx_hash: [u8; 32],
    pub(crate) prevouts_hash: [u8; 32],
    pub(crate) tx_inputs_hash: [u8; 32],
    pub(crate) tx_outputs_hash: [u8; 32],
    pub(crate) recovery_hash: TapNodeHash,
    pub(crate) vsize_lower_bound: u32,
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
    pub cooperative_leaf_hash: String,
    pub cooperative_sighash_default: String,
    pub policy_approval_hash: String,
    pub policy_transaction_approval_hash: String,
    pub service_pubkey: String,
    pub user_pubkey: String,
    pub recovery_leaf_hash: String,
    pub total_input_value: u64,
    pub total_output_value: u64,
    pub fee: u64,
    pub debit: u64,
    pub vsize_lower_bound: u32,
    pub script_pubkey_hex: String,
    pub provenance: String,
    pub chain_status_verified: bool,
    pub outputs: Vec<OutputSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSummary {
    pub index: u32,
    pub value: u64,
    pub script_pubkey_hex: String,
    pub script_hash: String,
    pub script_class: u8,
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        psbt: &Psbt,
        input_index: usize,
        cmr: [u8; 32],
        script: &[u8],
        network: Network,
        base_service_pubkey: XOnlyPublicKey,
        user_pubkey: XOnlyPublicKey,
        recovery_hash: TapNodeHash,
    ) -> Result<Self, Error> {
        let genesis_hash = genesis_hash(network)?;
        script_data_check(script)?;
        let tx = &psbt.unsigned_tx;
        if tx.version.0 != 2 {
            return Err(Error::InvalidVersion);
        }
        if !(1..=MAX_INPUTS).contains(&tx.input.len())
            || !(1..=MAX_OUTPUTS).contains(&tx.output.len())
        {
            return Err(Error::InvalidShape);
        }
        if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
            return Err(Error::MapCountMismatch);
        }
        if input_index >= tx.input.len() {
            return Err(Error::InputIndex(input_index));
        }
        for (index, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.len() > MAX_SCRIPT_BYTES {
                return Err(Error::OutputScriptTooLarge(index));
            }
        }
        let mut outpoints = BTreeSet::new();
        for (index, input) in tx.input.iter().enumerate() {
            if !outpoints.insert(input.previous_output) {
                return Err(Error::DuplicateOutpoint(index));
            }
            if !input.script_sig.is_empty() || !input.witness.is_empty() {
                return Err(Error::NonUnsignedInput(index));
            }
        }
        check_evidence_size(psbt)?;
        let cooperative = cooperative_output(
            base_service_pubkey,
            cmr,
            script,
            network,
            user_pubkey,
            recovery_hash,
        )?;
        let mut parents: BTreeMap<bitcoin::Txid, &Transaction> = BTreeMap::new();
        let mut prevouts = Vec::with_capacity(tx.input.len());
        let mut total_input_value = 0u64;
        for (index, (input, map)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
            if map
                .sighash_type
                .is_some_and(|s| s.taproot_hash_ty() != Ok(TapSighashType::Default))
                || map
                    .tap_key_sig
                    .is_some_and(|s| s.sighash_type != TapSighashType::Default)
                || map
                    .tap_script_sigs
                    .values()
                    .any(|s| s.sighash_type != TapSighashType::Default)
            {
                return Err(Error::NonDefaultSighash(index));
            }
            if map.final_script_sig.as_ref().is_some_and(|s| !s.is_empty()) {
                return Err(Error::FinalScriptSig(index));
            }
            if map
                .final_script_witness
                .as_ref()
                .is_some_and(|w| !w.is_empty())
            {
                return Err(Error::FinalWitness(index));
            }
            let parent = map
                .non_witness_utxo
                .as_ref()
                .ok_or(Error::MissingParent(index))?;
            let witness = map
                .witness_utxo
                .as_ref()
                .ok_or(Error::MissingWitnessUtxo(index))?;
            let known_parent = parents.get(&input.previous_output.txid);
            if known_parent.is_none_or(|&known| known != parent) {
                if parent.compute_txid() != input.previous_output.txid {
                    return Err(Error::ParentTxidMismatch(index));
                }
                parents.insert(input.previous_output.txid, parent);
            }
            let verified = parent
                .output
                .get(input.previous_output.vout as usize)
                .ok_or(Error::ParentVout(index))?;
            if verified != witness {
                return Err(Error::WitnessUtxoMismatch(index));
            }
            if verified.script_pubkey != cooperative.script_pubkey {
                return Err(Error::FundingScriptMismatch(index));
            }
            total_input_value = money_add(total_input_value, verified.value.to_sat())?;
            prevouts.push(verified.clone());
        }
        let total_output_value = tx
            .output
            .iter()
            .try_fold(0u64, |sum, output| money_add(sum, output.value.to_sat()))?;
        let fee = total_input_value
            .checked_sub(total_output_value)
            .ok_or(Error::Overspend)?;
        let returned_value = tx
            .output
            .iter()
            .filter(|o| o.script_pubkey == cooperative.script_pubkey)
            .try_fold(0u64, |sum, output| money_add(sum, output.value.to_sat()))?;
        let debit = total_input_value
            .checked_sub(returned_value)
            .ok_or(Error::Arithmetic)?;
        let input_script_hashes = prevouts
            .iter()
            .map(|o| sha256_bytes(o.script_pubkey.as_bytes()))
            .collect();
        let output_script_hashes = tx
            .output
            .iter()
            .map(|o| sha256_bytes(o.script_pubkey.as_bytes()))
            .collect();
        let unsigned_tx_hash = consensus_hash(tx);
        let prevouts_hash = consensus_hash(&prevouts);
        let tx_inputs_hash = consensus_hash(&tx.input);
        let tx_outputs_hash = consensus_hash(&tx.output);
        let commitment = signing_commitment(cmr, script, network)?;
        let sighash = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                cooperative.leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|_| Error::Sighash)?
            .to_byte_array();
        let transaction_approval_hash = tagged_hash(
            "SimplicityUnchained/PolicyTransactionApproval/v1",
            &[
                &profile_hash(),
                &genesis_hash,
                &commitment,
                &unsigned_tx_hash,
                &prevouts_hash,
                cooperative.leaf_hash.as_byte_array(),
                recovery_hash.as_byte_array(),
            ],
        );
        let approval_hash = tagged_hash(
            "SimplicityUnchained/PolicyInputApproval/v1",
            &[
                &transaction_approval_hash,
                &(input_index as u32).to_be_bytes(),
                &sighash,
            ],
        );
        let legacy_commitment = tagged_hash(
            "SimplicityUnchained/SigningCommitment/v1",
            &[&cmr, &sha256_bytes(script)],
        );
        let network_id = match network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Testnet4 => 2,
            _ => return Err(Error::UnsupportedNetwork),
        };
        let legacy_approval_hash = tagged_hash(
            "SimplicityUnchained/BitcoinApproval/v1",
            &[
                &[network_id],
                &(input_index as u32).to_be_bytes(),
                &legacy_commitment,
                &unsigned_tx_hash,
                &prevouts_hash,
            ],
        );
        let vsize_lower_bound = u32::try_from(tx.base_size()).map_err(|_| Error::Arithmetic)?;
        Ok(Self {
            tx: tx.clone(),
            prevouts,
            input_index,
            network,
            cmr,
            script_data: script.to_vec(),
            commitment,
            cooperative,
            user_pubkey,
            sighash,
            approval_hash,
            transaction_approval_hash,
            legacy_approval_hash,
            genesis_hash,
            script_data_hash: sha256_bytes(script),
            input_script_hashes,
            output_script_hashes,
            total_input_value,
            total_output_value,
            fee,
            returned_value,
            debit,
            unsigned_tx_hash,
            prevouts_hash,
            tx_inputs_hash,
            tx_outputs_hash,
            recovery_hash,
            vsize_lower_bound,
        })
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }
    pub fn prevouts(&self) -> &[TxOut] {
        &self.prevouts
    }
    pub fn input_index(&self) -> usize {
        self.input_index
    }
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn cmr(&self) -> [u8; 32] {
        self.cmr
    }
    pub fn script_data(&self) -> &[u8] {
        &self.script_data
    }
    pub fn signing_commitment(&self) -> [u8; 32] {
        self.commitment
    }
    pub fn service_pubkey(&self) -> XOnlyPublicKey {
        self.cooperative.service_pubkey
    }
    pub fn user_pubkey(&self) -> XOnlyPublicKey {
        self.user_pubkey
    }
    pub fn cooperative_script(&self) -> &ScriptBuf {
        &self.cooperative.script
    }
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.cooperative.script_pubkey
    }
    pub fn control_block(&self) -> &ControlBlock {
        &self.cooperative.control_block
    }
    pub fn cooperative_leaf_hash(&self) -> TapLeafHash {
        self.cooperative.leaf_hash
    }
    pub fn cooperative_sighash_default(&self) -> [u8; 32] {
        self.sighash
    }
    pub fn sighash(&self) -> [u8; 32] {
        self.sighash
    }
    pub fn policy_approval_hash(&self) -> [u8; 32] {
        self.approval_hash
    }
    pub fn policy_transaction_approval_hash(&self) -> [u8; 32] {
        self.transaction_approval_hash
    }
    pub fn legacy_approval_hash(&self) -> [u8; 32] {
        self.legacy_approval_hash
    }
    pub fn unsigned_tx_hash(&self) -> [u8; 32] {
        self.unsigned_tx_hash
    }
    pub fn prevouts_hash(&self) -> [u8; 32] {
        self.prevouts_hash
    }
    pub fn tx_inputs_hash(&self) -> [u8; 32] {
        self.tx_inputs_hash
    }
    pub fn tx_outputs_hash(&self) -> [u8; 32] {
        self.tx_outputs_hash
    }

    pub fn summary(&self) -> ContextSummary {
        ContextSummary {
            profile: PROFILE_NAME.to_owned(),
            profile_hash: hex::encode(profile_hash()),
            network: network_name(self.network)
                .expect("validated network")
                .to_owned(),
            genesis_hash: hex::encode(self.genesis_hash),
            cmr: hex::encode(self.cmr),
            signing_commitment: hex::encode(self.commitment),
            redeem_script_hash: hex::encode(self.script_data_hash),
            input_index: self.input_index as u32,
            input_count: self.tx.input.len() as u32,
            output_count: self.tx.output.len() as u32,
            unsigned_tx_hash: hex::encode(self.unsigned_tx_hash),
            prevouts_hash: hex::encode(self.prevouts_hash),
            cooperative_leaf_hash: hex::encode(self.cooperative.leaf_hash.to_byte_array()),
            cooperative_sighash_default: hex::encode(self.sighash),
            policy_approval_hash: hex::encode(self.approval_hash),
            policy_transaction_approval_hash: hex::encode(self.transaction_approval_hash),
            service_pubkey: self.service_pubkey().to_string(),
            user_pubkey: self.user_pubkey.to_string(),
            recovery_leaf_hash: hex::encode(self.recovery_hash.to_byte_array()),
            total_input_value: self.total_input_value,
            total_output_value: self.total_output_value,
            fee: self.fee,
            debit: self.debit,
            vsize_lower_bound: self.vsize_lower_bound,
            script_pubkey_hex: hex::encode(self.cooperative.script_pubkey.as_bytes()),
            provenance: "parent-txid-verified".to_owned(),
            chain_status_verified: false,
            outputs: self
                .tx
                .output
                .iter()
                .enumerate()
                .map(|(index, output)| OutputSummary {
                    index: index as u32,
                    value: output.value.to_sat(),
                    script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                    script_hash: hex::encode(self.output_script_hashes[index]),
                    script_class: script_class(&output.script_pubkey),
                })
                .collect(),
        }
    }
}

fn money_add(sum: u64, value: u64) -> Result<u64, Error> {
    if value > MAX_MONEY {
        return Err(Error::MoneyRange);
    }
    let result = sum.checked_add(value).ok_or(Error::Arithmetic)?;
    if result > MAX_MONEY {
        Err(Error::MoneyRange)
    } else {
        Ok(result)
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn consensus_hash<T: Encodable>(value: &T) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    value
        .consensus_encode(&mut engine)
        .expect("hash-engine writing");
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub(crate) fn script_class(script: &Script) -> u8 {
    if script.is_p2pkh() {
        1
    } else if script.is_p2sh() {
        2
    } else if script.is_p2wpkh() {
        3
    } else if script.is_p2wsh() {
        4
    } else if script.is_p2tr() {
        5
    } else if script.is_op_return() {
        6
    } else {
        0
    }
}

// Bound raw payloads before rust-bitcoin serializes each PSBT map into a buffer.
// The final counting writer enforces the exact serialized bound.
fn check_evidence_size(psbt: &Psbt) -> Result<(), Error> {
    let mut size = Admission(0);
    size.add(psbt.unsigned_tx.total_size())?;
    size.add(psbt.xpub.len().saturating_mul(78))?;
    for (_, path) in psbt.xpub.values() {
        size.add(path.len().saturating_mul(4))?;
    }
    size.raw_maps(&psbt.unknown, &psbt.proprietary)?;
    for input in &psbt.inputs {
        if let Some(parent) = &input.non_witness_utxo {
            size.add(parent.total_size())?;
        }
        if let Some(output) = &input.witness_utxo {
            size.add(output.size())?;
        }
        for script in [
            &input.redeem_script,
            &input.witness_script,
            &input.final_script_sig,
        ]
        .into_iter()
        .flatten()
        {
            size.add(script.len())?;
        }
        if let Some(witness) = &input.final_script_witness {
            size.add(witness.size())?;
        }
        size.add(input.partial_sigs.len().saturating_mul(64))?;
        size.add(input.tap_script_sigs.len().saturating_mul(128))?;
        for (_, path) in input.bip32_derivation.values() {
            size.add(33 + path.len().saturating_mul(4))?;
        }
        for (hashes, (_, path)) in input.tap_key_origins.values() {
            size.add(32 + hashes.len().saturating_mul(32) + path.len().saturating_mul(4))?;
        }
        for (control, (script, _)) in &input.tap_scripts {
            size.add(control.size() + script.len())?;
        }
        for value in input
            .ripemd160_preimages
            .values()
            .chain(input.sha256_preimages.values())
            .chain(input.hash160_preimages.values())
            .chain(input.hash256_preimages.values())
        {
            size.add(32 + value.len())?;
        }
        size.raw_maps(&input.unknown, &input.proprietary)?;
    }
    for output in &psbt.outputs {
        for script in [&output.redeem_script, &output.witness_script]
            .into_iter()
            .flatten()
        {
            size.add(script.len())?;
        }
        for (_, path) in output.bip32_derivation.values() {
            size.add(33 + path.len().saturating_mul(4))?;
        }
        for (hashes, (_, path)) in output.tap_key_origins.values() {
            size.add(32 + hashes.len().saturating_mul(32) + path.len().saturating_mul(4))?;
        }
        if let Some(tree) = &output.tap_tree {
            for leaf in tree.script_leaves() {
                size.add(2 + leaf.script().len())?;
            }
        }
        size.raw_maps(&output.unknown, &output.proprietary)?;
    }
    psbt.serialize_to_writer(&mut Admission(0))
        .map_err(|_| Error::EvidenceTooLarge)?;
    Ok(())
}

struct Admission(usize);

impl Admission {
    fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.0 = self.0.checked_add(bytes).ok_or(Error::EvidenceTooLarge)?;
        if self.0 > MAX_REQUEST_BYTES {
            Err(Error::EvidenceTooLarge)
        } else {
            Ok(())
        }
    }

    fn raw_maps(
        &mut self,
        unknown: &BTreeMap<psbt::raw::Key, Vec<u8>>,
        proprietary: &BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>,
    ) -> Result<(), Error> {
        for (key, value) in unknown {
            self.add(3 + key.key.len() + value.len())?;
        }
        for (key, value) in proprietary {
            self.add(5 + key.prefix.len() + key.key.len() + value.len())?;
        }
        Ok(())
    }
}

impl bitcoin::io::Write for Admission {
    fn write(&mut self, buf: &[u8]) -> Result<usize, bitcoin::io::Error> {
        self.add(buf.len())
            .map_err(|_| bitcoin::io::Error::from(bitcoin::io::ErrorKind::Other))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), bitcoin::io::Error> {
        Ok(())
    }
}
