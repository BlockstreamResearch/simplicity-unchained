use super::Builtin;
use elements::hashes::sha256;
use serde_json::{Value, json};
use std::sync::LazyLock;

pub const PROFILE_NAME: &str = "liquid-policy-v1";
const CONTRACT: &str = "Experimental off-chain Elements policy, not consensus Simplicity. Immutable fully verified PSET context; version2,1..8 inputs/outputs,<=2MiB evidence,<=10000-byte scripts; native NUMS P2TR cooperative leaf plus hidden recovery at depth1; all inputs same reconstructed profile/network-bound output; Elements TapLeaf/TapTweak and genesis-bound SIGHASH_DEFAULT only; no annex,issuance,pegin,final witnesses. Required full non_witness_utxo txid/vout and exact base witness_utxo. Confidential PSET amount/asset labels require elements RangeProof::blind_value_proof_verify and SurjectionProof::blind_asset_proof_verify against authenticated commitments. Input original rangeproof verified with script commitment. Transaction verify_tx_amt_proofs verifies output range/surjection proofs and Pedersen balance. Per-asset checked u64 conservation includes exactly one explicit network-policy-asset fee output. No chain inclusion/confirmation/consensus-validity/unspentness claim. Every pre-existing signature verified against canonical leaf,known keys,DEFAULT sighash before preparation/signing. No secret keys,clock,I/O,mutable state in jets.";
const PROJECTION: &str = "Scalar value jets select the CURRENT verified input asset (raw AssetId::to_byte_array bytes), except tx_fee which ALWAYS returns the explicit configured network fee-asset amount, independent of current asset; fee_asset returns its denomination. input_value/output_value return None for another asset, not zero or an untyped amount. current_value is current asset value. total_input_value,total_output_value (including fees),value_returned_to_current_script,current_script_debit select current asset. input_value_for_script/output_value_for_script/output_count_for_script filter BOTH current asset and script SHA256; returned value uses exact script equality. debit=all inputs of selected asset minus exact-script returns. Asset-selector totals/debit/fee return zero for absent asset. No all-asset scalar totals. input/output_value_asset return Some(asset32||value_be64) for any in-range index. Asset IDs in JSON use display order; jet words use raw bytes.";
const HASHES: &str = "Words MSB-first,options tag+zero padding; canonical BitValue layout. All hashes raw library bytes,no explorer reversal. SHA256 single unless tagged. unsigned_tx_hash hashes full extracted unsigned Elements transaction including output range/surjection witnesses; prevouts_hash hashes consensus TxOut vector (base fields only); tx_inputs_hash/tx_outputs_hash hash consensus vectors (counts included). disclosures_hash=SHA256(input_count_be32||each input(asset_raw32||value_be64||confidential_asset_u8||confidential_value_u8)||output_count_be32||same output tuples). It commits values,not randomly generated disclosure proof bytes; proofs are independently verified every time. signing_commitment=TaggedHash('SimplicityUnchained/LiquidPolicySigningCommitment/v1',profile_hash||Elements_genesis_raw||program_CMR||SHA256(script_data)); service_key=Elements TapTweak(base_xonly,commitment as root). Cooperative leaf version0xc4 (Elements tapscript),NUMS50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0. J54=TaggedHash('SimplicityUnchained/LiquidPolicyTransactionApproval/v1',profile_hash||genesis||signing_commitment||unsigned_tx_hash||prevouts_hash||disclosures_hash||cooperative_leaf_hash||recovery_hash). J53=TaggedHash('SimplicityUnchained/LiquidPolicyInputApproval/v1',J54||index_be32||Elements DEFAULT sighash); actual sighash uses genesis twice as Elements defines. vsize lower bound is serialized unsigned transaction with ALL witness proofs stripped; not final fee rate.";

fn body() -> Value {
    json!({
        "schema_version":1,"profile":PROFILE_NAME,"status":"experimental-offchain",
        "elements_version":"0.27","simplicity_version":"0.9",
        "namespace":"0||Core jet; 1||seven-bit Liquid builtin ID; no legacy extension fallback",
        "common_contract":CONTRACT,"amount_contract":PROJECTION,"hash_contract":HASHES,
        "cost_contract":"Fixed 10000 milliweight per extension; bounded <=8 scans; max execution 10000000 milliweight; context/proof verification separately admission bounded; no consensus calibration claim.",
        "limits":{"max_inputs":8,"max_outputs":8,"max_request_bytes":2097152,"max_script_bytes":10000,"max_value":"18446744073709551614","networks":["liquid","liquidtestnet"],"default_network":"liquidtestnet"},
        "jets":Builtin::all().map(|j| json!({"id":j.id(),"name":j.name(),"source_type":String::from_utf8_lossy(j.source_type().0),"target_type":String::from_utf8_lossy(j.target_type().0),"source_bits":j.source_bits(),"target_bits":j.target_bits(),"encoding":format!("1{:07b}",j.id()),"semantic_contract":semantics(j),"cost_milliweight":j.cost_milliweight(),"cmr":hex::encode(identity(j))})).collect::<Vec<_>>(),
    })
}

pub(crate) fn semantics(j: Builtin) -> String {
    use crate::Builtin::*;
    match j {
        Builtin::Policy(op) => match op {
            PolicyProfileHash => "Return SHA256 of canonical ordered-key JSON manifest without profile_hash.".into(),
            NetworkGenesisHash => "Return configured Liquid/LiquidTestnet Elements genesis hash raw bytes.".into(),
            SigningCommitmentHash | UnsignedTxHash | PrevoutsHash | TxInputsHash | TxOutputsHash | CooperativeLeafHash | CooperativeSighashDefault | PolicyApprovalHash | PolicyTransactionApprovalHash | TxVsizeLowerBound => HASHES.into(),
            InputValue | OutputValue | CurrentValue | TotalInputValue | TotalOutputValue | TxFee | InputValueForScript | OutputValueForScript | OutputCountForScript | CurrentScriptDebit | ValueReturnedToCurrentScript => PROJECTION.into(),
            // These operations only read shared public script/sequence/index/lock fields;
            // their Bitcoin wording below is not used for network/hash/wire/value operations.
            _ => op.semantic_contract().replace("Bitcoin", "Elements").replace("BIP-341", "Elements Taproot").replace("0xc0", "0xc4"),
        },
        Builtin::InputAsset | Builtin::OutputAsset => "Return Some(verified asset ID raw32) at zero-based input/output index; out of range canonical None; no PSET labels without cryptographic disclosure proof.".into(),
        Builtin::CurrentAsset => "Return current verified input asset raw32. Bind this explicitly before using current-asset scalar budgets.".into(),
        Builtin::FeeAsset => "Return configured network policy fee asset raw32; tx_fee is ALWAYS denominated in this asset.".into(),
        Builtin::AssetTotalInputValue => "Input asset_raw32; return checked sum of verified inputs in this asset, independent of current input asset; absent asset zero.".into(),
        Builtin::AssetTotalOutputValue => "Input asset_raw32; return checked sum of verified outputs (including fees) in this asset, independent of current input asset; absent asset zero.".into(),
        Builtin::AssetFee => "Input asset_raw32; return explicit fees in this asset. Only configured fee asset can have nonzero fees; absent asset zero.".into(),
        Builtin::AssetCurrentScriptDebit => "Input asset_raw32; return checked sum of ALL same-contract inputs in that asset minus outputs of that asset with EXACT current script equality; independent of current input asset, includes network fee if matching; absent asset zero.".into(),
        Builtin::DisclosuresHash => HASHES.into(),
        Builtin::InputValueAsset | Builtin::OutputValueAsset => "Return Some(verified asset_raw32||value_be64) for any in-range input/output index, regardless of current asset; out of range canonical None. Both asset and value disclosures cryptographically verified.".into(),
    }
}
pub(crate) fn identity(j: Builtin) -> [u8; 32] {
    // Identity does not reference profile_hash: fingerprinting remains acyclic.
    crate::context::tagged_hash("SimplicityUnchained/LiquidPolicyJetIdentity/v1", &[&serde_json::to_vec(&json!({
        "schema_version":1,"profile":PROFILE_NAME,"id":j.id(),"name":j.name(),
        "source_type":String::from_utf8_lossy(j.source_type().0),"target_type":String::from_utf8_lossy(j.target_type().0),
        "cost_milliweight":j.cost_milliweight(),"semantics":semantics(j),"common":CONTRACT,"projection":PROJECTION,"hashes":HASHES,
    })).expect("identity serialization")])
}

static BODY: LazyLock<Value> = LazyLock::new(body);
pub fn profile_hash() -> [u8; 32] {
    sha256::Hash::hash(&serde_json::to_vec(&*BODY).expect("manifest serialization")).to_byte_array()
}
pub fn manifest() -> Value {
    let mut value = BODY.clone();
    value["profile_hash"] = hex::encode(profile_hash()).into();
    value
}
