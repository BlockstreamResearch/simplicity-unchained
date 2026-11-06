use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use simplicity::bitcoin::hashes::{Hash, sha256};
use simplicity::jet::{Core, Jet};
use simplicity::{BitWriter, jet::type_name::TypeName};

use crate::{
    Builtin, MAX_EXECUTION_COST_MILLIWEIGHT, MAX_INPUTS, MAX_MONEY, MAX_OUTPUTS, MAX_REQUEST_BYTES,
    MAX_SCRIPT_BYTES,
};

pub const PROFILE_NAME: &str = "bitcoin-policy-v1";

const COMMON_CONTRACT: &str = "Experimental off-chain Bitcoin policy extensions, not Bitcoin consensus jets. All operations are deterministic and read one immutable, fully validated public context; no secret keys, I/O, clock, active chain, or mutable state. Required context never defaults. The profile accepts exactly version2, 1..=8 inputs/outputs, native P2TR cooperative script-path only. Every input has non_witness_utxo and exactly matching witness_utxo; parent txid/vout are verified; duplicate outpoints, negative fees, money-range violations and checked-arithmetic failure are rejected. All inputs spend the same reconstructed NUMS-internal-key output with canonical service CHECKSIG user CHECKSIGADD 2 EQUAL leaf and one hidden recovery hash at depth1. Every output script and script_data is at most10000 bytes; request/evidence at most2097152 bytes. Parent proofs are deduplicated and not retained in Context. Only configured Bitcoin/Testnet/Testnet4 networks. Only SIGHASH_DEFAULT; no annex or code-separator overrides; caller final witnesses cannot supply execution context. Parent verification proves content, NOT confirmation, consensus validity, chain inclusion or unspentness. Hash-keyed aggregates scan at most8 entries. Indexed missing entries/bytes return canonical None; failed Check rejects execution.";
const BIT_LAYOUT: &str = "Standard simplicity-lang0.9 TypeName prefix notation: 1=unit(0 bits),2=bit,c=u8,s=u16,i=u32,l=u64,h=u256,+=sum,*=product. Words unsigned MSB-first big-endian. Products concatenate. Sums: tag then zero left padding to maximum branch width then active payload; Either<(),T> None=0||zeroes(width(T)), Some=1||T. Unit has no bits; bool exactly one bit. Packed buffers have exact ceil(width/8) bytes with unused low bits zero; malformed source rejected.";
const IDENTITY_CONTRACT: &str = "New CMRs are application-defined off-chain custom extension identities, NOT standard/consensus Simplicity jet identities or claims of a formally derived native implementation. Identity = BIP340-style TaggedHash('SimplicityUnchained/PolicyJetIdentity/v1', compact serde_json bytes of ordered SemanticIdentity fields schema_version,profile,id,name,source_type,target_type,source_bits,target_bits,cost_milliweight,semantic_contract,common_contract,bit_layout,hash_contract,signing_contract,approval_contract,cost_contract,limits). The complete semantic contract and types, not only a name, are committed. No identity references profile_hash, so manifest fingerprinting is acyclic. Legacy Core and three existing extension identities remain byte-for-byte unchanged.";
const HASH_CONTRACT: &str = "All H values use Hash::to_byte_array in hash-library order, never explorer display reversal. SHA256 is single SHA256 unless explicitly tagged. TaggedHash(tag,m)=SHA256(SHA256(UTF8(tag))||SHA256(UTF8(tag))||m). Consensus vectors include CompactSize counts. All approval and signing-commitment fields are fixed-width32 bytes except input index:u32 big-endian. No strings, network labels, signature bytes or lengths enter these preimages.";
const SIGNING_CONTRACT: &str = "PolicySigningCommitment/v1 tag is 'SimplicityUnchained/PolicySigningCommitment/v1'; message=profile_hash||genesis_hash||program_cmr||SHA256(script_data). service_key=BIP341 TapTweak(base_service_xonly, merkle_root=that commitment), treating commitment as the32-byte root, then use tweaked xonly in canonical cooperative leaf. Internal output key is NUMS 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0; two leaves at depth1, cooperative leaf version0xc0 plus hidden supplied recovery TapNodeHash. Every verified input script must equal the resulting p2tr scriptPubKey. This domain is isolated from legacy SigningCommitment/v1.";
const APPROVAL_CONTRACT: &str = "J54=TaggedHash('SimplicityUnchained/PolicyTransactionApproval/v1',profile_hash||genesis_hash||signing_commitment||unsigned_tx_hash||prevouts_hash||cooperative_leaf_hash||recovery_hash). J53=TaggedHash('SimplicityUnchained/PolicyInputApproval/v1',J54||selected_index_be32||actual_default_sighash). J54 deliberately reusable across all same-contract inputs; J53 input-specific. Sign decoded digest bytes directly, no extra hash. Neither digest implements one-use permissions or includes its own signatures. Existing tx_approval_hash remains BitcoinApproval/v1 using legacy SigningCommitment/v1.";
const COST_CONTRACT: &str = "Each new extension costs fixed10000 milliweight, initially conservative for <=8-entry bounded cached-hash scans and <=321 combined source/target frame bits. VM execution admission is at most10000000 milliweight including combinator costs. Context construction/proof hashing is separately admission bounded, not paid by jet cost. Legacy costs unchanged. Experimental until end-to-end VM/compiler/service verification and cost-ceiling measurements complete; changing this frozen manifest requires explicit versioning.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub transaction_version: i32,
    pub min_inputs: usize,
    pub max_inputs: usize,
    pub min_outputs: usize,
    pub max_outputs: usize,
    pub max_output_script_bytes: usize,
    pub max_script_data_bytes: usize,
    pub max_request_bytes: usize,
    pub max_evidence_bytes: usize,
    pub max_execution_cost_milliweight: u32,
    pub max_money_satoshis: u64,
    pub max_jet_scan_entries: usize,
    pub max_jet_frame_bits: usize,
    pub networks: Vec<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            transaction_version: 2,
            min_inputs: 1,
            max_inputs: MAX_INPUTS,
            min_outputs: 1,
            max_outputs: MAX_OUTPUTS,
            max_output_script_bytes: MAX_SCRIPT_BYTES,
            max_script_data_bytes: MAX_SCRIPT_BYTES,
            max_request_bytes: MAX_REQUEST_BYTES,
            max_evidence_bytes: MAX_REQUEST_BYTES,
            max_execution_cost_milliweight: MAX_EXECUTION_COST_MILLIWEIGHT,
            max_money_satoshis: MAX_MONEY,
            max_jet_scan_entries: 8,
            max_jet_frame_bits: 321,
            networks: ["bitcoin", "testnet", "testnet4"]
                .map(str::to_owned)
                .to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JetMetadata {
    pub id: u16,
    pub name: String,
    pub source_type: String,
    pub target_type: String,
    pub source_bits: usize,
    pub target_bits: usize,
    pub encoding: String,
    pub cmr: String,
    pub cost_milliweight: u32,
    pub semantic_contract: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub profile_hash: String,
    #[serde(flatten)]
    pub body: ManifestBody,
}

impl std::ops::Deref for Manifest {
    type Target = ManifestBody;
    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

impl Manifest {
    /// The exact fingerprint preimage, without a self-referential hash field.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.body).expect("manifest serialization")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    pub schema_version: u32,
    pub profile: String,
    pub status: String,
    pub simplicity_version: String,
    pub namespace: String,
    pub fingerprint_contract: String,
    pub bit_layout: String,
    pub hash_contract: String,
    pub identity_contract: String,
    pub common_contract: String,
    pub signing_contract: String,
    pub approval_contract: String,
    pub cost_contract: String,
    pub limits: Limits,
    pub jets: Vec<JetMetadata>,
    pub legacy_jets: Vec<JetMetadata>,
}

#[derive(Serialize)]
struct SemanticIdentity {
    schema_version: u32,
    profile: &'static str,
    id: u8,
    name: &'static str,
    source_type: &'static str,
    target_type: &'static str,
    source_bits: usize,
    target_bits: usize,
    cost_milliweight: u32,
    semantic_contract: &'static str,
    common_contract: &'static str,
    bit_layout: &'static str,
    hash_contract: &'static str,
    signing_contract: &'static str,
    approval_contract: &'static str,
    cost_contract: &'static str,
    limits: Limits,
}

pub(crate) fn builtin_identity(jet: Builtin) -> [u8; 32] {
    static IDENTITIES: LazyLock<[[u8; 32]; 55]> = LazyLock::new(|| {
        Builtin::ALL.map(|jet| {
            let identity = SemanticIdentity {
                schema_version: 1,
                profile: PROFILE_NAME,
                id: jet.id(),
                name: jet.name(),
                source_type: type_string(jet.source_type()),
                target_type: type_string(jet.target_type()),
                source_bits: jet.source_bits(),
                target_bits: jet.target_bits(),
                cost_milliweight: jet.cost_milliweight(),
                semantic_contract: jet.semantic_contract(),
                common_contract: COMMON_CONTRACT,
                bit_layout: BIT_LAYOUT,
                hash_contract: HASH_CONTRACT,
                signing_contract: SIGNING_CONTRACT,
                approval_contract: APPROVAL_CONTRACT,
                cost_contract: COST_CONTRACT,
                limits: Limits::default(),
            };
            crate::context::tagged_hash(
                "SimplicityUnchained/PolicyJetIdentity/v1",
                &[&serde_json::to_vec(&identity).expect("fixed identity serialization")],
            )
        })
    });
    IDENTITIES[usize::from(jet.id())]
}

fn type_string(name: TypeName) -> &'static str {
    std::str::from_utf8(name.0).expect("standard ASCII TypeName")
}

#[allow(clippy::too_many_arguments)]
fn metadata(
    id: u16,
    name: String,
    source: TypeName,
    target: TypeName,
    encoding: String,
    cmr: [u8; 32],
    cost: u32,
    contract: &str,
) -> JetMetadata {
    JetMetadata {
        id,
        name,
        source_type: type_string(source.clone()).to_owned(),
        target_type: type_string(target.clone()).to_owned(),
        source_bits: source.to_bit_width(),
        target_bits: target.to_bit_width(),
        encoding,
        cmr: hex::encode(cmr),
        cost_milliweight: cost,
        semantic_contract: contract.to_owned(),
    }
}

fn legacy_metadata() -> Vec<JetMetadata> {
    let mut jets = Vec::with_capacity(Core::ALL.len() + 3);
    for (id, jet) in Core::ALL.into_iter().enumerate() {
        let mut bytes = Vec::new();
        let bits = {
            let mut writer = BitWriter::new(&mut bytes as &mut dyn std::io::Write);
            let bits = jet.encode(&mut writer).expect("Vec writing");
            writer.flush_all().expect("Vec writing");
            bits
        };
        let encoding = std::iter::once('0')
            .chain((0..bits).map(|i| {
                if bytes[i / 8] >> (7 - i % 8) & 1u8 == 1u8 {
                    '1'
                } else {
                    '0'
                }
            }))
            .collect();
        jets.push(metadata(
            id as u16,
            jet.to_string(),
            jet.source_ty(),
            jet.target_ty(),
            encoding,
            jet.cmr().to_byte_array(),
            jet.cost().to_string().parse().expect("Cost displays milliweight"),
            "Unchanged standard Core jet semantics, CMR, TypeName, cost and inner encoding pinned to simplicity-lang0.9.0; only outer policy namespace bit0 is prepended. No policy reinterpretation of this jet.",
        ));
    }
    for (name, source, target, encoding, cmr, cost, contract) in [
        (
            "get_opcode_from_script",
            b"c".as_slice(),
            b"c".as_slice(),
            "0111110",
            "dcccd2895922e75b018b0846e5cd4963808bbfd48b47234475607f90e70ee032",
            100,
            "Legacy byte accessor: u8 offset in script_data returns that raw byte; offset>=length fails. Despite name it does not parse instructions.",
        ),
        (
            "get_pubkey_from_script",
            b"c".as_slice(),
            b"h".as_slice(),
            "01111110",
            "27eab09068b035af619713335b73d2520ecc02090067c8fccabb4d72a655cdcb",
            100,
            "Legacy compressed-key extraction: u8 offset must have34 bytes remaining, byte0=0x21, byte1=0x02 or0x03; return following32 X-coordinate bytes without curve validation; otherwise fail.",
        ),
        (
            "tx_approval_hash",
            b"1".as_slice(),
            b"h".as_slice(),
            "01111111",
            "f0ed96ee8fbf1a69beb20deb3a7a9b748bdc18da284d15438debc7d4faeb9962",
            356,
            "Legacy BitcoinApproval/v1 tagged digest, unchanged: network byte0/1/2 for Bitcoin/Testnet/Testnet4 || input_index_be32 || legacy TaggedHash('SimplicityUnchained/SigningCommitment/v1',cmr||SHA256(script_data)) || SHA256(consensus unsigned tx) || SHA256(consensus verified TxOut vector). No new-domain alias.",
        ),
    ] {
        jets.push(metadata(
            jets.len() as u16,
            name.to_owned(),
            TypeName(source),
            TypeName(target),
            encoding.to_owned(),
            hex::decode(cmr).unwrap().try_into().unwrap(),
            cost,
            contract,
        ));
    }
    jets
}

static MANIFEST: LazyLock<Manifest> = LazyLock::new(|| {
    let body = ManifestBody {
        schema_version: 1,
        profile: PROFILE_NAME.to_owned(),
        status: "experimental".to_owned(),
        simplicity_version: "0.9.0".to_owned(),
        namespace: "0 || unchanged CoreExtension code; 1 || new id:u6 MSB-first; ids0..54 valid,55..63 invalid. Jet code only; outer Simplicity node encoding is unchanged.".to_owned(),
        fingerprint_contract: "profile_hash=SHA256(compact serde_json serialization of ManifestBody in declared field order, UTF8, no whitespace/newline, ordered jets ids0..54 and legacy Core::ALL then3 extensions). Manifest serializes profile_hash first then flattens body; remove only profile_hash to reproduce the body. Arrays and all contract/type/encoding/CMR/cost/limit fields are hashed. No maps with nondeterministic order, no circular self-hashing.".to_owned(),
        bit_layout: BIT_LAYOUT.to_owned(),
        hash_contract: HASH_CONTRACT.to_owned(),
        identity_contract: IDENTITY_CONTRACT.to_owned(),
        common_contract: COMMON_CONTRACT.to_owned(),
        signing_contract: SIGNING_CONTRACT.to_owned(),
        approval_contract: APPROVAL_CONTRACT.to_owned(),
        cost_contract: COST_CONTRACT.to_owned(),
        limits: Limits::default(),
        jets: Builtin::ALL.into_iter().map(|jet| metadata(
            u16::from(jet.id()), jet.name().to_owned(), jet.source_type(), jet.target_type(),
            jet.encoding(), jet.cmr(), jet.cost_milliweight(), jet.semantic_contract(),
        )).collect(),
        legacy_jets: legacy_metadata(),
    };
    let profile_hash = hex::encode(
        sha256::Hash::hash(&serde_json::to_vec(&body).expect("fixed manifest serialization"))
            .to_byte_array(),
    );
    Manifest { profile_hash, body }
});

pub fn manifest() -> Manifest {
    MANIFEST.clone()
}

pub fn profile_hash() -> [u8; 32] {
    hex::decode(&MANIFEST.profile_hash)
        .expect("generated hex")
        .try_into()
        .expect("32-byte hash")
}
