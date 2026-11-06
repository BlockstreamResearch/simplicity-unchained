//! Portable public transaction context for the experimental `bitcoin-policy-v1` profile.
//!
//! These are application-specific, off-chain extensions, not Bitcoin consensus jets.
//! Parent transaction verification authenticates content, not confirmation or unspentness.

mod context;
mod jets;
pub mod liquid;
mod manifest;
mod value;

pub use context::{
    Context, ContextSummary, CooperativeOutput, OutputSummary, cooperative_output, genesis_hash,
    network_name, signing_commitment, tweak_public_key,
};
pub use jets::Builtin;
pub use manifest::{
    JetMetadata, Limits, Manifest, ManifestBody, PROFILE_NAME, manifest, profile_hash,
};
pub use simplicity::bitcoin;
pub use value::BitValue;

pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 8;
pub const MAX_SCRIPT_BYTES: usize = 10_000;
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EXECUTION_COST_MILLIWEIGHT: u32 = 10_000_000;
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported Bitcoin network")]
    UnsupportedNetwork,
    #[error("script data exceeds the 10000-byte profile limit")]
    ScriptDataTooLarge,
    #[error("PSBT or parent evidence exceeds the 2 MiB profile limit")]
    EvidenceTooLarge,
    #[error("transaction must have version 2")]
    InvalidVersion,
    #[error("transaction must have 1..=8 inputs and 1..=8 outputs")]
    InvalidShape,
    #[error("PSBT input or output maps do not match the unsigned transaction")]
    MapCountMismatch,
    #[error("input index {0} is out of range")]
    InputIndex(usize),
    #[error("input {0} has a duplicate outpoint")]
    DuplicateOutpoint(usize),
    #[error("input {0} has a scriptSig or witness in the unsigned transaction")]
    NonUnsignedInput(usize),
    #[error("input {0} is missing non_witness_utxo")]
    MissingParent(usize),
    #[error("input {0} is missing witness_utxo")]
    MissingWitnessUtxo(usize),
    #[error("input {0} parent transaction id does not match the outpoint")]
    ParentTxidMismatch(usize),
    #[error("input {0} parent output index is out of range")]
    ParentVout(usize),
    #[error("input {0} witness_utxo differs from the verified parent output")]
    WitnessUtxoMismatch(usize),
    #[error("input {0} does not spend the reconstructed cooperative output")]
    FundingScriptMismatch(usize),
    #[error("input {0} requests a non-default sighash")]
    NonDefaultSighash(usize),
    #[error("input {0} has a nonempty finalized scriptSig")]
    FinalScriptSig(usize),
    #[error("input {0} has finalized witness data (annex/overrides are unsupported)")]
    FinalWitness(usize),
    #[error("output {0} script exceeds the 10000-byte profile limit")]
    OutputScriptTooLarge(usize),
    #[error("amount or total is outside Bitcoin's money range")]
    MoneyRange,
    #[error("arithmetic overflow")]
    Arithmetic,
    #[error("transaction spends more than its verified inputs")]
    Overspend,
    #[error("invalid Taproot reconstruction")]
    Taproot,
    #[error("could not construct SIGHASH_DEFAULT")]
    Sighash,
    #[error("invalid source frame: expected {expected} bits")]
    SourceShape { expected: usize },
    #[error("policy check rejected")]
    CheckFailed,
    #[error("unknown policy jet {0}")]
    UnknownJet(String),
}
