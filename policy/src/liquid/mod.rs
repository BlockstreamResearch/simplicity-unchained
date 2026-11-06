//! Portable `liquid-policy-v1`: verified PSET disclosures, never wallet labels.
mod context;
mod execution;
mod jets;
mod manifest;
mod operations;

pub use context::*;
pub use elements;
pub use execution::{PolicyJet, PreparedPolicy, policy_cmr};
pub use jets::Builtin;
pub use manifest::{PROFILE_NAME, manifest, profile_hash};
pub use operations::{
    CreateRequest, DisclosureProofs, Output, ProvenInput, add_signature, create_pset,
    create_pset_with_rng, disclosure_proofs, finalize, unblind_output,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Liquid policy context: {0}")]
    Invalid(String),
    #[error(transparent)]
    Frame(#[from] crate::Error),
}

pub(crate) fn require(ok: bool, message: impl Into<String>) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(message.into()))
    }
}
