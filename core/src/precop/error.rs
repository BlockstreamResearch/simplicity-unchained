use thiserror::Error;

/// Errors related to PRECOP Canonical Derivation Engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrecopError {
    /// Violation of mandatory output sequence or structure.
    #[error("Topology violation: {0}")]
    TopologyViolation(String),

    /// Missing UTXO context (witness_utxo) for an input.
    #[error("Missing UTXO context for input index {0}")]
    MissingUtxoContext(usize),

    /// Error returned by the underlying Simplicity backend.
    #[error("Simplicity backend error: {0}")]
    SimplicityBackendError(String),
}
