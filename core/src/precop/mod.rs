pub mod engine;
pub mod error;
pub mod topology;

pub use error::PrecopError;
pub use topology::TopologyEnforcer;

use hal_simplicity::simplicity::bitcoin::psbt::Psbt;

/// Validates the PSBT against PRECOP canonical rules and derives the execution context.
///
/// This function moves the oracle from "Passive Verification" to "Mathematical Necessity"
/// by enforcing strict output topology and exhaustive UTXO context hydration.
///
/// # Arguments
/// * `psbt` - The Partially Signed Bitcoin Transaction to validate.
///
/// # Returns
/// * `Ok(BitcoinEnv)` - The hydrated execution environment if valid.
/// * `Err(PrecopError)` - If any validation fails.
///
/// # Errors
/// * `PrecopError::TopologyViolation` - If output sequence is invalid (must be exactly 4 outputs).
/// * `PrecopError::MissingUtxoContext` - If any input context is incomplete.
pub fn validate_and_derive(psbt: &Psbt) -> Result<(), PrecopError> {
    // 1. Enforce Output Topology (Command-First)
    TopologyEnforcer::verify_command_first(&psbt.unsigned_tx)?;

    // 2. Hydrate Environment (Anti-Blind Signer)
    engine::PrecopEngine::hydrate_env(psbt)?;

    Ok(())
}
