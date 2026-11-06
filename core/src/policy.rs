//! Opt-in Bitcoin policy preparation and bounded execution.
//!
//! Programs and witnesses are binary here. There is no legacy decoder fallback.

use std::sync::Arc;

use simplicity::bit_machine::{ExecutionError, LimitError};
use simplicity::bitcoin::{self, XOnlyPublicKey, psbt::Psbt, taproot::TapNodeHash};
use simplicity::{BitIter, BitMachine, Cmr, CommitNode, Cost, DecodeError, RedeemNode};

use crate::jets::policy::{PolicyEnv, PolicyJet};
use crate::runner::MAX_EXECUTION_COST;

pub use simplicity_unchained_policy::{Builtin, Context, ContextSummary};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy program or witness: {0}")]
    Decode(#[source] DecodeError),
    #[error("invalid policy context: {0}")]
    Context(#[from] simplicity_unchained_policy::Error),
    #[error("witnessed program CMR differs from the prepared policy")]
    CommitmentMismatch,
    #[error("policy rejected: {0}")]
    PolicyRejected(#[source] ExecutionError),
    #[error("program execution cost {cost} exceeds maximum {max} milliweight")]
    ExecutionCostExceeded { cost: Cost, max: Cost },
    #[error("bit machine memory limit exceeded: {0}")]
    MemoryLimit(#[source] LimitError),
    #[error("internal policy VM error: {0}")]
    Vm(#[source] ExecutionError),
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub cmr: Cmr,
    pub context: ContextSummary,
    pub cost_milliweight: u32,
    /// Static upper bound, not a wall-clock measurement or consensus calibration.
    pub bounded_cost: Cost,
}

pub struct PreparedPolicy {
    program: Arc<[u8]>,
    commitment: Arc<CommitNode>,
    env: PolicyEnv,
}

/// Decode the original commitment without requiring any approval witness.
pub fn policy_cmr(program_bytes: &[u8]) -> Result<Cmr, PolicyError> {
    decode_commitment(program_bytes).map(|program| program.cmr())
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_policy(
    program_bytes: &[u8],
    psbt: &Psbt,
    input_index: usize,
    script: &[u8],
    network: bitcoin::Network,
    base_service_xonly: XOnlyPublicKey,
    user_xonly: XOnlyPublicKey,
    recovery: TapNodeHash,
) -> Result<PreparedPolicy, PolicyError> {
    PreparedPolicy::new(
        program_bytes,
        psbt,
        input_index,
        script,
        network,
        base_service_xonly,
        user_xonly,
        recovery,
    )
}

fn decode_commitment(program_bytes: &[u8]) -> Result<Arc<CommitNode>, PolicyError> {
    CommitNode::decode::<_, PolicyJet>(BitIter::from(program_bytes)).map_err(PolicyError::Decode)
}

impl PreparedPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program_bytes: &[u8],
        psbt: &Psbt,
        input_index: usize,
        script: &[u8],
        network: bitcoin::Network,
        base_service_xonly: XOnlyPublicKey,
        user_xonly: XOnlyPublicKey,
        recovery: TapNodeHash,
    ) -> Result<Self, PolicyError> {
        let commitment = decode_commitment(program_bytes)?;
        let context = Context::new(
            psbt,
            input_index,
            commitment.cmr().to_byte_array(),
            script,
            network,
            base_service_xonly,
            user_xonly,
            recovery,
        )?;
        Ok(Self {
            program: Arc::from(program_bytes),
            commitment,
            env: PolicyEnv::new(context),
        })
    }

    pub fn context(&self) -> &Context {
        self.env.context()
    }

    pub fn summary(&self) -> ContextSummary {
        self.context().summary()
    }

    pub fn cmr(&self) -> Cmr {
        self.commitment.cmr()
    }

    pub fn evaluate_default(&self, witness_bytes: &[u8]) -> Result<EvaluationResult, PolicyError> {
        self.evaluate(witness_bytes, MAX_EXECUTION_COST)
    }

    pub fn evaluate_milliweight(
        &self,
        witness_bytes: &[u8],
        max_milliweight: u32,
    ) -> Result<EvaluationResult, PolicyError> {
        self.evaluate(witness_bytes, Cost::from_milliweight(max_milliweight))
    }

    /// A caller may lower, but never raise, the runner's default execution cap.
    pub fn evaluate(
        &self,
        witness_bytes: &[u8],
        limit: Cost,
    ) -> Result<EvaluationResult, PolicyError> {
        let program = RedeemNode::decode::<_, _, PolicyJet>(
            BitIter::from(self.program.as_ref()),
            BitIter::from(witness_bytes),
        )
        .map_err(PolicyError::Decode)?;
        if program.cmr() != self.cmr() {
            return Err(PolicyError::CommitmentMismatch);
        }
        let mut machine = bounded_machine(&program, limit)?;
        machine
            .exec(&program, &self.env)
            .map_err(|error| match error {
                ExecutionError::ReachedFailNode(..)
                | ExecutionError::ReachedPrunedBranch(..)
                | ExecutionError::JetFailed(..) => PolicyError::PolicyRejected(error),
                ExecutionError::LimitExceeded(limit) => PolicyError::MemoryLimit(limit),
                _ => PolicyError::Vm(error),
            })?;
        Ok(EvaluationResult {
            cmr: self.cmr(),
            context: self.summary(),
            // Simplicity 0.9 exposes Cost's exact milliweight only through Display.
            cost_milliweight: program
                .bounds()
                .cost
                .to_string()
                .parse()
                .expect("Cost displays its u32 milliweight"),
            bounded_cost: program.bounds().cost,
        })
    }
}

fn bounded_machine(program: &RedeemNode, limit: Cost) -> Result<BitMachine, PolicyError> {
    let max = limit.min(MAX_EXECUTION_COST);
    let cost = program.bounds().cost;
    if cost > max {
        return Err(PolicyError::ExecutionCostExceeded { cost, max });
    }
    BitMachine::for_program(program).map_err(PolicyError::MemoryLimit)
}

#[cfg(test)]
pub(crate) mod tests;
