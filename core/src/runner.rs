use std::sync::Arc;

use simplicity::bit_machine::ExecutionError;
use simplicity::bitcoin::psbt;
use simplicity::elements::taproot::{LeafVersion, TaprootMerkleBranch};
use simplicity::elements::{BlockHash, Script};
use simplicity::elements::{Transaction, pset, schnorr::UntweakedPublicKey};
use simplicity::{BitMachine, Cost, RedeemNode};
use simplicity::{
    Cmr,
    elements::taproot::ControlBlock,
    jet::CoreEnv,
    jet::elements::{ElementsEnv, ElementsUtxo},
};

use hex_literal::hex;

use crate::jets::bitcoin::CoreExtension;
use crate::jets::elements::ElementsExtension;
use crate::jets::environments::UnchainedEnv;
use crate::program::Program;
use crate::{BitcoinNetwork, ElementsNetwork};

pub struct SimplicityRunner;

/// Maximum execution cost accepted by the off-chain runner, in milliweight.
pub const MAX_EXECUTION_COST: Cost = Cost::from_milliweight(10_000_000);

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("input index {index} out-of-range for PSET with {total} inputs")]
    InputIndexOutOfRange { index: usize, total: usize },

    #[error("could not find Simplicity leaf in PSET taptree with CMR {cmr})")]
    MissingSimplicityLeaf { cmr: String },

    #[error("failed to extract transaction from PSET: {0}")]
    PsetExtract(simplicity::elements::pset::Error),

    #[error("witness_utxo field not populated for input {0}")]
    MissingWitnessUtxo(usize),

    #[error("invalid program: {0}")]
    ProgramParse(simplicity::ParseError),

    #[error("program does not have a redeem node")]
    NoRedeemNode,

    #[error("program execution cost {cost} exceeds maximum {max} milliweight")]
    ExecutionCostExceeded { cost: Cost, max: Cost },

    #[error("failed to construct bit machine: {0}")]
    BitMachineConstruction(simplicity::bit_machine::LimitError),

    #[error("execution error: {0}")]
    ExecutionError(ExecutionError),
}

impl SimplicityRunner {
    pub fn execute_elements(
        program: &str,
        witness: Option<&str>,
        input_idx: usize,
        pset: &pset::PartiallySignedTransaction,
        redeem_script: Script,
        network: ElementsNetwork,
    ) -> Result<Cmr, RunnerError> {
        let program = Program::<ElementsExtension>::from_str(program, witness)
            .map_err(RunnerError::ProgramParse)?;

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;
        let mut mac = bounded_machine(redeem_node)?;

        let elements_env =
            elements_execution_environment(pset, input_idx, program.cmr(), network.genesis_hash())?;

        let env = UnchainedEnv::new(redeem_script, elements_env);

        mac.exec(redeem_node, &env)
            .map_err(RunnerError::ExecutionError)?;

        Ok(program.commit_prog().cmr())
    }

    // NOTE: We will need unused parameters later when we will add more jets.
    pub fn execute_bitcoin(
        program: &str,
        witness: Option<&str>,
        _input_idx: usize,
        _psbt: &psbt::Psbt,
        redeem_script: Script,
        _network: BitcoinNetwork,
    ) -> Result<Cmr, RunnerError> {
        let program = Program::<CoreExtension>::from_str(program, witness)
            .map_err(RunnerError::ProgramParse)?;

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;
        let mut mac = bounded_machine(redeem_node)?;

        let env = UnchainedEnv::new(redeem_script, CoreEnv::new());

        mac.exec(redeem_node, &env)
            .map_err(RunnerError::ExecutionError)?;

        Ok(program.commit_prog().cmr())
    }
}

fn check_execution_cost(cost: Cost) -> Result<(), RunnerError> {
    if cost > MAX_EXECUTION_COST {
        return Err(RunnerError::ExecutionCostExceeded {
            cost,
            max: MAX_EXECUTION_COST,
        });
    }
    Ok(())
}

fn bounded_machine(program: &RedeemNode) -> Result<BitMachine, RunnerError> {
    check_execution_cost(program.bounds().cost)?;
    BitMachine::for_program(program).map_err(RunnerError::BitMachineConstruction)
}

pub fn elements_execution_environment(
    pset: &pset::PartiallySignedTransaction,
    input_idx: usize,
    cmr: Cmr,
    genesis_hash: BlockHash,
) -> Result<ElementsEnv<Arc<Transaction>>, RunnerError> {
    let tx = pset.extract_tx().map_err(RunnerError::PsetExtract)?;

    let input_utxos = pset
        .inputs()
        .iter()
        .enumerate()
        .map(|(n, input)| match input.witness_utxo {
            Some(ref utxo) => Ok(ElementsUtxo {
                script_pubkey: utxo.script_pubkey.clone(),
                asset: utxo.asset,
                value: utxo.value,
            }),
            None => Err(RunnerError::MissingWitnessUtxo(n)),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let tx_env = ElementsEnv::new(
        Arc::new(tx),
        input_utxos,
        input_idx as u32, // cast fine, input indices are always small
        cmr,
        dummy_control_block(),
        None, // FIXME populate this; needs https://github.com/BlockstreamResearch/rust-simplicity/issues/315 first
        genesis_hash,
    );

    Ok(tx_env)
}

// We need to make control block optional later, for now just return a dummy one
fn dummy_control_block() -> ControlBlock {
    let leaf_version = LeafVersion::from_u8(0xc0).expect("should return valid leaf version");

    // Random valid public key
    let data = hex!("4fd02a8753d2024a969b504b6b64c4d6824d87a001120e0cceea31771533ca70");

    let internal_key =
        UntweakedPublicKey::from_slice(&data).expect("should return valid public key");

    ControlBlock {
        leaf_version,
        internal_key,
        output_key_parity: simplicity::elements::secp256k1_zkp::Parity::Even,
        merkle_branch: TaprootMerkleBranch::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simplicity::{
        ConstructNode,
        base64::prelude::{BASE64_STANDARD, Engine as _},
        node::CoreConstructible,
        types,
    };

    fn shared_program(levels: usize) -> String {
        let bytes = types::Context::with_context(|ctx| {
            let mut node = Arc::<ConstructNode>::unit(&ctx);
            for _ in 0..levels {
                node = Arc::<ConstructNode>::comp(&node, &node).unwrap();
            }
            node.finalize_types().unwrap().to_vec_without_witness()
        });
        assert!(bytes.len() < 256);
        BASE64_STANDARD.encode(bytes)
    }

    #[test]
    fn execution_cost_boundary() {
        assert!(check_execution_cost(MAX_EXECUTION_COST).is_ok());
        assert!(matches!(
            check_execution_cost(MAX_EXECUTION_COST + Cost::from_milliweight(1)),
            Err(RunnerError::ExecutionCostExceeded { .. })
        ));
        assert!(check_execution_cost(Cost::from_milliweight(u32::MAX)).is_err());
    }

    #[test]
    fn both_runners_reject_expensive_shared_dags() {
        let tx = simplicity::bitcoin::Transaction {
            version: simplicity::bitcoin::transaction::Version::TWO,
            lock_time: simplicity::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = psbt::Psbt::from_unsigned_tx(tx).unwrap();
        let pset = pset::PartiallySignedTransaction::new_v2();
        for levels in [20, 60] {
            let encoded = shared_program(levels);
            let program = Program::<CoreExtension>::from_str(&encoded, Some("")).unwrap();
            let redeem = program.redeem_node().unwrap();
            // Memory checks alone accept these tiny, exponentially costly DAGs.
            assert!(BitMachine::for_program(redeem).is_ok());
            assert!(redeem.bounds().cost > MAX_EXECUTION_COST);
            if levels == 20 {
                assert!(redeem.bounds().cost.is_consensus_valid());
            }
            assert!(matches!(
                SimplicityRunner::execute_bitcoin(
                    &encoded,
                    Some(""),
                    0,
                    &psbt,
                    Script::new(),
                    BitcoinNetwork::Testnet,
                ),
                Err(RunnerError::ExecutionCostExceeded { .. })
            ));
            assert!(matches!(
                SimplicityRunner::execute_elements(
                    &encoded,
                    Some(""),
                    0,
                    &pset,
                    Script::new(),
                    ElementsNetwork::LiquidTestnet,
                ),
                Err(RunnerError::ExecutionCostExceeded { .. })
            ));
        }
    }

    #[test]
    fn inexpensive_program_still_executes() {
        let encoded = shared_program(3);
        let program = Program::<CoreExtension>::from_str(&encoded, Some("")).unwrap();
        let redeem = program.redeem_node().unwrap();
        let mut machine = bounded_machine(redeem).unwrap();
        machine
            .exec(redeem, &UnchainedEnv::new(Script::new(), CoreEnv::new()))
            .unwrap();
    }
}
