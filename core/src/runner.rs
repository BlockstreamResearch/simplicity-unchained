use std::sync::Arc;

use hal_simplicity::hal_simplicity::Program;
use hal_simplicity::simplicity::BitMachine;
use hal_simplicity::simplicity::bit_machine::ExecutionError;
use hal_simplicity::simplicity::bitcoin::psbt;
use hal_simplicity::simplicity::elements::taproot::{LeafVersion, TaprootMerkleBranch};
use hal_simplicity::simplicity::elements::{BlockHash, Script};
use hal_simplicity::simplicity::elements::{Transaction, pset, schnorr::UntweakedPublicKey};
use hal_simplicity::simplicity::{
    Cmr,
    elements::taproot::ControlBlock,
    jet::elements::{ElementsEnv, ElementsUtxo},
};

use hex_literal::hex;

use crate::jets::bitcoin::CoreExtension;
use crate::jets::elements::ElementsExtension;
use crate::jets::environments::UnchainedEnv;
use crate::{BitcoinNetwork, ElementsNetwork};

pub struct SimplicityRunner;

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("input index {index} out-of-range for PSET with {total} inputs")]
    InputIndexOutOfRange { index: usize, total: usize },

    #[error("failed to parse genesis hash: {0}")]
    GenesisHashParse(hal_simplicity::simplicity::elements::hashes::hex::HexToArrayError),

    #[error("could not find Simplicity leaf in PSET taptree with CMR {cmr})")]
    MissingSimplicityLeaf { cmr: String },

    #[error("failed to extract transaction from PSET: {0}")]
    PsetExtract(hal_simplicity::simplicity::elements::pset::Error),

    #[error("witness_utxo field not populated for input {0}")]
    MissingWitnessUtxo(usize),

    #[error("invalid program: {0}")]
    ProgramParse(hal_simplicity::simplicity::ParseError),

    #[error("program does not have a redeem node")]
    NoRedeemNode,

    #[error("failed to construct bit machine: {0}")]
    BitMachineConstruction(hal_simplicity::simplicity::bit_machine::LimitError),

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

        let elements_env =
            elements_execution_environment(pset, input_idx, program.cmr(), network.genesis_hash())?;

        let env = UnchainedEnv::new(redeem_script, elements_env);

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;

        let mut mac =
            BitMachine::for_program(redeem_node).map_err(RunnerError::BitMachineConstruction)?;

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

        let env = UnchainedEnv::new(redeem_script, ());

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;

        let mut mac =
            BitMachine::for_program(redeem_node).map_err(RunnerError::BitMachineConstruction)?;

        mac.exec(redeem_node, &env)
            .map_err(RunnerError::ExecutionError)?;

        Ok(program.commit_prog().cmr())
    }
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
        output_key_parity: hal_simplicity::simplicity::elements::secp256k1_zkp::Parity::Even,
        merkle_branch: TaprootMerkleBranch::default(),
    }
}
