use std::sync::Arc;

use hal_simplicity::hal_simplicity::Program;
use hal_simplicity::simplicity::bit_machine::ExecutionError;
use hal_simplicity::simplicity::elements::BlockHash;
use hal_simplicity::simplicity::elements::taproot::{LeafVersion, TaprootMerkleBranch};
use hal_simplicity::simplicity::elements::{
    Transaction, pset::PartiallySignedTransaction, schnorr::UntweakedPublicKey,
};
use hal_simplicity::simplicity::{BitMachine, jet};
use hal_simplicity::simplicity::{
    Cmr,
    elements::taproot::ControlBlock,
    jet::elements::{ElementsEnv, ElementsUtxo},
};

use hex_literal::hex;

use crate::Network;

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
    pub fn execute(
        program: &str,
        witness: &str,
        input_idx: usize,
        pset: &PartiallySignedTransaction,
        network: Network,
    ) -> Result<(), RunnerError> {
        let program = Program::<jet::Elements>::from_str(program, Some(witness))
            .map_err(RunnerError::ProgramParse)?;

        let env = execution_environment(&pset, input_idx, program.cmr(), network.genesis_hash())?;

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;

        let mut mac =
            BitMachine::for_program(redeem_node).map_err(RunnerError::BitMachineConstruction)?;

        mac.exec(redeem_node, &env)
            .map_err(RunnerError::ExecutionError)?;

        Ok(())
    }
}

fn execution_environment(
    pset: &PartiallySignedTransaction,
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
        output_key_parity: elements::secp256k1_zkp::Parity::Even,
        merkle_branch: TaprootMerkleBranch::default(),
    }
}

#[cfg(test)]
mod tests {
    use crate::runner::SimplicityRunner;

    use hex_literal::hex;

    use hal_simplicity::simplicity::elements::pset::PartiallySignedTransaction;
    use simplicity::elements::encode::deserialize;

    #[test]
    fn it_works() {
        let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA";

        let pset_bytes = hex!(
            "70736574ff0102040200000001030400000000010401010105010201fb04020000000001014e01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000186a000220020649be4e4f326f85b2187adb0698d9cab59c4b1c747cc6d884211e90e60484cf001070001080100010e201b42ba45a12d33a9efd32b738e603f5c606dcd59353fc5826f7486d4d5459858010f0400000000011004ffffffff00010308b88201000000000007fc04707365740220499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140104220020649be4e4f326f85b2187adb0698d9cab59c4b1c747cc6d884211e90e60484cf000010308e80300000000000007fc04707365740220499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c1401040000"
        );

        let pset: PartiallySignedTransaction = deserialize(&pset_bytes).expect("valid PSET");

        SimplicityRunner::execute(program, "", 0, &pset, crate::Network::LiquidTestnet)
            .expect("should run")
    }
}
