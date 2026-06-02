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
use crate::jets::custom_jet::{CustomJet, JetApiProvider};
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

    // NOTE: We will need unused parameters later when we will add more jets.
    pub fn execute_custom<P, Network, Env: 'static, JetApi: JetApiProvider>(
        program: Program<CustomJet<Env, JetApi>>,
        _input_idx: usize,
        _pst: &P,
        redeem_script: Script,
        env: Env,
        _network: Network,
    ) -> Result<Cmr, RunnerError> {
        let unchained_env = UnchainedEnv::<Env>::new(redeem_script, env);

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;

        let mut mac =
            BitMachine::for_program(redeem_node).map_err(RunnerError::BitMachineConstruction)?;

        mac.exec(redeem_node, &unchained_env)
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};

    use crate::jets::custom_jet::{CustomJet, JetApiProvider};
    use crate::jets::jet_dyn::CustomJetApi;
    use crate::runner::{SimplicityRunner, elements_execution_environment};

    use dlopen2::wrapper::Container;
    use hal_simplicity::hal_simplicity::Program;
    use hal_simplicity::simplicity::elements::hex::FromHex;
    use hal_simplicity::simplicity::elements::{Script, Transaction};
    use hal_simplicity::simplicity::jet::elements::ElementsEnv;
    use hex_literal::hex;

    use hal_simplicity::simplicity::elements::encode::deserialize;
    use hal_simplicity::simplicity::elements::pset::PartiallySignedTransaction;

    static TEST_DLL: LazyLock<Option<Container<CustomJetApi>>> = LazyLock::new(|| unsafe {
        let path = format!(
            "{}/../target/debug/libopcode_pubkey_elements.{}",
            env!("CARGO_MANIFEST_DIR"),
            std::env::consts::DLL_EXTENSION
        );
        Container::<CustomJetApi>::load(&path).ok()
    });

    struct TestApi;
    impl JetApiProvider for TestApi {
        fn get() -> &'static Option<Container<CustomJetApi>> {
            &TEST_DLL
        }
    }

    #[test]
    fn it_works() {
        let script = Script::from_hex(
            "5221033523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf21025eb4655feae15a304653e27441ca8e8ced2bef89c22ab6b20424b4c07b3d14cc52ae"
        ).unwrap();

        // cli/assets/check_opcode.simf
        let program_str = "4AmwAAR/oHAIsFIGQVZtoIwCBNiDgUA=";

        let pset_bytes = hex!(
            "70736574ff0102040200000001030400000000010401010105010201fb04020000000001014e01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000186a000220020649be4e4f326f85b2187adb0698d9cab59c4b1c747cc6d884211e90e60484cf001070001080100010e201b42ba45a12d33a9efd32b738e603f5c606dcd59353fc5826f7486d4d5459858010f0400000000011004ffffffff00010308b88201000000000007fc04707365740220499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140104220020649be4e4f326f85b2187adb0698d9cab59c4b1c747cc6d884211e90e60484cf000010308e80300000000000007fc04707365740220499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c1401040000"
        );

        let input_index = 0;

        let pset: PartiallySignedTransaction = deserialize(&pset_bytes).expect("valid PSET");

        let program = Program::<CustomJet<ElementsEnv<Arc<Transaction>>, TestApi>>::from_str(
            program_str,
            Some(""),
        )
        .expect("Simplicity execution failed");

        let elements_env = elements_execution_environment(
            &pset,
            input_index,
            program.cmr(),
            crate::ElementsNetwork::LiquidTestnet.genesis_hash(),
        )
        .expect("Failed to initialize env");

        _ = SimplicityRunner::execute_custom(
            program,
            input_index,
            &pset,
            script,
            elements_env,
            crate::ElementsNetwork::LiquidTestnet,
        )
        .expect("should run");
    }
}
