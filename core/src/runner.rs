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
use crate::jets::environments::{BitcoinTxEnv, UnchainedEnv};
use crate::program::Program;
use crate::utils::signing_commitment;
use crate::{BitcoinNetwork, ElementsNetwork};

pub struct SimplicityRunner;

/// Maximum execution cost accepted by the off-chain runner, in milliweight.
pub const MAX_EXECUTION_COST: Cost = Cost::from_milliweight(10_000_000);

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("input index {index} out-of-range for transaction with {total} inputs")]
    InputIndexOutOfRange { index: usize, total: usize },

    #[error("PSBT input count {psbt_inputs} does not match transaction input count {tx_inputs}")]
    PsbtInputCountMismatch {
        psbt_inputs: usize,
        tx_inputs: usize,
    },

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

    pub fn execute_bitcoin(
        program: &str,
        witness: Option<&str>,
        input_idx: usize,
        psbt: &psbt::Psbt,
        redeem_script: Script,
        network: BitcoinNetwork,
    ) -> Result<Cmr, RunnerError> {
        let program = Program::<CoreExtension>::from_str(program, witness)
            .map_err(RunnerError::ProgramParse)?;

        let redeem_node = program.redeem_node().ok_or(RunnerError::NoRedeemNode)?;
        let mut mac = bounded_machine(redeem_node)?;

        let bitcoin_env =
            bitcoin_execution_environment(psbt, input_idx, program.cmr(), &redeem_script, network)?;
        let env = UnchainedEnv::new(redeem_script, bitcoin_env);

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

/// Builds the Bitcoin context and `tx_approval_hash` digest for a selected input.
///
/// The digest commits to the network, input index, program/script commitment,
/// unsigned transaction and all `witness_utxo` values and scripts. It is not a
/// BIP-341 sighash; approvers must independently verify the PSBT's prevouts.
pub fn bitcoin_execution_environment(
    psbt: &psbt::Psbt,
    input_idx: usize,
    cmr: Cmr,
    redeem_script: &Script,
    network: BitcoinNetwork,
) -> Result<BitcoinTxEnv, RunnerError> {
    use simplicity::bitcoin::{
        consensus::serialize,
        hashes::{Hash, HashEngine, sha256},
    };

    let tx_inputs = psbt.unsigned_tx.input.len();
    if psbt.inputs.len() != tx_inputs {
        return Err(RunnerError::PsbtInputCountMismatch {
            psbt_inputs: psbt.inputs.len(),
            tx_inputs,
        });
    }
    let input_index = u32::try_from(input_idx)
        .ok()
        .filter(|_| input_idx < tx_inputs)
        .ok_or(RunnerError::InputIndexOutOfRange {
            index: input_idx,
            total: tx_inputs,
        })?;
    let prevouts = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(RunnerError::MissingWitnessUtxo(index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let network_id = match network {
        BitcoinNetwork::Mainnet => 0,
        BitcoinNetwork::Testnet => 1,
        BitcoinNetwork::Testnet4 => 2,
    };
    let tag = sha256::Hash::hash(b"SimplicityUnchained/BitcoinApproval/v1");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(&[network_id]);
    engine.input(&input_index.to_be_bytes());
    engine.input(&signing_commitment(cmr, redeem_script.as_bytes()));
    engine.input(sha256::Hash::hash(&serialize(&psbt.unsigned_tx)).as_byte_array());
    engine.input(sha256::Hash::hash(&serialize(&prevouts)).as_byte_array());

    Ok(BitcoinTxEnv {
        tx: psbt.unsigned_tx.clone(),
        input_index,
        approval_hash: sha256::Hash::from_engine(engine).to_byte_array(),
        core_env: CoreEnv::new(),
    })
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
        let env = bitcoin_execution_environment(
            &approval_psbt(),
            0,
            program.cmr(),
            &Script::new(),
            BitcoinNetwork::Testnet,
        )
        .unwrap();
        machine
            .exec(redeem, &UnchainedEnv::new(Script::new(), env))
            .unwrap();
    }

    fn approval_psbt() -> psbt::Psbt {
        use simplicity::bitcoin::{self, Amount, TxIn, TxOut};
        let mut inputs = vec![TxIn::default(), TxIn::default()];
        inputs[0].previous_output.vout = 0;
        inputs[1].previous_output.vout = 1;
        let mut psbt = psbt::Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        })
        .unwrap();
        for input in &mut psbt.inputs {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            });
        }
        psbt
    }

    #[test]
    fn approval_hash_binds_transaction_prevouts_input_network_and_policy() {
        use simplicity::bitcoin::{self, Amount, Sequence};
        let psbt = approval_psbt();
        let cmr = Cmr::from_byte_array([1; 32]);
        let script = Script::from(vec![0x52]);
        let hash = |psbt: &psbt::Psbt| {
            bitcoin_execution_environment(psbt, 0, cmr, &script, BitcoinNetwork::Testnet)
                .unwrap()
                .approval_hash
        };
        let original = hash(&psbt);
        assert_eq!(
            hex::encode(original),
            "1b05942d9d96d9625b39f626593058f550e999463bd361f77512af00a7a20a8d",
        );
        let mut variants = Vec::new();
        let mut changed = psbt.clone();
        changed.unsigned_tx.output[0].value = Amount::from_sat(49_999);
        variants.push(changed);
        let mut changed = psbt.clone();
        changed.unsigned_tx.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x52]);
        variants.push(changed);
        let mut changed = psbt.clone();
        changed.unsigned_tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        variants.push(changed);
        let mut changed = psbt.clone();
        changed.unsigned_tx.version = bitcoin::transaction::Version::ONE;
        variants.push(changed);
        let mut changed = psbt.clone();
        changed.unsigned_tx.input[0].sequence = Sequence::from_consensus(1);
        variants.push(changed);
        let mut changed = psbt.clone();
        changed.unsigned_tx.input[0].previous_output.vout = 2;
        variants.push(changed);
        for index in 0..2 {
            let mut changed = psbt.clone();
            changed.inputs[index].witness_utxo.as_mut().unwrap().value = Amount::from_sat(99_999);
            variants.push(changed);
            let mut changed = psbt.clone();
            changed.inputs[index]
                .witness_utxo
                .as_mut()
                .unwrap()
                .script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x52]);
            variants.push(changed);
        }
        for (index, changed) in variants.iter().enumerate() {
            assert_ne!(original, hash(changed), "mutation {index}");
        }
        for (index, cmr, script, network) in [
            (1, cmr, script.clone(), BitcoinNetwork::Testnet),
            (0, cmr, script.clone(), BitcoinNetwork::Mainnet),
            (0, cmr, script.clone(), BitcoinNetwork::Testnet4),
            (
                0,
                Cmr::from_byte_array([2; 32]),
                script.clone(),
                BitcoinNetwork::Testnet,
            ),
            (0, cmr, Script::new(), BitcoinNetwork::Testnet),
        ] {
            assert_ne!(
                original,
                bitcoin_execution_environment(&psbt, index, cmr, &script, network)
                    .unwrap()
                    .approval_hash
            );
        }
        assert_eq!(
            original,
            bitcoin_execution_environment(&psbt, 0, cmr, &script, BitcoinNetwork::Testnet)
                .unwrap()
                .approval_hash,
        );
    }

    #[test]
    fn bitcoin_context_rejects_missing_or_inconsistent_inputs() {
        let mut psbt = approval_psbt();
        let context = |psbt: &psbt::Psbt, index| {
            bitcoin_execution_environment(
                psbt,
                index,
                Cmr::from_byte_array([1; 32]),
                &Script::new(),
                BitcoinNetwork::Testnet,
            )
        };
        assert!(matches!(
            context(&psbt, 2),
            Err(RunnerError::InputIndexOutOfRange { .. })
        ));
        psbt.inputs[1].witness_utxo = None;
        assert!(matches!(
            context(&psbt, 0),
            Err(RunnerError::MissingWitnessUtxo(1))
        ));
        psbt.inputs.pop();
        assert!(matches!(
            context(&psbt, 0),
            Err(RunnerError::PsbtInputCountMismatch { .. })
        ));
    }

    #[test]
    fn approval_jet_returns_the_context_digest_and_plugins_receive_the_transaction() {
        use crate::plugin::PluginBase;
        use simplicity::{Word, jet::Core};
        let psbt = approval_psbt();
        let env = UnchainedEnv::new(
            Script::new(),
            bitcoin_execution_environment(
                &psbt,
                1,
                Cmr::from_byte_array([1; 32]),
                &Script::new(),
                BitcoinNetwork::Testnet,
            )
            .unwrap(),
        );
        let redeem = types::Context::with_context(|ctx| {
            let actual = Arc::<ConstructNode>::jet(&ctx, &CoreExtension::TxApprovalHash);
            let expected =
                Arc::<ConstructNode>::const_word(&ctx, Word::u256(env.env.approval_hash));
            let pair = Arc::<ConstructNode>::pair(&actual, &expected).unwrap();
            let eq = Arc::<ConstructNode>::jet(&ctx, &CoreExtension::Core(Core::Eq256));
            let equal = Arc::<ConstructNode>::comp(&pair, &eq).unwrap();
            let verify = Arc::<ConstructNode>::jet(&ctx, &CoreExtension::Core(Core::Verify));
            Arc::<ConstructNode>::comp(&equal, &verify)
                .unwrap()
                .finalize_unpruned()
                .unwrap()
        });
        bounded_machine(&redeem)
            .unwrap()
            .exec(&redeem, &env)
            .unwrap();
        assert_eq!(CoreExtension::input_index(&env), 1);
        assert_eq!(
            CoreExtension::tx(&env),
            simplicity::bitcoin::consensus::serialize(&psbt.unsigned_tx)
        );
    }
}
