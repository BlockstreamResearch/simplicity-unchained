use super::*;
use simplicity::bitcoin::hashes::Hash;
use simplicity::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use simplicity::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, absolute, transaction,
};
use simplicity::node::{CoreConstructible, WitnessConstructible};
use simplicity::{ConstructNode, Word, jet::Core, types};

pub(crate) struct Fixture {
    pub psbt: Psbt,
    pub script: Vec<u8>,
    pub network: bitcoin::Network,
    pub base: XOnlyPublicKey,
    pub user: XOnlyPublicKey,
    pub recovery: TapNodeHash,
}

impl Fixture {
    pub fn new(program: &[u8], inputs: usize, outputs: usize, max_scripts: bool) -> Self {
        Self::new_on_network(
            program,
            inputs,
            outputs,
            max_scripts,
            bitcoin::Network::Testnet,
        )
    }

    pub fn new_on_network(
        program: &[u8],
        inputs: usize,
        outputs: usize,
        max_scripts: bool,
        network: bitcoin::Network,
    ) -> Self {
        let secp = Secp256k1::new();
        let key = |byte| {
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
                .x_only_public_key()
                .0
        };
        let base = key(1);
        let user = key(2);
        let recovery = TapNodeHash::from_byte_array([3; 32]);
        // Include a compressed pubkey for both legacy script-reader adapters.
        let mut script = vec![0x21, 0x02];
        script.extend_from_slice(&user.serialize());
        let cmr = policy_cmr(program).unwrap();
        let service = simplicity_unchained_policy::tweak_public_key(
            base,
            cmr.to_byte_array(),
            &script,
            network,
        )
        .unwrap();
        let full = |key| {
            bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                key,
                bitcoin::secp256k1::Parity::Even,
            ))
        };
        let (address, _) =
            crate::utils::generate_p2tr_address_btc(&full(service), &full(user), recovery, network)
                .unwrap();
        let parent = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: address.script_pubkey(),
                };
                inputs
            ],
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(500),
            input: (0..inputs)
                .map(|vout| TxIn {
                    previous_output: OutPoint {
                        txid: parent.compute_txid(),
                        vout: vout as u32,
                    },
                    sequence: Sequence::from_consensus(10),
                    ..TxIn::default()
                })
                .collect(),
            output: vec![
                TxOut {
                    value: Amount::from_sat(90_000 * inputs as u64 / outputs as u64),
                    script_pubkey: if max_scripts {
                        ScriptBuf::from_bytes(vec![0x51; 10_000])
                    } else {
                        address.script_pubkey()
                    },
                };
                outputs
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            input.non_witness_utxo = Some(parent.clone());
            input.witness_utxo = Some(parent.output[index].clone());
        }
        Self {
            psbt,
            script,
            network,
            base,
            user,
            recovery,
        }
    }

    pub fn prepare(&self, program: &[u8], index: usize) -> Result<PreparedPolicy, PolicyError> {
        prepare_policy(
            program,
            &self.psbt,
            index,
            &self.script,
            self.network,
            self.base,
            self.user,
            self.recovery,
        )
    }
}

pub(crate) fn unit_program() -> Vec<u8> {
    types::Context::with_context(|ctx| {
        Arc::<ConstructNode>::unit(&ctx)
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    })
}

fn approval_program(approver: XOnlyPublicKey) -> Vec<u8> {
    types::Context::with_context(|ctx| {
        let pk = Arc::<ConstructNode>::const_word(&ctx, Word::u256(approver.serialize()));
        let message = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Builtin(Builtin::PolicyTransactionApprovalHash),
        );
        let pk_message = Arc::<ConstructNode>::pair(&pk, &message).unwrap();
        let signature = Arc::<ConstructNode>::witness(&ctx, None);
        let arguments = Arc::<ConstructNode>::pair(&pk_message, &signature).unwrap();
        let verify = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Legacy(crate::jets::bitcoin::CoreExtension::Core(
                Core::Bip0340Verify,
            )),
        );
        Arc::<ConstructNode>::comp(&arguments, &verify)
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    })
}

#[test]
fn prepare_approval_without_witness_then_execute_exact_approved_context() {
    let secp = Secp256k1::new();
    let approver = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
    let program = approval_program(approver.x_only_public_key().0);
    let fixture = Fixture::new(&program, 2, 2, false);
    let prepared = fixture.prepare(&program, 0).unwrap();
    assert_eq!(policy_cmr(&program).unwrap(), prepared.cmr());
    assert_eq!(prepared.context().cmr(), prepared.cmr().to_byte_array());
    assert!(matches!(
        prepared.evaluate_default(&[]),
        Err(PolicyError::Decode(_))
    ));
    let digest = prepared.context().policy_transaction_approval_hash();
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &approver);
    let result = prepared.evaluate_default(signature.as_ref()).unwrap();
    assert_eq!(result.cmr, prepared.cmr());
    assert!(result.cost_milliweight > 10_000);
    assert_eq!(
        result.context.policy_transaction_approval_hash,
        prepared.summary().policy_transaction_approval_hash
    );
    let mut invalid = signature.as_ref().to_vec();
    invalid[0] ^= 1;
    assert!(matches!(
        prepared.evaluate_default(&invalid),
        Err(PolicyError::PolicyRejected(_))
    ));
    let mut extra = signature.as_ref().to_vec();
    extra.push(0);
    assert!(matches!(
        prepared.evaluate_default(&extra),
        Err(PolicyError::Decode(_))
    ));
    let second = fixture.prepare(&program, 1).unwrap();
    assert_eq!(digest, second.context().policy_transaction_approval_hash());
    assert_ne!(
        prepared.context().policy_approval_hash(),
        second.context().policy_approval_hash()
    );
    second.evaluate_default(signature.as_ref()).unwrap();
    let mut changed = fixture;
    changed.psbt.unsigned_tx.output[0].value = Amount::from_sat(89_999);
    let changed = changed.prepare(&program, 0).unwrap();
    assert!(matches!(
        changed.evaluate_default(signature.as_ref()),
        Err(PolicyError::PolicyRejected(_))
    ));
}

#[test]
fn prepared_context_is_immutable_and_preserves_legacy_approval_semantics() {
    let program = unit_program();
    for (network, legacy_network) in [
        (bitcoin::Network::Bitcoin, crate::BitcoinNetwork::Mainnet),
        (bitcoin::Network::Testnet, crate::BitcoinNetwork::Testnet),
        (bitcoin::Network::Testnet4, crate::BitcoinNetwork::Testnet4),
    ] {
        let fixture = Fixture::new_on_network(&program, 2, 2, false, network);
        for index in 0..2 {
            let prepared = fixture.prepare(&program, index).unwrap();
            let expected = crate::runner::bitcoin_execution_environment(
                &fixture.psbt,
                index,
                prepared.cmr(),
                &simplicity::elements::Script::from(fixture.script.clone()),
                legacy_network,
            )
            .unwrap();
            assert_eq!(
                prepared.context().legacy_approval_hash(),
                expected.approval_hash
            );
            assert_ne!(
                prepared.context().signing_commitment(),
                crate::utils::signing_commitment(prepared.cmr(), &fixture.script),
            );
        }
    }
    let mut fixture = Fixture::new(&program, 2, 2, false);
    let prepared = fixture.prepare(&program, 1).unwrap();
    let digest = prepared.context().cooperative_sighash_default();
    fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(1);
    fixture.psbt.inputs[0].witness_utxo = None;
    prepared.evaluate_default(&[]).unwrap();
    assert_eq!(digest, prepared.context().cooperative_sighash_default());
}

#[test]
fn cost_boundary_and_preallocation_rejection_are_exact() {
    assert_eq!(
        MAX_EXECUTION_COST,
        Cost::from_milliweight(simplicity_unchained_policy::MAX_EXECUTION_COST_MILLIWEIGHT),
    );
    let program = unit_program();
    let fixture = Fixture::new(&program, 1, 1, false);
    let prepared = fixture.prepare(&program, 0).unwrap();
    let result = prepared.evaluate_default(&[]).unwrap();
    prepared
        .evaluate(&[], result.bounded_cost)
        .expect("exact limit is inclusive");
    assert!(matches!(
        prepared.evaluate_milliweight(&[], result.cost_milliweight - 1),
        Err(PolicyError::ExecutionCostExceeded { .. })
    ));
    for levels in [20, 60] {
        let expensive = types::Context::with_context(|ctx| {
            let mut node = Arc::<ConstructNode>::unit(&ctx);
            for _ in 0..levels {
                node = Arc::<ConstructNode>::comp(&node, &node).unwrap();
            }
            node.finalize_types().unwrap().to_vec_without_witness()
        });
        assert!(expensive.len() < 256);
        let fixture = Fixture::new(&expensive, 1, 1, false);
        let prepared = fixture.prepare(&expensive, 0).unwrap();
        let redeem = RedeemNode::decode::<_, _, PolicyJet>(
            BitIter::from(expensive.as_slice()),
            BitIter::from(&[][..]),
        )
        .unwrap();
        assert!(BitMachine::for_program(&redeem).is_ok());
        assert!(redeem.bounds().cost > MAX_EXECUTION_COST);
        assert!(matches!(
            prepared.evaluate(&[], Cost::from_milliweight(u32::MAX)),
            Err(PolicyError::ExecutionCostExceeded {
                max: MAX_EXECUTION_COST,
                ..
            })
        ));
    }
}

#[test]
fn malformed_program_and_invalid_context_remain_distinct() {
    assert!(matches!(policy_cmr(&[]), Err(PolicyError::Decode(_))));
    let program = unit_program();
    let mut fixture = Fixture::new(&program, 1, 1, false);
    fixture.psbt.inputs[0].non_witness_utxo = None;
    assert!(matches!(
        fixture.prepare(&program, 0),
        Err(PolicyError::Context(
            simplicity_unchained_policy::Error::MissingParent(0)
        ))
    ));
}

#[test]
fn new_profile_program_is_not_interpreted_as_legacy() {
    let program = types::Context::with_context(|ctx| {
        let current = Arc::<ConstructNode>::jet(&ctx, &PolicyJet::Builtin(Builtin::CurrentIndex));
        let expected = Arc::<ConstructNode>::const_word(&ctx, Word::u32(0));
        let pair = Arc::<ConstructNode>::pair(&current, &expected).unwrap();
        let equal = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Legacy(crate::jets::bitcoin::CoreExtension::Core(Core::Eq32)),
        );
        let check = Arc::<ConstructNode>::comp(&pair, &equal).unwrap();
        let verify = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Legacy(crate::jets::bitcoin::CoreExtension::Core(Core::Verify)),
        );
        Arc::<ConstructNode>::comp(&check, &verify)
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    let fixture = Fixture::new(&program, 2, 2, false);
    fixture
        .prepare(&program, 0)
        .unwrap()
        .evaluate_default(&[])
        .unwrap();
    assert!(matches!(
        fixture.prepare(&program, 1).unwrap().evaluate_default(&[]),
        Err(PolicyError::PolicyRejected(_))
    ));
    if let Ok(legacy) = CommitNode::decode::<_, crate::jets::bitcoin::CoreExtension>(BitIter::from(
        program.as_slice(),
    )) {
        assert_ne!(legacy.cmr(), policy_cmr(&program).unwrap());
    }
}
