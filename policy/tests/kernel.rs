use std::collections::BTreeSet;

use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey, absolute,
    consensus::serialize,
    hashes::{Hash, sha256},
    psbt::{self, Psbt},
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TapNodeHash},
    transaction,
};
use simplicity_unchained_policy::{
    BitValue, Builtin, Context, ContextSummary, Error, MAX_MONEY, MAX_REQUEST_BYTES,
    MAX_SCRIPT_BYTES, PROFILE_NAME, bitcoin, cooperative_output, genesis_hash, manifest,
    network_name, profile_hash, signing_commitment, tweak_public_key,
};

struct Fixture {
    psbt: Psbt,
    cmr: [u8; 32],
    data: Vec<u8>,
    network: Network,
    base: XOnlyPublicKey,
    user: XOnlyPublicKey,
    recovery: TapNodeHash,
}

fn key(seed: u8) -> XOnlyPublicKey {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
    .x_only_public_key()
    .0
}

fn txin(outpoint: OutPoint, sequence: u32) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence(sequence),
        witness: Witness::new(),
    }
}

fn output(value: u64, script: ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script,
    }
}

impl Fixture {
    fn new() -> Self {
        let cmr = [0x11; 32];
        let data = b"policy-data".to_vec();
        let network = Network::Testnet4;
        let base = key(1);
        let user = key(2);
        let recovery = TapNodeHash::from_byte_array([0x33; 32]);
        let funding = cooperative_output(base, cmr, &data, network, user, recovery).unwrap();
        let parent = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin(
                OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x77; 32]),
                    vout: 1,
                },
                u32::MAX,
            )],
            output: vec![
                output(60_000, funding.script_pubkey.clone()),
                output(40_000, funding.script_pubkey.clone()),
            ],
        };
        let mut recipient = vec![0, 20];
        recipient.extend_from_slice(&[0x44; 20]);
        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(1000),
            input: vec![
                txin(
                    OutPoint {
                        txid: parent.compute_txid(),
                        vout: 0,
                    },
                    5,
                ),
                txin(
                    OutPoint {
                        txid: parent.compute_txid(),
                        vout: 1,
                    },
                    0x0040_0008,
                ),
            ],
            output: vec![
                output(20_000, ScriptBuf::from_bytes(recipient)),
                output(70_000, funding.script_pubkey),
                output(0, ScriptBuf::from_bytes(vec![0x6a, 1, 0xff])),
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(parent.output[index].clone());
            input.non_witness_utxo = Some(parent.clone());
        }
        Self {
            psbt,
            cmr,
            data,
            network,
            base,
            user,
            recovery,
        }
    }

    fn context(&self, index: usize) -> Result<Context, Error> {
        Context::new(
            &self.psbt,
            index,
            self.cmr,
            &self.data,
            self.network,
            self.base,
            self.user,
            self.recovery,
        )
    }

    fn parent(&self) -> Transaction {
        self.psbt.inputs[0].non_witness_utxo.clone().unwrap()
    }

    fn set_parent(&mut self, parent: Transaction) {
        let txid = parent.compute_txid();
        for (txin, input) in self
            .psbt
            .unsigned_tx
            .input
            .iter_mut()
            .zip(&mut self.psbt.inputs)
        {
            txin.previous_output.txid = txid;
            input.witness_utxo = parent
                .output
                .get(txin.previous_output.vout as usize)
                .cloned();
            input.non_witness_utxo = Some(parent.clone());
        }
    }

    fn rebind(&mut self) {
        let funded = cooperative_output(
            self.base,
            self.cmr,
            &self.data,
            self.network,
            self.user,
            self.recovery,
        )
        .unwrap();
        let mut parent = self.parent();
        for output in &mut parent.output {
            output.script_pubkey = funded.script_pubkey.clone();
        }
        self.psbt.unsigned_tx.output[1].script_pubkey = funded.script_pubkey;
        self.set_parent(parent);
    }
}

fn raw(bytes: &[u8]) -> BitValue {
    BitValue {
        bytes: bytes.to_vec(),
        bit_len: bytes.len() * 8,
    }
}

fn uint(value: u64, bits: usize) -> BitValue {
    assert!(matches!(bits, 8 | 16 | 32 | 64));
    raw(&value.to_be_bytes()[8 - bits / 8..])
}

fn join(a: &BitValue, b: &BitValue) -> BitValue {
    let bits = a.bit_len + b.bit_len;
    let mut bytes = vec![0; bits.div_ceil(8)];
    for (offset, value) in [(0, a), (a.bit_len, b)] {
        for i in 0..value.bit_len {
            if value.bit(i).unwrap() {
                bytes[(offset + i) / 8] |= 0x80 >> ((offset + i) % 8);
            }
        }
    }
    BitValue {
        bytes,
        bit_len: bits,
    }
}

fn some(value: BitValue) -> BitValue {
    join(
        &BitValue {
            bytes: vec![0x80],
            bit_len: 1,
        },
        &value,
    )
}

fn none(bits: usize) -> BitValue {
    BitValue {
        bytes: vec![0; (bits + 1).div_ceil(8)],
        bit_len: bits + 1,
    }
}

fn sha(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha(tag.as_bytes());
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(data);
    sha(&preimage)
}

fn eval(context: &Context, jet: Builtin, source: BitValue) -> BitValue {
    let result = context.evaluate(jet, &source).unwrap();
    result.validate(jet.target_bits()).unwrap();
    result
}

fn evaluate_unit(context: &Context, jet: Builtin) -> BitValue {
    eval(context, jet, BitValue::unit())
}

#[test]
fn all_55_reference_functions_have_exact_outputs() {
    use Builtin::*;
    let fixture = Fixture::new();
    let ctx = fixture.context(0).unwrap();
    let summary = ctx.summary();
    let hash_string = |s: &str| raw(&hex::decode(s).unwrap());
    let outpoint = join(
        &raw(&ctx.tx().input[0].previous_output.txid.to_byte_array()),
        &uint(0, 32),
    );
    let script_hash = sha(ctx.prevouts()[0].script_pubkey.as_bytes());
    let mut cases = vec![
        (PolicyProfileHash, BitValue::unit(), raw(&profile_hash())),
        (PolicyCmr, BitValue::unit(), raw(&fixture.cmr)),
        (
            SigningCommitmentHash,
            BitValue::unit(),
            hash_string(&summary.signing_commitment),
        ),
        (RedeemScriptHash, BitValue::unit(), raw(&sha(&fixture.data))),
        (
            NetworkGenesisHash,
            BitValue::unit(),
            raw(&genesis_hash(fixture.network).unwrap()),
        ),
        (CurrentIndex, BitValue::unit(), uint(0, 32)),
        (Version, BitValue::unit(), uint(2, 32)),
        (TxLockTime, BitValue::unit(), uint(1000, 32)),
        (NumInputs, BitValue::unit(), uint(2, 32)),
        (NumOutputs, BitValue::unit(), uint(3, 32)),
        (InputPrevOutpoint, uint(0, 32), some(outpoint.clone())),
        (InputValue, uint(0, 32), some(uint(60_000, 64))),
        (InputScriptHash, uint(0, 32), some(raw(&script_hash))),
        (InputScriptSize, uint(0, 32), some(uint(34, 32))),
        (
            InputScriptByte,
            join(&uint(0, 32), &uint(0, 32)),
            some(uint(0x51, 8)),
        ),
        (InputSequence, uint(0, 32), some(uint(5, 32))),
        (CurrentPrevOutpoint, BitValue::unit(), outpoint),
        (CurrentValue, BitValue::unit(), uint(60_000, 64)),
        (CurrentScriptHash, BitValue::unit(), raw(&script_hash)),
        (CurrentSequence, BitValue::unit(), uint(5, 32)),
        (OutputValue, uint(0, 32), some(uint(20_000, 64))),
        (
            OutputScriptHash,
            uint(0, 32),
            some(raw(&sha(ctx.tx().output[0].script_pubkey.as_bytes()))),
        ),
        (OutputScriptSize, uint(0, 32), some(uint(22, 32))),
        (
            OutputScriptByte,
            join(&uint(0, 32), &uint(1, 32)),
            some(uint(0x14, 8)),
        ),
        (OutputScriptClass, uint(0, 32), some(uint(3, 8))),
        (TotalInputValue, BitValue::unit(), uint(100_000, 64)),
        (TotalOutputValue, BitValue::unit(), uint(90_000, 64)),
        (TxFee, BitValue::unit(), uint(10_000, 64)),
        (InputValueForScript, raw(&script_hash), uint(100_000, 64)),
        (OutputValueForScript, raw(&script_hash), uint(70_000, 64)),
        (OutputCountForScript, raw(&script_hash), uint(1, 32)),
        (
            ValueReturnedToCurrentScript,
            BitValue::unit(),
            uint(70_000, 64),
        ),
        (CurrentScriptDebit, BitValue::unit(), uint(30_000, 64)),
        (
            IsRbfSignaled,
            BitValue::unit(),
            BitValue {
                bytes: vec![0x80],
                bit_len: 1,
            },
        ),
        (
            HasEffectiveLockTime,
            BitValue::unit(),
            BitValue {
                bytes: vec![0x80],
                bit_len: 1,
            },
        ),
        (InputLockBlocks, uint(0, 32), some(uint(5, 16))),
        (InputLockIntervals, uint(1, 32), some(uint(8, 16))),
        (CurrentLockBlocks, BitValue::unit(), some(uint(5, 16))),
        (CurrentLockIntervals, BitValue::unit(), none(16)),
        (CheckCsvBlocks, uint(5, 16), BitValue::unit()),
        (CheckCltvHeight, uint(1000, 32), BitValue::unit()),
        (
            UnsignedTxHash,
            BitValue::unit(),
            raw(&sha(&serialize(ctx.tx()))),
        ),
        (
            PrevoutsHash,
            BitValue::unit(),
            raw(&sha(&serialize(&ctx.prevouts().to_vec()))),
        ),
        (
            TxInputsHash,
            BitValue::unit(),
            raw(&sha(&serialize(&ctx.tx().input))),
        ),
        (
            TxOutputsHash,
            BitValue::unit(),
            raw(&sha(&serialize(&ctx.tx().output))),
        ),
        (
            CooperativeLeafHash,
            BitValue::unit(),
            raw(&ctx.cooperative_leaf_hash().to_byte_array()),
        ),
        (
            CooperativeSighashDefault,
            BitValue::unit(),
            raw(&ctx.sighash()),
        ),
        (
            CooperativeUserPubkey,
            BitValue::unit(),
            raw(&fixture.user.serialize()),
        ),
        (
            CooperativeServicePubkey,
            BitValue::unit(),
            raw(&ctx.service_pubkey().serialize()),
        ),
        (
            RecoveryLeafHash,
            BitValue::unit(),
            raw(&fixture.recovery.to_byte_array()),
        ),
        (
            PolicyApprovalHash,
            BitValue::unit(),
            raw(&ctx.policy_approval_hash()),
        ),
        (
            PolicyTransactionApprovalHash,
            BitValue::unit(),
            raw(&ctx.policy_transaction_approval_hash()),
        ),
        (
            TxVsizeLowerBound,
            BitValue::unit(),
            uint(serialize(ctx.tx()).len() as u64, 32),
        ),
    ];
    let mut covered = BTreeSet::new();
    for (jet, source, expected) in cases.drain(..) {
        assert_eq!(eval(&ctx, jet, source), expected, "{jet}");
        covered.insert(jet.id());
    }
    assert_eq!(
        eval(&fixture.context(1).unwrap(), CheckCsvIntervals, uint(8, 16)),
        BitValue::unit()
    );
    covered.insert(CheckCsvIntervals.id());
    let mut timed = Fixture::new();
    timed.psbt.unsigned_tx.lock_time = absolute::LockTime::from_consensus(500_000_100);
    assert_eq!(
        eval(
            &timed.context(0).unwrap(),
            CheckCltvTime,
            uint(500_000_000, 32)
        ),
        BitValue::unit()
    );
    covered.insert(CheckCltvTime.id());
    assert_eq!(covered, (0..55).collect());
}

#[test]
fn indexed_missing_entries_and_bytes_are_canonical_none() {
    use Builtin::*;
    let fixture = Fixture::new();
    let ctx = fixture.context(0).unwrap();
    for jet in [
        InputPrevOutpoint,
        InputValue,
        InputScriptHash,
        InputScriptSize,
        InputSequence,
        InputLockBlocks,
        InputLockIntervals,
    ] {
        for missing in [2, u32::MAX] {
            assert_eq!(
                eval(&ctx, jet, uint(missing.into(), 32)),
                none(jet.target_bits() - 1),
                "{jet}"
            );
        }
        assert!(eval(&ctx, jet, uint(1, 32)).bit(0).unwrap() || jet == InputLockBlocks);
    }
    for jet in [
        OutputValue,
        OutputScriptHash,
        OutputScriptSize,
        OutputScriptClass,
    ] {
        assert!(eval(&ctx, jet, uint(2, 32)).bit(0).unwrap());
        for missing in [3, u32::MAX] {
            assert_eq!(
                eval(&ctx, jet, uint(missing.into(), 32)),
                none(jet.target_bits() - 1),
                "{jet}"
            );
        }
    }
    for (jet, index, script) in [
        (
            InputScriptByte,
            1,
            ctx.prevouts()[1].script_pubkey.as_bytes(),
        ),
        (
            OutputScriptByte,
            0,
            ctx.tx().output[0].script_pubkey.as_bytes(),
        ),
    ] {
        let last = script.len() - 1;
        assert_eq!(
            eval(&ctx, jet, join(&uint(index, 32), &uint(last as u64, 32))),
            some(uint(u64::from(script[last]), 8)),
        );
        for (i, offset) in [
            (index, script.len() as u64),
            (index, u32::MAX.into()),
            (8, 0),
        ] {
            assert_eq!(
                eval(&ctx, jet, join(&uint(i, 32), &uint(offset, 32))),
                none(8)
            );
        }
    }
}

#[test]
fn exact_source_shape_sum_tag_bool_and_trailing_padding() {
    let fixture = Fixture::new();
    let ctx = fixture.context(0).unwrap();
    for jet in Builtin::ALL {
        let invalid = BitValue {
            bytes: vec![],
            bit_len: jet.source_bits() + 1,
        };
        assert_eq!(
            ctx.evaluate(jet, &invalid),
            Err(Error::SourceShape {
                expected: jet.source_bits()
            })
        );
        let invalid = BitValue {
            bytes: vec![0; jet.source_bits().div_ceil(8) + 1],
            bit_len: jet.source_bits(),
        };
        assert_eq!(
            ctx.evaluate(jet, &invalid),
            Err(Error::SourceShape {
                expected: jet.source_bits()
            })
        );
    }
    assert_eq!(
        some(uint(0xab, 8)),
        BitValue {
            bytes: vec![0xd5, 0x80],
            bit_len: 9
        }
    );
    assert_eq!(none(256).bytes, vec![0; 33]);
    assert_eq!(some(uint(1, 64)).bit_len, 65);
    assert_eq!(some(join(&raw(&[0; 32]), &uint(1, 32))).bit_len, 289);
    assert_eq!(
        evaluate_unit(&ctx, Builtin::IsRbfSignaled),
        BitValue {
            bytes: vec![0x80],
            bit_len: 1
        }
    );
    assert_eq!(
        BitValue::from_bytes(vec![0x81], 1),
        Err(Error::SourceShape { expected: 1 })
    );
    assert!(BitValue::from_bytes(vec![0x80], 1).is_ok());
    assert_eq!(
        BitValue::from_bytes(vec![0], 0),
        Err(Error::SourceShape { expected: 0 })
    );
    assert_eq!(BitValue::unit().bit(0), None);
}

#[test]
fn exact_script_patterns_and_empty_script_behavior() {
    let scripts: Vec<(Vec<u8>, u8)> = vec![
        (vec![], 0),
        (
            [vec![0x76, 0xa9, 0x14], vec![7; 20], vec![0x88, 0xac]].concat(),
            1,
        ),
        ([vec![0xa9, 0x14], vec![7; 20], vec![0x87]].concat(), 2),
        ([vec![0, 0x14], vec![7; 20]].concat(), 3),
        ([vec![0, 0x20], vec![7; 32]].concat(), 4),
        ([vec![0x51, 0x20], vec![7; 32]].concat(), 5),
        (vec![0x6a], 6),
        (vec![0x6a, 0xff, 0xff], 6),
        ([vec![0x52, 0x20], vec![7; 32]].concat(), 0),
        ([vec![0x51, 0x14], vec![7; 20]].concat(), 0),
        ([vec![0, 0x20], vec![7; 31]].concat(), 0),
        (vec![0x4c, 1, 0x6a], 0),
    ];
    for (script, class) in scripts {
        let mut fixture = Fixture::new();
        fixture.psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(script.clone());
        let ctx = fixture.context(0).unwrap();
        assert_eq!(
            eval(&ctx, Builtin::OutputScriptClass, uint(0, 32)),
            some(uint(class.into(), 8))
        );
        assert_eq!(
            eval(&ctx, Builtin::OutputScriptSize, uint(0, 32)),
            some(uint(script.len() as u64, 32))
        );
        if script.is_empty() {
            assert_eq!(
                eval(
                    &ctx,
                    Builtin::OutputScriptByte,
                    join(&uint(0, 32), &uint(0, 32))
                ),
                none(8)
            );
        }
    }
}

#[test]
fn accounting_scans_all_funding_inputs_and_ignores_change_labels() {
    let mut fixture = Fixture::new();
    fixture.psbt.outputs[0].unknown.insert(
        psbt::raw::Key {
            type_value: 0x70,
            key: vec![],
        },
        b"change".to_vec(),
    );
    let ctx = fixture.context(0).unwrap();
    assert_eq!(ctx.summary().debit, 30_000);
    assert_eq!(fixture.context(1).unwrap().summary().debit, 30_000);
    for jet in [Builtin::InputValueForScript, Builtin::OutputValueForScript] {
        assert_eq!(eval(&ctx, jet, raw(&[0; 32])), uint(0, 64));
    }
    assert_eq!(
        eval(&ctx, Builtin::OutputCountForScript, raw(&[0; 32])),
        uint(0, 32)
    );
    let script = ctx.prevouts()[0].script_pubkey.clone();
    fixture.psbt.unsigned_tx.output[0] = output(20_000, script);
    let ctx = fixture.context(0).unwrap();
    assert_eq!(
        evaluate_unit(&ctx, Builtin::ValueReturnedToCurrentScript),
        uint(90_000, 64)
    );
    assert_eq!(
        evaluate_unit(&ctx, Builtin::CurrentScriptDebit),
        uint(10_000, 64)
    );
    assert_eq!(
        eval(
            &ctx,
            Builtin::OutputCountForScript,
            raw(&sha(ctx.prevouts()[0].script_pubkey.as_bytes()))
        ),
        uint(2, 32)
    );
}

#[test]
fn proof_validation_rejects_missing_mismatch_conflict_and_duplicate() {
    let mut f = Fixture::new();
    f.psbt.inputs[0].non_witness_utxo = None;
    assert_eq!(f.context(0).unwrap_err(), Error::MissingParent(0));
    let mut f = Fixture::new();
    f.psbt.inputs[0].witness_utxo = None;
    assert_eq!(f.context(0).unwrap_err(), Error::MissingWitnessUtxo(0));
    let mut f = Fixture::new();
    f.psbt.inputs[0]
        .non_witness_utxo
        .as_mut()
        .unwrap()
        .lock_time = absolute::LockTime::from_consensus(1);
    assert_eq!(f.context(0).unwrap_err(), Error::ParentTxidMismatch(0));
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.input[0].previous_output.vout = u32::MAX;
    assert_eq!(f.context(0).unwrap_err(), Error::ParentVout(0));
    let mut f = Fixture::new();
    f.psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
    assert_eq!(f.context(0).unwrap_err(), Error::WitnessUtxoMismatch(0));
    let mut f = Fixture::new();
    f.psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = ScriptBuf::new();
    assert_eq!(f.context(0).unwrap_err(), Error::WitnessUtxoMismatch(0));
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.input[1].previous_output = f.psbt.unsigned_tx.input[0].previous_output;
    assert_eq!(f.context(0).unwrap_err(), Error::DuplicateOutpoint(1));
    let mut f = Fixture::new();
    let mut parent = f.parent();
    parent.output[1].script_pubkey = ScriptBuf::new();
    f.set_parent(parent);
    assert_eq!(f.context(0).unwrap_err(), Error::FundingScriptMismatch(1));
}

#[test]
fn reconstruction_binds_every_funding_input_and_all_public_parameters() {
    for change in 0..6 {
        let mut f = Fixture::new();
        match change {
            0 => f.cmr[0] ^= 1,
            1 => f.data.push(0),
            2 => f.network = Network::Testnet,
            3 => f.base = key(3),
            4 => f.user = key(3),
            5 => f.recovery = TapNodeHash::from_byte_array([0x34; 32]),
            _ => unreachable!(),
        }
        assert_eq!(f.context(0).unwrap_err(), Error::FundingScriptMismatch(0));
    }
    let f = Fixture::new();
    let ctx = f.context(0).unwrap();
    assert_eq!(
        tweak_public_key(f.base, f.cmr, &f.data, f.network).unwrap(),
        ctx.service_pubkey()
    );
    assert_eq!(ctx.cooperative_script().len(), 70);
    assert_eq!(ctx.control_block().serialize().len(), 65);
    assert!(ctx.control_block().verify_taproot_commitment(
        &Secp256k1::verification_only(),
        XOnlyPublicKey::from_slice(&ctx.script_pubkey().as_bytes()[2..]).unwrap(),
        ctx.cooperative_script(),
    ));
    assert_eq!(
        ctx.cooperative_leaf_hash(),
        TapLeafHash::from_script(ctx.cooperative_script(), LeafVersion::TapScript)
    );
    let actual = SighashCache::new(ctx.tx())
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(ctx.prevouts()),
            ctx.cooperative_leaf_hash(),
            TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    assert_eq!(ctx.sighash(), actual);
    let secp = Secp256k1::new();
    let base_pair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
    use bitcoin::key::TapTweak;
    let tweaked = base_pair.tap_tweak(
        &secp,
        Some(TapNodeHash::from_byte_array(ctx.signing_commitment())),
    );
    assert_eq!(
        tweaked.public_parts().0.to_x_only_public_key(),
        ctx.service_pubkey()
    );
    let sig =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(ctx.sighash()), &tweaked.to_keypair());
    secp.verify_schnorr(&sig, &Message::from_digest(actual), &ctx.service_pubkey())
        .unwrap();
}

#[test]
fn context_is_immutable_and_does_not_keep_parent_or_metadata_copies() {
    let mut f = Fixture::new();
    let ctx = f.context(0).unwrap();
    let before = ctx.summary();
    for input in &mut f.psbt.inputs {
        input.non_witness_utxo = None;
        input.witness_utxo = None;
    }
    f.psbt.unsigned_tx.output.clear();
    f.data.fill(0);
    assert_eq!(ctx.summary(), before);
    assert_eq!(before.provenance, "parent-txid-verified");
    assert!(!before.chain_status_verified);
    assert_eq!(
        serde_json::from_str::<ContextSummary>(&serde_json::to_string(&before).unwrap()).unwrap(),
        before
    );
}

#[test]
fn empty_script_data_and_exact_zero_return_are_not_missing_context() {
    let mut f = Fixture::new();
    f.data.clear();
    f.rebind();
    f.psbt.unsigned_tx.output[1].script_pubkey = ScriptBuf::new();
    let ctx = f.context(0).unwrap();
    assert_eq!(
        evaluate_unit(&ctx, Builtin::RedeemScriptHash),
        raw(&sha(&[]))
    );
    assert_eq!(
        evaluate_unit(&ctx, Builtin::ValueReturnedToCurrentScript),
        uint(0, 64)
    );
    assert_eq!(
        evaluate_unit(&ctx, Builtin::CurrentScriptDebit),
        uint(100_000, 64)
    );
    assert_ne!(
        ctx.signing_commitment(),
        tagged(
            "SimplicityUnchained/SigningCommitment/v1",
            &[f.cmr, sha(&[])].concat()
        )
    );
}

#[test]
fn repeated_parents_are_content_verified_and_psbt_hints_cannot_override_context() {
    let mut f = Fixture::new();
    let expected = f.context(0).unwrap().summary();
    // Witnesses do not enter txid, so this is a content-equivalent parent proof.
    f.psbt.inputs[1].non_witness_utxo.as_mut().unwrap().input[0]
        .witness
        .push([1, 2, 3]);
    f.psbt.inputs[0].tap_internal_key = Some(key(3));
    f.psbt.inputs[0].tap_merkle_root = Some(TapNodeHash::from_byte_array([0xff; 32]));
    let control = f.context(0).unwrap().control_block().clone();
    f.psbt.inputs[0]
        .tap_scripts
        .insert(control, (ScriptBuf::new(), LeafVersion::TapScript));
    assert_eq!(f.context(0).unwrap().summary(), expected);
}

#[test]
fn shape_version_map_unsigned_and_index_validation() {
    for version in [i32::MIN, -1, 0, 1, 3, i32::MAX] {
        let mut f = Fixture::new();
        f.psbt.unsigned_tx.version = transaction::Version(version);
        assert_eq!(f.context(0).unwrap_err(), Error::InvalidVersion);
    }
    for inputs in [true, false] {
        for count in [0, 9] {
            let mut f = Fixture::new();
            if inputs {
                f.psbt
                    .unsigned_tx
                    .input
                    .resize(count, f.psbt.unsigned_tx.input[0].clone());
            } else {
                f.psbt
                    .unsigned_tx
                    .output
                    .resize(count, f.psbt.unsigned_tx.output[0].clone());
            }
            assert_eq!(f.context(0).unwrap_err(), Error::InvalidShape);
        }
    }
    for inputs in [true, false] {
        let mut f = Fixture::new();
        if inputs {
            f.psbt.inputs.pop();
        } else {
            f.psbt.outputs.pop();
        }
        assert_eq!(f.context(0).unwrap_err(), Error::MapCountMismatch);
    }
    let f = Fixture::new();
    for index in [2, usize::MAX] {
        assert_eq!(f.context(index).unwrap_err(), Error::InputIndex(index));
    }
    for witness in [true, false] {
        let mut f = Fixture::new();
        if witness {
            f.psbt.unsigned_tx.input[0].witness.push([0x50]);
        } else {
            f.psbt.unsigned_tx.input[0].script_sig = ScriptBuf::from_bytes(vec![1]);
        }
        assert_eq!(f.context(0).unwrap_err(), Error::NonUnsignedInput(0));
    }
}

#[test]
fn zero_and_max_money_checked_totals_and_negative_fee() {
    let mut f = Fixture::new();
    let mut parent = f.parent();
    parent.output[0].value = Amount::ZERO;
    parent.output[1].value = Amount::ZERO;
    f.set_parent(parent);
    for output in &mut f.psbt.unsigned_tx.output {
        output.value = Amount::ZERO;
    }
    assert_eq!(f.context(0).unwrap().summary().fee, 0);
    assert_eq!(f.context(0).unwrap().summary().debit, 0);
    let mut parent = f.parent();
    parent.output[0].value = Amount::from_sat(MAX_MONEY);
    f.set_parent(parent);
    f.psbt.unsigned_tx.output[1].value = Amount::from_sat(MAX_MONEY);
    let ctx = f.context(0).unwrap();
    assert_eq!(ctx.summary().total_input_value, MAX_MONEY);
    assert_eq!(ctx.summary().total_output_value, MAX_MONEY);
    assert_eq!(ctx.summary().fee, 0);
    assert_eq!(ctx.summary().debit, 0);
    for invalid in [MAX_MONEY + 1, u64::MAX] {
        let mut f = Fixture::new();
        let mut parent = f.parent();
        parent.output[0].value = Amount::from_sat(invalid);
        f.set_parent(parent);
        assert_eq!(f.context(0).unwrap_err(), Error::MoneyRange);
        let mut f = Fixture::new();
        f.psbt.unsigned_tx.output[0].value = Amount::from_sat(invalid);
        assert_eq!(f.context(0).unwrap_err(), Error::MoneyRange);
    }
    let mut f = Fixture::new();
    let mut parent = f.parent();
    parent.output[0].value = Amount::from_sat(MAX_MONEY);
    parent.output[1].value = Amount::from_sat(1);
    f.set_parent(parent);
    assert_eq!(f.context(0).unwrap_err(), Error::MoneyRange);
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.output[0].value = Amount::from_sat(MAX_MONEY);
    assert_eq!(f.context(0).unwrap_err(), Error::MoneyRange);
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.output[0].value = Amount::from_sat(30_001);
    assert_eq!(f.context(0).unwrap_err(), Error::Overspend);
}

#[test]
fn maximum_shape_and_script_bounds_are_enforced_without_truncating() {
    let mut f = Fixture::new();
    let mut parent = f.parent();
    parent.output.resize(8, parent.output[1].clone());
    for o in &mut parent.output {
        o.value = Amount::from_sat(20_000);
    }
    f.psbt
        .unsigned_tx
        .input
        .resize(8, f.psbt.unsigned_tx.input[0].clone());
    f.psbt.inputs.resize(8, psbt::Input::default());
    for (index, input) in f.psbt.unsigned_tx.input.iter_mut().enumerate() {
        input.previous_output.vout = index as u32;
    }
    f.set_parent(parent);
    f.psbt
        .unsigned_tx
        .output
        .resize(8, output(1, ScriptBuf::new()));
    f.psbt.outputs.resize(8, psbt::Output::default());
    for o in &mut f.psbt.unsigned_tx.output {
        o.script_pubkey = ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_BYTES]);
    }
    let ctx = f.context(7).unwrap();
    assert_eq!(evaluate_unit(&ctx, Builtin::NumInputs), uint(8, 32));
    assert_eq!(evaluate_unit(&ctx, Builtin::NumOutputs), uint(8, 32));
    assert_eq!(
        eval(
            &ctx,
            Builtin::OutputScriptByte,
            join(&uint(7, 32), &uint(9999, 32))
        ),
        some(uint(0x51, 8))
    );
    assert_eq!(
        eval(&ctx, Builtin::InputValue, uint(7, 32)),
        some(uint(20_000, 64))
    );
    f.psbt.unsigned_tx.output[7]
        .script_pubkey
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1);
    assert_eq!(f.context(7).unwrap_err(), Error::OutputScriptTooLarge(7));
    let mut f = Fixture::new();
    f.data = vec![0x51; MAX_SCRIPT_BYTES];
    f.rebind();
    assert!(f.context(0).is_ok());
    f.data.push(0);
    assert_eq!(f.context(0).unwrap_err(), Error::ScriptDataTooLarge);
    assert_eq!(
        signing_commitment(f.cmr, &f.data, f.network),
        Err(Error::ScriptDataTooLarge)
    );
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.input.truncate(1);
    f.psbt.inputs.truncate(1);
    f.psbt.unsigned_tx.output.truncate(1);
    f.psbt.outputs.truncate(1);
    assert_eq!(f.context(0).unwrap().summary().input_count, 1);
}

#[test]
fn exact_evidence_ceiling_and_giant_proof_or_metadata_rejection() {
    let mut f = Fixture::new();
    let key = psbt::raw::Key {
        type_value: 0x70,
        key: vec![1],
    };
    f.psbt
        .unknown
        .insert(key.clone(), vec![0; MAX_REQUEST_BYTES - 4096]);
    let size = f.psbt.serialize().len();
    let len = f.psbt.unknown[&key].len() + MAX_REQUEST_BYTES - size;
    f.psbt.unknown.get_mut(&key).unwrap().resize(len, 0);
    assert_eq!(f.psbt.serialize().len(), MAX_REQUEST_BYTES);
    assert!(f.context(0).is_ok());
    f.psbt.unknown.get_mut(&key).unwrap().push(0);
    assert_eq!(f.context(0).unwrap_err(), Error::EvidenceTooLarge);
    let mut f = Fixture::new();
    f.psbt.inputs[0]
        .non_witness_utxo
        .as_mut()
        .unwrap()
        .output
        .push(output(0, ScriptBuf::from_bytes(vec![0; MAX_REQUEST_BYTES])));
    assert_eq!(f.context(0).unwrap_err(), Error::EvidenceTooLarge);
}

#[test]
fn relative_lock_flags_units_reserved_bits_and_zero_delay() {
    use Builtin::*;
    for (sequence, blocks, intervals) in [
        (0, Some(0), None),
        (0xffff, Some(0xffff), None),
        (0x003f_0001, Some(1), None),
        (0x0040_0000, None, Some(0)),
        (0x0040_ffff, None, Some(0xffff)),
        (0x7fff_0001, None, Some(1)),
        (0x8000_0000, None, None),
        (0x8040_ffff, None, None),
        (u32::MAX, None, None),
    ] {
        let mut f = Fixture::new();
        f.psbt.unsigned_tx.input[0].sequence = Sequence(sequence);
        let ctx = f.context(0).unwrap();
        assert_eq!(
            evaluate_unit(&ctx, CurrentSequence),
            uint(sequence.into(), 32)
        );
        for (value, indexed, current, check) in [
            (blocks, InputLockBlocks, CurrentLockBlocks, CheckCsvBlocks),
            (
                intervals,
                InputLockIntervals,
                CurrentLockIntervals,
                CheckCsvIntervals,
            ),
        ] {
            let expected = value.map_or_else(|| none(16), |v| some(uint(v, 16)));
            assert_eq!(eval(&ctx, indexed, uint(0, 32)), expected);
            assert_eq!(evaluate_unit(&ctx, current), expected);
            for request in [0, 1, 0xffff] {
                assert_eq!(
                    ctx.evaluate(check, &uint(request, 16)).is_ok(),
                    value.is_some_and(|delay| delay >= request),
                    "{check} seq={sequence:x} req={request}",
                );
            }
        }
    }
}

#[test]
fn absolute_locktime_unit_boundary_current_finality_and_global_signaling() {
    use Builtin::*;
    for actual in [0, 1, 499_999_999, 500_000_000, 500_000_001, u32::MAX] {
        for sequence in [0, 0xffff_fffd, 0xffff_fffe, u32::MAX] {
            let mut f = Fixture::new();
            f.psbt.unsigned_tx.lock_time = absolute::LockTime::from_consensus(actual);
            for input in &mut f.psbt.unsigned_tx.input {
                input.sequence = Sequence(sequence);
            }
            let ctx = f.context(0).unwrap();
            for request in [0, 1, 499_999_999, 500_000_000, 500_000_001, u32::MAX] {
                for (jet, timed) in [(CheckCltvHeight, false), (CheckCltvTime, true)] {
                    let expected = (actual >= 500_000_000) == timed
                        && (request >= 500_000_000) == timed
                        && actual >= request
                        && sequence != u32::MAX;
                    assert_eq!(
                        ctx.evaluate(jet, &uint(request.into(), 32)).is_ok(),
                        expected
                    );
                }
            }
            assert_eq!(
                evaluate_unit(&ctx, HasEffectiveLockTime).bit(0),
                Some(actual != 0 && sequence != u32::MAX)
            );
            assert_eq!(
                evaluate_unit(&ctx, IsRbfSignaled).bit(0),
                Some(sequence < 0xffff_fffe)
            );
        }
    }
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.input[1].sequence = Sequence::MAX;
    let ctx = f.context(1).unwrap();
    assert_eq!(evaluate_unit(&ctx, HasEffectiveLockTime).bit(0), Some(true));
    assert_eq!(
        ctx.evaluate(CheckCltvHeight, &uint(1000, 32)),
        Err(Error::CheckFailed)
    );
}

#[test]
fn network_default_sighash_and_no_final_witness_overrides() {
    let f = Fixture::new();
    for network in [Network::Regtest, Network::Signet] {
        assert_eq!(genesis_hash(network), Err(Error::UnsupportedNetwork));
        assert_eq!(
            signing_commitment(f.cmr, &f.data, network),
            Err(Error::UnsupportedNetwork)
        );
        assert_eq!(
            Context::new(
                &f.psbt, 0, f.cmr, &f.data, network, f.base, f.user, f.recovery
            )
            .unwrap_err(),
            Error::UnsupportedNetwork
        );
    }
    let names = [
        (Network::Bitcoin, "bitcoin"),
        (Network::Testnet, "testnet"),
        (Network::Testnet4, "testnet4"),
    ];
    for (network, name) in names {
        assert_eq!(network_name(network).unwrap(), name);
        let mut f = Fixture::new();
        f.network = network;
        f.rebind();
        assert_eq!(f.context(0).unwrap().summary().network, name);
    }
    for hash_type in [1u32, 2, 3, 0x80, 0x81, 0xff, u32::MAX] {
        let mut f = Fixture::new();
        f.psbt.inputs[1].sighash_type = Some(psbt::PsbtSighashType::from_u32(hash_type));
        assert_eq!(f.context(0).unwrap_err(), Error::NonDefaultSighash(1));
    }
    let mut f = Fixture::new();
    f.psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());
    assert!(f.context(0).is_ok());
    f.psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[&[0x50]]));
    assert_eq!(f.context(0).unwrap_err(), Error::FinalWitness(0));
    let mut f = Fixture::new();
    f.psbt.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0]));
    assert_eq!(f.context(0).unwrap_err(), Error::FinalScriptSig(0));
    let mut f = Fixture::new();
    let signature = bitcoin::taproot::Signature {
        signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap(),
        sighash_type: TapSighashType::All,
    };
    f.psbt.inputs[0].tap_key_sig = Some(signature);
    assert_eq!(f.context(0).unwrap_err(), Error::NonDefaultSighash(0));
    f.psbt.inputs[0].tap_key_sig = None;
    f.psbt.inputs[0].tap_script_sigs.insert(
        (
            f.user,
            TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript),
        ),
        signature,
    );
    assert_eq!(f.context(0).unwrap_err(), Error::NonDefaultSighash(0));
}

#[test]
fn approval_domains_preimages_and_cross_input_reuse_are_explicit() {
    let f = Fixture::new();
    let ctx0 = f.context(0).unwrap();
    let ctx1 = f.context(1).unwrap();
    assert_ne!(ctx0.sighash(), ctx1.sighash());
    assert_ne!(ctx0.policy_approval_hash(), ctx1.policy_approval_hash());
    assert_eq!(
        ctx0.policy_transaction_approval_hash(),
        ctx1.policy_transaction_approval_hash()
    );
    let fields = [
        profile_hash(),
        genesis_hash(f.network).unwrap(),
        ctx0.signing_commitment(),
        ctx0.unsigned_tx_hash(),
        ctx0.prevouts_hash(),
        ctx0.cooperative_leaf_hash().to_byte_array(),
        f.recovery.to_byte_array(),
    ];
    let j54 = tagged(
        "SimplicityUnchained/PolicyTransactionApproval/v1",
        &fields.concat(),
    );
    assert_eq!(j54, ctx0.policy_transaction_approval_hash());
    for (index, ctx) in [(0u32, &ctx0), (1, &ctx1)] {
        assert_eq!(
            tagged(
                "SimplicityUnchained/PolicyInputApproval/v1",
                &[j54.as_slice(), &index.to_be_bytes(), &ctx.sighash(),].concat()
            ),
            ctx.policy_approval_hash(),
        );
    }
    let legacy_commitment = tagged(
        "SimplicityUnchained/SigningCommitment/v1",
        &[f.cmr, sha(&f.data)].concat(),
    );
    assert_ne!(ctx0.signing_commitment(), legacy_commitment);
    let legacy = tagged(
        "SimplicityUnchained/BitcoinApproval/v1",
        &[
            [2u8].as_slice(),
            &0u32.to_be_bytes(),
            &legacy_commitment,
            &ctx0.unsigned_tx_hash(),
            &ctx0.prevouts_hash(),
        ]
        .concat(),
    );
    assert_eq!(ctx0.legacy_approval_hash(), legacy);
    assert_ne!(legacy, ctx0.policy_approval_hash());
    assert_ne!(legacy, j54);
    for change in 0..8 {
        let mut changed = Fixture::new();
        match change {
            0 => changed.psbt.unsigned_tx.output[0].value = Amount::from_sat(20_001),
            1 => changed.psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::new(),
            2 => changed.psbt.unsigned_tx.input[0].sequence = Sequence(6),
            3 => changed.psbt.unsigned_tx.lock_time = absolute::LockTime::from_consensus(1001),
            4 => {
                changed.data.push(0);
                changed.rebind();
            }
            5 => {
                changed.network = Network::Bitcoin;
                changed.rebind();
            }
            6 => {
                changed.cmr[0] ^= 1;
                changed.rebind();
            }
            7 => {
                let mut parent = changed.parent();
                parent.output[1].value = Amount::from_sat(40_001);
                changed.set_parent(parent);
            }
            _ => unreachable!(),
        }
        let actual = changed.context(0).unwrap();
        assert_ne!(
            actual.policy_approval_hash(),
            ctx0.policy_approval_hash(),
            "mutation{change}"
        );
        assert_ne!(
            actual.policy_transaction_approval_hash(),
            j54,
            "mutation{change}"
        );
        assert_ne!(actual.sighash(), ctx0.sighash(), "mutation{change}");
    }
}

#[test]
fn catalogue_manifest_types_legacy_identity_cost_and_prefix_freedom() {
    use simplicity::jet::{Core, Jet};
    let metadata = manifest();
    assert_eq!(metadata.profile, PROFILE_NAME);
    assert_eq!(metadata.status, "experimental");
    assert_eq!(metadata.jets.len(), 55);
    assert_eq!(metadata.legacy_jets.len(), Core::ALL.len() + 3);
    assert_eq!(
        hex::encode(sha(&metadata.canonical_bytes())),
        metadata.profile_hash
    );
    assert_eq!(manifest(), metadata);
    let decoded: simplicity_unchained_policy::Manifest =
        serde_json::from_slice(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert_eq!(decoded, metadata);
    let mut identities = BTreeSet::new();
    for (i, jet) in Builtin::ALL.into_iter().enumerate() {
        assert_eq!(jet.id() as usize, i);
        assert_eq!(Builtin::from_id(i as u8), Some(jet));
        assert_eq!(jet.name().parse::<Builtin>().unwrap(), jet);
        assert_eq!(jet.to_string(), jet.name());
        assert_eq!(jet.cost_milliweight(), 10_000);
        assert_eq!(jet.source_bits(), jet.source_type().to_final().bit_width());
        assert_eq!(jet.target_bits(), jet.target_type().to_final().bit_width());
        assert_eq!(metadata.jets[i].encoding, format!("1{i:06b}"));
        assert_eq!(metadata.jets[i].cmr, hex::encode(jet.cmr()));
        assert_ne!(jet.cmr(), sha(jet.name().as_bytes()));
        assert!(identities.insert(jet.cmr()));
        assert!(jet.source_bits() + jet.target_bits() <= 321);
    }
    for reserved in 55..=255 {
        assert_eq!(Builtin::from_id(reserved), None);
    }
    assert!("unknown_jet".parse::<Builtin>().is_err());
    for (i, jet) in Core::ALL.into_iter().enumerate() {
        let row = &metadata.legacy_jets[i];
        assert_eq!(row.name, jet.to_string());
        assert_eq!(row.cmr, hex::encode(jet.cmr().to_byte_array()));
        assert_eq!(row.cost_milliweight.to_string(), jet.cost().to_string());
    }
    let tail = &metadata.legacy_jets[Core::ALL.len()..];
    assert_eq!(
        tail.iter().map(|j| j.encoding.as_str()).collect::<Vec<_>>(),
        ["0111110", "01111110", "01111111"]
    );
    assert_eq!(
        tail.iter().map(|j| j.cost_milliweight).collect::<Vec<_>>(),
        [100, 100, 356]
    );
    assert_eq!(
        tail[0].cmr,
        "dcccd2895922e75b018b0846e5cd4963808bbfd48b47234475607f90e70ee032"
    );
    assert_eq!(
        tail[1].cmr,
        "27eab09068b035af619713335b73d2520ecc02090067c8fccabb4d72a655cdcb"
    );
    assert_eq!(
        tail[2].cmr,
        "f0ed96ee8fbf1a69beb20deb3a7a9b748bdc18da284d15438debc7d4faeb9962"
    );
    let encodings: Vec<_> = metadata
        .jets
        .iter()
        .chain(&metadata.legacy_jets)
        .map(|j| &j.encoding)
        .collect();
    for (i, a) in encodings.iter().enumerate() {
        for (j, b) in encodings.iter().enumerate() {
            if i != j {
                assert!(!a.starts_with(b.as_str()), "{a} prefixes{b}");
            }
        }
    }
    let mut changed = metadata.clone();
    changed.body.jets[0].semantic_contract.push('!');
    assert_ne!(sha(&changed.canonical_bytes()), profile_hash());
    changed = metadata.clone();
    changed.body.limits.max_inputs -= 1;
    assert_ne!(sha(&changed.canonical_bytes()), profile_hash());
}

#[test]
fn golden_manifest_and_transaction_vectors() {
    let f = Fixture::new();
    let ctx = f.context(0).unwrap();
    let other = f.context(1).unwrap();
    let value = serde_json::json!({
        "profile_hash": hex::encode(profile_hash()),
        "first_jet_identity": hex::encode(Builtin::PolicyProfileHash.cmr()),
        "last_jet_identity": hex::encode(Builtin::TxVsizeLowerBound.cmr()),
        "base_service_pubkey": f.base.to_string(),
        "script_data_hex": hex::encode(&f.data),
        "parent_tx_hex": hex::encode(serialize(&f.parent())),
        "unsigned_tx_hex": hex::encode(serialize(ctx.tx())),
        "prevouts_vector_hex": hex::encode(serialize(&ctx.prevouts().to_vec())),
        "inputs_vector_hex": hex::encode(serialize(&ctx.tx().input)),
        "outputs_vector_hex": hex::encode(serialize(&ctx.tx().output)),
        "tx_inputs_hash": hex::encode(ctx.tx_inputs_hash()),
        "tx_outputs_hash": hex::encode(ctx.tx_outputs_hash()),
        "cooperative_script_hex": hex::encode(ctx.cooperative_script().as_bytes()),
        "control_block_hex": hex::encode(ctx.control_block().serialize()),
        "legacy_approval_hash": hex::encode(ctx.legacy_approval_hash()),
        "input1_sighash": hex::encode(other.sighash()),
        "input1_approval_hash": hex::encode(other.policy_approval_hash()),
        "summary": ctx.summary(),
    });
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    if std::env::var_os("POLICY_DUMP_VECTORS").is_some() {
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    }
    assert_eq!(
        value, expected,
        "frozen profile or transaction vectors changed"
    );
}
