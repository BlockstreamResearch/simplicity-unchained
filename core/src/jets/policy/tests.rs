use super::*;
use std::collections::HashSet;
use std::sync::Arc;

use simplicity::bit_machine::{ExecTracker, NodeOutput};
use simplicity::bitcoin::{Sequence, absolute};
use simplicity::ffi::c_jets::c_frame::uword_width;
use simplicity::ffi::ffi::UWORD;
use simplicity::node::{CoreConstructible, Inner, WitnessConstructible};
use simplicity::{BitMachine, ConstructNode, RedeemNode, Value, types};
use simplicity_unchained_policy::Error;

use crate::policy::tests::{Fixture, unit_program};

fn packed(bits: impl IntoIterator<Item = bool>) -> BitValue {
    let bits = bits.into_iter().collect::<Vec<_>>();
    let mut bytes = vec![0; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            bytes[index / 8] |= 1 << (7 - index % 8);
        }
    }
    BitValue {
        bytes,
        bit_len: bits.len(),
    }
}

fn word(value: u64, bits: usize) -> BitValue {
    packed((0..bits).rev().map(|bit| value & (1 << bit) != 0))
}

fn arguments(jet: Builtin, env: &PolicyEnv) -> Vec<BitValue> {
    match jet.source_bits() {
        0 => vec![BitValue::unit()],
        16 => vec![word(0, 16), word(10, 16), word(11, 16), word(65_535, 16)],
        32 => [0, 1, 7, 8, 500, 500_000_000, u32::MAX]
            .map(|value| word(value.into(), 32))
            .to_vec(),
        64 => [
            (0, 0),
            (0, 1),
            (0, 33),
            (0, 34),
            (0, 9_999),
            (0, 10_000),
            (8, 0),
            (u32::MAX, u32::MAX),
        ]
        .map(|(index, offset)| {
            let mut bytes = index.to_be_bytes().to_vec();
            bytes.extend_from_slice(&offset.to_be_bytes());
            BitValue { bytes, bit_len: 64 }
        })
        .to_vec(),
        256 => {
            use simplicity::bitcoin::hashes::{Hash, sha256};
            vec![
                BitValue {
                    bytes: vec![0; 32],
                    bit_len: 256,
                },
                BitValue {
                    bytes: sha256::Hash::hash(env.context().prevouts()[0].script_pubkey.as_bytes())
                        .to_byte_array()
                        .to_vec(),
                    bit_len: 256,
                },
                BitValue {
                    bytes: sha256::Hash::hash(
                        env.context().tx().output[0].script_pubkey.as_bytes(),
                    )
                    .to_byte_array()
                    .to_vec(),
                    bit_len: 256,
                },
            ]
        }
        bits => panic!("unhandled source width {bits} for {jet}"),
    }
}

struct Capture(Option<BitValue>);

impl ExecTracker for Capture {
    fn visit_node(
        &mut self,
        node: &RedeemNode,
        _input: simplicity::bit_machine::FrameIter,
        output: NodeOutput,
    ) {
        if matches!(node.inner(), Inner::Jet(_))
            && let NodeOutput::Success(frame) = output
        {
            self.0 = Some(packed(frame.take(node.arrow().target.bit_width())));
        }
    }
}

fn vm_program(jet: PolicyJet, source: &BitValue) -> Arc<RedeemNode> {
    types::Context::with_context(|ctx| {
        let value = Value::from_padded_bits(
            &mut BitIter::from(source.bytes.as_slice()),
            &jet.source_ty().to_final(),
        )
        .unwrap();
        let argument = Arc::<ConstructNode>::witness(&ctx, Some(value));
        let function = Arc::<ConstructNode>::jet(&ctx, &jet);
        let apply = Arc::<ConstructNode>::comp(&argument, &function).unwrap();
        let discard = Arc::<ConstructNode>::unit(&ctx);
        Arc::<ConstructNode>::comp(&apply, &discard)
            .unwrap()
            .finalize_unpruned()
            .unwrap()
    })
}

fn ffi_call(jet: PolicyJet, source: &BitValue, env: &PolicyEnv, offset: usize) -> (bool, BitValue) {
    const GUARD: UWORD = 0x5a5a;
    let target_bits = jet.target_ty().to_bit_width();
    let input_bits = offset + source.bit_len + 9;
    let output_bits = offset + target_bits + 9;
    let input_words = uword_width(input_bits);
    let output_words = uword_width(output_bits);
    let mut input = vec![GUARD; input_words + 2];
    let mut output = vec![UWORD::MAX; output_words + 2];
    output[0] = GUARD;
    output[output_words + 1] = GUARD;
    unsafe {
        let mut frame = CFrameItem::new_write(input_bits, input.as_mut_ptr().add(input_words + 1));
        for _ in 0..offset {
            c_writeBit(&mut frame, true);
        }
        for index in 0..source.bit_len {
            c_writeBit(&mut frame, source.bit(index).unwrap());
        }
        for bit in 0..9 {
            c_writeBit(&mut frame, bit % 2 == 0);
        }
        let saved_input = input.clone();
        let mut src = CFrameItem::new_read(input_bits, input.as_ptr().add(1));
        for _ in 0..offset {
            assert!(c_readBit(&mut src));
        }
        let mut dst = CFrameItem::new_write(output_bits, output.as_mut_ptr().add(output_words + 1));
        for _ in 0..offset {
            c_writeBit(&mut dst, true);
        }
        let before = dst.len;
        let result = PolicyEnv::c_jet_ptr(&jet)(&mut dst, src, env);
        if result {
            assert_eq!(before - dst.len, target_bits, "{jet}");
        } else {
            assert_eq!(
                before, dst.len,
                "rejected jet must not partially write: {jet}"
            );
        }
        assert_eq!(input, saved_input, "{jet} modified its source");
        let written = before - dst.len;
        for bit in written..target_bits {
            c_writeBit(&mut dst, false);
            assert!(bit < target_bits);
        }
        for bit in 0..9 {
            c_writeBit(&mut dst, bit % 2 == 0);
        }
        assert_eq!(output[0], GUARD, "{jet} underflow");
        assert_eq!(output[output_words + 1], GUARD, "{jet} overflow");
        let mut read = CFrameItem::new_read(output_bits, output.as_ptr().add(1));
        for _ in 0..offset {
            assert!(c_readBit(&mut read), "{jet} prefix canary");
        }
        let actual = packed((0..target_bits).map(|_| c_readBit(&mut read)));
        for bit in 0..9 {
            assert_eq!(c_readBit(&mut read), bit % 2 == 0, "{jet} suffix canary");
        }
        (result, actual)
    }
}

#[test]
fn every_builtin_executes_in_vm_and_matches_reference_at_frame_offsets() {
    let program = unit_program();
    let mut fixture = Fixture::new(&program, 8, 8, true);
    let mut observed = HashSet::new();
    for (sequence, lock_time) in [(10, 500), ((1 << 22) | 10, 500_000_010), (u32::MAX, 500)] {
        for input in &mut fixture.psbt.unsigned_tx.input {
            input.sequence = Sequence::from_consensus(sequence);
        }
        fixture.psbt.unsigned_tx.lock_time = absolute::LockTime::from_consensus(lock_time);
        let prepared = fixture.prepare(&program, 0).unwrap();
        let context = Context::new(
            &fixture.psbt,
            0,
            prepared.cmr().to_byte_array(),
            &fixture.script,
            fixture.network,
            fixture.base,
            fixture.user,
            fixture.recovery,
        )
        .unwrap();
        let env = PolicyEnv::new(context);
        for builtin in Builtin::ALL {
            observed.insert(builtin.id());
            let jet = PolicyJet::Builtin(builtin);
            for argument in arguments(builtin, &env) {
                let expected = env.context().evaluate(builtin, &argument);
                let redeem = vm_program(jet, &argument);
                let mut capture = Capture(None);
                let result = BitMachine::for_program(&redeem).unwrap().exec_with_tracker(
                    &redeem,
                    &env,
                    &mut capture,
                );
                match &expected {
                    Ok(value) => {
                        result.unwrap();
                        assert_eq!(capture.0.as_ref(), Some(value), "{builtin} {argument:?}");
                    }
                    Err(Error::CheckFailed) => assert!(result.is_err(), "{builtin}"),
                    Err(error) => panic!("unexpected reference error {builtin}: {error}"),
                }
                for offset in [0, 1, 3, 7] {
                    let (ok, output) = ffi_call(jet, &argument, &env, offset);
                    assert_eq!(ok, expected.is_ok(), "{builtin} offset={offset}");
                    if let Ok(expected) = &expected {
                        assert_eq!(&output, expected, "{builtin} offset={offset}");
                    }
                }
            }
        }
    }
    assert_eq!(observed.len(), 55);
}

#[test]
fn shared_core_and_all_three_legacy_jets_execute_in_policy_environment() {
    let program = unit_program();
    let fixture = Fixture::new(&program, 2, 2, false);
    let prepared = fixture.prepare(&program, 1).unwrap();
    let context = Context::new(
        &fixture.psbt,
        1,
        prepared.cmr().to_byte_array(),
        &fixture.script,
        fixture.network,
        fixture.base,
        fixture.user,
        fixture.recovery,
    )
    .unwrap();
    let env = PolicyEnv::new(context);
    for (jet, argument, expected) in [
        (
            CoreExtension::Core(simplicity::jet::Core::Eq32),
            word(0, 64),
            word(1, 1),
        ),
        (
            CoreExtension::GetOpcodeFromScript,
            word(0, 8),
            word(0x21, 8),
        ),
        (
            CoreExtension::GetPubkeyFromScript,
            word(0, 8),
            BitValue {
                bytes: fixture.user.serialize().to_vec(),
                bit_len: 256,
            },
        ),
        (
            CoreExtension::TxApprovalHash,
            BitValue::unit(),
            BitValue {
                bytes: env.context().legacy_approval_hash().to_vec(),
                bit_len: 256,
            },
        ),
    ] {
        let jet = PolicyJet::Legacy(jet);
        let redeem = vm_program(jet, &argument);
        let mut capture = Capture(None);
        BitMachine::for_program(&redeem)
            .unwrap()
            .exec_with_tracker(&redeem, &env, &mut capture)
            .unwrap();
        assert_eq!(capture.0, Some(expected.clone()), "{jet}");
        if !matches!(jet, PolicyJet::Legacy(CoreExtension::Core(_))) {
            assert_eq!(ffi_call(jet, &argument, &env, 3), (true, expected));
        }
    }
}

#[test]
fn namespace_metadata_indices_and_all_offset_roundtrips_are_complete() {
    let mut cmrs = HashSet::new();
    let mut names = HashSet::new();
    for (index, jet) in PolicyJet::ALL.into_iter().enumerate() {
        assert_eq!(jet.index(), index);
        assert!(cmrs.insert(jet.cmr()));
        assert!(names.insert(jet.to_string()));
        assert_eq!(jet.to_string().parse::<PolicyJet>().unwrap(), jet);
        assert_eq!(PolicyJet::parse(&jet.to_string()).unwrap(), jet);
        assert_eq!(
            jet.source_ty().to_bit_width(),
            jet.source_ty().to_final().bit_width()
        );
        assert_eq!(
            jet.target_ty().to_bit_width(),
            jet.target_ty().to_final().bit_width()
        );
        match jet {
            PolicyJet::Legacy(legacy) => {
                assert_eq!(jet.cmr(), legacy.cmr());
                assert_eq!(jet.source_ty(), legacy.source_ty());
                assert_eq!(jet.target_ty(), legacy.target_ty());
                assert_eq!(jet.cost(), legacy.cost());
            }
            PolicyJet::Builtin(builtin) => {
                assert_eq!(jet.source_ty().to_bit_width(), builtin.source_bits());
                assert_eq!(jet.target_ty().to_bit_width(), builtin.target_bits());
                assert_eq!(jet.cmr().to_byte_array(), builtin.cmr());
                assert_eq!(jet.cost(), Cost::from_milliweight(10_000));
            }
        }
        for offset in 0..8 {
            let mut encoded = Vec::new();
            let mut writer = BitWriter::new(&mut encoded as &mut dyn Write);
            for _ in 0..offset {
                writer.write_bit(true).unwrap();
            }
            let length = jet.encode(&mut writer).unwrap();
            writer.write_bits_be(0x55, 7).unwrap();
            writer.flush_all().unwrap();
            let mut bits = BitIter::byte_slice_window(&encoded, offset, offset + length + 7);
            assert_eq!(
                PolicyJet::decode(&mut bits).unwrap(),
                jet,
                "offset={offset}"
            );
            assert_eq!(bits.n_total_read(), length);
            for bit in (0..7).rev() {
                assert_eq!(bits.next(), Some((0x55 >> bit) & 1 != 0));
            }
            for _ in offset + length + 7..encoded.len() * 8 {
                assert_eq!(bits.next(), Some(false));
            }
            assert_eq!(bits.next(), None);
        }
    }
    assert!("definitely_not_a_policy_jet".parse::<PolicyJet>().is_err());
}

#[test]
fn reserved_codes_and_truncated_prefixes_fail_at_every_bit_offset() {
    for offset in 0..8 {
        for id in 0..64 {
            let mut bytes = Vec::new();
            let mut writer = BitWriter::new(&mut bytes as &mut dyn Write);
            for _ in 0..offset {
                writer.write_bit(false).unwrap();
            }
            writer.write_bits_be(64 | id, 7).unwrap();
            writer.flush_all().unwrap();
            let mut bits = BitIter::byte_slice_window(&bytes, offset, offset + 7);
            let decoded = PolicyJet::decode(&mut bits);
            if id < 55 {
                assert_eq!(
                    decoded.unwrap(),
                    PolicyJet::Builtin(Builtin::from_id(id as u8).unwrap())
                );
            } else {
                assert!(matches!(decoded, Err(decode::Error::InvalidJet)));
            }
        }
    }
    for jet in PolicyJet::ALL {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes as &mut dyn Write);
        let length = jet.encode(&mut writer).unwrap();
        writer.flush_all().unwrap();
        for prefix in 0..length {
            // BitIter only bounds whole bytes at its right edge. Right-align a
            // truncated prefix so padding cannot accidentally finish the code.
            let offset = (8 - prefix % 8) % 8;
            let mut truncated = Vec::new();
            let mut writer = BitWriter::new(&mut truncated as &mut dyn Write);
            for _ in 0..offset {
                writer.write_bit(false).unwrap();
            }
            for index in 0..prefix {
                writer
                    .write_bit(bytes[index / 8] >> (7 - index % 8) & 1u8 != 0u8)
                    .unwrap();
            }
            writer.flush_all().unwrap();
            let mut bits = BitIter::byte_slice_window(&truncated, offset, offset + prefix);
            let result = PolicyJet::decode(&mut bits);
            assert!(result.is_err(), "{jet} offset={offset} prefix={prefix}");
            if matches!(jet, PolicyJet::Builtin(_)) {
                assert!(matches!(result, Err(decode::Error::EndOfStream)));
            }
        }
    }
}

#[test]
fn fixed_namespace_vectors_and_option_widths() {
    for (jet, byte) in [
        (PolicyJet::Builtin(Builtin::PolicyProfileHash), 0x80u8),
        (PolicyJet::Builtin(Builtin::TxVsizeLowerBound), 0xec),
        (PolicyJet::Legacy(CoreExtension::GetOpcodeFromScript), 0x7c),
        (PolicyJet::Legacy(CoreExtension::GetPubkeyFromScript), 0x7e),
        (PolicyJet::Legacy(CoreExtension::TxApprovalHash), 0x7f),
    ] {
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes as &mut dyn Write);
        jet.encode(&mut writer).unwrap();
        writer.flush_all().unwrap();
        assert_eq!(bytes, [byte]);
    }
    for (name, width) in [
        ("input_prev_outpoint", 289),
        ("input_value", 65),
        ("input_script_hash", 257),
        ("input_script_size", 33),
        ("input_script_byte", 9),
        ("input_sequence", 33),
        ("output_script_class", 9),
        ("input_lock_blocks", 17),
        ("current_lock_intervals", 17),
    ] {
        let jet: PolicyJet = name.parse().unwrap();
        assert_eq!(jet.target_ty().to_bit_width(), width, "{name}");
    }
}

#[test]
fn all_policy_type_names_match_the_frozen_contract() {
    let types: [(&[u8], &[u8]); 55] = [
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"i"),
        (b"1", b"i"),
        (b"1", b"i"),
        (b"1", b"i"),
        (b"1", b"i"),
        (b"i", b"+1*hi"),
        (b"i", b"+1l"),
        (b"i", b"+1h"),
        (b"i", b"+1i"),
        (b"*ii", b"+1c"),
        (b"i", b"+1i"),
        (b"1", b"*hi"),
        (b"1", b"l"),
        (b"1", b"h"),
        (b"1", b"i"),
        (b"i", b"+1l"),
        (b"i", b"+1h"),
        (b"i", b"+1i"),
        (b"*ii", b"+1c"),
        (b"i", b"+1c"),
        (b"1", b"l"),
        (b"1", b"l"),
        (b"1", b"l"),
        (b"h", b"l"),
        (b"h", b"l"),
        (b"h", b"i"),
        (b"1", b"l"),
        (b"1", b"l"),
        (b"1", b"2"),
        (b"1", b"2"),
        (b"i", b"+1s"),
        (b"i", b"+1s"),
        (b"1", b"+1s"),
        (b"1", b"+1s"),
        (b"s", b"1"),
        (b"s", b"1"),
        (b"i", b"1"),
        (b"i", b"1"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"h"),
        (b"1", b"i"),
    ];
    for (jet, (source, target)) in Builtin::ALL.into_iter().zip(types) {
        let wrapper = PolicyJet::Builtin(jet);
        assert_eq!(wrapper.source_ty().0, source, "{jet}");
        assert_eq!(wrapper.target_ty().0, target, "{jet}");
    }
}

#[test]
#[ignore = "bounded local timing report; not a consensus-cost calibration"]
fn timing_at_profile_maxshape_and_execution_cap() {
    use std::hint::black_box;
    use std::time::Instant;
    let program = unit_program();
    let fixture = Fixture::new(&program, 8, 8, true);
    let started = Instant::now();
    let prepared = fixture.prepare(&program, 0).unwrap();
    let preparation = started.elapsed();
    let context = Context::new(
        &fixture.psbt,
        0,
        prepared.cmr().to_byte_array(),
        &fixture.script,
        fixture.network,
        fixture.base,
        fixture.user,
        fixture.recovery,
    )
    .unwrap();
    let env = PolicyEnv::new(context);
    let mut calls = 0;
    let started = Instant::now();
    for _ in 0..10 {
        for builtin in Builtin::ALL {
            let argument = arguments(builtin, &env).remove(0);
            let jet = PolicyJet::Builtin(builtin);
            let redeem = vm_program(jet, &argument);
            black_box(
                BitMachine::for_program(&redeem)
                    .unwrap()
                    .exec(&redeem, &env),
            )
            .ok();
            calls += 1;
        }
    }
    eprintln!(
        "experimental policy timing: 8 inputs, 8 x 10000-byte scripts; prepare={preparation:?}, {calls} VM calls={:?}; 10000mw/jet is a conservative application budget, not consensus calibration",
        started.elapsed()
    );
    assert!(calls * 10_000 <= 10_000_000);
    let program = types::Context::with_context(|ctx| {
        let current =
            Arc::<ConstructNode>::jet(&ctx, &PolicyJet::Builtin(Builtin::CurrentScriptHash));
        let aggregate =
            Arc::<ConstructNode>::jet(&ctx, &PolicyJet::Builtin(Builtin::InputValueForScript));
        let call = Arc::<ConstructNode>::comp(&current, &aggregate).unwrap();
        let unit = Arc::<ConstructNode>::unit(&ctx);
        let call = Arc::<ConstructNode>::comp(&call, &unit).unwrap();
        let mut program = Arc::clone(&call);
        for _ in 1..450 {
            program = Arc::<ConstructNode>::comp(&program, &call).unwrap();
        }
        program.finalize_types().unwrap().to_vec_without_witness()
    });
    let fixture = Fixture::new(&program, 8, 8, true);
    let started = Instant::now();
    let prepared = fixture.prepare(&program, 0).unwrap();
    let construction = started.elapsed();
    let started = Instant::now();
    let evaluation = prepared.evaluate_default(&[]).unwrap();
    eprintln!(
        "near-cap actual policy: cost={}mw, prepare={construction:?}, evaluate={:?} (includes decode, cost check, allocation and 900 jet calls)",
        evaluation.cost_milliweight,
        started.elapsed(),
    );
    assert!(evaluation.cost_milliweight >= 9_000_000);
    assert!(evaluation.cost_milliweight <= 10_000_000);
}
