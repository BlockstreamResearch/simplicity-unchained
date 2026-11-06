mod common {
    include!("common/liquid.rs");
}
use common::*;
use liquid::elements::{
    self, SchnorrSighashType,
    encode::{deserialize, serialize},
    secp256k1_zkp::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
};
use simplicity::{
    BitIter, BitWriter, CommitNode, ConstructNode, jet::Jet, node::CoreConstructible, types,
};
use simplicity_unchained_policy::{
    BitValue,
    liquid::{self, Builtin, Context, PolicyJet},
};
use std::{io::Write, sync::Arc};

fn value(c: &Context, j: Builtin, input: &[u8]) -> BitValue {
    c.evaluate(
        j,
        &BitValue::from_bytes(input.to_vec(), j.source_bits()).unwrap(),
    )
    .unwrap()
}
fn u64_result(v: BitValue) -> u64 {
    u64::from_be_bytes(v.bytes.try_into().unwrap())
}

#[test]
fn confidential_multi_asset_verified_signing_roundtrip() {
    let mut f = Fixture::new();
    let summary = f.context(0).unwrap().summary();
    assert!(
        summary
            .inputs
            .iter()
            .all(|d| d.confidential_asset && d.confidential_value)
    );
    assert!(
        summary.outputs[..4]
            .iter()
            .all(|d| d.confidential_asset && d.confidential_value)
    );
    let fee = summary
        .assets
        .iter()
        .find(|a| a.asset_id == f.network.fee_asset().to_string())
        .unwrap();
    assert_eq!(
        (
            fee.total_input_value,
            fee.total_output_value,
            fee.fee,
            fee.returned_value,
            fee.debit
        ),
        (100_000, 100_000, 1_000, 79_000, 21_000)
    );
    let other = summary
        .assets
        .iter()
        .find(|a| a.asset_id == f.other_asset.to_string())
        .unwrap();
    assert_eq!(
        (
            other.total_input_value,
            other.total_output_value,
            other.fee,
            other.debit
        ),
        (70_000, 70_000, 0, 15_000)
    );
    assert!(!summary.chain_status_verified);
    let out = &f.pset.inputs()[0].non_witness_utxo.as_ref().unwrap().output[0];
    let opening =
        liquid::unblind_output(out, Some(&hex::encode(f.blinding_secret.secret_bytes()))).unwrap();
    assert_eq!(opening.value, 100_000);
    assert!(liquid::unblind_output(out, Some(&hex::encode(f.user_secret.secret_bytes()))).is_err());
    for index in 0..2 {
        let p = liquid::PreparedPolicy::new(
            &f.program, &f.pset, index, &f.data, f.network, f.base, f.user, f.recovery,
        )
        .unwrap();
        assert!(p.evaluate_default(&[]).unwrap() > 0);
    }
    f.sign_all();
    let c = f.context(0).unwrap();
    assert_eq!(c.summary(), summary);
    let tx = liquid::finalize(&c, &f.pset).unwrap();
    assert!(tx.input.iter().all(|i| i.witness.script_witness.len() == 4));
    tx.verify_tx_amt_proofs(&Secp256k1::new(), c.prevouts())
        .unwrap();
    for index in 0..2 {
        let digest = SighashCache::new(c.tx())
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(c.prevouts()),
                c.cooperative().leaf_hash,
                SchnorrSighashType::Default,
                f.network.genesis_hash(),
            )
            .unwrap();
        for ((key, _), sig) in &f.pset.inputs()[index].tap_script_sigs {
            Secp256k1::verification_only()
                .verify_schnorr(&sig.sig, &Message::from_digest(digest.to_byte_array()), key)
                .unwrap();
        }
    }
    let roundtrip: elements::Transaction = deserialize(&serialize(&tx)).unwrap();
    assert_eq!(roundtrip, tx);
}

#[test]
fn amounts_assets_and_disclosure_proof_tampering_rejected() {
    let f = Fixture::new();
    for input in [true, false] {
        for kind in 0..6 {
            let mut p = f.pset.clone();
            if input {
                let m = &mut p.inputs_mut()[0];
                match kind {
                    0 => m.amount = Some(m.amount.unwrap() + 1),
                    1 => m.asset = Some(f.other_asset),
                    2 => m.blind_value_proof = None,
                    3 => m.blind_asset_proof = None,
                    4 => m.blind_value_proof = f.pset.inputs()[1].blind_value_proof.clone(),
                    _ => m.blind_asset_proof = f.pset.inputs()[1].blind_asset_proof.clone(),
                }
            } else {
                let m = &mut p.outputs_mut()[0];
                match kind {
                    0 => m.amount = Some(m.amount.unwrap() + 1),
                    1 => m.asset = Some(f.other_asset),
                    2 => m.blind_value_proof = None,
                    3 => m.blind_asset_proof = None,
                    4 => m.blind_value_proof = f.pset.outputs()[1].blind_value_proof.clone(),
                    _ => m.blind_asset_proof = f.pset.outputs()[2].blind_asset_proof.clone(),
                }
            }
            assert!(
                f.context_for(&p, 0).is_err(),
                "input={input} mutation={kind}"
            );
        }
    }
    let mut p = f.pset.clone();
    let mut proof = p.outputs()[0].blind_value_proof.as_ref().unwrap().to_vec();
    let last = proof.len() - 1;
    proof[last] ^= 1;
    if let Ok(proof) = elements::RangeProof::from_slice(&proof) {
        p.outputs_mut()[0].blind_value_proof = Some(proof);
        assert!(f.context_for(&p, 0).is_err());
    }
}

#[test]
fn missing_parent_witness_and_original_transaction_proofs_rejected() {
    let f = Fixture::new();
    for kind in 0..8 {
        let mut p = f.pset.clone();
        match kind {
            0 => p.inputs_mut()[0].non_witness_utxo = None,
            1 => p.inputs_mut()[0].witness_utxo = None,
            2 => {
                p.inputs_mut()[0]
                    .non_witness_utxo
                    .as_mut()
                    .unwrap()
                    .lock_time = elements::LockTime::from_consensus(1)
            }
            3 => {
                p.inputs_mut()[0].witness_utxo.as_mut().unwrap().value =
                    elements::confidential::Value::Explicit(100_000)
            }
            4 => p.outputs_mut()[0].value_rangeproof = None,
            5 => p.outputs_mut()[0].asset_surjection_proof = None,
            6 => {
                p.inputs_mut()[0].non_witness_utxo.as_mut().unwrap().output[0]
                    .witness
                    .rangeproof = elements::RangeProof::EMPTY
            }
            _ => {
                p.inputs_mut()[0].non_witness_utxo.as_mut().unwrap().output[0]
                    .witness
                    .rangeproof = f.pset.inputs()[1].non_witness_utxo.as_ref().unwrap().output[1]
                    .witness
                    .rangeproof
                    .clone()
            }
        }
        assert!(f.context_for(&p, 0).is_err(), "mutation={kind}");
    }
}

#[test]
fn current_asset_projection_and_explicit_budgets_cannot_switch_assets() {
    let f = Fixture::new();
    let a = f.context(0).unwrap();
    let b = f.context(1).unwrap();
    let fee = Builtin::Policy(simplicity_unchained_policy::Builtin::TxFee);
    assert_eq!(u64_result(value(&a, fee, &[])), 1_000);
    assert_eq!(u64_result(value(&b, fee, &[])), 1_000);
    for c in [&a, &b] {
        assert_eq!(
            u64_result(value(
                c,
                Builtin::AssetCurrentScriptDebit,
                &f.network.fee_asset().to_byte_array()
            )),
            21_000
        );
        assert_eq!(
            u64_result(value(
                c,
                Builtin::AssetCurrentScriptDebit,
                &f.other_asset.to_byte_array()
            )),
            15_000
        );
        assert_eq!(
            u64_result(value(
                c,
                Builtin::AssetTotalInputValue,
                &f.other_asset.to_byte_array()
            )),
            70_000
        );
    }
    let input_value = Builtin::Policy(simplicity_unchained_policy::Builtin::InputValue);
    assert_eq!(
        value(&a, input_value, &1u32.to_be_bytes()).bit(0),
        Some(false)
    );
    assert_eq!(
        value(&b, input_value, &0u32.to_be_bytes()).bit(0),
        Some(false)
    );
    assert_ne!(
        value(&a, Builtin::CurrentAsset, &[]),
        value(&b, Builtin::CurrentAsset, &[])
    );
    assert_eq!(
        value(&a, Builtin::InputValueAsset, &1u32.to_be_bytes()).bit(0),
        Some(true)
    );
}

#[test]
fn genesis_profile_program_script_and_approval_digests_are_bound() {
    let f = Fixture::new();
    let a = f.context(0).unwrap().summary();
    let b = f.context(1).unwrap().summary();
    assert_ne!(a.policy_approval_hash, b.policy_approval_hash);
    assert_eq!(
        a.policy_transaction_approval_hash,
        b.policy_transaction_approval_hash
    );
    assert_ne!(a.cooperative_sighash_default, b.cooperative_sighash_default);
    assert_ne!(
        liquid::profile_hash(),
        simplicity_unchained_policy::profile_hash()
    );
    assert_ne!(
        liquid::signing_commitment(f.cmr, &f.data, f.network).unwrap(),
        simplicity_unchained_policy::signing_commitment(
            f.cmr,
            &f.data,
            simplicity_unchained_policy::bitcoin::Network::Testnet4
        )
        .unwrap()
    );
    assert!(
        Context::new(
            &f.pset,
            0,
            f.cmr,
            &f.data,
            liquid::Network::Liquid,
            f.base,
            f.user,
            f.recovery
        )
        .is_err()
    );
    assert!(
        Context::new(
            &f.pset, 0, [1; 32], &f.data, f.network, f.base, f.user, f.recovery
        )
        .is_err()
    );
    assert!(
        Context::new(
            &f.pset, 0, f.cmr, b"changed", f.network, f.base, f.user, f.recovery
        )
        .is_err()
    );
    assert_eq!(
        hex::encode(f.network.genesis_hash().to_byte_array()),
        "c1b16ae24f2423aea2ea34552292793b5b5e82999a1eed81d56aee528eda71a7"
    );
    let wrong = SighashCache::new(&f.pset.extract_tx().unwrap())
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(f.context(0).unwrap().prevouts()),
            f.context(0).unwrap().cooperative().leaf_hash,
            SchnorrSighashType::Default,
            liquid::Network::Liquid.genesis_hash(),
        )
        .unwrap();
    assert_ne!(wrong.to_byte_array(), f.context(0).unwrap().sighash());
}

#[test]
fn stale_invalid_unknown_and_missing_signatures_cannot_sign_or_finalize() {
    let mut f = Fixture::new();
    f.sign_all();
    let c = f.context(0).unwrap();
    for kind in 0..4 {
        let mut p = f.pset.clone();
        match kind {
            0 => {
                p.inputs_mut()[0].tap_script_sigs.clear();
            }
            1 => {
                p.inputs_mut()[0].tap_script_sigs = f.pset.inputs()[1].tap_script_sigs.clone();
            }
            2 => {
                p.outputs_mut()[0].amount = Some(20_001);
            }
            _ => {
                p.inputs_mut()[0].sequence = Some(elements::Sequence(11));
            }
        }
        assert!(liquid::finalize(&c, &p).is_err());
        assert!(
            liquid::add_signature(&c, &mut p, f.user_secret, false).is_err(),
            "mutation {kind}"
        );
    }
    let p = f.pset.clone();
    let key = Keypair::from_secret_key(&Secp256k1::new(), &f.user_secret);
    let fake = Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest([9; 32]), &key);
    let mut p = p;
    p.inputs_mut()[0].tap_script_sigs.insert(
        (f.user, c.cooperative().leaf_hash),
        elements::SchnorrSig {
            sig: fake,
            hash_ty: SchnorrSighashType::Default,
        },
    );
    assert!(f.context_for(&p, 0).is_err());
}

#[test]
fn every_liquid_jet_identity_type_encoding_and_vm_admission_are_separate() {
    let mut cmrs = std::collections::BTreeSet::new();
    for j in Builtin::all() {
        assert!(cmrs.insert(j.cmr()));
        if let Builtin::Policy(old) = j {
            assert_ne!(j.cmr(), old.cmr());
        }
        let jet = PolicyJet::Builtin(j);
        let mut bytes = Vec::new();
        let mut writer = BitWriter::new(&mut bytes as &mut dyn Write);
        assert_eq!(jet.encode(&mut writer).unwrap(), 8);
        writer.flush_all().unwrap();
        assert_eq!(PolicyJet::decode(&mut BitIter::from(bytes)).unwrap(), jet);
    }
    assert_eq!(cmrs.len(), 66);
    let program = types::Context::with_context(|ctx| {
        let profile = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Builtin(Builtin::Policy(
                simplicity_unchained_policy::Builtin::PolicyProfileHash,
            )),
        );
        let unit = Arc::<ConstructNode>::unit(&ctx);
        Arc::<ConstructNode>::comp(&profile, &unit)
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    assert!(
        CommitNode::decode::<_, simplicity::jet::Core>(BitIter::from(program.as_slice())).is_err()
    );
    let f = Fixture::with_program(program);
    let p = liquid::PreparedPolicy::new(
        &f.program, &f.pset, 0, &f.data, f.network, f.base, f.user, f.recovery,
    )
    .unwrap();
    assert!(p.evaluate_default(&[]).unwrap() > 10_000);
}

#[test]
fn mixed_commitment_external_disclosures_are_verified_not_trusted() {
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::secp256k1_zkp::{PublicKey, SecretKey, rand::rngs::OsRng};
    let f = Fixture::new();
    let secp = Secp256k1::new();
    let vbf = ValueBlindingFactor::from_slice(&[7; 32]).unwrap();
    let asset = f.network.fee_asset();
    let script = f.context(0).unwrap().cooperative().script_pubkey.clone();
    let blinded = |amount| {
        let (value, nonce, proof) = Value::Explicit(amount)
            .blind(
                &secp,
                vbf,
                PublicKey::from_secret_key(&secp, &f.blinding_secret),
                SecretKey::from_slice(&[8; 32]).unwrap(),
                &script,
                &elements::RangeProofMessage::new(asset, AssetBlindingFactor::zero()),
            )
            .unwrap();
        elements::TxOut {
            asset: Asset::Explicit(asset),
            value,
            nonce,
            script_pubkey: script.clone(),
            witness: elements::TxOutWitness {
                rangeproof: proof,
                surjection_proof: elements::SurjectionProof::EMPTY,
            },
        }
    };
    let input = blinded(10_000);
    let output = blinded(9_000);
    let parent = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn::default()],
        output: vec![input.clone()],
    };
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(parent.txid(), 0),
            ..Default::default()
        }],
        output: vec![
            output.clone(),
            elements::TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(1_000),
                nonce: Nonce::Null,
                script_pubkey: Default::default(),
                witness: Default::default(),
            },
        ],
    };
    let mut p = elements::pset::PartiallySignedTransaction::from_tx(tx);
    p.inputs_mut()[0].non_witness_utxo = Some(parent);
    p.inputs_mut()[0].witness_utxo = Some(input.clone());
    p.inputs_mut()[0].amount = Some(10_000);
    let generator = input.asset.into_asset_gen(&secp).unwrap();
    p.inputs_mut()[0].blind_value_proof = Some(
        elements::RangeProof::blind_value_proof(
            &mut OsRng,
            &secp,
            10_000,
            input.value.commitment().unwrap(),
            generator,
            vbf,
        )
        .unwrap(),
    );
    p.outputs_mut()[0].amount = Some(9_000);
    p.outputs_mut()[0].blind_value_proof = Some(
        elements::RangeProof::blind_value_proof(
            &mut OsRng,
            &secp,
            9_000,
            output.value.commitment().unwrap(),
            generator,
            vbf,
        )
        .unwrap(),
    );
    assert!(f.context_for(&p, 0).is_ok());
    let mut missing = p.clone();
    missing.inputs_mut()[0].blind_value_proof = None;
    assert!(f.context_for(&missing, 0).is_err());
    let mut wrong = p.clone();
    wrong.outputs_mut()[0].amount = Some(8_999);
    assert!(f.context_for(&wrong, 0).is_err());
    assert!(
        liquid::unblind_output(&input, Some(&hex::encode(f.blinding_secret.secret_bytes())))
            .is_err()
    );
    let abf = AssetBlindingFactor::from_slice(&[9; 32]).unwrap();
    let other_mixed = elements::TxOut {
        asset: Asset::new_confidential(&secp, asset, abf),
        value: Value::Explicit(100),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    };
    let proof =
        elements::SurjectionProof::blind_asset_proof(&mut OsRng, &secp, asset, abf).unwrap();
    assert!(liquid::verify_disclosure(&other_mixed, None, Some(asset), None, Some(&proof)).is_ok());
    assert!(liquid::verify_disclosure(&other_mixed, None, Some(asset), None, None).is_err());
    assert!(
        liquid::verify_disclosure(&other_mixed, None, Some(f.other_asset), None, Some(&proof))
            .is_err()
    );
}

#[test]
fn real_approval_witnesses_bind_the_entire_disclosed_transaction_and_profile() {
    use simplicity::node::WitnessConstructible;
    let secp = Secp256k1::new();
    let approver = Keypair::from_secret_key(
        &secp,
        &elements::secp256k1_zkp::SecretKey::from_slice(&[0x44; 32]).unwrap(),
    );
    let program = types::Context::with_context(|ctx| {
        let pk = Arc::<ConstructNode>::const_word(
            &ctx,
            simplicity::Word::u256(approver.x_only_public_key().0.serialize()),
        );
        let digest = Arc::<ConstructNode>::jet(
            &ctx,
            &PolicyJet::Builtin(Builtin::Policy(
                simplicity_unchained_policy::Builtin::PolicyTransactionApprovalHash,
            )),
        );
        let pk_digest = Arc::<ConstructNode>::pair(&pk, &digest).unwrap();
        let signature = Arc::<ConstructNode>::witness(&ctx, None);
        let arguments = Arc::<ConstructNode>::pair(&pk_digest, &signature).unwrap();
        Arc::<ConstructNode>::comp(
            &arguments,
            &Arc::<ConstructNode>::jet(
                &ctx,
                &PolicyJet::Core(simplicity::jet::Core::Bip0340Verify),
            ),
        )
        .unwrap()
        .finalize_types()
        .unwrap()
        .to_vec_without_witness()
    });
    let f = Fixture::with_program(program.clone());
    let prepare = |f: &Fixture, index| {
        liquid::PreparedPolicy::new(
            &program, &f.pset, index, &f.data, f.network, f.base, f.user, f.recovery,
        )
        .unwrap()
    };
    let p = prepare(&f, 0);
    let digest = hex::decode(&p.summary().policy_transaction_approval_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &approver);
    assert!(p.evaluate_default(sig.as_ref()).is_ok());
    assert!(prepare(&f, 1).evaluate_default(sig.as_ref()).is_ok());
    assert!(p.evaluate_default(&[]).is_err());
    let mut tampered = sig.as_ref().to_vec();
    tampered[1] ^= 1;
    assert!(p.evaluate_default(&tampered).is_err());
    let mut extra = sig.as_ref().to_vec();
    extra.push(0);
    assert!(p.evaluate_default(&extra).is_err());
    // A separately blinded, fully valid same-policy transaction cannot replay approval.
    let other = Fixture::with_program(program);
    assert!(
        liquid::PreparedPolicy::new(
            &other.program,
            &other.pset,
            0,
            &other.data,
            other.network,
            other.base,
            other.user,
            other.recovery
        )
        .unwrap()
        .evaluate_default(sig.as_ref())
        .is_err()
    );
    let wrong = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(
            simplicity_unchained_policy::signing_commitment(
                f.cmr,
                &f.data,
                simplicity_unchained_policy::bitcoin::Network::Testnet4,
            )
            .unwrap(),
        ),
        &approver,
    );
    assert!(p.evaluate_default(wrong.as_ref()).is_err());
}

#[test]
fn frozen_confidential_fixture_manifest_and_signatures_are_reproducible() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/liquid-policy-v1.json")).unwrap();
    let f = Fixture::deterministic();
    assert_eq!(fixture["pset_hex"], hex::encode(serialize(&f.pset)));
    assert_eq!(
        fixture["source_parent_tx_hex"],
        hex::encode(serialize(&f.source_parent))
    );
    assert_eq!(
        hex::encode(liquid::profile_hash()),
        "6097ac61cbd923269edaaed8cf14691cc8ba756e45949f7478f7f907f42d8ce2"
    );
    assert_eq!(
        hex::encode(simplicity_unchained_policy::profile_hash()),
        "0890429432ce3f797ae26e43ca6d47bdea6cd9369b32a48722a8b6385addd0c7"
    );
    let signed =
        deserialize(&hex::decode(fixture["fully_signed_pset_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    for index in 0..2 {
        let context = f.context_for(&signed, index).unwrap();
        assert_eq!(
            fixture["contexts"][index],
            serde_json::to_value(context.summary()).unwrap()
        );
    }

    let tx = liquid::finalize(&f.context_for(&signed, 0).unwrap(), &signed).unwrap();
    assert_eq!(fixture["transaction_hex"], hex::encode(serialize(&tx)));
    for (_, encoded) in fixture["negative_psets"].as_object().unwrap() {
        if let Ok(p) = deserialize(&hex::decode(encoded.as_str().unwrap()).unwrap()) {
            assert!(f.context_for(&p, 0).is_err());
        }
    }
    let mut manifest = liquid::manifest();
    manifest.as_object_mut().unwrap().remove("profile_hash");
    assert_eq!(
        elements::hashes::sha256::Hash::hash(&serde_json::to_vec(&manifest).unwrap())
            .to_byte_array(),
        liquid::profile_hash()
    );
}

#[test]
fn bitcoin_profile_funding_script_is_not_reinterpreted_as_liquid_contract() {
    use simplicity_unchained_policy::bitcoin::hashes::Hash as _;
    let f = Fixture::new();
    let btc = simplicity_unchained_policy::bitcoin::XOnlyPublicKey::from_slice(&f.base.serialize())
        .unwrap();
    let user =
        simplicity_unchained_policy::bitcoin::XOnlyPublicKey::from_slice(&f.user.serialize())
            .unwrap();
    let recovery = simplicity_unchained_policy::bitcoin::TapNodeHash::from_byte_array(
        f.recovery.to_byte_array(),
    );
    let old = simplicity_unchained_policy::cooperative_output(
        btc,
        f.cmr,
        &f.data,
        simplicity_unchained_policy::bitcoin::Network::Testnet4,
        user,
        recovery,
    )
    .unwrap();
    let mut p = f.pset.clone();
    let mut parent = p.inputs()[0].non_witness_utxo.as_ref().unwrap().clone();
    parent.output[0].script_pubkey = elements::Script::from(old.script_pubkey.as_bytes().to_vec());
    for (index, map) in p.inputs_mut().iter_mut().enumerate() {
        map.previous_txid = parent.txid();
        map.witness_utxo = Some(parent.output[index].clone());
        map.non_witness_utxo = Some(parent.clone());
    }
    let error = f.context_for(&p, 0).unwrap_err().to_string();
    assert!(
        error.contains("funding script/profile/network mismatch"),
        "{error}"
    );
}
