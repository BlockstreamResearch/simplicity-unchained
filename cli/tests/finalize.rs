use std::process::{Command, Output};

use simplicity::{
    bitcoin::{self as btc, hashes::Hash},
    elements::{
        self as el,
        secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey},
    },
};
use simplicity_unchained_core::{
    ElementsNetwork,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc, p2tr_multisig_leaf_elements},
};

#[derive(Clone, Copy)]
enum Leaves {
    Cooperative,
    OpcodeLookalike,
    Ambiguous,
}

fn keypairs() -> [Keypair; 2] {
    let secp = Secp256k1::new();
    [0x11, 0x22]
        .map(|byte| Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap()))
}

fn public_keys(keys: &[Keypair; 2]) -> [btc::PublicKey; 2] {
    keys.map(|key| btc::PublicKey::new(key.public_key()))
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(args)
        .output()
        .unwrap()
}

fn assert_failure(output: Output, expected: &str) {
    assert!(
        !output.status.success(),
        "invalid envelope was reported finalized"
    );
    assert!(
        output.stdout.is_empty(),
        "failure emitted success-shaped stdout"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(expected), "expected {expected}, got {error}");
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["finalized"], true);
    assert_eq!(result["inputs"], 2);
    result["transaction_hex"].as_str().unwrap().to_string()
}

mod bitcoin {
    use super::*;
    use btc::{
        psbt::Psbt,
        sighash::{Prevouts, SighashCache},
        taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    };

    fn fixture(leaves: Leaves) -> Psbt {
        let secp = Secp256k1::new();
        let keys = keypairs();
        let [cosigner, user] = public_keys(&keys);
        let mut leaf = p2tr_multisig_leaf_btc(&cosigner, &user);
        if matches!(leaves, Leaves::OpcodeLookalike) {
            let mut bytes = leaf.into_bytes();
            bytes[33] = btc::opcodes::all::OP_DROP.to_u8();
            leaf = btc::ScriptBuf::from_bytes(bytes);
        }
        let other_leaf = if matches!(leaves, Leaves::Ambiguous) {
            p2tr_multisig_leaf_btc(&user, &cosigner)
        } else {
            btc::script::Builder::new().push_int(1).into_script()
        };
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, leaf.clone())
            .unwrap()
            .add_leaf(1, other_leaf.clone())
            .unwrap()
            .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
            .unwrap();
        let tx = btc::Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::ZERO,
            input: (0..2)
                .map(|vout| btc::TxIn {
                    previous_output: btc::OutPoint {
                        txid: btc::Txid::all_zeros(),
                        vout,
                    },
                    ..btc::TxIn::default()
                })
                .collect(),
            output: vec![btc::TxOut {
                value: btc::Amount::from_sat(190_000),
                script_pubkey: btc::ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let prevouts = vec![
            btc::TxOut {
                value: btc::Amount::from_sat(100_000),
                script_pubkey: btc::ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            };
            2
        ];
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[index].clone());
            input
                .tap_scripts
                .insert(control.clone(), (leaf.clone(), LeafVersion::TapScript));
            if matches!(leaves, Leaves::Ambiguous) {
                let other_control = spend_info
                    .control_block(&(other_leaf.clone(), LeafVersion::TapScript))
                    .unwrap();
                input
                    .tap_scripts
                    .insert(other_control, (other_leaf.clone(), LeafVersion::TapScript));
            }
            for (key, sighash_type) in keys
                .iter()
                .zip([btc::TapSighashType::Default, btc::TapSighashType::All])
            {
                let hash = SighashCache::new(&psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        sighash_type,
                    )
                    .unwrap();
                input.tap_script_sigs.insert(
                    (key.x_only_public_key().0, leaf_hash),
                    btc::taproot::Signature {
                        signature: secp
                            .sign_schnorr(&Message::from_digest(hash.to_byte_array()), key),
                        sighash_type,
                    },
                );
            }
        }
        psbt
    }

    fn run(psbt: &Psbt) -> Output {
        invoke(&[
            "btc-tx",
            "finalize",
            "--psbt",
            &hex::encode(psbt.serialize()),
        ])
    }

    #[test]
    fn earlier_decoys_do_not_change_a_verified_cooperative_witness() {
        let original = fixture(Leaves::Cooperative);
        let expected = success(run(&original));
        for swapped in [false, true] {
            let mut psbt = original.clone();
            for input in &mut psbt.inputs {
                let (control, (leaf, version)) = input.tap_scripts.first_key_value().unwrap();
                let mut decoy = control.clone();
                decoy.merkle_branch = Default::default();
                let decoy_leaf = if swapped {
                    let [cosigner, user] = public_keys(&keypairs());
                    p2tr_multisig_leaf_btc(&user, &cosigner)
                } else {
                    btc::script::Builder::new().push_int(1).into_script()
                };
                assert!(decoy < *control);
                assert_ne!(decoy_leaf, *leaf);
                let version = *version;
                input
                    .tap_scripts
                    .insert(decoy.clone(), (decoy_leaf, version));
                assert_eq!(input.tap_scripts.first_key_value().unwrap().0, &decoy);
                input.final_script_witness = Some(btc::Witness::from_slice(&[vec![1, 2, 3]]));
            }
            assert_eq!(success(run(&psbt)), expected);
        }
        let tx: btc::Transaction =
            btc::consensus::deserialize(&hex::decode(expected).unwrap()).unwrap();
        let [cosigner, user] = public_keys(&keypairs());
        let leaf = p2tr_multisig_leaf_btc(&cosigner, &user);
        let hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        for (input, finalized) in original.inputs.iter().zip(&tx.input) {
            let expected = [
                input.tap_script_sigs[&(user.inner.x_only_public_key().0, hash)]
                    .serialize()
                    .to_vec(),
                input.tap_script_sigs[&(cosigner.inner.x_only_public_key().0, hash)]
                    .serialize()
                    .to_vec(),
                leaf.to_bytes(),
                input.tap_scripts.first_key_value().unwrap().0.serialize(),
            ];
            assert_eq!(finalized.witness.to_vec(), expected);
        }
    }

    #[test]
    fn rejects_committed_opcode_lookalikes_and_ambiguous_leaves() {
        assert_failure(
            run(&fixture(Leaves::OpcodeLookalike)),
            "no committed canonical multisig leaf",
        );
        assert_failure(
            run(&fixture(Leaves::Ambiguous)),
            "ambiguous committed multisig leaves",
        );
    }

    #[test]
    fn rejects_invalid_control_versions_and_foreign_output() {
        let original = fixture(Leaves::Cooperative);
        let mut changed = original.clone();
        let (control, value) = changed.inputs[0].tap_scripts.pop_first().unwrap();
        let mut invalid = control.clone();
        invalid.merkle_branch = Default::default();
        changed.inputs[0].tap_scripts.insert(invalid, value.clone());
        assert_failure(run(&changed), "no committed canonical multisig leaf");
        let mut changed = original.clone();
        changed.inputs[0].tap_scripts.insert(
            control,
            (value.0, LeafVersion::from_consensus(0xc2).unwrap()),
        );
        assert_failure(run(&changed), "no committed canonical multisig leaf");
        let mut changed = original.clone();
        changed.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = original.unsigned_tx.output[0].script_pubkey.clone();
        assert_failure(run(&changed), "spent output is not P2TR");
        let mut changed = original.clone();
        changed.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey =
            btc::ScriptBuf::new_p2tr(&Secp256k1::new(), keypairs()[0].x_only_public_key().0, None);
        assert_failure(run(&changed), "no committed canonical multisig leaf");
    }

    #[test]
    fn verifies_each_signature_and_all_transaction_inputs() {
        let original = fixture(Leaves::Cooperative);
        for key in keypairs() {
            let mut changed = original.clone();
            let input = &mut changed.inputs[1];
            let entry = input
                .tap_script_sigs
                .iter_mut()
                .find(|((public_key, _), _)| *public_key == key.x_only_public_key().0)
                .unwrap();
            entry.1.signature = Secp256k1::new().sign_schnorr(&Message::from_digest([0; 32]), &key);
            assert_failure(run(&changed), "Input 1 invalid tap_script_sig");
        }
        let mut changed = original.clone();
        changed.inputs[1].tap_script_sigs.pop_first();
        assert_failure(run(&changed), "Input 1 missing tap_script_sig");
        let mut changed = original.clone();
        changed.unsigned_tx.output[0].value = btc::Amount::from_sat(180_000);
        assert_failure(run(&changed), "invalid tap_script_sig");
        let mut changed = original.clone();
        changed.inputs[1].witness_utxo.as_mut().unwrap().value = btc::Amount::from_sat(99_999);
        assert_failure(run(&changed), "invalid tap_script_sig");
        let mut changed = original.clone();
        changed.inputs[1].witness_utxo = None;
        assert_failure(run(&changed), "Input 1 missing witness_utxo");
    }
}

mod elements {
    use super::*;
    use el::{
        pset::PartiallySignedTransaction as Pset,
        sighash::{Prevouts, SighashCache},
        taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    };

    fn fixture(leaves: Leaves) -> Pset {
        let secp = Secp256k1::new();
        let keys = keypairs();
        let [cosigner, user] = public_keys(&keys);
        let mut leaf = p2tr_multisig_leaf_elements(&cosigner, &user);
        if matches!(leaves, Leaves::OpcodeLookalike) {
            let mut bytes = leaf.to_bytes();
            bytes[33] = el::opcodes::all::OP_DROP.into_u8();
            leaf = el::Script::from(bytes);
        }
        let other_leaf = if matches!(leaves, Leaves::Ambiguous) {
            p2tr_multisig_leaf_elements(&user, &cosigner)
        } else {
            el::script::Builder::new().push_int(1).into_script()
        };
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, leaf.clone())
            .unwrap()
            .add_leaf(1, other_leaf.clone())
            .unwrap()
            .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
            .unwrap();
        let tx = el::Transaction {
            version: 2,
            lock_time: el::LockTime::ZERO,
            input: (0..2)
                .map(|vout| el::TxIn {
                    previous_output: el::OutPoint {
                        txid: el::Txid::from_byte_array([0; 32]),
                        vout,
                    },
                    ..el::TxIn::default()
                })
                .collect(),
            output: vec![el::TxOut {
                asset: el::confidential::Asset::Explicit(el::AssetId::default()),
                value: el::confidential::Value::Explicit(190_000),
                ..el::TxOut::default()
            }],
        };
        let mut pset = Pset::from_tx(tx.clone());
        let prevouts = vec![
            el::TxOut {
                asset: el::confidential::Asset::Explicit(el::AssetId::default()),
                value: el::confidential::Value::Explicit(100_000),
                script_pubkey: el::Script::new_v1_p2tr_tweaked(spend_info.output_key()),
                ..el::TxOut::default()
            };
            2
        ];
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::default());
        let control = spend_info
            .control_block(&(leaf.clone(), LeafVersion::default()))
            .unwrap();
        for (index, input) in pset.inputs_mut().iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[index].clone());
            input
                .tap_scripts
                .insert(control.clone(), (leaf.clone(), LeafVersion::default()));
            if matches!(leaves, Leaves::Ambiguous) {
                let other_control = spend_info
                    .control_block(&(other_leaf.clone(), LeafVersion::default()))
                    .unwrap();
                input
                    .tap_scripts
                    .insert(other_control, (other_leaf.clone(), LeafVersion::default()));
            }
            for (key, hash_ty) in keys
                .iter()
                .zip([el::SchnorrSighashType::Default, el::SchnorrSighashType::All])
            {
                let hash = SighashCache::new(&tx)
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        hash_ty,
                        ElementsNetwork::LiquidTestnet.genesis_hash(),
                    )
                    .unwrap();
                input.tap_script_sigs.insert(
                    (key.x_only_public_key().0, leaf_hash),
                    el::SchnorrSig {
                        sig: secp.sign_schnorr(&Message::from_digest(hash.to_byte_array()), key),
                        hash_ty,
                    },
                );
            }
        }
        pset
    }

    fn run(pset: &Pset) -> Output {
        invoke(&[
            "tx",
            "finalize",
            "--pset",
            &hex::encode(el::encode::serialize(pset)),
            "--network",
            "liquid_testnet",
        ])
    }

    #[test]
    fn earlier_decoys_do_not_change_a_verified_cooperative_witness() {
        let original = fixture(Leaves::Cooperative);
        let expected = success(run(&original));
        for swapped in [false, true] {
            let mut pset = original.clone();
            for input in pset.inputs_mut() {
                let (control, (leaf, version)) = input.tap_scripts.first_key_value().unwrap();
                let mut decoy = control.clone();
                decoy.merkle_branch = Default::default();
                let decoy_leaf = if swapped {
                    let [cosigner, user] = public_keys(&keypairs());
                    p2tr_multisig_leaf_elements(&user, &cosigner)
                } else {
                    el::script::Builder::new().push_int(1).into_script()
                };
                assert!(decoy < *control);
                assert_ne!(decoy_leaf, *leaf);
                let version = *version;
                input
                    .tap_scripts
                    .insert(decoy.clone(), (decoy_leaf, version));
                assert_eq!(input.tap_scripts.first_key_value().unwrap().0, &decoy);
                input.final_script_witness = Some(vec![vec![1, 2, 3]].into());
            }
            assert_eq!(success(run(&pset)), expected);
        }
        let tx: el::Transaction = el::encode::deserialize(&hex::decode(expected).unwrap()).unwrap();
        let [cosigner, user] = public_keys(&keypairs());
        let leaf = p2tr_multisig_leaf_elements(&cosigner, &user);
        let hash = TapLeafHash::from_script(&leaf, LeafVersion::default());
        for (input, finalized) in original.inputs().iter().zip(&tx.input) {
            let expected = [
                input.tap_script_sigs[&(user.inner.x_only_public_key().0, hash)].to_vec(),
                input.tap_script_sigs[&(cosigner.inner.x_only_public_key().0, hash)].to_vec(),
                leaf.to_bytes(),
                input.tap_scripts.first_key_value().unwrap().0.serialize(),
            ];
            assert_eq!(
                finalized.witness.script_witness,
                el::Witness::from(expected.to_vec())
            );
        }
    }

    #[test]
    fn rejects_committed_opcode_lookalikes_and_ambiguous_leaves() {
        assert_failure(
            run(&fixture(Leaves::OpcodeLookalike)),
            "no committed canonical multisig leaf",
        );
        assert_failure(
            run(&fixture(Leaves::Ambiguous)),
            "ambiguous committed multisig leaves",
        );
    }

    #[test]
    fn rejects_invalid_control_versions_and_foreign_output() {
        let original = fixture(Leaves::Cooperative);
        let mut changed = original.clone();
        let (control, value) = changed.inputs_mut()[0].tap_scripts.pop_first().unwrap();
        let mut invalid = control.clone();
        invalid.merkle_branch = Default::default();
        changed.inputs_mut()[0]
            .tap_scripts
            .insert(invalid, value.clone());
        assert_failure(run(&changed), "no committed canonical multisig leaf");
        let mut changed = original.clone();
        changed.inputs_mut()[0]
            .tap_scripts
            .insert(control, (value.0, LeafVersion::from_u8(0xc2).unwrap()));
        assert_failure(run(&changed), "no committed canonical multisig leaf");
        let mut changed = original.clone();
        changed.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = el::Script::new();
        assert_failure(run(&changed), "spent output is not P2TR");
        let mut changed = original.clone();
        changed.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey =
            el::Script::new_v1_p2tr(&Secp256k1::new(), keypairs()[0].x_only_public_key().0, None);
        assert_failure(run(&changed), "no committed canonical multisig leaf");
    }

    #[test]
    fn verifies_each_signature_all_transaction_inputs_and_network() {
        let original = fixture(Leaves::Cooperative);
        for key in keypairs() {
            let mut changed = original.clone();
            let input = &mut changed.inputs_mut()[1];
            let entry = input
                .tap_script_sigs
                .iter_mut()
                .find(|((public_key, _), _)| *public_key == key.x_only_public_key().0)
                .unwrap();
            entry.1.sig = Secp256k1::new().sign_schnorr(&Message::from_digest([0; 32]), &key);
            assert_failure(run(&changed), "Input 1 invalid tap_script_sig");
        }
        let mut changed = original.clone();
        changed.inputs_mut()[1].tap_script_sigs.pop_first();
        assert_failure(run(&changed), "Input 1 missing tap_script_sig");
        let mut changed = original.clone();
        changed.outputs_mut()[0].amount = Some(180_000);
        assert_failure(run(&changed), "invalid tap_script_sig");
        let mut changed = original.clone();
        changed.inputs_mut()[1].witness_utxo.as_mut().unwrap().value =
            el::confidential::Value::Explicit(99_999);
        assert_failure(run(&changed), "invalid tap_script_sig");
        let mut changed = original.clone();
        changed.inputs_mut()[1].witness_utxo = None;
        assert_failure(run(&changed), "Input 1 missing witness_utxo");
        assert_failure(
            invoke(&[
                "tx",
                "finalize",
                "--pset",
                &hex::encode(el::encode::serialize(&original)),
                "--network",
                "liquid",
            ]),
            "invalid tap_script_sig",
        );
    }
}
