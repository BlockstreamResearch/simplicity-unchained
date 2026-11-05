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
enum Chain {
    Bitcoin,
    Elements,
}

impl Chain {
    fn command(self) -> &'static str {
        match self {
            Self::Bitcoin => "btc-tx",
            Self::Elements => "tx",
        }
    }

    fn envelope_key(self) -> &'static str {
        match self {
            Self::Bitcoin => "psbt",
            Self::Elements => "pset",
        }
    }
}

const CHAINS: [Chain; 2] = [Chain::Bitcoin, Chain::Elements];

fn keys() -> [Keypair; 2] {
    [0x11, 0x22].map(|value| {
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[value; 32]).unwrap(),
        )
    })
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_failure(output: Output, expected: &str) {
    assert!(!output.status.success(), "invalid recovery spend succeeded");
    assert!(output.stdout.is_empty(), "failure emitted success JSON");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(expected), "expected {expected}, got {error}");
}

fn recovery_leaf(chain: Chain, blocks: u16) -> Vec<u8> {
    let result = success(invoke(&[
        chain.command(),
        "build-csv-leaf",
        "--user-pubkey",
        &btc::PublicKey::new(keys()[1].public_key()).to_string(),
        "--timelock",
        &blocks.to_string(),
    ]));
    hex::decode(result["script"].as_str().unwrap()).unwrap()
}

fn fixture(chain: Chain, version: u32, sequences: [u32; 2], script: &[u8]) -> String {
    let secp = Secp256k1::new();
    let [cosigner_key, user_key] = keys();
    let cosigner = btc::PublicKey::new(cosigner_key.public_key());
    let user = btc::PublicKey::new(user_key.public_key());
    match chain {
        Chain::Bitcoin => {
            use btc::{
                sighash::{Prevouts, SighashCache},
                taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
            };
            let leaf = btc::ScriptBuf::from_bytes(script.to_vec());
            let spend = TaprootBuilder::new()
                .add_leaf(1, p2tr_multisig_leaf_btc(&cosigner, &user))
                .unwrap()
                .add_leaf(1, leaf.clone())
                .unwrap()
                .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
                .unwrap();
            let tx = btc::Transaction {
                version: btc::transaction::Version(i32::try_from(version).unwrap()),
                lock_time: btc::absolute::LockTime::ZERO,
                input: sequences
                    .into_iter()
                    .enumerate()
                    .map(|(index, sequence)| btc::TxIn {
                        previous_output: btc::OutPoint {
                            txid: btc::Txid::all_zeros(),
                            vout: u32::try_from(index).unwrap(),
                        },
                        sequence: btc::Sequence(sequence),
                        ..btc::TxIn::default()
                    })
                    .collect(),
                output: vec![btc::TxOut {
                    value: btc::Amount::from_sat(190_000),
                    script_pubkey: btc::ScriptBuf::new(),
                }],
            };
            let prevouts = vec![
                btc::TxOut {
                    value: btc::Amount::from_sat(100_000),
                    script_pubkey: btc::ScriptBuf::new_p2tr_tweaked(spend.output_key()),
                };
                2
            ];
            let mut psbt = btc::Psbt::from_unsigned_tx(tx).unwrap();
            let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
            let control = spend
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .unwrap();
            for (index, input) in psbt.inputs.iter_mut().enumerate() {
                input.witness_utxo = Some(prevouts[index].clone());
                input
                    .tap_scripts
                    .insert(control.clone(), (leaf.clone(), LeafVersion::TapScript));
                let digest = SighashCache::new(&psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        btc::TapSighashType::Default,
                    )
                    .unwrap();
                input.tap_script_sigs.insert(
                    (user_key.x_only_public_key().0, leaf_hash),
                    btc::taproot::Signature {
                        signature: secp
                            .sign_schnorr(&Message::from_digest(digest.to_byte_array()), &user_key),
                        sighash_type: btc::TapSighashType::Default,
                    },
                );
            }
            hex::encode(psbt.serialize())
        }
        Chain::Elements => {
            use el::{
                pset::PartiallySignedTransaction as Pset,
                sighash::{Prevouts, SighashCache},
                taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
            };
            let leaf = el::Script::from(script.to_vec());
            let spend = TaprootBuilder::new()
                .add_leaf(1, p2tr_multisig_leaf_elements(&cosigner, &user))
                .unwrap()
                .add_leaf(1, leaf.clone())
                .unwrap()
                .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
                .unwrap();
            let tx = el::Transaction {
                version,
                lock_time: el::LockTime::ZERO,
                input: sequences
                    .into_iter()
                    .enumerate()
                    .map(|(index, sequence)| el::TxIn {
                        previous_output: el::OutPoint {
                            txid: el::Txid::from_byte_array([0; 32]),
                            vout: u32::try_from(index).unwrap(),
                        },
                        sequence: el::Sequence(sequence),
                        ..el::TxIn::default()
                    })
                    .collect(),
                output: vec![el::TxOut {
                    asset: el::confidential::Asset::Explicit(el::AssetId::default()),
                    value: el::confidential::Value::Explicit(190_000),
                    ..el::TxOut::default()
                }],
            };
            let prevouts = vec![
                el::TxOut {
                    asset: el::confidential::Asset::Explicit(el::AssetId::default()),
                    value: el::confidential::Value::Explicit(100_000),
                    script_pubkey: el::Script::new_v1_p2tr_tweaked(spend.output_key()),
                    ..el::TxOut::default()
                };
                2
            ];
            let mut pset = Pset::from_tx(tx.clone());
            let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::default());
            let control = spend
                .control_block(&(leaf.clone(), LeafVersion::default()))
                .unwrap();
            for (index, input) in pset.inputs_mut().iter_mut().enumerate() {
                input.witness_utxo = Some(prevouts[index].clone());
                input
                    .tap_scripts
                    .insert(control.clone(), (leaf.clone(), LeafVersion::default()));
                let digest = SighashCache::new(&tx)
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        el::SchnorrSighashType::Default,
                        ElementsNetwork::LiquidTestnet.genesis_hash(),
                    )
                    .unwrap();
                input.tap_script_sigs.insert(
                    (user_key.x_only_public_key().0, leaf_hash),
                    el::SchnorrSig {
                        sig: secp
                            .sign_schnorr(&Message::from_digest(digest.to_byte_array()), &user_key),
                        hash_ty: el::SchnorrSighashType::Default,
                    },
                );
            }
            hex::encode(el::encode::serialize(&pset))
        }
    }
}

fn sign(chain: Chain, envelope: &str, script: &[u8], index: usize) -> Output {
    invoke(&[
        chain.command(),
        "spend-user-leaf",
        "--psbt",
        envelope,
        "--secret-key",
        &hex::encode([0x22; 32]),
        "--user-leaf-script",
        &hex::encode(script),
        "--cosigner-pubkey",
        &btc::PublicKey::new(keys()[0].public_key()).to_string(),
        "--input-index",
        &index.to_string(),
    ])
}

fn finalize(chain: Chain, envelope: &str) -> Output {
    invoke(&[chain.command(), "finalize-user-leaf", "--psbt", envelope])
}

fn txid(chain: Chain, envelope: &str) -> String {
    let bytes = hex::decode(envelope).unwrap();
    match chain {
        Chain::Bitcoin => btc::Psbt::deserialize(&bytes)
            .unwrap()
            .unsigned_tx
            .compute_txid()
            .to_string(),
        Chain::Elements => el::encode::deserialize::<el::pset::PartiallySignedTransaction>(&bytes)
            .unwrap()
            .extract_tx()
            .unwrap()
            .txid()
            .to_string(),
    }
}

#[test]
fn recovery_commands_reject_incompatible_sequences_on_each_chain() {
    for chain in CHAINS {
        let script = recovery_leaf(chain, 144);
        for sequence in [u32::MAX, 0x8000_0090, 0x0040_0090, 0, 143] {
            let envelope = fixture(chain, 2, [144, sequence], &script);
            assert_failure(
                sign(chain, &envelope, &script, 1),
                "Input 1: CSV recovery requires a block-based sequence of at least 144",
            );
            assert_failure(
                finalize(chain, &envelope),
                "Input 1: CSV recovery requires a block-based sequence of at least 144",
            );
            success(sign(chain, &envelope, &script, 0));
        }
        let default_sequences = fixture(chain, 2, [u32::MAX; 2], &script);
        assert_failure(
            finalize(chain, &default_sequences),
            "Input 0: CSV recovery requires a block-based sequence",
        );
    }
}

#[test]
fn recovery_commands_reject_old_transaction_versions_on_each_chain() {
    for chain in CHAINS {
        let script = recovery_leaf(chain, 144);
        let envelope = fixture(chain, 1, [144; 2], &script);
        assert_failure(
            sign(chain, &envelope, &script, 0),
            "transaction version >= 2",
        );
        assert_failure(finalize(chain, &envelope), "transaction version >= 2");
    }
}

#[test]
fn valid_recovery_delays_preserve_transactions_through_signing_and_finalization() {
    for chain in CHAINS {
        for blocks in [0, 1, 16, 144, u16::MAX] {
            let script = recovery_leaf(chain, blocks);
            let envelope = fixture(chain, 2, [u32::from(blocks), u32::from(u16::MAX)], &script);
            let expected_txid = txid(chain, &envelope);
            let mut signed = envelope;
            for index in 0..2 {
                let result = success(sign(chain, &signed, &script, index));
                signed = result[chain.envelope_key()].as_str().unwrap().to_string();
                assert_eq!(txid(chain, &signed), expected_txid);
            }
            let finalized = success(finalize(chain, &signed));
            assert_eq!(finalized["txid"], expected_txid);
            assert!(!finalized["transaction_hex"].as_str().unwrap().is_empty());
        }
    }
}

#[test]
fn other_csv_scripts_fail_explicitly_and_non_csv_leaves_remain_supported() {
    for chain in CHAINS {
        let mut script = recovery_leaf(chain, 144);
        script.push(btc::opcodes::all::OP_NOP.to_u8());
        let envelope = fixture(chain, 2, [144; 2], &script);
        assert_failure(
            sign(chain, &envelope, &script, 0),
            "unsupported CSV recovery script",
        );
        assert_failure(
            finalize(chain, &envelope),
            "unsupported CSV recovery script",
        );

        let script = btc::script::Builder::new()
            .push_x_only_key(&keys()[1].x_only_public_key().0)
            .push_opcode(btc::opcodes::all::OP_CHECKSIG)
            .into_script()
            .into_bytes();
        let envelope = fixture(chain, 1, [u32::MAX; 2], &script);
        let result = success(sign(chain, &envelope, &script, 0));
        let finalized = success(finalize(
            chain,
            result[chain.envelope_key()].as_str().unwrap(),
        ));
        assert_eq!(finalized["txid"], txid(chain, &envelope));
    }
}
