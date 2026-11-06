mod common;

use std::{collections::BTreeMap, process::Command, time::Duration};

use serde::Deserialize;
use simplicity::{
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bitcoin::{
        self as btc, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapNodeHash,
        Transaction, TxIn, TxOut, XOnlyPublicKey,
        hashes::{Hash, sha256},
        secp256k1::{Keypair, Message, Secp256k1, SecretKey, schnorr::Signature},
    },
};
use simplicity_unchained_core::policy::{PolicyError, PreparedPolicy, policy_cmr};
use simplicity_unchained_policy::{PROFILE_NAME, cooperative_output, profile_hash};

#[derive(Deserialize)]
struct Bundle {
    profile: String,
    profile_hash: String,
    templates: BTreeMap<String, Template>,
}

#[derive(Deserialize)]
struct Template {
    source_sha256: String,
    program_base64: String,
    cmr_hex: String,
    profile_hash: String,
    duplicate_keys_program_base64: Option<String>,
    duplicate_keys_cmr_hex: Option<String>,
}

fn templates() -> Bundle {
    serde_json::from_str(include_str!("../../examples/policy/compiled.json")).unwrap()
}

fn program(name: &str) -> Vec<u8> {
    BASE64_STANDARD
        .decode(&templates().templates[name].program_base64)
        .unwrap()
}

fn scalar_key(value: u8) -> Keypair {
    let mut secret = [0; 32];
    secret[31] = value;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap())
}

#[derive(Clone)]
enum Destination {
    Return,
    Script(ScriptBuf),
}

fn recipient() -> Destination {
    Destination::Script(
        ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap(),
    )
}

struct Fixture {
    program: Vec<u8>,
    psbt: Psbt,
    script: Vec<u8>,
    base: XOnlyPublicKey,
}

impl Fixture {
    fn new(program: Vec<u8>, inputs: usize, outputs: &[(u64, Destination)]) -> Self {
        Self::with_base(
            program,
            inputs,
            outputs,
            scalar_key(41).x_only_public_key().0,
        )
    }

    fn with_base(
        program: Vec<u8>,
        inputs: usize,
        outputs: &[(u64, Destination)],
        base: XOnlyPublicKey,
    ) -> Self {
        let script = vec![0x52];
        let cmr = policy_cmr(&program).unwrap();
        let output = cooperative_output(
            base,
            cmr.to_byte_array(),
            &script,
            Network::Testnet4,
            scalar_key(42).x_only_public_key().0,
            TapNodeHash::from_byte_array([43; 32]),
        )
        .unwrap();
        let parent = Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: output.script_pubkey.clone(),
                };
                inputs
            ],
        };
        let tx = Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::from_consensus(1000),
            input: (0..inputs)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(parent.compute_txid(), vout as u32),
                    sequence: Sequence::from_height(16),
                    ..TxIn::default()
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(value, destination)| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: match destination {
                        Destination::Return => output.script_pubkey.clone(),
                        Destination::Script(script) => script.clone(),
                    },
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            input.non_witness_utxo = Some(parent.clone());
            input.witness_utxo = Some(parent.output[index].clone());
        }
        Self {
            program,
            psbt,
            script,
            base,
        }
    }

    fn prepare(&self, index: usize) -> Result<PreparedPolicy, PolicyError> {
        PreparedPolicy::new(
            &self.program,
            &self.psbt,
            index,
            &self.script,
            Network::Testnet4,
            self.base,
            scalar_key(42).x_only_public_key().0,
            TapNodeHash::from_byte_array([43; 32]),
        )
    }

    fn update_parent(&mut self, parent: Transaction) {
        for (txin, input) in self
            .psbt
            .unsigned_tx
            .input
            .iter_mut()
            .zip(&mut self.psbt.inputs)
        {
            txin.previous_output.txid = parent.compute_txid();
            input.witness_utxo = Some(parent.output[txin.previous_output.vout as usize].clone());
            input.non_witness_utxo = Some(parent.clone());
        }
    }
}

fn signature(digest: [u8; 32], key: u8) -> Signature {
    Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &scalar_key(key))
}

// Witness encoding is compact sums, not the padded Option frames used by VM jets.
fn signature_witness(signatures: &[Option<Signature>]) -> Vec<u8> {
    let mut bits = Vec::new();
    for signature in signatures {
        bits.push(signature.is_some());
        if let Some(signature) = signature {
            for byte in signature.as_ref() {
                bits.extend((0..8).map(|offset| byte & (1 << (7 - offset)) != 0));
            }
        }
    }
    let mut bytes = vec![0; bits.len().div_ceil(8)];
    for (index, bit) in bits.into_iter().enumerate() {
        bytes[index / 8] |= u8::from(bit) << (7 - index % 8);
    }
    bytes
}

fn approval_witness(prepared: &PreparedPolicy, input_scoped: bool) -> Vec<u8> {
    let digest = if input_scoped {
        prepared.context().policy_approval_hash()
    } else {
        prepared.context().policy_transaction_approval_hash()
    };
    signature_witness(&[Some(signature(digest, 1)), Some(signature(digest, 2)), None])
}

fn source_witness(prepared: &PreparedPolicy) -> Vec<u8> {
    let context = prepared.context();
    let tag = sha256::Hash::hash(b"SimplicityUnchained/PolicySourceOutpoint/v1").to_byte_array();
    let mut signatures = Vec::new();
    for input in &context.tx().input {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(&context.signing_commitment());
        preimage.extend_from_slice(&input.previous_output.txid.to_byte_array());
        preimage.extend_from_slice(&input.previous_output.vout.to_be_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        signatures.push(Some(signature(digest, 1)));
    }
    signatures.resize(8, None);
    signature_witness(&signatures)
}

fn rejects(prepared: &PreparedPolicy, witness: &[u8]) {
    assert!(
        matches!(
            prepared.evaluate_default(witness),
            Err(PolicyError::PolicyRejected(_))
        ),
        "Expected policy rejection, got {:?}",
        prepared.evaluate_default(witness)
    );
}

#[test]
fn compiled_templates_pin_the_reviewed_source_cmr_and_registry() {
    let bundle = templates();
    assert_eq!(bundle.profile, PROFILE_NAME);
    assert_eq!(bundle.profile_hash, hex::encode(profile_hash()));
    let sources = [
        (
            "recipient_allowlist.simf",
            include_str!("../../examples/policy/recipient_allowlist.simf"),
        ),
        (
            "capped_debit.simf",
            include_str!("../../examples/policy/capped_debit.simf"),
        ),
        (
            "approvals_2_of_3.simf",
            include_str!("../../examples/policy/approvals_2_of_3.simf"),
        ),
        (
            "approvals_2_of_3_per_input.simf",
            include_str!("../../examples/policy/approvals_2_of_3_per_input.simf"),
        ),
        (
            "constrained_source.simf",
            include_str!("../../examples/policy/constrained_source.simf"),
        ),
    ];
    assert_eq!(bundle.templates.len(), sources.len());
    for (name, source) in sources {
        let template = &bundle.templates[name];
        assert_eq!(template.profile_hash, bundle.profile_hash);
        assert_eq!(
            template.source_sha256,
            hex::encode(sha256::Hash::hash(source.as_bytes()).to_byte_array()),
            "Stale compiled source for {name}"
        );
        assert_eq!(
            template.cmr_hex,
            policy_cmr(&program(name)).unwrap().to_string(),
            "Stale compiled CMR for {name}"
        );
        if let Some(duplicate) = &template.duplicate_keys_program_base64 {
            let bytes = BASE64_STANDARD.decode(duplicate).unwrap();
            assert_eq!(
                template.duplicate_keys_cmr_hex.as_deref(),
                Some(policy_cmr(&bytes).unwrap().to_string().as_str()),
                "Stale duplicate-key mutation CMR for {name}"
            );
        }
    }
}

#[test]
fn allowlist_checks_every_output_including_zero_value_and_last_slot() {
    let bytes = program("recipient_allowlist.simf");
    for count in [1, 8] {
        let mut fixture = Fixture::new(bytes.clone(), 1, &vec![(10_000, recipient()); count]);
        fixture.prepare(0).unwrap().evaluate_default(&[]).unwrap();
        let last = fixture.psbt.unsigned_tx.output.last_mut().unwrap();
        last.value = Amount::ZERO;
        let mut script = last.script_pubkey.to_bytes();
        *script.last_mut().unwrap() ^= 1;
        last.script_pubkey = ScriptBuf::from_bytes(script);
        rejects(&fixture.prepare(0).unwrap(), &[]);
    }
    let returning = Fixture::new(bytes.clone(), 1, &[(99_000, Destination::Return)]);
    returning.prepare(0).unwrap().evaluate_default(&[]).unwrap();
    let excess = Fixture::new(bytes, 1, &vec![(1_000, recipient()); 9]);
    assert!(excess.prepare(0).is_err());
}

#[test]
fn debit_and_fee_caps_use_all_eight_inputs_and_inclusive_satoshi_boundaries() {
    let bytes = program("capped_debit.simf");
    let mut outputs = vec![(14_000, recipient()); 7];
    outputs.push((700_000, Destination::Return));
    let mut fixture = Fixture::new(bytes.clone(), 8, &outputs);
    let prepared = fixture.prepare(7).unwrap();
    assert_eq!(prepared.summary().fee, 2_000);
    assert_eq!(prepared.summary().debit, 100_000);
    prepared.evaluate_default(&[]).unwrap();

    // Same total outputs/fee, but one satoshi more leaves the common script.
    fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(14_001);
    fixture.psbt.unsigned_tx.output[7].value = Amount::from_sat(699_999);
    rejects(&fixture.prepare(7).unwrap(), &[]);

    // Same debit, one satoshi above the absolute fee limit.
    fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(13_999);
    fixture.psbt.unsigned_tx.output[7].value = Amount::from_sat(700_000);
    rejects(&fixture.prepare(7).unwrap(), &[]);

    let aggregate = Fixture::new(
        bytes,
        2,
        &[(99_000, recipient()), (99_000, Destination::Return)],
    );
    assert_eq!(aggregate.prepare(0).unwrap().summary().debit, 101_000);
    rejects(&aggregate.prepare(0).unwrap(), &[]);
}

#[test]
fn approval_threshold_requires_distinct_keys_and_checks_every_present_signature() {
    let fixture = Fixture::new(
        program("approvals_2_of_3.simf"),
        2,
        &[(199_000, Destination::Return)],
    );
    let prepared = fixture.prepare(0).unwrap();
    let digest = prepared.context().policy_transaction_approval_hash();
    let [sig1, sig2, sig3] = [1, 2, 3].map(|key| signature(digest, key));
    prepared
        .evaluate_default(&signature_witness(&[Some(sig1), Some(sig2), None]))
        .unwrap();
    prepared
        .evaluate_default(&signature_witness(&[Some(sig1), Some(sig2), Some(sig3)]))
        .unwrap();
    rejects(&prepared, &signature_witness(&[Some(sig1), None, None]));
    rejects(
        &prepared,
        &signature_witness(&[Some(sig1), Some(sig1), None]),
    );
    rejects(
        &prepared,
        &signature_witness(&[Some(sig1), Some(sig2), Some(sig1)]),
    );
}

#[test]
fn duplicate_committed_keys_cannot_inflate_either_approval_threshold() {
    for name in ["approvals_2_of_3.simf", "approvals_2_of_3_per_input.simf"] {
        let bundle = templates();
        let duplicate_program = BASE64_STANDARD
            .decode(
                bundle.templates[name]
                    .duplicate_keys_program_base64
                    .as_ref()
                    .expect("Compiler must include the duplicate-key mutation fixture"),
            )
            .unwrap();
        let fixture = Fixture::new(duplicate_program, 1, &[(99_000, Destination::Return)]);
        let prepared = fixture.prepare(0).unwrap();
        let digest = if name.contains("per_input") {
            prepared.context().policy_approval_hash()
        } else {
            prepared.context().policy_transaction_approval_hash()
        };
        let repeated = signature(digest, 1);
        rejects(
            &prepared,
            &signature_witness(&[Some(repeated), Some(repeated), None]),
        );
    }
}

#[test]
fn transaction_and_input_approval_scopes_reject_relevant_mutations() {
    for (name, input_scoped) in [
        ("approvals_2_of_3.simf", false),
        ("approvals_2_of_3_per_input.simf", true),
    ] {
        let mut fixture = Fixture::new(program(name), 2, &[(199_000, Destination::Return)]);
        let first = fixture.prepare(0).unwrap();
        let witness = approval_witness(&first, input_scoped);
        first.evaluate_default(&witness).unwrap();
        let second = fixture.prepare(1).unwrap();
        if input_scoped {
            rejects(&second, &witness);
            second
                .evaluate_default(&approval_witness(&second, true))
                .unwrap();
        } else {
            second.evaluate_default(&witness).unwrap();
        }
        let original = fixture.psbt.clone();
        fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(198_999);
        rejects(&fixture.prepare(0).unwrap(), &witness);
        fixture.psbt = original.clone();
        let mut bytes = fixture.psbt.unsigned_tx.output[0].script_pubkey.to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        fixture.psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(bytes);
        rejects(&fixture.prepare(0).unwrap(), &witness);
        fixture.psbt = original.clone();
        fixture.psbt.unsigned_tx.input[1].sequence = Sequence::from_height(17);
        rejects(&fixture.prepare(0).unwrap(), &witness);
        fixture.psbt = original.clone();
        fixture.psbt.unsigned_tx.lock_time = btc::absolute::LockTime::from_consensus(1001);
        rejects(&fixture.prepare(0).unwrap(), &witness);
        fixture.psbt = original;
        let mut parent = fixture.psbt.inputs[0].non_witness_utxo.clone().unwrap();
        parent.output[1].value = Amount::from_sat(100_001);
        fixture.update_parent(parent);
        rejects(&fixture.prepare(0).unwrap(), &witness);
    }
}

#[test]
fn source_constraints_check_all_inputs_csv_cltv_script_bytes_and_authorization() {
    let one_input = Fixture::new(
        program("constrained_source.simf"),
        1,
        &[(99_000, Destination::Return)],
    );
    let prepared = one_input.prepare(0).unwrap();
    prepared
        .evaluate_default(&source_witness(&prepared))
        .unwrap();
    let mut fixture = Fixture::new(
        program("constrained_source.simf"),
        8,
        &vec![(99_000, Destination::Return); 8],
    );
    let prepared = fixture.prepare(0).unwrap();
    let witness = source_witness(&prepared);
    prepared.evaluate_default(&witness).unwrap();
    fixture
        .prepare(7)
        .unwrap()
        .evaluate_default(&witness)
        .unwrap();
    let original = fixture.psbt.clone();
    for sequence in [Sequence::MAX, Sequence::from_height(15)] {
        fixture.psbt.unsigned_tx.input[7].sequence = sequence;
        rejects(&fixture.prepare(0).unwrap(), &witness);
    }
    fixture.psbt = original.clone();
    for lock_time in [999, 500_000_000] {
        fixture.psbt.unsigned_tx.lock_time = btc::absolute::LockTime::from_consensus(lock_time);
        rejects(&fixture.prepare(0).unwrap(), &witness);
    }
    fixture.psbt = original.clone();
    let mut script = fixture.psbt.unsigned_tx.output[7].script_pubkey.to_bytes();
    script[0] = 0x52;
    fixture.psbt.unsigned_tx.output[7].script_pubkey = ScriptBuf::from_bytes(script);
    rejects(&fixture.prepare(0).unwrap(), &witness);
    fixture.psbt = original.clone();
    let mut damaged = witness.clone();
    damaged[1] ^= 1;
    rejects(&fixture.prepare(0).unwrap(), &damaged);

    // Even an authenticated source cannot exceed the committed vout restriction.
    fixture.psbt = original;
    let mut parent = fixture.psbt.inputs[0].non_witness_utxo.clone().unwrap();
    parent.output.push(parent.output[0].clone());
    fixture.psbt.unsigned_tx.input[7].previous_output.vout = 8;
    fixture.update_parent(parent);
    let prepared = fixture.prepare(0).unwrap();
    rejects(&prepared, &source_witness(&prepared));
}

fn live_cli(args: &[String]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "requires an explicitly configured unfunded testnet4 policy service"]
fn live_cli_compiled_policy_prepare_approve_cosign_and_verified_finalize() {
    let service = std::env::var("SIMPLICITY_TEST_SERVICE_URL")
        .expect("Set SIMPLICITY_TEST_SERVICE_URL to an unfunded testnet4 policy service");
    let capabilities = live_cli(&[
        "policy".into(),
        "capabilities".into(),
        "--network".into(),
        "testnet4".into(),
        "--service".into(),
        service.clone(),
    ]);
    // This local integration fixture deliberately discovers the ephemeral test signer's key.
    let base = XOnlyPublicKey::from_slice(
        &hex::decode(capabilities["base_public_key_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let program = program("approvals_2_of_3.simf");
    let tweaked = live_cli(&[
        "policy".into(),
        "tweak".into(),
        "--network".into(),
        "testnet4".into(),
        "--program".into(),
        BASE64_STANDARD.encode(&program),
        "--redeem-script-hex".into(),
        "52".into(),
        "--base-public-key".into(),
        base.to_string(),
        "--service".into(),
        service.clone(),
    ]);
    let fixture = Fixture::with_base(program, 2, &[(199_000, Destination::Return)], base);
    let prepared = fixture.prepare(0).unwrap();
    assert_eq!(
        tweaked["public_key_hex"],
        prepared.context().service_pubkey().to_string()
    );
    let witness = BASE64_STANDARD.encode(approval_witness(&prepared, false));
    let policy_args = |operation: &str, psbt: &str, index: usize| {
        let mut args = vec![
            "policy".into(),
            operation.into(),
            "--network".into(),
            "testnet4".into(),
            "--profile-hash".into(),
            hex::encode(profile_hash()),
            "--program".into(),
            BASE64_STANDARD.encode(&fixture.program),
            "--redeem-script-hex".into(),
            hex::encode(&fixture.script),
            "--psbt".into(),
            psbt.into(),
            "--input-index".into(),
            index.to_string(),
            "--user-pubkey".into(),
            scalar_key(42).x_only_public_key().0.to_string(),
            "--user-leaf-hash-hex".into(),
            hex::encode([43; 32]),
            "--base-public-key".into(),
            base.to_string(),
            "--offline".into(),
        ];
        if matches!(operation, "prepare" | "evaluate" | "sign") {
            args.extend(["--service".into(), service.clone()]);
        }
        if matches!(operation, "evaluate" | "sign") {
            args.extend(["--witness".into(), witness.clone()]);
        }
        args
    };
    let mut psbt_hex = hex::encode(fixture.psbt.serialize());
    let local = live_cli(&policy_args("approval-hash", &psbt_hex, 0));
    let remote = live_cli(&policy_args("prepare", &psbt_hex, 0));
    assert_eq!(local, remote);
    assert_eq!(
        remote["context"],
        serde_json::to_value(prepared.summary()).unwrap()
    );
    let evaluated = live_cli(&policy_args("evaluate", &psbt_hex, 0));
    assert_eq!(evaluated["accepted"], true);
    assert_eq!(evaluated["context"], remote["context"]);
    for index in 0..2 {
        let signed = live_cli(&policy_args("sign", &psbt_hex, index));
        psbt_hex = signed["psbt_hex"].as_str().unwrap().to_owned();
    }
    let mut user_secret = [0; 32];
    user_secret[31] = 42;
    let key_file = common::SecretFile::new(user_secret);
    for index in 0..2 {
        let mut args = policy_args("user-sign", &psbt_hex, index);
        args.extend([
            "--secret-key-file".into(),
            key_file.0.to_str().unwrap().into(),
        ]);
        let signed = live_cli(&args);
        psbt_hex = signed["psbt_hex"].as_str().unwrap().to_owned();
    }
    let finalized = live_cli(&policy_args("finalize", &psbt_hex, 0));
    assert_eq!(finalized["finalized"], true);
    let tx: Transaction = btc::consensus::deserialize(
        &hex::decode(finalized["transaction_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(tx.input.iter().all(|input| input.witness.len() == 4));
    assert_eq!(tx.output, fixture.psbt.unsigned_tx.output);

    let mut changed = fixture.psbt.clone();
    changed.unsigned_tx.output[0].value = Amount::from_sat(198_999);
    let denied = reqwest::blocking::Client::new()
        .post(format!(
            "{service}/simplicity-unchained/policy/bitcoin/sign"
        ))
        .timeout(Duration::from_secs(30))
        .json(&serde_json::json!({
            "profile_hash": hex::encode(profile_hash()),
            "network": "testnet4",
            "program": BASE64_STANDARD.encode(&fixture.program),
            "redeem_script_hex": hex::encode(&fixture.script),
            "psbt_hex": hex::encode(changed.serialize()),
            "input_index": 0,
            "user_pubkey": scalar_key(42).x_only_public_key().0.to_string(),
            "user_leaf_hash_hex": hex::encode([43;32]),
            "witness": witness,
        }))
        .send()
        .unwrap();
    assert!(!denied.status().is_success());
    let body: serde_json::Value = denied.json().unwrap();
    assert!(body.get("error").is_some());
    assert!(body.get("signature_hex").is_none());
}
