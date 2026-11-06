mod common;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use simplicity::{
    ConstructNode,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bitcoin::{
        self as btc, Amount, Network, OutPoint, Psbt, PublicKey, ScriptBuf, TapNodeHash,
        Transaction, TxIn, TxOut, XOnlyPublicKey,
        consensus::serialize,
        hashes::Hash,
        key::TapTweak,
        secp256k1::{Keypair, Message, Parity, Secp256k1, SecretKey},
        taproot::LeafVersion,
    },
    node::CoreConstructible,
    types,
};
use simplicity_unchained_core::{
    policy::{PreparedPolicy, policy_cmr},
    utils::generate_p2tr_address_btc,
};
use simplicity_unchained_policy::{
    PROFILE_NAME, genesis_hash, manifest, profile_hash, signing_commitment, tweak_public_key,
};

const PREFIX: &str = "/simplicity-unchained/policy/bitcoin";

struct Fixture {
    program: Vec<u8>,
    script: Vec<u8>,
    psbt: Psbt,
    base: Keypair,
    user: Keypair,
    recovery: TapNodeHash,
}

impl Fixture {
    fn new() -> Self {
        let program = types::Context::with_context(|ctx| {
            Arc::<ConstructNode>::unit(&ctx)
                .finalize_types()
                .unwrap()
                .to_vec_without_witness()
        });
        let script = vec![0x52];
        let secp = Secp256k1::new();
        let key =
            |byte| Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap());
        let base = key(1);
        let user = key(2);
        let recovery = TapNodeHash::from_byte_array([3; 32]);
        let cmr = policy_cmr(&program).unwrap();
        let service = tweak_public_key(
            base.x_only_public_key().0,
            cmr.to_byte_array(),
            &script,
            Network::Testnet4,
        )
        .unwrap();
        let full = |key: XOnlyPublicKey| PublicKey::new(key.public_key(Parity::Even));
        let (address, _) = generate_p2tr_address_btc(
            &full(service),
            &full(user.x_only_public_key().0),
            recovery,
            Network::Testnet4,
        )
        .unwrap();
        let parent = Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: address.script_pubkey(),
                };
                2
            ],
        };
        let tx = Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::ZERO,
            input: (0..2)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(parent.compute_txid(), vout),
                    ..TxIn::default()
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(199_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            input.non_witness_utxo = Some(parent.clone());
            input.witness_utxo = Some(parent.output[index].clone());
        }
        Self {
            program,
            script,
            psbt,
            base,
            user,
            recovery,
        }
    }

    fn prepared(&self) -> PreparedPolicy {
        PreparedPolicy::new(
            &self.program,
            &self.psbt,
            0,
            &self.script,
            Network::Testnet4,
            self.base.x_only_public_key().0,
            self.user.x_only_public_key().0,
            self.recovery,
        )
        .unwrap()
    }

    fn capabilities(&self) -> Value {
        let mut limits = serde_json::to_value(&manifest().limits).unwrap();
        limits["max_body_bytes"] = json!(2 * 1024 * 1024);
        limits["max_blocking_jobs"] = json!(8);
        json!({
            "profile": PROFILE_NAME,
            "profile_hash": hex::encode(profile_hash()),
            "network": "testnet4",
            "genesis_hash": hex::encode(genesis_hash(Network::Testnet4).unwrap()),
            "base_public_key_hex": self.base.x_only_public_key().0.to_string(),
            "manifest": manifest(),
            "limits": limits,
            "provenance": "parent-txid-verified",
        })
    }

    fn args(&self, operation: &str) -> Vec<String> {
        [
            "policy".into(),
            operation.into(),
            "--network".into(),
            "testnet4".into(),
            "--program".into(),
            BASE64_STANDARD.encode(&self.program),
            "--redeem-script-hex".into(),
            hex::encode(&self.script),
            "--psbt".into(),
            hex::encode(self.psbt.serialize()),
            "--input-index".into(),
            "0".into(),
            "--user-pubkey".into(),
            self.user.public_key().to_string(),
            "--user-leaf-hash-hex".into(),
            hex::encode(self.recovery.to_byte_array()),
            "--base-public-key".into(),
            self.base.x_only_public_key().0.to_string(),
        ]
        .into()
    }

    fn sign_response(&self, include_user: bool) -> Value {
        let prepared = self.prepared();
        let context = prepared.context();
        let commitment = signing_commitment(
            prepared.cmr().to_byte_array(),
            &self.script,
            Network::Testnet4,
        )
        .unwrap();
        let tweaked = self
            .base
            .tap_tweak(
                &Secp256k1::new(),
                Some(TapNodeHash::from_byte_array(commitment)),
            )
            .to_keypair();
        let message = Message::from_digest(context.cooperative_sighash_default());
        let signature = Secp256k1::new().sign_schnorr(&message, &tweaked);
        let leaf_hash = context.cooperative_leaf_hash();
        let mut psbt = self.psbt.clone();
        psbt.inputs[0].tap_script_sigs.insert(
            (context.service_pubkey(), leaf_hash),
            btc::taproot::Signature {
                signature,
                sighash_type: btc::TapSighashType::Default,
            },
        );
        if include_user {
            psbt.inputs[0].tap_script_sigs.insert(
                (context.user_pubkey(), leaf_hash),
                btc::taproot::Signature {
                    signature: Secp256k1::new().sign_schnorr(&message, &self.user),
                    sighash_type: btc::TapSighashType::Default,
                },
            );
        }
        psbt.inputs[0].tap_scripts.insert(
            context.control_block().clone(),
            (context.cooperative_script().clone(), LeafVersion::TapScript),
        );
        json!({
            "psbt_hex": hex::encode(psbt.serialize()),
            "signature_hex": hex::encode(signature.as_ref()),
            "public_key_hex": context.service_pubkey().to_string(),
            "input_index": 0,
            "context": prepared.summary(),
            "execution_cost_milliweight": prepared.evaluate_default(&[]).unwrap().cost_milliweight,
        })
    }
}

struct Reply {
    method: &'static str,
    path: String,
    status: u16,
    body: Vec<u8>,
}

impl Reply {
    fn json(method: &'static str, operation: &str, body: Value) -> Self {
        Self {
            method,
            path: format!("{PREFIX}/{operation}"),
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
}

struct MockServer {
    origin: String,
    thread: JoinHandle<Vec<(String, Vec<u8>)>>,
}

impl MockServer {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let deadline = Instant::now() + Duration::from_secs(10);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connected) => break connected,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "Expected HTTP request was not made"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("Mock accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(
                    headers.starts_with(&format!("{} {} HTTP/1.1", reply.method, reply.path)),
                    "Unexpected request: {headers}"
                );
                write!(
                    stream,
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
                    reply.status,
                    reply.body.len()
                )
                .unwrap();
                stream.write_all(&reply.body).unwrap();
                requests.push((headers, body));
            }
            requests
        });
        Self { origin, thread }
    }

    fn finish(self) -> Vec<(String, Vec<u8>)> {
        self.thread.join().unwrap()
    }
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "Request ended before headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "Request body ended early");
        bytes.extend_from_slice(&chunk[..count]);
    }
    (headers, bytes[header_end..].to_vec())
}

fn invoke(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn failure(output: Output, expected: &str) -> Value {
    assert!(!output.status.success(), "Command unexpectedly succeeded");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let error = value["error"].as_str().expect("Stable JSON error output");
    assert!(error.contains(expected), "Expected {expected}, got {error}");
    assert!(value.get("signature_hex").is_none());
    value
}

fn set_arg(args: &mut [String], name: &str, value: &str) {
    let index = args.iter().position(|arg| arg == name).unwrap();
    args[index + 1] = value.to_owned();
}

fn remote_args(fixture: &Fixture, operation: &str, origin: &str) -> Vec<String> {
    let mut args = fixture.args(operation);
    args.extend(["--service".into(), origin.into()]);
    if matches!(operation, "evaluate" | "sign") {
        args.extend(["--witness".into(), "".into()]);
    }
    args
}

#[test]
fn policy_help_exposes_all_primary_operations() {
    let result = invoke(&["policy".into(), "--help".into()]);
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    for name in [
        "capabilities",
        "tweak",
        "prepare",
        "evaluate",
        "approval-hash",
        "sign",
        "address",
        "build-csv-leaf",
        "user-sign",
        "finalize",
    ] {
        assert!(help.contains(name));
    }
}

#[test]
fn local_approval_uses_the_shared_verified_constructor_without_contacting_service() {
    let fixture = Fixture::new();
    let expected = serde_json::to_value(fixture.prepared().summary()).unwrap();
    let mut args = fixture.args("approval-hash");
    args.push("--offline".into());
    let actual = success(invoke(&args));
    assert_eq!(actual, json!({ "context": expected }));
    assert_eq!(actual["context"]["provenance"], "parent-txid-verified");
    assert_eq!(actual["context"]["chain_status_verified"], false);
    set_arg(&mut args, "--input-index", "1");
    let another_input = success(invoke(&args));
    assert_eq!(
        actual["context"]["policy_transaction_approval_hash"],
        another_input["context"]["policy_transaction_approval_hash"]
    );
    assert_ne!(
        actual["context"]["policy_approval_hash"],
        another_input["context"]["policy_approval_hash"]
    );
    set_arg(&mut args, "--input-index", "0");
    let mut mutated = fixture.psbt.clone();
    mutated.unsigned_tx.output[0].value = Amount::from_sat(198_999);
    set_arg(&mut args, "--psbt", &hex::encode(mutated.serialize()));
    let changed = success(invoke(&args));
    assert_ne!(
        actual["context"]["policy_approval_hash"],
        changed["context"]["policy_approval_hash"]
    );
    assert_ne!(
        actual["context"]["policy_transaction_approval_hash"],
        changed["context"]["policy_transaction_approval_hash"]
    );
}

#[test]
fn profile_fingerprint_network_and_base64_fail_closed_before_network_io() {
    let fixture = Fixture::new();
    for (flag, value, expected) in [
        ("--network", "regtest", "Unsupported policy network"),
        ("--network", "Testnet4", "Unsupported policy network"),
        ("--program", "not-base64!", "standard-base64"),
        ("--base-public-key", "00", "Public key must be"),
        ("--user-leaf-hash-hex", "00", "exactly 32 bytes"),
    ] {
        let mut args = fixture.args("approval-hash");
        set_arg(&mut args, flag, value);
        failure(invoke(&args), expected);
    }
    for (flag, value, expected) in [
        ("--profile", "legacy", "Unsupported policy profile"),
        (
            "--profile-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "compiled registry",
        ),
    ] {
        let mut args = fixture.args("approval-hash");
        args.extend([flag.into(), value.into()]);
        failure(invoke(&args), expected);
    }
}

#[test]
fn every_input_requires_full_parent_evidence_even_when_witness_utxo_is_present() {
    let mut fixture = Fixture::new();
    fixture.psbt.inputs[1].non_witness_utxo = None;
    // Both inputs share a parent. An available full parent can be reused safely.
    success(invoke(&fixture.args("approval-hash")));
    fixture.psbt.inputs[1].non_witness_utxo = fixture.psbt.inputs[0].non_witness_utxo.take();
    success(invoke(&fixture.args("approval-hash")));
    for input in &mut fixture.psbt.inputs {
        input.non_witness_utxo = None;
    }
    let mut args = fixture.args("prepare");
    args.extend([
        "--offline".into(),
        "--service".into(),
        "http://127.0.0.1:1".into(),
    ]);
    failure(
        invoke(&args),
        "missing non_witness_utxo full parent evidence",
    );
}

#[test]
fn parent_content_is_verified_and_missing_witness_utxo_is_populated() {
    let mut fixture = Fixture::new();
    let expected = fixture.prepared().summary();
    fixture.psbt.inputs[0].witness_utxo = None;
    let result = success(invoke(&fixture.args("approval-hash")));
    assert_eq!(result["context"], serde_json::to_value(expected).unwrap());

    fixture.psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::new(),
    });
    failure(
        invoke(&fixture.args("approval-hash")),
        "conflicts with verified parent",
    );
    fixture.psbt.inputs[0].witness_utxo = None;
    fixture.psbt.inputs[0]
        .non_witness_utxo
        .as_mut()
        .unwrap()
        .output[0]
        .value = Amount::from_sat(1);
    failure(
        invoke(&fixture.args("approval-hash")),
        "parent transaction txid mismatch",
    );
}

#[test]
fn capabilities_checks_full_manifest_network_profile_and_genesis() {
    let fixture = Fixture::new();
    let expected = fixture.capabilities();
    let server = MockServer::start(vec![Reply::json("GET", "capabilities", expected.clone())]);
    let args = [
        "policy".into(),
        "capabilities".into(),
        "--network".into(),
        "testnet4".into(),
        "--service".into(),
        server.origin.clone(),
    ];
    assert_eq!(success(invoke(&args)), expected);
    server.finish();

    for (field, replacement, expected_error) in [
        ("profile", json!("legacy"), "profile mismatch"),
        ("profile_hash", json!("00"), "fingerprint mismatch"),
        ("network", json!("testnet"), "network mismatch"),
        ("genesis_hash", json!("00"), "genesis hash mismatch"),
        (
            "provenance",
            json!("confirmed"),
            "verification provenance mismatch",
        ),
    ] {
        let mut caps = fixture.capabilities();
        caps[field] = replacement;
        let server = MockServer::start(vec![Reply::json("GET", "capabilities", caps)]);
        let mut args = args.clone();
        set_arg(&mut args, "--service", &server.origin);
        failure(invoke(&args), expected_error);
        server.finish();
    }
    for (field, child, value, expected_error) in [
        ("manifest", "status", json!("wrong"), "manifest differs"),
        (
            "manifest",
            "unknown_semantic_field",
            json!(true),
            "manifest differs",
        ),
        ("limits", "max_inputs", json!(9), "limits differ"),
    ] {
        let mut caps = fixture.capabilities();
        caps[field][child] = value;
        let server = MockServer::start(vec![Reply::json("GET", "capabilities", caps)]);
        let mut args = args.clone();
        set_arg(&mut args, "--service", &server.origin);
        failure(invoke(&args), expected_error);
        server.finish();
    }
}

#[test]
fn tweak_is_profile_bound_and_validated_locally_before_address_generation() {
    let fixture = Fixture::new();
    let prepared = fixture.prepared();
    let context = prepared.context();
    let expected = json!({
        "profile": PROFILE_NAME,
        "profile_hash": hex::encode(profile_hash()),
        "network": "testnet4",
        "genesis_hash": hex::encode(genesis_hash(Network::Testnet4).unwrap()),
        "cmr": hex::encode(context.cmr()),
        "signing_commitment": hex::encode(context.signing_commitment()),
        "public_key_hex": context.service_pubkey().to_string(),
        "base_public_key_hex": fixture.base.x_only_public_key().0.to_string(),
    });
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "tweak", expected.clone()),
    ]);
    let args = [
        "policy".into(),
        "tweak".into(),
        "--network".into(),
        "testnet4".into(),
        "--service".into(),
        server.origin.clone(),
        "--program".into(),
        BASE64_STANDARD.encode(&fixture.program),
        "--redeem-script-hex".into(),
        hex::encode(&fixture.script),
        "--base-public-key".into(),
        fixture.base.x_only_public_key().0.to_string(),
    ];
    assert_eq!(success(invoke(&args)), expected);
    let requests = server.finish();
    let body: Value = serde_json::from_slice(&requests[1].1).unwrap();
    assert_eq!(
        body,
        json!({
            "profile_hash": hex::encode(profile_hash()),
            "network": "testnet4",
            "program": BASE64_STANDARD.encode(&fixture.program),
            "redeem_script_hex": hex::encode(&fixture.script),
        })
    );
}

#[test]
fn prepare_matches_local_digests_and_uses_the_new_http_field_names() {
    let fixture = Fixture::new();
    let expected = json!({ "context": fixture.prepared().summary() });
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "prepare", expected.clone()),
    ]);
    assert_eq!(
        success(invoke(&remote_args(&fixture, "prepare", &server.origin))),
        expected
    );
    let requests = server.finish();
    let body: Value = serde_json::from_slice(&requests[1].1).unwrap();
    assert_eq!(body["psbt_hex"], hex::encode(fixture.psbt.serialize()));
    assert_eq!(body["input_index"], 0);
    assert_eq!(body["program"], BASE64_STANDARD.encode(&fixture.program));
    assert_eq!(body["redeem_script_hex"], "52");
    assert_eq!(body["user_leaf_hash_hex"], hex::encode([3; 32]));
    assert_eq!(body["user_pubkey"], fixture.user.public_key().to_string());
    assert!(body.get("witness").is_none());
    assert!(body.get("psbt").is_none());
    assert!(body.get("user_leaf_hash").is_none());
}

#[test]
fn remote_digest_or_signer_key_mismatches_are_not_accepted() {
    let fixture = Fixture::new();
    let mut context = serde_json::to_value(fixture.prepared().summary()).unwrap();
    context["policy_transaction_approval_hash"] = json!(hex::encode([9; 32]));
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "prepare", json!({ "context": context })),
    ]);
    failure(
        invoke(&remote_args(&fixture, "prepare", &server.origin)),
        "differ from the locally verified context",
    );
    server.finish();

    let mut caps = fixture.capabilities();
    caps["base_public_key_hex"] = json!(fixture.user.x_only_public_key().0.to_string());
    let server = MockServer::start(vec![Reply::json("GET", "capabilities", caps)]);
    failure(
        invoke(&remote_args(&fixture, "prepare", &server.origin)),
        "base public key does not match",
    );
    server.finish();
}

#[test]
fn evaluate_executes_a_real_subcommand_and_rejects_success_shaped_denial() {
    let fixture = Fixture::new();
    for accepted in [true, false] {
        let expected = json!({
            "accepted": accepted,
            "context": fixture.prepared().summary(),
            "execution_cost_milliweight": fixture.prepared().evaluate_default(&[]).unwrap().cost_milliweight,
        });
        let server = MockServer::start(vec![
            Reply::json("GET", "capabilities", fixture.capabilities()),
            Reply::json("POST", "evaluate", expected.clone()),
        ]);
        let result = invoke(&remote_args(&fixture, "evaluate", &server.origin));
        if accepted {
            assert_eq!(success(result), expected);
        } else {
            failure(result, "did not accept the policy");
        }
        let requests = server.finish();
        let body: Value = serde_json::from_slice(&requests[1].1).unwrap();
        assert_eq!(body["witness"], "");
    }
}

#[test]
fn sign_verifies_the_actual_cooperative_signature_and_psbt_metadata() {
    let fixture = Fixture::new();
    let expected = fixture.sign_response(false);
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "sign", expected.clone()),
    ]);
    assert_eq!(
        success(invoke(&remote_args(&fixture, "sign", &server.origin))),
        expected
    );
    server.finish();
    for (field, value, expected_error) in [
        (
            "signature_hex",
            json!(hex::encode([0; 64])),
            "invalid cooperative signature",
        ),
        ("input_index", json!(1), "unexpected input index"),
        (
            "execution_cost_milliweight",
            json!(10_000_001),
            "above the policy execution limit",
        ),
        (
            "execution_cost_milliweight",
            json!(expected["execution_cost_milliweight"].as_u64().unwrap() + 1),
            "differs from local policy evaluation",
        ),
    ] {
        let mut invalid = fixture.sign_response(false);
        invalid[field] = value;
        let server = MockServer::start(vec![
            Reply::json("GET", "capabilities", fixture.capabilities()),
            Reply::json("POST", "sign", invalid),
        ]);
        failure(
            invoke(&remote_args(&fixture, "sign", &server.origin)),
            expected_error,
        );
        server.finish();
    }
    let mut invalid = fixture.sign_response(false);
    let mut psbt =
        Psbt::deserialize(&hex::decode(invalid["psbt_hex"].as_str().unwrap()).unwrap()).unwrap();
    psbt.unsigned_tx.output[0].value = Amount::from_sat(198_999);
    invalid["psbt_hex"] = json!(hex::encode(psbt.serialize()));
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "sign", invalid),
    ]);
    failure(
        invoke(&remote_args(&fixture, "sign", &server.origin)),
        "Service changed the transaction",
    );
    server.finish();
}

#[test]
fn service_errors_have_stable_json_and_nonzero_status_without_signing_retries() {
    let fixture = Fixture::new();
    for status in [400, 413, 422, 503, 504] {
        let mut denied = Reply::json("POST", "sign", json!({ "error": "explicit denial" }));
        denied.status = status;
        let server = MockServer::start(vec![
            Reply::json("GET", "capabilities", fixture.capabilities()),
            denied,
        ]);
        let error = failure(
            invoke(&remote_args(&fixture, "sign", &server.origin)),
            &format!("HTTP {status}"),
        );
        assert!(error["error"].as_str().unwrap().contains("explicit denial"));
        assert_eq!(server.finish().len(), 2);
    }
}

#[test]
fn malformed_success_responses_and_unexpected_redirects_fail_explicitly() {
    let fixture = Fixture::new();
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "prepare", json!({ "accepted": true })),
    ]);
    failure(
        invoke(&remote_args(&fixture, "prepare", &server.origin)),
        "Invalid policy service response JSON/shape",
    );
    server.finish();

    let mut redirect = Reply::json("GET", "capabilities", json!({}));
    redirect.status = 302;
    let server = MockServer::start(vec![redirect]);
    failure(
        invoke(&remote_args(&fixture, "prepare", &server.origin)),
        "HTTP 302",
    );
    server.finish();
}

#[test]
fn policy_service_signature_flows_through_policy_user_sign_and_verified_finalize() {
    let mut fixture = Fixture::new();
    fixture.psbt.unsigned_tx.input.truncate(1);
    fixture.psbt.inputs.truncate(1);
    fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(99_000);
    let service_response = fixture.sign_response(false);
    let server = MockServer::start(vec![
        Reply::json("GET", "capabilities", fixture.capabilities()),
        Reply::json("POST", "sign", service_response),
    ]);
    let signed = success(invoke(&remote_args(&fixture, "sign", &server.origin)));
    server.finish();
    let key_file = common::SecretFile::new([2; 32]);
    let mut args = fixture.args("user-sign");
    set_arg(&mut args, "--psbt", signed["psbt_hex"].as_str().unwrap());
    args.extend([
        "--secret-key-file".into(),
        key_file.0.to_str().unwrap().into(),
    ]);
    let user_signed = success(invoke(&args));
    let mut args = fixture.args("finalize");
    set_arg(
        &mut args,
        "--psbt",
        user_signed["psbt_hex"].as_str().unwrap(),
    );
    let finalized = success(invoke(&args));
    assert_eq!(finalized["finalized"], true);
    let tx: Transaction = btc::consensus::deserialize(
        &hex::decode(finalized["transaction_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(tx.input[0].witness.len(), 4);
    assert_eq!(tx.output, fixture.psbt.unsigned_tx.output);
}

#[test]
fn policy_funding_address_matches_verified_context_and_defaults_to_testnet4() {
    let fixture = Fixture::new();
    let args = vec![
        "policy".into(),
        "address".into(),
        "--program".into(),
        BASE64_STANDARD.encode(&fixture.program),
        "--redeem-script-hex".into(),
        hex::encode(&fixture.script),
        "--base-public-key".into(),
        fixture.base.x_only_public_key().0.to_string(),
        "--user-pubkey".into(),
        fixture.user.x_only_public_key().0.to_string(),
        "--user-leaf-hash-hex".into(),
        hex::encode(fixture.recovery.to_byte_array()),
    ];
    let address = success(invoke(&args));
    assert_eq!(address["network"], "testnet4");
    assert_eq!(address["profile_hash"], hex::encode(profile_hash()));
    assert_eq!(
        address["script_pubkey_hex"],
        hex::encode(
            fixture.psbt.inputs[0]
                .witness_utxo
                .as_ref()
                .unwrap()
                .script_pubkey
                .as_bytes()
        ),
    );
    let mut other_network = args.clone();
    other_network.extend(["--network".into(), "testnet".into()]);
    let different = success(invoke(&other_network));
    assert_ne!(different["script_pubkey_hex"], address["script_pubkey_hex"]);
    let mut bad_profile = args;
    bad_profile.extend(["--profile".into(), "legacy".into()]);
    failure(invoke(&bad_profile), "Unsupported policy profile");
}

#[test]
fn policy_csv_leaf_accepts_xonly_keys_and_requires_a_real_delay() {
    let fixture = Fixture::new();
    let args = vec![
        "policy".into(),
        "build-csv-leaf".into(),
        "--user-pubkey".into(),
        fixture.user.x_only_public_key().0.to_string(),
        "--timelock".into(),
        "144".into(),
    ];
    let recovery = success(invoke(&args));
    let script = ScriptBuf::from_hex(recovery["script"].as_str().unwrap()).unwrap();
    assert_eq!(
        recovery["leaf_hash"],
        hex::encode(btc::TapLeafHash::from_script(&script, LeafVersion::TapScript).to_byte_array()),
    );
    let mut bad_delay = args;
    set_arg(&mut bad_delay, "--timelock", "0");
    failure(
        invoke(&bad_delay),
        "Recovery timelock must be at least one block",
    );
}

#[test]
fn user_sign_rejects_wrong_key_and_unverified_or_different_contracts() {
    let mut fixture = Fixture::new();
    let wrong_key = common::SecretFile::new([4; 32]);
    let mut args = fixture.args("user-sign");
    args.extend([
        "--secret-key-file".into(),
        wrong_key.0.to_str().unwrap().into(),
    ]);
    failure(invoke(&args), "User secret key does not match");
    for input in &mut fixture.psbt.inputs {
        input.non_witness_utxo = None;
    }
    set_arg(&mut args, "--psbt", &hex::encode(fixture.psbt.serialize()));
    failure(
        invoke(&args),
        "missing non_witness_utxo full parent evidence",
    );

    let fixture = Fixture::new();
    let mut args = fixture.args("user-sign");
    args.extend([
        "--secret-key-file".into(),
        wrong_key.0.to_str().unwrap().into(),
    ]);
    set_arg(&mut args, "--redeem-script-hex", "53");
    failure(invoke(&args), "Failed to construct verified policy context");
}

#[test]
fn policy_finalize_requires_valid_signatures_and_committed_leaf_metadata() {
    let mut fixture = Fixture::new();
    fixture.psbt.unsigned_tx.input.truncate(1);
    fixture.psbt.inputs.truncate(1);
    fixture.psbt.unsigned_tx.output[0].value = Amount::from_sat(99_000);
    let mut args = fixture.args("finalize");
    failure(invoke(&args), "no committed canonical multisig leaf");
    let signed = fixture.sign_response(true);
    let signed_psbt =
        Psbt::deserialize(&hex::decode(signed["psbt_hex"].as_str().unwrap()).unwrap()).unwrap();
    set_arg(&mut args, "--psbt", signed["psbt_hex"].as_str().unwrap());
    assert_eq!(success(invoke(&args))["finalized"], true);

    let prepared = fixture.prepared();
    let signature_key = (
        prepared.context().user_pubkey(),
        prepared.context().cooperative_leaf_hash(),
    );
    let mut missing = signed_psbt.clone();
    missing.inputs[0].tap_script_sigs.remove(&signature_key);
    set_arg(&mut args, "--psbt", &hex::encode(missing.serialize()));
    failure(invoke(&args), "missing tap_script_sig");

    let mut invalid = signed_psbt.clone();
    invalid.inputs[0]
        .tap_script_sigs
        .get_mut(&signature_key)
        .unwrap()
        .signature = Secp256k1::new().sign_schnorr(&Message::from_digest([0; 32]), &fixture.user);
    set_arg(&mut args, "--psbt", &hex::encode(invalid.serialize()));
    failure(invoke(&args), "invalid tap_script_sig");

    let mut wrong_leaf = signed_psbt.clone();
    wrong_leaf.inputs[0]
        .tap_scripts
        .values_mut()
        .next()
        .unwrap()
        .0 = ScriptBuf::new();
    set_arg(&mut args, "--psbt", &hex::encode(wrong_leaf.serialize()));
    failure(invoke(&args), "no committed canonical multisig leaf");

    let mut wrong_sighash = signed_psbt.clone();
    wrong_sighash.inputs[0]
        .tap_script_sigs
        .get_mut(&signature_key)
        .unwrap()
        .sighash_type = btc::TapSighashType::All;
    set_arg(&mut args, "--psbt", &hex::encode(wrong_sighash.serialize()));
    failure(invoke(&args), "Failed to construct verified policy context");

    let mut missing_parent = signed_psbt;
    missing_parent.inputs[0].non_witness_utxo = None;
    set_arg(
        &mut args,
        "--psbt",
        &hex::encode(missing_parent.serialize()),
    );
    failure(
        invoke(&args),
        "missing non_witness_utxo full parent evidence",
    );
}

#[test]
fn policy_user_sign_and_finalize_verify_every_input() {
    let fixture = Fixture::new();
    let mut psbt = fixture.psbt.clone();
    let secp = Secp256k1::new();
    let commitment = fixture.prepared().context().signing_commitment();
    let service_key = fixture
        .base
        .tap_tweak(&secp, Some(TapNodeHash::from_byte_array(commitment)))
        .to_keypair();
    for index in 0..psbt.inputs.len() {
        let prepared = PreparedPolicy::new(
            &fixture.program,
            &fixture.psbt,
            index,
            &fixture.script,
            Network::Testnet4,
            fixture.base.x_only_public_key().0,
            fixture.user.x_only_public_key().0,
            fixture.recovery,
        )
        .unwrap();
        let context = prepared.context();
        psbt.inputs[index].tap_script_sigs.insert(
            (context.service_pubkey(), context.cooperative_leaf_hash()),
            btc::taproot::Signature {
                signature: secp.sign_schnorr(
                    &Message::from_digest(context.cooperative_sighash_default()),
                    &service_key,
                ),
                sighash_type: btc::TapSighashType::Default,
            },
        );
        psbt.inputs[index].tap_scripts.insert(
            context.control_block().clone(),
            (context.cooperative_script().clone(), LeafVersion::TapScript),
        );
    }
    let key_file = common::SecretFile::new([2; 32]);
    let mut hex_psbt = hex::encode(psbt.serialize());
    for index in 0..2 {
        let mut args = fixture.args("user-sign");
        set_arg(&mut args, "--input-index", &index.to_string());
        set_arg(&mut args, "--psbt", &hex_psbt);
        args.extend([
            "--secret-key-file".into(),
            key_file.0.to_str().unwrap().into(),
        ]);
        hex_psbt = success(invoke(&args))["psbt_hex"].as_str().unwrap().into();
        if index == 0 {
            let mut finalize = fixture.args("finalize");
            set_arg(&mut finalize, "--psbt", &hex_psbt);
            failure(invoke(&finalize), "Input 1 missing tap_script_sig");
        }
    }
    let mut args = fixture.args("finalize");
    set_arg(&mut args, "--psbt", &hex_psbt);
    let output = success(invoke(&args));
    assert_eq!(output["inputs"], 2);
    let tx: Transaction = btc::consensus::deserialize(
        &hex::decode(output["transaction_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(tx.input.iter().all(|input| input.witness.len() == 4));
    assert_eq!(tx.output, fixture.psbt.unsigned_tx.output);
}

#[test]
fn configured_esplora_fetches_full_raw_parent_once_and_verifies_before_service_io() {
    let mut fixture = Fixture::new();
    let parent = fixture.psbt.inputs[0].non_witness_utxo.clone().unwrap();
    let expected = fixture.prepared().summary();
    for input in &mut fixture.psbt.inputs {
        input.non_witness_utxo = None;
        input.witness_utxo = None;
    }
    let explorer = MockServer::start(vec![Reply {
        method: "GET",
        path: format!("/tx/{}/raw", parent.compute_txid()),
        status: 200,
        body: serialize(&parent),
    }]);
    let mut args = fixture.args("approval-hash");
    args.extend(["--esplora-url".into(), explorer.origin.clone()]);
    assert_eq!(
        success(invoke(&args))["context"],
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(explorer.finish().len(), 1);

    let mut wrong_parent = parent;
    wrong_parent.output[0].value = Amount::from_sat(1);
    let explorer = MockServer::start(vec![Reply {
        method: "GET",
        path: format!(
            "/tx/{}/raw",
            fixture.psbt.unsigned_tx.input[0].previous_output.txid
        ),
        status: 200,
        body: serialize(&wrong_parent),
    }]);
    set_arg(&mut args, "--esplora-url", &explorer.origin);
    failure(invoke(&args), "parent transaction txid mismatch");
    explorer.finish();
}
