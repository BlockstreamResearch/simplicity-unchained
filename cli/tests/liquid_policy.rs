#[allow(dead_code)]
mod common {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../policy/tests/common/liquid.rs"
    ));
}
use common::*;
use serde_json::{Value, json};
use simplicity::base64::{Engine, engine::general_purpose::STANDARD};
use simplicity_unchained_policy::liquid::{self as policy, elements::encode::serialize};
use std::{path::PathBuf, process::Command};

struct File(PathBuf);
impl File {
    fn new(label: &str, data: &[u8]) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "target-liquid-test-{}-{label}.json",
            std::process::id()
        ));
        std::fs::write(&path, data).unwrap();
        Self(path)
    }
}
impl Drop for File {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}
fn request(f: &Fixture) -> Value {
    json!({"profile":"liquid-policy-v1","network":"liquidtestnet","program":STANDARD.encode(&f.program),"redeem_script_hex":hex::encode(&f.data),"base_public_key_hex":f.base.to_string(),"pset_hex":hex::encode(serialize(&f.pset)),"input_index":0,"user_pubkey":f.user.to_string(),"user_leaf_hash_hex":hex::encode(f.recovery.to_byte_array()),"witness":""})
}
fn run(op: &str, file: &File) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(["liquid-policy", op, "--request-file"])
        .arg(&file.0)
        .output()
        .unwrap()
}
#[test]
fn liquid_cli_registry_prepare_evaluate_address_finalize_and_rejections() {
    let mut f = Fixture::new();
    let registry = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(["liquid-policy", "registry"])
        .output()
        .unwrap();
    assert!(registry.status.success());
    let registry: Value = serde_json::from_slice(&registry.stdout).unwrap();
    assert_eq!(
        registry["profile_hash"],
        hex::encode(policy::profile_hash())
    );
    let file = File::new("unsigned", &serde_json::to_vec(&request(&f)).unwrap());
    for operation in ["prepare", "approval-hash", "evaluate", "tweak", "address"] {
        let output = run(operation, &file);
        assert!(
            output.status.success(),
            "{operation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        if let Some(context) = response.get("context") {
            assert_eq!(
                context,
                &serde_json::to_value(f.context(0).unwrap().summary()).unwrap()
            );
        }
    }
    f.sign_all();
    let signed = File::new("signed", &serde_json::to_vec(&request(&f)).unwrap());
    let key = File::new(
        "user-key",
        hex::encode(f.user_secret.secret_bytes()).as_bytes(),
    );
    let cosigned = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(["liquid-policy", "user-sign", "--request-file"])
        .arg(&signed.0)
        .arg("--secret-key-file")
        .arg(&key.0)
        .output()
        .unwrap();
    assert!(
        cosigned.status.success(),
        "{}",
        String::from_utf8_lossy(&cosigned.stderr)
    );
    let cosigned: Value = serde_json::from_slice(&cosigned.stdout).unwrap();
    assert_eq!(cosigned["public_key_hex"], f.user.to_string());
    let secp = policy::elements::secp256k1_zkp::Secp256k1::new();
    let blinding =
        policy::elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &f.blinding_secret);
    let creation = json!({
        "network":"liquidtestnet",
        "inputs":f.pset.inputs().iter().map(|i|json!({"txid":i.previous_txid.to_string(),"vout":i.previous_output_index,"parent_tx_hex":hex::encode(serialize(i.non_witness_utxo.as_ref().unwrap())),"blinding_secret_key_hex":hex::encode(f.blinding_secret.secret_bytes())})).collect::<Vec<_>>(),
        "outputs":f.pset.outputs().iter().map(|o|json!({"address":if o.script_pubkey.is_empty() {"fee".into()} else {policy::elements::Address::from_script(&o.script_pubkey,Some(blinding),f.network.address_params()).unwrap().to_string()},"asset_id":o.asset.unwrap().to_string(),"value_sat":o.amount.unwrap()})).collect::<Vec<_>>(),
    });
    let create_file = File::new("create", &serde_json::to_vec(&creation).unwrap());
    let created = run("create", &create_file);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let p = policy::elements::encode::deserialize(
        &hex::decode(created["pset_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(f.context_for(&p, 0).is_ok());
    let output = run("finalize", &signed);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["finalized"],
        true
    );
    let mut wrong = request(&f);
    wrong["profile_hash"] = json!(hex::encode(simplicity_unchained_policy::profile_hash()));
    let bad = File::new("profile", &serde_json::to_vec(&wrong).unwrap());
    assert!(!run("prepare", &bad).status.success());
    let mut p = f.pset.clone();
    p.inputs_mut()[0].amount = Some(1);
    let mut wrong = request(&f);
    wrong["pset_hex"] = hex::encode(serialize(&p)).into();
    let bad = File::new("disclosure", &serde_json::to_vec(&wrong).unwrap());
    assert!(!run("prepare", &bad).status.success());
}

#[test]
fn liquid_cli_remote_sign_independently_checks_complete_context_and_signature() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };
    let mut f = Fixture::new();
    let unsigned = request(&f);
    let prepared = policy::PreparedPolicy::new(
        &f.program, &f.pset, 0, &f.data, f.network, f.base, f.user, f.recovery,
    )
    .unwrap();
    let context = prepared.context().clone();
    let cost = prepared.evaluate_default(&[]).unwrap();
    let secret = f.service_secret();
    let sig = policy::add_signature(&context, &mut f.pset, secret, true).unwrap();
    let capabilities = json!({"profile":"liquid-policy-v1","profile_hash":hex::encode(policy::profile_hash()),"network":"liquidtestnet","genesis_hash":hex::encode(f.network.genesis_hash().to_byte_array()),"base_public_key_hex":f.base.to_string(),"manifest":policy::manifest()});
    let signed = json!({"pset_hex":hex::encode(serialize(&f.pset)),"signature_hex":hex::encode(sig.sig.as_ref()),"public_key_hex":context.cooperative().service_pubkey.to_string(),"input_index":0,"context":context.summary(),"execution_cost_milliweight":cost});
    for tamper in [false, true] {
        let mut response = signed.clone();
        if tamper {
            response["signature_hex"] = json!(hex::encode([1; 64]));
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let caps = capabilities.clone();
        let server = std::thread::spawn(move || {
            for response in [caps, response] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let read = socket.read(&mut buffer).unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&buffer[..read]);
                    if let Some(header) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let length = String::from_utf8_lossy(&bytes[..header])
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|s| s.parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= header + 4 + length {
                            break;
                        }
                    }
                }
                let body = response.to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
        });
        let file = File::new(
            if tamper { "remote-bad" } else { "remote" },
            &serde_json::to_vec(&unsigned).unwrap(),
        );
        let result = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
            .args(["liquid-policy", "sign", "--request-file"])
            .arg(&file.0)
            .args(["--service", &format!("http://127.0.0.1:{port}")])
            .output()
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            result.status.success(),
            !tamper,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
