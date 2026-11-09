use std::process::Command;

#[test]
fn primary_help_is_policy_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("policy"));
    assert!(help.contains("keypair"));
    assert!(help.contains("liquid-policy"));
    for removed in ["btc-tx", "Elements", "address   ", "tx   "] {
        assert!(!help.contains(removed), "{help}");
    }
}

#[test]
fn legacy_command_workflows_are_unavailable() {
    for namespace in ["tx", "btc-tx"] {
        for operation in [
            "create",
            "sign",
            "finalize",
            "approval-hash",
            "build-csv-leaf",
            "spend-user-leaf",
            "finalize-user-leaf",
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
                .args([namespace, operation, "--help"])
                .output()
                .unwrap();
            assert!(!output.status.success(), "{namespace} {operation}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(["address", "multisig", "--help"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
        .args(["btc-tx", "policy", "--help"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn native_demo_help_and_syntax_are_policy_only() {
    let script = format!("{}/scripts/demo_btc.sh", env!("CARGO_MANIFEST_DIR"));
    assert!(
        Command::new("bash")
            .args(["-n", &script])
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new("bash")
        .args([&script, "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("policy-v1"));
    assert!(help.contains("testnet4"));
    assert!(help.contains("never requests a signature"));
    for removed in ["btc-tx", "Liquid", "regtest", "/sign/psbt", "/sign/pset"] {
        assert!(!help.contains(removed), "{help}");
    }
}
