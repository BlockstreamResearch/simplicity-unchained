use std::process::Command;

use simplicity::{
    bitcoin::{self, psbt::Psbt},
    elements::Script,
};
use simplicity_unchained_core::{
    BitcoinNetwork, jets::bitcoin::CoreExtension, program::Program,
    runner::bitcoin_execution_environment,
};

#[test]
fn approval_hash_command_matches_the_execution_context() {
    let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA";
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::new(),
    });
    let cmr = Program::<CoreExtension>::from_str(program, None)
        .unwrap()
        .cmr();
    let expected = bitcoin_execution_environment(
        &psbt,
        0,
        cmr,
        &Script::from(vec![0x52]),
        BitcoinNetwork::Testnet4,
    )
    .unwrap();
    let invoke = |psbt: &Psbt| {
        Command::new(env!("CARGO_BIN_EXE_simplicity-unchained"))
            .args([
                "btc-tx",
                "approval-hash",
                "--psbt",
                &hex::encode(psbt.serialize()),
                "--input-index",
                "0",
                "--program",
                program,
                "--network",
                "testnet4",
                "--redeem-script-hex",
                "52",
            ])
            .output()
            .unwrap()
    };
    let result = invoke(&psbt);
    assert!(result.status.success());
    let output: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        output,
        serde_json::json!({
            "approval_hash_hex": hex::encode(expected.approval_hash),
            "cmr_hex": hex::encode(cmr.to_byte_array()),
        })
    );
    psbt.inputs[0].witness_utxo = None;
    let result = invoke(&psbt);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("witness_utxo"));
}
