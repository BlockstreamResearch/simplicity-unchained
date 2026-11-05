use std::str::FromStr;

use anyhow::{Context, Result};
use serde_json::json;
use simplicity::{bitcoin::psbt::Psbt, elements::Script};
use simplicity_unchained_core::{
    BitcoinNetwork, jets::bitcoin::CoreExtension, program::Program,
    runner::bitcoin_execution_environment,
};

pub fn execute(
    psbt_hex: &str,
    input_index: usize,
    program: &str,
    redeem_script_hex: Option<&str>,
    network: &str,
) -> Result<()> {
    let psbt = Psbt::deserialize(&hex::decode(psbt_hex).context("Failed to decode PSBT hex")?)
        .context("Failed to deserialize PSBT")?;
    let program = Program::<CoreExtension>::from_str(program, None).context("Invalid program")?;
    let script = Script::from(
        hex::decode(redeem_script_hex.unwrap_or("")).context("Invalid redeem script hex")?,
    );
    let network = BitcoinNetwork::from_str(network).map_err(anyhow::Error::msg)?;
    let env = bitcoin_execution_environment(&psbt, input_index, program.cmr(), &script, network)
        .context("Failed to construct approval context")?;
    let output = json!({
        "approval_hash_hex": hex::encode(env.approval_hash),
        "cmr_hex": hex::encode(program.cmr().to_byte_array()),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
