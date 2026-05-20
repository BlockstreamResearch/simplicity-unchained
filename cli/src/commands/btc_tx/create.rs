use anyhow::{Context, Result, anyhow};

use hal_simplicity::simplicity::bitcoin;

use bitcoin::{
    Address, Amount, Network, OutPoint, Transaction, TxIn, TxOut, psbt::Psbt, script::ScriptBuf,
};

use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[derive(serde::Deserialize)]
struct BlockstreamTx {
    vout: Vec<BlockstreamVout>,
}

#[derive(serde::Deserialize)]
struct BlockstreamVout {
    value: Option<u64>,
    scriptpubkey: Option<String>,
}

fn fetch_tx_output(txid: &str, vout: u32, network: &str) -> Result<TxOut> {
    let api_url = match network {
        "bitcoin" => format!("https://blockstream.info/api/tx/{}", txid),
        "testnet" => format!("https://blockstream.info/testnet/api/tx/{}", txid),
        "testnet4" => format!("https://mempool.space/testnet4/api/tx/{}", txid),
        "regtest" => {
            return fetch_tx_output_rpc(txid, vout);
        }
        _ => return Err(anyhow!("Cannot fetch transaction for network: {}", network)),
    };

    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 3;

    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match reqwest::blocking::get(&api_url)
            .context("Failed to fetch transaction")
            .and_then(|resp| resp.text().context("Failed to read response"))
            .and_then(|response| {
                serde_json::from_str::<BlockstreamTx>(&response)
                    .context("Failed to parse transaction JSON")
            }) {
            Ok(tx_data) => {
                let output = tx_data
                    .vout
                    .get(vout as usize)
                    .ok_or_else(|| anyhow!("Output {} not found in transaction", vout))?;

                let value = output
                    .value
                    .ok_or_else(|| anyhow!("Output {} has no value", vout))?;
                let scriptpubkey_str = output
                    .scriptpubkey
                    .as_ref()
                    .ok_or_else(|| anyhow!("Output {} has no scriptpubkey", vout))?;

                let script_bytes =
                    hex::decode(scriptpubkey_str).context("Invalid scriptpubkey hex")?;

                return Ok(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: ScriptBuf::from_bytes(script_bytes),
                });
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    eprintln!(
                        "Attempt {}/{} failed, RPC is not responding, retrying in {} seconds...",
                        attempt, MAX_RETRIES, RETRY_DELAY_SECS
                    );
                    thread::sleep(Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }

    Err(anyhow!(
        "Server is down or unreachable after {} attempts: {}",
        MAX_RETRIES,
        last_error.unwrap()
    ))
}

fn fetch_tx_output_rpc(txid: &str, vout: u32) -> Result<TxOut> {
    let output = Command::new("bitcoin-cli")
        .args(["-regtest", "getrawtransaction", txid, "true"])
        .output()
        .context("failed to call bitcoin-cli")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("bitcoin-cli failed: stderr={}", stderr,));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).context("invalid JSON")?;

    let vout_obj = json["vout"]
        .get(vout as usize)
        .ok_or_else(|| anyhow!("vout not found"))?;

    let value_btc = vout_obj["value"]
        .as_f64()
        .ok_or_else(|| anyhow!("no value"))?;

    let script_hex = vout_obj["scriptPubKey"]["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("no script"))?;

    let script_bytes = hex::decode(script_hex)?;

    Ok(TxOut {
        value: Amount::from_btc(value_btc)?,
        script_pubkey: ScriptBuf::from_bytes(script_bytes),
    })
}

fn get_network_kind(network: &str) -> Result<Network> {
    match network {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "regtest" => Ok(Network::Regtest),
        _ => Err(anyhow!(
            "Unsupported network '{}'. Supported networks are: bitcoin, testnet.",
            network
        )),
    }
}

pub fn execute(
    inputs: &[String],
    outputs: &[String],
    network: &str,
    sequence: Option<u16>,
) -> Result<()> {
    let network_type = get_network_kind(network)?;

    // Parse inputs (txid:vout)
    let mut tx_inputs = Vec::new();
    for input_str in inputs {
        let parts: Vec<&str> = input_str.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid input format. Expected txid:vout, got: {}",
                input_str
            ));
        }

        let txid =
            bitcoin::Txid::from_str(parts[0]).context(format!("Invalid txid: {}", parts[0]))?;
        let vout: u32 = parts[1]
            .parse()
            .context(format!("Invalid vout: {}", parts[1]))?;

        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: sequence
                .map(bitcoin::Sequence::from_height)
                .unwrap_or(bitcoin::Sequence::MAX),
            witness: Default::default(),
        });
    }

    // Parse outputs (address:value)
    let mut tx_outputs = Vec::new();
    for output_str in outputs {
        let parts: Vec<&str> = output_str.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid output format. Expected address:value, got: {}",
                output_str
            ));
        }

        let value: u64 = parts[1]
            .parse()
            .context(format!("Invalid value: {}", parts[1]))?;

        let address = Address::from_str(parts[0])
            .context(format!("Invalid address: {}", parts[0]))?
            .require_network(network_type)
            .context(format!(
                "Address {} is not valid for network {}",
                parts[0], network
            ))?;

        tx_outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: address.script_pubkey(),
        });
    }

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;

    // Populate witness UTXO for each input by fetching from the blockchain
    for (i, input_str) in inputs.iter().enumerate() {
        let parts: Vec<&str> = input_str.split(':').collect();
        let txid_str = parts[0];
        let vout: u32 = parts[1].parse().unwrap();

        match fetch_tx_output(txid_str, vout, network) {
            Ok(prev_output) => {
                psbt.inputs[i].witness_utxo = Some(prev_output);
            }
            Err(e) => {
                return Err(anyhow!("Could not fetch UTXO for input {}: {}", i, e));
            }
        }
    }

    let output = serde_json::json!({
        "psbt": hex::encode(psbt.serialize()),
        "inputs": psbt.inputs.len(),
        "outputs": psbt.outputs.len(),
        "network": network,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
