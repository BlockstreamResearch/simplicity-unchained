use anyhow::{Context, Result, anyhow};

use hal_simplicity::simplicity::elements;

use elements::{
    Address, AddressParams, AssetId, OutPoint, Transaction, TxIn, TxOut, confidential,
    encode::serialize, pset::PartiallySignedTransaction,
};

use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[derive(serde::Deserialize)]
struct BlockstreamTx {
    vout: Vec<BlockstreamVout>,
}

#[derive(serde::Deserialize)]
struct BlockstreamVout {
    asset: Option<String>,
    value: Option<u64>,
    scriptpubkey: Option<String>,
}

fn fetch_tx_output(txid: &str, vout: u32, network: &str) -> Result<TxOut> {
    let api_url = match network {
        "liquid" => format!("https://blockstream.info/liquid/api/tx/{}", txid),
        "liquid_testnet" => format!("https://blockstream.info/liquidtestnet/api/tx/{}", txid),
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

                let asset_str = output
                    .asset
                    .as_ref()
                    .ok_or_else(|| anyhow!("Output {} has no asset", vout))?;
                let value = output
                    .value
                    .ok_or_else(|| anyhow!("Output {} has no value", vout))?;
                let scriptpubkey_str = output
                    .scriptpubkey
                    .as_ref()
                    .ok_or_else(|| anyhow!("Output {} has no scriptpubkey", vout))?;

                let asset = AssetId::from_str(asset_str).context("Invalid asset ID")?;
                let script_bytes =
                    hex::decode(scriptpubkey_str).context("Invalid scriptpubkey hex")?;

                return Ok(TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(value),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: elements::script::Script::from(script_bytes),
                    witness: elements::TxOutWitness::default(),
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

fn get_network_params(network: &str) -> Result<&'static AddressParams> {
    match network {
        "elements" => Ok(&AddressParams::ELEMENTS),
        "liquid" => Ok(&AddressParams::LIQUID),
        "liquid_testnet" => Ok(&AddressParams::LIQUID_TESTNET),
        _ => Err(anyhow!(
            "Unsupported network '{}'. Supported networks are: elements, liquid, liquid_testnet.",
            network
        )),
    }
}

fn get_default_asset(network: &str) -> &'static str {
    match network {
        "liquid" => "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        "liquid_testnet" => "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
        _ => "0000000000000000000000000000000000000000000000000000000000000000",
    }
}

pub fn execute(
    inputs: &[String],
    outputs: &[String],
    asset_id: Option<&str>,
    network: &str,
) -> Result<()> {
    let params = get_network_params(network)?;

    let asset = if let Some(asset_str) = asset_id {
        AssetId::from_str(asset_str).context("Invalid asset ID")?
    } else {
        AssetId::from_str(get_default_asset(network)).context("Invalid default asset ID")?
    };

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
            elements::Txid::from_str(parts[0]).context(format!("Invalid txid: {}", parts[0]))?;
        let vout: u32 = parts[1]
            .parse()
            .context(format!("Invalid vout: {}", parts[1]))?;

        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            is_pegin: false,
            script_sig: elements::script::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
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

        let script_pubkey = match parts[0] {
            "fee" => elements::script::Script::new(),
            address_str => {
                let address = Address::parse_with_params(address_str, params)
                    .context(format!("Invalid address: {}", address_str))?;
                address.script_pubkey()
            }
        };

        tx_outputs.push(TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey,
            witness: elements::TxOutWitness::default(),
        });
    }

    let tx = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut pset = PartiallySignedTransaction::from_tx(tx);

    // Populate witness UTXO for each input by fetching from the blockchain
    for (i, input_str) in inputs.iter().enumerate() {
        let parts: Vec<&str> = input_str.split(':').collect();
        let txid_str = parts[0];
        let vout: u32 = parts[1].parse().unwrap();

        match fetch_tx_output(txid_str, vout, network) {
            Ok(prev_output) => {
                pset.inputs_mut()[i].witness_utxo = Some(prev_output);
            }
            Err(e) => {
                return Err(anyhow!("Could not fetch UTXO for input {}: {}", i, e));
            }
        }
    }

    let output = serde_json::json!({
        "pset": hex::encode(serialize(&pset)),
        "inputs": pset.inputs().len(),
        "outputs": pset.outputs().len(),
        "network": network,
        "asset": asset.to_string()
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
