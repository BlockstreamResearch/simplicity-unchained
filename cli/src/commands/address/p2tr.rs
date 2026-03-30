use anyhow::{Context, Result};
use hal_simplicity::bitcoin;
use hal_simplicity::simplicity::ToXOnlyPubkey;
use hal_simplicity::simplicity::elements::{self};
use serde_json::json;

use hal_simplicity::simplicity::elements::AddressParams;

use crate::commands::address::{BitcoinNetwork, ElementsNetwork};

pub fn execute(pubkey: &str, network: &str) -> Result<()> {
    let pk_bytes = hex::decode(pubkey).context("Failed to decode pubkey")?;

    if let Ok(network) = ElementsNetwork::try_from(network) {
        let output = json!({
            "address": execute_over_elements(&pk_bytes, network)?,
            "script_type": "p2tr",
            "pubkey": pubkey,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if let Ok(network) = BitcoinNetwork::try_from(network) {
        let output = json!({
            "address": execute_over_bitcoin(&pk_bytes, network)?,
            "script_type": "p2tr",
            "pubkey": pubkey,
        });

        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    Ok(())
}

fn execute_over_elements(pk_bytes: &[u8], network: ElementsNetwork) -> Result<String> {
    let params = match network {
        ElementsNetwork::Elements => &AddressParams::ELEMENTS,
        ElementsNetwork::Liquid => &AddressParams::LIQUID,
        ElementsNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
    };

    let pk = elements::secp256k1_zkp::PublicKey::from_slice(pk_bytes).context("Invalid pubkey")?;
    let (xonly, _) = pk.x_only_public_key();

    let script =
        elements::Script::new_v1_p2tr_tweaked(elements::schnorr::TweakedPublicKey::new(xonly));
    let address = elements::Address::from_script(&script, None, params)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive address from script"))?;

    Ok(address.to_string())
}

fn execute_over_bitcoin(pk_bytes: &[u8], network: BitcoinNetwork) -> Result<String> {
    let params = match network {
        BitcoinNetwork::Bitcoin => bitcoin::params::Params::BITCOIN,
        BitcoinNetwork::Testnet => bitcoin::params::Params::TESTNET3,
        BitcoinNetwork::Testnet4 => bitcoin::params::Params::TESTNET4,
        BitcoinNetwork::Signet => bitcoin::params::Params::SIGNET,
        BitcoinNetwork::Regtest => bitcoin::params::Params::REGTEST,
    };

    let pk = bitcoin::PublicKey::from_slice(pk_bytes).context("Invalid pubkey")?;
    let xonly = pk.to_x_only_pubkey();

    let script = bitcoin::ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
    );
    let address = bitcoin::Address::from_script(&script, &params)
        .map_err(|e| anyhow::anyhow!("Failed to derive address from script: {e}"))?;

    Ok(address.to_string())
}
