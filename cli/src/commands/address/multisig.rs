use anyhow::{Context, Result};
use hal_simplicity::bitcoin::hashes::Hash;
use hal_simplicity::{bitcoin::TapNodeHash, simplicity::elements::AddressParams};
use serde_json::json;

use hal_simplicity::simplicity::elements::bitcoin::PublicKey;
use hal_simplicity::simplicity::{bitcoin, elements};

use simplicity_unchained_core::utils::{generate_p2tr_address_btc, generate_p2tr_address_elements};

use crate::commands::address::{BitcoinNetwork, ElementsNetwork};

pub fn execute(
    pubkey1: &str,
    pubkey2: &str,
    user_leaf_hash_hex: &str,
    network: &str,
) -> Result<()> {
    let pk1_bytes = hex::decode(pubkey1).context("Failed to decode pubkey1")?;
    let pk2_bytes = hex::decode(pubkey2).context("Failed to decode pubkey2")?;

    let pk1 = PublicKey::from_slice(&pk1_bytes).context("Invalid pubkey1")?;
    let pk2 = PublicKey::from_slice(&pk2_bytes).context("Invalid pubkey2")?;

    let user_leaf_hash_bytes = hex::decode(user_leaf_hash_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode user leaf hash hex: {}", e))?;

    if let Ok(network) = ElementsNetwork::try_from(network) {
        let output = execute_over_elements(
            &pk1,
            &pk2,
            elements::hashes::sha256::Hash::from_slice(&user_leaf_hash_bytes)?,
            network,
        )?;
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if let Ok(network) = BitcoinNetwork::try_from(network) {
        let output = execute_over_bitcoin(
            &pk1,
            &pk2,
            TapNodeHash::from_slice(&user_leaf_hash_bytes).map_err(|e| anyhow::anyhow!(e))?,
            network,
        )?;
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "Unsupported network: {}. Supported networks are elements, liquid, liquid_testnet, bitcoin, testnet, testnet4, signet, regtest",
        network
    ))
}

fn execute_over_bitcoin(
    service_key: &PublicKey,
    user_key: &PublicKey,
    user_leaf_hash: bitcoin::TapNodeHash,
    network: BitcoinNetwork,
) -> Result<serde_json::Value> {
    let network = match network {
        BitcoinNetwork::Bitcoin => bitcoin::Network::Bitcoin,
        BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
        BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet4,
        BitcoinNetwork::Signet => bitcoin::Network::Signet,
        BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
    };

    let (address, _spend_info) =
        generate_p2tr_address_btc(service_key, user_key, user_leaf_hash, network)?;

    Ok(json!({
        "address": address.to_string(),
    }))
}

fn execute_over_elements(
    service_key: &PublicKey,
    user_key: &PublicKey,
    user_leaf_hash: elements::hashes::sha256::Hash,
    network: ElementsNetwork,
) -> Result<serde_json::Value> {
    let params = match network {
        ElementsNetwork::Elements => &AddressParams::ELEMENTS,
        ElementsNetwork::Liquid => &AddressParams::LIQUID,
        ElementsNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
    };

    let (address, _spend_info) =
        generate_p2tr_address_elements(service_key, user_key, user_leaf_hash, params)?;
    Ok(json!({
        "address": address.to_string(),
    }))
}
