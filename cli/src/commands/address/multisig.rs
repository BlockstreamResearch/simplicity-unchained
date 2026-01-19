use anyhow::{Context, Result};
use hal_simplicity::simplicity::elements::{AddressParams, bitcoin::PublicKey};
use serde_json::json;
use simplicity_unchained_core::utils::generate_2of2_multisig_address;

pub fn execute(pubkey1: &str, pubkey2: &str, network: &str) -> Result<()> {
    let pk1_bytes = hex::decode(pubkey1).context("Failed to decode pubkey1")?;
    let pk2_bytes = hex::decode(pubkey2).context("Failed to decode pubkey2")?;

    let pk1 = PublicKey::from_slice(&pk1_bytes).context("Invalid pubkey1")?;
    let pk2 = PublicKey::from_slice(&pk2_bytes).context("Invalid pubkey2")?;

    let pubkeys = vec![pk1, pk2];

    let params = match network {
        "elements" => &AddressParams::ELEMENTS,
        "liquid" => &AddressParams::LIQUID,
        "liquid_testnet" => &AddressParams::LIQUID_TESTNET,
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported network '{}'. Supported networks are: elements, liquid, liquid_testnet.",
                network
            ));
        }
    };

    let (address, redeem_script) = generate_2of2_multisig_address(&pubkeys, params)?;

    let output = json!({
        "address": address.to_string(),
        "redeem_script": hex::encode(&redeem_script.to_bytes()),
        "network": network
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
