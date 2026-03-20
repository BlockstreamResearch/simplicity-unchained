use anyhow::{Context, Result};
use serde_json::json;

use hal_simplicity::simplicity::elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use hal_simplicity::simplicity::elements::{Address, AddressParams, bitcoin::PublicKey};

pub fn execute(pubkey: &str, network: &str) -> Result<()> {
    let pk_bytes = hex::decode(pubkey).context("Failed to decode pubkey")?;
    let pk = PublicKey::from_slice(&pk_bytes).context("Invalid pubkey")?;

    let params = match network {
        "elements" => &AddressParams::ELEMENTS,
        "liquid" => &AddressParams::LIQUID,
        "liquid_testnet" => &AddressParams::LIQUID_TESTNET,
        _ => {
            return Err(anyhow::anyhow!(
                "P2TR is only supported for Elements networks: elements, liquid, liquid_testnet"
            ));
        }
    };

    let secp = Secp256k1::verification_only();
    let xonly = XOnlyPublicKey::from(pk.inner);

    // Pass None for merkle_root (key-path only, no script tree)
    // Pass None for blinder (unconfidential address)
    let address = Address::p2tr(&secp, xonly, None, None, params);

    let output = json!({
        "address": address.to_string(),
        "script_type": "p2tr",
        "pubkey": pubkey,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
