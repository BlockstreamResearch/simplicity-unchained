use anyhow::{Context, Result};
use hal_simplicity::simplicity::elements::Script;
use hal_simplicity::simplicity::elements::schnorr::TweakedPublicKey;
use serde_json::json;

use hal_simplicity::simplicity::elements::secp256k1_zkp::XOnlyPublicKey;
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

    let xonly = XOnlyPublicKey::from(pk.inner);

    let script = Script::new_v1_p2tr_tweaked(TweakedPublicKey::new(xonly));
    let address = Address::from_script(&script, None, params)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive address from script"))?;

    let output = json!({
        "address": address.to_string(),
        "script_type": "p2tr",
        "pubkey": pubkey,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
