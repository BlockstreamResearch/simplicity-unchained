use anyhow::{Context, Result};
use serde_json::json;

use hal_simplicity::simplicity::bitcoin;
use hal_simplicity::simplicity::elements::{AddressParams, bitcoin::PublicKey};

use simplicity_unchained_core::utils::{
    TransactionType, generate_2of2_multisig_address_bitcoin,
    generate_2of2_multisig_address_elements,
};

pub fn execute(pubkey1: &str, pubkey2: &str, network: &str, script_type: &str) -> Result<()> {
    let pk1_bytes = hex::decode(pubkey1).context("Failed to decode pubkey1")?;
    let pk2_bytes = hex::decode(pubkey2).context("Failed to decode pubkey2")?;

    let pk1 = PublicKey::from_slice(&pk1_bytes).context("Invalid pubkey1")?;
    let pk2 = PublicKey::from_slice(&pk2_bytes).context("Invalid pubkey2")?;

    let pubkeys = vec![pk1, pk2];

    let address_ty = match script_type {
        "p2sh" => TransactionType::P2SH,
        "p2wsh" => TransactionType::P2WSH,
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported script type: {}. Supported types are: p2sh, p2wsh",
                script_type
            ));
        }
    };

    if let Ok(network) = ElementsNetwork::try_from(network) {
        let output = execute_over_elements(&pubkeys, network, address_ty)?;
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if let Ok(network) = BitcoinNetwork::try_from(network) {
        let output = execute_over_bitcoin(&pubkeys, network, address_ty)?;
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "Unsupported network: {}. Supported networks are elements, liquid, liquid_testnet, bitcoin, testnet, testnet4, signet, regtest",
        network
    ))
}

fn execute_over_elements(
    pubkeys: &[PublicKey],
    network: ElementsNetwork,
    address_ty: TransactionType,
) -> Result<serde_json::Value> {
    let params = match network {
        ElementsNetwork::Elements => &AddressParams::ELEMENTS,
        ElementsNetwork::Liquid => &AddressParams::LIQUID,
        ElementsNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
    };

    let (address, redeem_script) =
        generate_2of2_multisig_address_elements(pubkeys, params, address_ty)?;
    Ok(json!({
        "address": address.to_string(),
        "redeem_script": hex::encode(redeem_script.to_bytes()),
        "script_type": address_ty.to_string()
    }))
}

fn execute_over_bitcoin(
    pubkeys: &[PublicKey],
    network: BitcoinNetwork,
    _address_ty: TransactionType,
) -> Result<serde_json::Value> {
    let network = match network {
        BitcoinNetwork::Bitcoin => bitcoin::Network::Bitcoin,
        BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
        BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet4,
        BitcoinNetwork::Signet => bitcoin::Network::Signet,
        BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
    };

    let (address, redeem_script) = generate_2of2_multisig_address_bitcoin(pubkeys, network)?;

    Ok(json!({
        "address": address.to_string(),
        "redeem_script": hex::encode(redeem_script.to_bytes()),
    }))
}

#[derive(Debug)]
enum ElementsNetwork {
    Elements,
    Liquid,
    LiquidTestnet,
}

impl TryFrom<&str> for ElementsNetwork {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "elements" => Ok(ElementsNetwork::Elements),
            "liquid" => Ok(ElementsNetwork::Liquid),
            "liquid_testnet" => Ok(ElementsNetwork::LiquidTestnet),
            _ => Err(anyhow::anyhow!("Unsupported elements network: {}", s)),
        }
    }
}

#[derive(Debug)]
enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl TryFrom<&str> for BitcoinNetwork {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "bitcoin" => Ok(BitcoinNetwork::Bitcoin),
            "testnet" => Ok(BitcoinNetwork::Testnet),
            "testnet4" => Ok(BitcoinNetwork::Testnet4),
            "signet" => Ok(BitcoinNetwork::Signet),
            "regtest" => Ok(BitcoinNetwork::Regtest),
            _ => Err(anyhow::anyhow!("Unsupported bitcoin network: {}", s)),
        }
    }
}
