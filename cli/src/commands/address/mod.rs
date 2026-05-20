// TODO: remove when elements updated
#![allow(dead_code)]
pub mod multisig;

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
