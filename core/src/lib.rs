use std::str::FromStr;

use hal_simplicity::simplicity::elements::BlockHash;
use hal_simplicity::simplicity::elements::hashes::Hash;

pub mod jets;
pub mod precop;
pub mod runner;
pub mod utils;

#[derive(Clone, Copy, Debug)]
pub enum ElementsNetwork {
    Liquid,
    LiquidTestnet,
}

impl ElementsNetwork {
    pub fn genesis_hash(&self) -> BlockHash {
        let data = match self {
            ElementsNetwork::Liquid => [
                3, 96, 32, 138, 136, 150, 146, 55, 44, 141, 104, 176, 132, 166, 46, 253, 246, 14,
                161, 163, 89, 160, 76, 148, 178, 13, 34, 54, 88, 39, 102, 20,
            ],
            ElementsNetwork::LiquidTestnet => [
                193, 177, 106, 226, 79, 36, 35, 174, 162, 234, 52, 85, 34, 146, 121, 59, 91, 94,
                130, 153, 154, 30, 237, 129, 213, 106, 238, 82, 142, 218, 113, 167,
            ],
        };

        BlockHash::from_byte_array(data)
    }
}

impl FromStr for ElementsNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "liquid" => Ok(ElementsNetwork::Liquid),
            "liquidtestnet" | "liquid_testnet" | "testnet" => Ok(ElementsNetwork::LiquidTestnet),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Testnet4,
}

impl FromStr for BitcoinNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bitcoin" => Ok(BitcoinNetwork::Mainnet),
            "testnet" => Ok(BitcoinNetwork::Testnet),
            "testnet4" => Ok(BitcoinNetwork::Testnet4),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}
