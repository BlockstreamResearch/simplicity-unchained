use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read config file: {0}")]
    Io(std::io::Error),
    #[error("failed to parse config file; check TOML syntax and required service fields")]
    Toml(toml::de::Error),
}

#[derive(Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
}

#[derive(Deserialize)]
pub struct ServiceConfig {
    pub port: u16,
    pub private_key: String,
    pub bitcoin_network: String,
    #[serde(default = "default_liquid_network")]
    pub liquid_network: String,
}

fn default_liquid_network() -> String {
    "liquidtestnet".into()
}

impl Config {
    pub fn from_file(path: PathBuf) -> Result<Self, Error> {
        let contents = std::fs::read_to_string(path).map_err(Error::Io)?;
        let config: Config = toml::from_str(&contents).map_err(Error::Toml)?;

        Ok(config)
    }
}
