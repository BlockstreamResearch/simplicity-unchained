use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read config file: {0}")]
    Io(std::io::Error),
    #[error("failed to parse config file: {0}")]
    Toml(toml::de::Error),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub port: u16,
    pub private_key: String,
    pub network: String,
}

impl Config {
    pub fn from_file(path: PathBuf) -> Result<Self, Error> {
        let contents = std::fs::read_to_string(path).map_err(Error::Io)?;
        let config: Config = toml::from_str(&contents).map_err(Error::Toml)?;

        Ok(config)
    }
}
