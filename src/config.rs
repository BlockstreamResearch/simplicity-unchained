// SPDX-License-Identifier: LGPL-3.0-or-later

use p2c_s2c::secp256k1::SecretKey;

pub fn deserialize_from_str<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: core::str::FromStr,
    <T as core::str::FromStr>::Err: core::fmt::Display,
{
    use serde::{Deserialize as _, de::Error as _};
    
    let s = String::deserialize(d)?;
    s.parse().map_err(D::Error::custom)
}

#[derive(serde::Deserialize)]
pub struct Configuration {
    pub listen_url: String,
    #[serde(deserialize_with = "deserialize_from_str")]
    pub untweaked_secret_key: SecretKey,
}
