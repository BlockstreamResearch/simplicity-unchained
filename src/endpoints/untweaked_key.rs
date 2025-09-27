// SPDX-License-Identifier: LGPL-3.0-or-later

use p2c_s2c::secp256k1::XOnlyPublicKey;

use super::Endpoint;

/// The `untweaked-key` endpoint.
pub enum UntweakedKeyEndpoint {}

impl Endpoint for UntweakedKeyEndpoint {
    const URL: &'static str = "/simplicity-unchained/untweaked-key";

    type RequestData = ();
    type ResponseData = String;
    type ResponseError = ();

    fn handle(
        untweaked_key: &XOnlyPublicKey,
        _: Self::RequestData,
    ) -> Result<Self::ResponseData, Self::ResponseError> {
        Ok(untweaked_key.to_string())

    }
}

