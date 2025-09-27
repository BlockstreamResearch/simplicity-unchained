// SPDX-License-Identifier: LGPL-3.0-or-later

use p2c_s2c::secp256k1::Keypair;

use super::Endpoint;

/// The `untweaked-key` endpoint.
pub enum UntweakedKeyEndpoint {}

impl Endpoint for UntweakedKeyEndpoint {
    const URL: &'static str = "/simplicity-unchained/untweaked-key";

    type RequestData = ();
    type ResponseData = String;
    type ResponseError = ();

    fn handle(
        untweaked_key: &Keypair,
        _: Self::RequestData,
    ) -> Result<Self::ResponseData, Self::ResponseError> {
        Ok(untweaked_key.x_only_public_key().0.to_string())

    }
}

