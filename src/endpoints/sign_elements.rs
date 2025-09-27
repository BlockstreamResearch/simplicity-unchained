// SPDX-License-Identifier: LGPL-3.0-or-later

use super::Endpoint;
use p2c_s2c::secp256k1::XOnlyPublicKey;
use p2c_s2c::{bitcoin_hashes, TweakedKey};
use simplicity::{Cmr, RedeemNode};
use simplicity::jet;

use crate::hashes::SimplicityUnchainedHash;

#[derive(serde::Deserialize)]
pub struct Request {
    simplicity_base64: String,
    witness_hex: String,
    #[serde(default)]
    cmr: Option<Cmr>,
}

#[derive(serde::Serialize)]
pub enum Error {
    Parse {
        err: String,
    },
    CmrMismatch {
        program_cmr: Cmr,
        provided_cmr: Cmr,
    }
}

#[derive(serde::Serialize)]
pub struct Response {
    program_cmr: Cmr,
    tweaked_key: TweakedKey<XOnlyPublicKey, SimplicityUnchainedHash>,
}

/// The `sign-elements` endpoint.
pub enum SignElementsEndpoint {}

impl Endpoint for SignElementsEndpoint {
    const URL: &'static str = "/simplicity-unchained/sign-elements";

    type RequestData = Request;
    type ResponseData = Response;
    type ResponseError = Error;

    fn handle(
        untweaked_key: &XOnlyPublicKey,
        req: Self::RequestData,
    ) -> Result<Self::ResponseData, Self::ResponseError> {
        // FIXME make a dummy environment and then execute the bit machine
        let env = jet::elements::ElementsEnv::new();

        let prog = RedeemNode::<jet::Elements>::from_str(&req
            .simplicity_base64, &req.witness_hex)
            .map_err(|e| Error::Parse { err: e.to_string() })?;
        
        let cmr = prog.cmr();
        if req.cmr.is_some() && req.cmr != Some(cmr) {
            return Err(Error::CmrMismatch {
                program_cmr: cmr,
                provided_cmr: req.cmr.unwrap(),
            });
        }

        let tweaked_key = TweakedKey::new(untweaked_key, cmr.as_ref());
        Ok(Response {
            program_cmr: cmr,
            tweaked_key,
        })
    }
}

