// SPDX-License-Identifier: LGPL-3.0-or-later

use super::Endpoint;
use p2c_s2c::secp256k1::{Keypair, XOnlyPublicKey};
use p2c_s2c::TweakedKey;
use simplicity::{Cmr, CommitNode};
use simplicity::jet;

use crate::hashes::SimplicityUnchainedHash;

#[derive(serde::Deserialize)]
pub struct Request {
    simplicity_base64: String,
    #[serde(default)]
    cmr: Option<Cmr>,
}

#[derive(serde::Serialize)]
pub enum Error {
    Base64Parse {
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

/// The `untweaked-key` endpoint.
pub enum TweakedKeyEndpoint {}

impl Endpoint for TweakedKeyEndpoint {
    const URL: &'static str = "/simplicity-unchained/tweaked-key";

    type RequestData = Request;
    type ResponseData = Response;
    type ResponseError = Error;

    fn handle(
        untweaked_key: &Keypair,
        req: Self::RequestData,
    ) -> Result<Self::ResponseData, Self::ResponseError> {
        let prog = CommitNode::<jet::Elements>::from_str(&req.simplicity_base64)
            .map_err(|e| Error::Base64Parse { err: e.to_string() })?;
        
        let cmr = prog.cmr();
        if req.cmr.is_some() && req.cmr != Some(cmr) {
            return Err(Error::CmrMismatch {
                program_cmr: cmr,
                provided_cmr: req.cmr.unwrap(),
            });
        }

        let tweaked_key = TweakedKey::new(&untweaked_key.x_only_public_key().0, cmr.as_ref());
        Ok(Response {
            program_cmr: cmr,
            tweaked_key,
        })
    }
}

