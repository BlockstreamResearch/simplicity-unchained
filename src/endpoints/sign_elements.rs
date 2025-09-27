// SPDX-License-Identifier: LGPL-3.0-or-later

use std::sync::Arc;
use super::Endpoint;
use p2c_s2c::secp256k1::{Keypair, XOnlyPublicKey, schnorr};
use p2c_s2c::TweakedKey;
use simplicity::{Cmr, RedeemNode, BitMachine};
use simplicity::jet;
use simplicity::elements::{Transaction, TxOut, confidential, LockTime, TxOutWitness, taproot::ControlBlock};
use simplicity::hashes::Hash as _;

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
    },
    Execution {
        err: String,
    },
}

#[derive(serde::Serialize)]
pub struct Response {
    program_cmr: Cmr,
    tweaked_key: TweakedKey<XOnlyPublicKey, SimplicityUnchainedHash>,
    signature: schnorr::Signature,
    original_nonce: XOnlyPublicKey,
}

/// The `sign-elements` endpoint.
pub enum SignElementsEndpoint {}

impl Endpoint for SignElementsEndpoint {
    const URL: &'static str = "/simplicity-unchained/sign-elements";

    type RequestData = Request;
    type ResponseData = Response;
    type ResponseError = Error;

    fn handle(
        untweaked_key: &Keypair,
        req: Self::RequestData,
    ) -> Result<Self::ResponseData, Self::ResponseError> {
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

        // Create a dummy transaction for testing
        let dummy_tx = Arc::new(Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: confidential::Value::Explicit(100000),
                script_pubkey: simplicity::elements::Script::new(),
                asset: confidential::Asset::Explicit(simplicity::elements::AssetId::default()),
                nonce: confidential::Nonce::Null,
                witness: TxOutWitness::default(),
            }],
        });

        // Create a dummy control block (33 bytes: 1 byte version + 32 bytes internal key)
        let dummy_control_block_bytes = vec![1u8; 33];
        let control_block = ControlBlock::from_slice(&dummy_control_block_bytes)
            .map_err(|e| Error::Execution { err: format!("Failed to create control block: {}", e) })?;

        // Create Elements environment with the dummy transaction
        let env = jet::elements::ElementsEnv::new(
            dummy_tx,
            vec![], // empty utxos
            0,      // input index
            cmr,    // script CMR
            control_block, // control block
            None,   // annex
            simplicity::elements::BlockHash::all_zeros(),
        );

        // Execute the Simplicity program on the Bit Machine
        let mut mac = BitMachine::for_program(&prog)
            .map_err(|e| Error::Execution { err: e.to_string() })?;
        mac.exec(&prog, &env)
            .map_err(|e| Error::Execution { err: e.to_string() })?;

        // Create tweaked key for signing
        let tweaked_keypair = TweakedKey::new(untweaked_key, cmr.as_ref());
        let tweaked_key = tweaked_keypair.to_x_only_public_key();

        // For now, we'll create a dummy signature since we don't have the secret key
        // In a real implementation, you'd use the tweaked secret key to sign
        let secp = p2c_s2c::secp256k1::Secp256k1::new();
        let (signature, original_nonce) = tweaked_keypair
            .sign_schnorr(&secp, b"dummy message", prog.ihr().as_ref());

        Ok(Response {
            program_cmr: cmr,
            tweaked_key,
            signature,
            original_nonce,
        })
    }
}

