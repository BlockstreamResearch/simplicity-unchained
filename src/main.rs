// SPDX-License-Identifier: LGPL-3.0-or-later

mod config;
mod endpoints;
mod hashes;

use std::{env, fs};

use anyhow::Context as _;
use p2c_s2c::secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use p2c_s2c::TweakedKey;
use simplicity::Cmr;
use simplicity::jet;
use tiny_http::Server;

use crate::hashes::SimplicityUnchainedHash;

fn handle_error(_: &str, _: std::io::Error) {
    // FIXME do something
}

fn main() -> Result<(), anyhow::Error> {
    let mut args = env::args();
    let config: config::Configuration = match (args.next(), args.next(), args.next()) {
        (Some(_), Some(s), None) => {
            let fh = fs::File::open(&s)
                .with_context(|| format!("opening configuration file {s}"))?;
            serde_json::from_reader(&fh)
                .with_context(|| format!("parsing configuration file as JSON {s}"))?
        },
        _ => {
            eprintln!("Usage: simplicity-unchained <config.json>\n");
            return Err(anyhow::Error::msg("invalid usage"));
        }
    };

    let server = Server::http(&config.listen_url)
        .map_err(|e| anyhow::Error::msg(format!("failed to listening on URL {}: {}", &config.listen_url, e)))?;
    let secp = Secp256k1::new();

    let kp = Keypair::from_secret_key(&secp, &config.untweaked_secret_key);
    let (pk, _parity) = kp.x_only_public_key();
    let hex_pk = pk.to_string();

    for mut request in server.incoming_requests() {
        match request.url() {
            "/simplicity-unchained/untweaked-key" => {
                let response = endpoints::json_response(&hex_pk, 200);
                if let Err(e) = request.respond(response) {
                    handle_error("responding to untweaked-key", e);
                }
            },
            "/simplicity-unchained/generate-address" => {
                #[derive(serde::Deserialize)]
                struct Request {
                    simplicity_base64: String,
                    #[serde(default)]
                    cmr: Option<Cmr>,
                }

               
                let read = request.as_reader();
                let response = match serde_json::from_reader::<_, Request>(read) {
                    Ok(req) => match simplicity::CommitNode::<jet::Elements>::from_str(&req.simplicity_base64) {
                        Ok(prog) => {
                            let cmr = prog.cmr();
                            if req.cmr.is_some() && req.cmr != Some(cmr) {
                                #[derive(serde::Serialize)]
                                struct CmrMismatch {
                                    program_cmr: Cmr,
                                    provided_cmr: Cmr,
                                }
                                endpoints::json_response(&CmrMismatch {
                                    program_cmr: cmr,
                                    provided_cmr: req.cmr.unwrap(),
                                }, 400)
                            } else {
                                #[derive(serde::Serialize)]
                                struct TweakInfo {
                                    program_cmr: Cmr,
                                    tweaked_key: TweakedKey<XOnlyPublicKey, SimplicityUnchainedHash>,
                                }

                                let tweaked_key = TweakedKey::new(&pk, cmr.as_ref());

                                endpoints::json_response(&TweakInfo {
                                    program_cmr: cmr,
                                    tweaked_key,
                                }, 400)
                            }
                        }
                        Err(e) => {
                            // FIXME: provide more specific error; attempt to parse as bitcoin maybe
                            endpoints::json_response(&e.to_string(), 400)
                        },

                    },
                    Err(e) => {
                        endpoints::json_response(&e.to_string(), 400)
                    },
                };
                
                if let Err(e) = request.respond(response) {
                    handle_error("responding to generate-address", e);
                }
            },
            x => {
                let response = endpoints::response_404(x);
                if let Err(e) = request.respond(response) {
                    handle_error("responding with 404", e);
                }
            }
        }
    }

    Ok(())
}
