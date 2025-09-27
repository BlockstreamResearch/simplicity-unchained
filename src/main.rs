// SPDX-License-Identifier: LGPL-3.0-or-later

mod config;
mod endpoints;
mod hashes;

use std::{env, fs};

use anyhow::Context as _;
use p2c_s2c::secp256k1::{Keypair, Secp256k1};
use tiny_http::Server;

use crate::endpoints::{UntweakedKeyEndpoint, TweakedKeyEndpoint, Endpoint, SignElementsEndpoint};

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

    for mut request in server.incoming_requests() {
        let url = request.url().to_owned();

        macro_rules! handle_endpoint {
            ($endpoint_ty:ty) => {
                if url == <$endpoint_ty>::URL {
                    let read = request.as_reader();
                    let response = match serde_json::from_reader::<_, <$endpoint_ty as Endpoint>::RequestData>(read) {
                        Ok(data) => match <$endpoint_ty>::handle(&kp, data) {
                            Ok(resp) => endpoints::json_response(&resp, 200),
                            Err(e) => endpoints::json_response(&e, 400),
                        },
                        Err(e) => {
                            endpoints::json_response(&e.to_string(), 400)
                        },
                    };

                    if let Err(e) = request.respond(response) {
                        handle_error(&format!("responding to {}", url), e);
                    }

                    // Ideally we would make each instance here a match clause, or at
                    // least an if-else, but we cannot because Rust macros are garbage.
                    continue;
                }
            }
        }

        handle_endpoint!(UntweakedKeyEndpoint);
        handle_endpoint!(TweakedKeyEndpoint);
        handle_endpoint!(SignElementsEndpoint);

        let response = endpoints::response_404(&url);
        if let Err(e) = request.respond(response) {
            handle_error(&format!("responding to {}", url), e);
        }
    }

    Ok(())
}
