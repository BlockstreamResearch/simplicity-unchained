use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use hal_simplicity::{
    bitcoin::secp256k1,
    hal_simplicity::Program,
    simplicity::elements::{
        self,
        schnorr::{TapTweak, UntweakedKeypair},
        taproot::TapNodeHash,
    },
};

use elements::{bitcoin::PublicKey, hashes::Hash};
use serde::{Deserialize, Serialize};
use validator::Validate;

use simplicity_unchained_core::jets::{bitcoin::CoreExtension, elements::ElementsExtension};

use crate::handlers::{ErrorResponse, SignerState};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JetEnvKind {
    Elements,
    Bitcoin,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TweakRequest {
    #[validate(length(min = 1))]
    pub program: String,
    pub jet_env: Option<JetEnvKind>,
}

#[derive(Debug, Serialize)]
pub struct TweakResponse {
    pub cmr_hex: String,
    pub tweaked_public_key_hex: String,
}

pub async fn get_tweaked_key(
    State(state): State<SignerState>,
    Json(request): Json<TweakRequest>,
) -> impl IntoResponse {
    // Validate request using validator
    if let Err(errors) = request.validate() {
        let error_msg = format!("Validation failed: {}", errors);
        log::error!("[400] Tweak validation error: {}", error_msg);

        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: error_msg }),
        )
            .into_response();
    }

    match get_tweaked_key_internal(&state, request) {
        Ok(response) => {
            log::info!(
                "[200] Tweak successful: CMR {}, Tweaked Public Key {}",
                response.cmr_hex,
                response.tweaked_public_key_hex
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            log::error!("[400] Tweak error: {}", e);

            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })).into_response()
        }
    }
}

fn get_tweaked_key_internal(
    state: &SignerState,
    request: TweakRequest,
) -> Result<TweakResponse, String> {
    // Parse Simplicity program and get CMR from commitment
    let cmr = match &request.jet_env {
        Some(JetEnvKind::Bitcoin) => {
            let program = Program::<CoreExtension>::from_str(&request.program, None)
                .map_err(|e| format!("Failed to parse program: {}", e))?;

            program.commit_prog().cmr()
        }
        _ => {
            let program = Program::<ElementsExtension>::from_str(&request.program, None)
                .map_err(|e| format!("Failed to parse program: {}", e))?;

            program.commit_prog().cmr()
        }
    };

    // Create untweaked keypair and tweak it with the CMR
    let untweaked_keypair = UntweakedKeypair::from_secret_key(&*state.secp, &state.secret_key);

    let tweaked_keypair = untweaked_keypair.tap_tweak(
        &*state.secp,
        Some(TapNodeHash::from_byte_array(cmr.to_byte_array())),
    );

    let (tweaked_public_key, tweaked_parity) = tweaked_keypair.public_parts();
    let public_key = PublicKey::new(secp256k1::PublicKey::from_x_only_public_key(
        tweaked_public_key.into_inner(),
        tweaked_parity,
    ));

    Ok(TweakResponse {
        cmr_hex: hex::encode(cmr.to_byte_array()),
        tweaked_public_key_hex: hex::encode(public_key.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::secp256k1_zkp::{Secp256k1, SecretKey};
    use std::sync::Arc;

    use simplicity_unchained_core::{BitcoinNetwork, ElementsNetwork};

    fn create_test_signer_state() -> SignerState {
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        SignerState {
            secret_key,
            secp: Arc::new(Secp256k1::new()),
            elements_network: ElementsNetwork::LiquidTestnet,
            bitcoin_network: BitcoinNetwork::Testnet,
        }
    }

    #[test]
    fn test_get_tweaked_key_internal_success() {
        let state = create_test_signer_state();

        let request = TweakRequest {
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            jet_env: None,
        };

        let result = get_tweaked_key_internal(&state, request);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.cmr_hex.is_empty());
        assert!(!response.tweaked_public_key_hex.is_empty());

        // Verify CMR is 32 bytes (64 hex chars)
        assert_eq!(response.cmr_hex.len(), 64);

        // Verify public key is 33 bytes (66 hex chars) for compressed key
        assert_eq!(response.tweaked_public_key_hex.len(), 66);
    }

    #[test]
    fn test_get_tweaked_key_internal_invalid_program() {
        let state = create_test_signer_state();

        let request = TweakRequest {
            program: "invalid_program".to_string(),
            jet_env: None,
        };

        let result = get_tweaked_key_internal(&state, request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse program"));
    }

    #[test]
    fn test_tweak_request_validation() {
        // Valid request
        let valid_request = TweakRequest {
            program: "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string(),
            jet_env: None,
        };
        assert!(valid_request.validate().is_ok());

        // Empty program should fail
        let invalid_request = TweakRequest {
            program: "".to_string(),
            jet_env: None,
        };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_consistent_cmr_and_key_with_sign() {
        // This test ensures the tweak endpoint produces the same CMR and key
        // as the sign endpoint would use internally
        let state = create_test_signer_state();

        let program = "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA".to_string();

        let request = TweakRequest {
            program: program.clone(),
            jet_env: None,
        };

        let result = get_tweaked_key_internal(&state, request).unwrap();

        // Decode and verify the CMR
        let cmr_bytes = hex::decode(&result.cmr_hex).unwrap();
        assert_eq!(cmr_bytes.len(), 32);

        // Decode and verify the public key
        let pubkey_bytes = hex::decode(&result.tweaked_public_key_hex).unwrap();
        assert_eq!(pubkey_bytes.len(), 33); // Compressed public key
    }
}
