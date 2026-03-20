use hal_simplicity::simplicity::bitcoin;
use hal_simplicity::simplicity::elements::{
    self,
    bitcoin::PublicKey,
    hashes::Hash as ElementsHash,
    secp256k1_zkp::{Secp256k1, SecretKey, rand::rngs::OsRng},
};
use hal_simplicity::simplicity::hashes::{HashEngine, sha256};

use thiserror::Error;

/// Errors that can occur in utility functions
#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("Expected 2 public keys for 2-of-2 multisig, got {0}")]
    InvalidPublicKeyCount(usize),
}

const SIMPLICITY_TAG_PREFIX: &[u8] = b"Simplicity\x1fCommitment\x1f";

const JETIV: sha256::Midstate = sha256::Midstate([
    0x95, 0x32, 0xee, 0x28, 0xcd, 0xca, 0x69, 0xde, 0xc8, 0xa0, 0xa2, 0x18, 0xb7, 0x9b, 0xe3, 0x62,
    0xf7, 0x40, 0xce, 0xaf, 0x64, 0x7f, 0x15, 0xb3, 0x8a, 0xed, 0x91, 0x68, 0x16, 0x3f, 0x92, 0x1b,
]);

// Warning: The CMRs generated here does not follow the proper Simplicity specification.
//
// TODO(ivanlele): Build valid Simplicity in Haskell from which we can extract the true CMRs.
#[allow(unused)]
fn cmr(name: &str) -> [u8; 32] {
    let name = SIMPLICITY_TAG_PREFIX
        .iter()
        .chain(name.as_bytes().iter())
        .copied()
        .collect::<Vec<u8>>();

    let right_state = sha256::Hash::hash(&name).as_byte_array().to_owned();

    let mut engine = sha256::HashEngine::from_midstate(JETIV, 0);
    engine.input(&right_state);

    right_state
}

/// Generate a new keypair using the secp256k1 curve
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);

    let public_key = PublicKey {
        compressed: true,
        inner: public_key,
    };

    (secret_key, public_key)
}

pub fn generate_2of2_multisig_address_elements(
    pubkeys: &[PublicKey],
    address_params: &'static elements::AddressParams,
    use_p2sh: bool,
) -> Result<(elements::Address, elements::script::Script), UtilsError> {
    if pubkeys.len() != 2 {
        return Err(UtilsError::InvalidPublicKeyCount(pubkeys.len()));
    }

    let redeem_script = elements::script::Builder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_int(2)
        .push_opcode(elements::opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    let address = if use_p2sh {
        elements::Address::p2sh(&redeem_script, None, address_params)
    } else {
        elements::Address::p2wsh(&redeem_script, None, address_params)
    };

    Ok((address, redeem_script))
}
/// Generate a 2-of-2 multisig address from a list of public keys
/// Returns the address and the redeem script
pub fn generate_2of2_multisig_address_bitcoin(
    pubkeys: &[PublicKey],
    network: bitcoin::Network,
) -> Result<(bitcoin::Address, bitcoin::script::ScriptBuf), UtilsError> {
    if pubkeys.len() != 2 {
        return Err(UtilsError::InvalidPublicKeyCount(pubkeys.len()));
    }

    // Build the 2-of-2 multisig script
    let redeem_script = bitcoin::script::Builder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_int(2)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    let address = bitcoin::address::Address::p2wsh(&redeem_script, network);

    Ok((address, redeem_script))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_simplicity::simplicity::elements::secp256k1_zkp::{
        PublicKey as Secp256k1PublicKey, Secp256k1,
    };

    #[test]
    fn test_generate_keypair() {
        let (secret_key, public_key) = generate_keypair();

        // Verify the public key corresponds to the secret key
        let secp = Secp256k1::new();
        let derived_pubkey = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);

        assert_eq!(public_key.inner, derived_pubkey);
        assert!(public_key.compressed);
    }

    #[test]
    fn test_generate_2of2_multisig_address() {
        let (_sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();

        let pubkeys = vec![pk1, pk2];
        let result = generate_2of2_multisig_address_elements(
            &pubkeys,
            &elements::AddressParams::ELEMENTS,
            false,
        );

        assert!(result.is_ok());
        let (address, redeem_script) = result.unwrap();

        // Verify the script is not empty
        assert!(!redeem_script.is_empty());

        // Verify address is valid
        assert!(!address.to_string().is_empty());
    }

    #[test]
    fn test_generate_2of2_multisig_address_wrong_count() {
        let (_sk1, pk1) = generate_keypair();

        let pubkeys = vec![pk1];
        let result = generate_2of2_multisig_address_elements(
            &pubkeys,
            &elements::AddressParams::ELEMENTS,
            false,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UtilsError::InvalidPublicKeyCount(1)
        ));
    }

    #[test]
    fn test_generate_multiple_keypairs_unique() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        // Verify keys are different
        assert_ne!(sk1.secret_bytes(), sk2.secret_bytes());
        assert_ne!(pk1.inner, pk2.inner);
    }
}
