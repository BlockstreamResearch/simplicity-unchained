use std::str::FromStr;
use std::sync::LazyLock;

use hal_simplicity::bitcoin::KnownHrp;
use hal_simplicity::bitcoin::taproot::TaprootSpendInfo;
use hal_simplicity::simplicity::elements::{
    self,
    bitcoin::PublicKey,
    hashes::Hash as ElementsHash,
    secp256k1_zkp::{Secp256k1, SecretKey, rand::rngs::OsRng},
};
use hal_simplicity::simplicity::hashes::{HashEngine, sha256};
use hal_simplicity::simplicity::{ToXOnlyPubkey, bitcoin};

use thiserror::Error;

/// Errors that can occur in utility functions
#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("Expected 2 public keys for 2-of-2 multisig, got {0}")]
    InvalidPublicKeyCount(usize),
    #[error(transparent)]
    TaprootBuilderErrorBtc(bitcoin::taproot::TaprootBuilderError),
    #[error(transparent)]
    TaprootBuilderErrorElements(elements::taproot::TaprootBuilderError),
    #[error("Failed to finalize taproot")]
    TaprootFinalizationError,
}

const SIMPLICITY_TAG_PREFIX: &[u8] = b"Simplicity\x1fCommitment\x1f";

const JETIV: sha256::Midstate = sha256::Midstate([
    0x95, 0x32, 0xee, 0x28, 0xcd, 0xca, 0x69, 0xde, 0xc8, 0xa0, 0xa2, 0x18, 0xb7, 0x9b, 0xe3, 0x62,
    0xf7, 0x40, 0xce, 0xaf, 0x64, 0x7f, 0x15, 0xb3, 0x8a, 0xed, 0x91, 0x68, 0x16, 0x3f, 0x92, 0x1b,
]);

/// The standard NUMS internal key for Taproot outputs.
///
/// Used as the internal key in P2TR outputs that enforce spending exclusively
/// via script-path.
///
/// Reference: BIP-341 — <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
pub static UNSPENDABLE_KEY_P2TR: LazyLock<bitcoin::XOnlyPublicKey> = LazyLock::new(|| {
    bitcoin::XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap()
});

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

#[derive(Error, Debug)]
pub enum SigExtractionError {
    #[error("Input {0}: failed to parse tapscript leaf")]
    ParseFail(usize),
    #[error("Input {0}: unexpected number of instructions; expected {1}, got {2}")]
    ScriptLenMismatch(usize, usize, usize),
    #[error("Input {0}: invalid xonly pk at position {1}")]
    InvalidPubKey(usize, usize),
    #[error("Input {0}: expected 32-byte xonly pk at position {1}")]
    ExpectedPubkey(usize, usize),
    #[error("Input {0}: recovery key does not match multisig user key")]
    RecoveryKeyMismatch(usize),
}

/// Builds the P2TR multisig leaf script for the normal cooperative spend path.
/// Script structure:
/// ```text
/// <cosigner_xonly> OP_CHECKSIG <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
/// ```
///
/// Witness order during finalization: `<user_sig> <cosigner_sig> <script> <control_block>`
pub fn p2tr_multisig_leaf_btc(
    cosigner_pk: &PublicKey,
    user_pk: &PublicKey,
) -> bitcoin::script::ScriptBuf {
    bitcoin::script::Builder::new()
        .push_x_only_key(&cosigner_pk.to_x_only_pubkey())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .push_x_only_key(&user_pk.to_x_only_pubkey())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script()
}

/// Builds the P2TR multisig leaf script for the normal cooperative spend path.
/// Script structure:
/// ```text
/// <cosigner_xonly> OP_CHECKSIG <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
/// ```
///
/// Witness order during finalization: `<user_sig> <cosigner_sig> <script> <control_block>`
pub fn p2tr_multisig_leaf_elements(
    cosigner_pk: &PublicKey,
    user_pk: &PublicKey,
) -> elements::script::Script {
    let cosigner_x_only_bytes = cosigner_pk.to_x_only_pubkey().serialize();
    let user_x_only_bytes = user_pk.to_x_only_pubkey().serialize();

    elements::script::Builder::new()
        .push_slice(&cosigner_x_only_bytes)
        .push_opcode(elements::opcodes::all::OP_CHECKSIG)
        .push_slice(&user_x_only_bytes)
        .push_opcode(elements::opcodes::all::OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(elements::opcodes::all::OP_EQUAL)
        .into_script()
}

/// Extracts the cosigner and user x-only pubkeys from a P2TR multisig leaf.
///
/// Expected script structure:
/// ```text
/// <cosigner_xonly(32)> OP_CHECKSIG <user_xonly(32)> OP_CHECKSIGADD OP_2 OP_EQUAL
/// ```
///
/// Returns `[cosigner_xonly, user_xonly]`
pub fn extract_pubkeys_from_p2tr_multisig_leaf_btc(
    script: &bitcoin::blockdata::script::Script,
    input_index: usize,
) -> Result<[bitcoin::XOnlyPublicKey; 2], SigExtractionError> {
    let instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SigExtractionError::ParseFail(input_index))?;

    // Expected: <cosigner_xonly> OP_CHECKSIG <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
    if instructions.len() != 6 {
        return Err(SigExtractionError::ScriptLenMismatch(
            input_index,
            6,
            instructions.len(),
        ));
    }

    let pk1 = match &instructions[0] {
        bitcoin::blockdata::script::Instruction::PushBytes(b) if b.len() == 32 => {
            bitcoin::XOnlyPublicKey::from_slice(b.as_bytes())
                .map_err(|_| SigExtractionError::InvalidPubKey(input_index, 0))?
        }
        _ => return Err(SigExtractionError::ExpectedPubkey(input_index, 0)),
    };

    let pk2 = match &instructions[2] {
        bitcoin::blockdata::script::Instruction::PushBytes(b) if b.len() == 32 => {
            bitcoin::XOnlyPublicKey::from_slice(b.as_bytes())
                .map_err(|_| SigExtractionError::InvalidPubKey(input_index, 2))?
        }
        _ => return Err(SigExtractionError::ExpectedPubkey(input_index, 2)),
    };

    Ok([pk1, pk2])
}

/// Extracts the cosigner and user x-only pubkeys from a P2TR multisig leaf.
///
/// Expected script structure:
/// ```text
/// <cosigner_xonly(32)> OP_CHECKSIG <user_xonly(32)> OP_CHECKSIGADD OP_2 OP_EQUAL
/// ```
///
/// Returns `[cosigner_xonly, user_xonly]`
pub fn extract_pubkeys_from_p2tr_multisig_leaf_elements(
    script: &elements::script::Script,
    input_index: usize,
) -> Result<[elements::secp256k1_zkp::XOnlyPublicKey; 2], SigExtractionError> {
    let instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SigExtractionError::ParseFail(input_index))?;

    // Expected: <cosigner_xonly> OP_CHECKSIG <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
    if instructions.len() != 6 {
        return Err(SigExtractionError::ScriptLenMismatch(
            input_index,
            6,
            instructions.len(),
        ));
    }

    let pk1 = match &instructions[0] {
        elements::script::Instruction::PushBytes(b) if b.len() == 32 => {
            elements::secp256k1_zkp::XOnlyPublicKey::from_slice(b)
                .map_err(|_| SigExtractionError::InvalidPubKey(input_index, 0))?
        }
        _ => return Err(SigExtractionError::ExpectedPubkey(input_index, 0)),
    };

    let pk2 = match &instructions[2] {
        elements::script::Instruction::PushBytes(b) if b.len() == 32 => {
            elements::secp256k1_zkp::XOnlyPublicKey::from_slice(b)
                .map_err(|_| SigExtractionError::InvalidPubKey(input_index, 2))?
        }
        _ => return Err(SigExtractionError::ExpectedPubkey(input_index, 2)),
    };

    Ok([pk1, pk2])
}

/// Generate a 2-of-2 multisig address from a list of public keys
/// Returns the address and the redeem script
pub fn generate_p2tr_address_elements(
    service_key: &PublicKey,
    user_key: &PublicKey,
    user_leaf_hash: elements::hashes::sha256::Hash,
    address_params: &'static elements::AddressParams,
) -> Result<(elements::Address, elements::taproot::TaprootSpendInfo), UtilsError> {
    let secp = elements::secp256k1_zkp::Secp256k1::verification_only();

    let multisig_leaf = p2tr_multisig_leaf_elements(service_key, user_key);

    let spend_info = elements::taproot::TaprootBuilder::new()
        .add_leaf(1, multisig_leaf)
        .map_err(UtilsError::TaprootBuilderErrorElements)?
        .add_hidden(1, user_leaf_hash)
        .map_err(UtilsError::TaprootBuilderErrorElements)?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| UtilsError::TaprootFinalizationError)?;

    let address =
        elements::address::Address::p2tr_tweaked(spend_info.output_key(), None, address_params);

    Ok((address, spend_info))
}

pub fn generate_p2tr_address_btc(
    service_key: &PublicKey,
    user_key: &PublicKey,
    user_leaf_hash: bitcoin::TapNodeHash,
    network: bitcoin::Network,
) -> Result<(bitcoin::Address, TaprootSpendInfo), UtilsError> {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();

    let multisig_leaf = p2tr_multisig_leaf_btc(service_key, user_key);

    let spend_info = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(1, multisig_leaf)
        .map_err(UtilsError::TaprootBuilderErrorBtc)?
        .add_hidden_node(1, user_leaf_hash)
        .map_err(UtilsError::TaprootBuilderErrorBtc)?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| UtilsError::TaprootFinalizationError)?;

    let address =
        bitcoin::address::Address::p2tr_tweaked(spend_info.output_key(), KnownHrp::from(network));

    Ok((address, spend_info))
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
    fn test_generate_multiple_keypairs_unique() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        // Verify keys are different
        assert_ne!(sk1.secret_bytes(), sk2.secret_bytes());
        assert_ne!(pk1.inner, pk2.inner);
    }
}
