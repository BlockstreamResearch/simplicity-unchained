use std::str::FromStr;
use std::sync::LazyLock;

use simplicity::bitcoin::KnownHrp;
use simplicity::bitcoin::taproot::TaprootSpendInfo;
use simplicity::elements::{
    self,
    bitcoin::PublicKey,
    secp256k1_zkp::{Secp256k1, SecretKey, rand::rngs::OsRng},
};
use simplicity::hashes::{HashEngine, sha256};
use simplicity::{Cmr, ToXOnlyPubkey, bitcoin};

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

/// Version 1 key commitment: tagged SHA256 of `CMR || SHA256(redeem_script)`.
///
/// The script bytes must be identical at address generation and execution time.
/// Empty scripts are committed too; this never falls back to a CMR-only tweak.
pub fn signing_commitment(cmr: Cmr, redeem_script: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"SimplicityUnchained/SigningCommitment/v1");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(&cmr.to_byte_array());
    engine.input(sha256::Hash::hash(redeem_script).as_byte_array());
    sha256::Hash::from_engine(engine).to_byte_array()
}

const JETIV: sha256::Midstate = sha256::Midstate::new(
    [
        0x95, 0x32, 0xee, 0x28, 0xcd, 0xca, 0x69, 0xde, 0xc8, 0xa0, 0xa2, 0x18, 0xb7, 0x9b, 0xe3,
        0x62, 0xf7, 0x40, 0xce, 0xaf, 0x64, 0x7f, 0x15, 0xb3, 0x8a, 0xed, 0x91, 0x68, 0x16, 0x3f,
        0x92, 0x1b,
    ],
    0,
);

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

    let mut engine = sha256::HashEngine::from_midstate(JETIV);
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
    #[error("Input {0}: unexpected opcode at position {1}")]
    UnexpectedOpcode(usize, usize),
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
        .instructions_minimal()
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

    for (position, opcode) in [
        (1, bitcoin::opcodes::all::OP_CHECKSIG),
        (3, bitcoin::opcodes::all::OP_CHECKSIGADD),
        (4, bitcoin::opcodes::all::OP_PUSHNUM_2),
        (5, bitcoin::opcodes::all::OP_EQUAL),
    ] {
        if instructions[position] != bitcoin::script::Instruction::Op(opcode) {
            return Err(SigExtractionError::UnexpectedOpcode(input_index, position));
        }
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
        .instructions_minimal()
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

    for (position, opcode) in [
        (1, elements::opcodes::all::OP_CHECKSIG),
        (3, elements::opcodes::all::OP_CHECKSIGADD),
        (4, elements::opcodes::all::OP_PUSHNUM_2),
        (5, elements::opcodes::all::OP_EQUAL),
    ] {
        if instructions[position] != elements::script::Instruction::Op(opcode) {
            return Err(SigExtractionError::UnexpectedOpcode(input_index, position));
        }
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
        .add_hidden(
            1,
            elements::taproot::TapNodeHash::from_byte_array(user_leaf_hash.to_byte_array()),
        )
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
    use simplicity::elements::secp256k1_zkp::{PublicKey as Secp256k1PublicKey, Secp256k1};

    #[test]
    fn multisig_leaf_parsers_require_every_opcode_and_canonical_pushes() {
        let (_, cosigner) = generate_keypair();
        let (_, user) = generate_keypair();
        let btc = p2tr_multisig_leaf_btc(&cosigner, &user);
        let elements = p2tr_multisig_leaf_elements(&cosigner, &user);
        assert_eq!(
            extract_pubkeys_from_p2tr_multisig_leaf_btc(&btc, 0).unwrap(),
            [cosigner.to_x_only_pubkey(), user.to_x_only_pubkey()],
        );
        assert_eq!(
            extract_pubkeys_from_p2tr_multisig_leaf_elements(&elements, 0).unwrap(),
            [cosigner.to_x_only_pubkey(), user.to_x_only_pubkey()],
        );
        for original in [btc.as_bytes(), elements.as_bytes()] {
            for position in [33, 67, 68, 69] {
                let mut changed = original.to_vec();
                changed[position] = 0x61; // OP_NOP preserves instruction count.
                assert!(matches!(
                    extract_pubkeys_from_p2tr_multisig_leaf_btc(
                        &bitcoin::ScriptBuf::from_bytes(changed.clone()),
                        3
                    ),
                    Err(SigExtractionError::UnexpectedOpcode(3, _)),
                ));
                assert!(matches!(
                    extract_pubkeys_from_p2tr_multisig_leaf_elements(
                        &elements::Script::from(changed),
                        3
                    ),
                    Err(SigExtractionError::UnexpectedOpcode(3, _)),
                ));
            }
            let mut nonminimal = vec![0x4c, 0x20];
            nonminimal.extend_from_slice(&original[1..]);
            assert!(
                extract_pubkeys_from_p2tr_multisig_leaf_btc(
                    &bitcoin::ScriptBuf::from_bytes(nonminimal.clone()),
                    0,
                )
                .is_err()
            );
            assert!(
                extract_pubkeys_from_p2tr_multisig_leaf_elements(
                    &elements::Script::from(nonminimal),
                    0,
                )
                .is_err()
            );
            let mut invalid_key = original.to_vec();
            invalid_key[1..33].fill(0xff);
            assert!(
                extract_pubkeys_from_p2tr_multisig_leaf_btc(
                    &bitcoin::ScriptBuf::from_bytes(invalid_key.clone()),
                    0,
                )
                .is_err()
            );
            assert!(
                extract_pubkeys_from_p2tr_multisig_leaf_elements(
                    &elements::Script::from(invalid_key),
                    0,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn test_signing_commitment() {
        let cmr = Cmr::from_byte_array([1; 32]);
        let mut script = vec![0x52, 0x21, 0x02];
        script.extend_from_slice(&[2; 32]);
        let commitment = signing_commitment(cmr, &script);
        assert_eq!(
            hex::encode(commitment),
            "d1eeca3675cdeeb910edb4644dc13ffba0b2d8f1ee9c10133ea724f089994f57"
        );
        assert_ne!(
            commitment,
            signing_commitment(Cmr::from_byte_array([2; 32]), &script)
        );
        script[2] = 0x03;
        assert_ne!(commitment, signing_commitment(cmr, &script));
        assert_ne!(signing_commitment(cmr, &[]), cmr.to_byte_array());
        assert_ne!(signing_commitment(cmr, &[]), signing_commitment(cmr, &[0]));
    }

    #[test]
    fn legacy_tweak_and_address_golden_vector() {
        use bitcoin::hashes::Hash;
        use bitcoin::key::TapTweak;
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};

        // Independently calculated with SHA256 and secp256k1 point arithmetic.
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let base = bitcoin::XOnlyPublicKey::from_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let user = bitcoin::XOnlyPublicKey::from_str(
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let mut script = vec![0x52, 0x21, 0x02];
        script.extend_from_slice(&[2; 32]);
        let commitment = signing_commitment(Cmr::from_byte_array([1; 32]), &script);
        assert_eq!(
            hex::encode(commitment),
            "d1eeca3675cdeeb910edb4644dc13ffba0b2d8f1ee9c10133ea724f089994f57",
        );
        let (service, _) = base.tap_tweak(&secp, Some(TapNodeHash::from_byte_array(commitment)));
        assert_eq!(
            hex::encode(service.serialize()),
            "c38d3764be1552da4b3a4a9e2fa2bb5334b1e95e2693d3200e300f85e6432c7d",
        );
        let full = |key| {
            bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                key,
                bitcoin::secp256k1::Parity::Even,
            ))
        };
        let service = full(service.to_x_only_public_key());
        let user = full(user);
        let leaf = p2tr_multisig_leaf_btc(&service, &user);
        assert_eq!(
            hex::encode(TapLeafHash::from_script(&leaf, LeafVersion::TapScript).to_byte_array()),
            "b6c4db550a7e7aaccc121cb65c72c68af7c959775644991cdce8c862cbe9e285",
        );
        for (network, expected) in [
            (
                bitcoin::Network::Testnet,
                "tb1plkhkj9m23n9aqdme05a0257egx3ktlgnxlpmg0u8xvu07amq2jvsy3yfy7",
            ),
            (
                bitcoin::Network::Bitcoin,
                "bc1plkhkj9m23n9aqdme05a0257egx3ktlgnxlpmg0u8xvu07amq2jvsnejx73",
            ),
        ] {
            let (address, spend) = generate_p2tr_address_btc(
                &service,
                &user,
                TapNodeHash::from_byte_array([3; 32]),
                network,
            )
            .unwrap();
            assert_eq!(address.to_string(), expected);
            assert_eq!(
                hex::encode(spend.merkle_root().unwrap().to_byte_array()),
                "78d9fdaea0b27a14cbe0934f75790861efef3f584ca0319da635f67c31f9ee0a",
            );
            assert_eq!(
                hex::encode(address.script_pubkey().as_bytes()),
                "5120fdaf69176a8ccbd037797d3af553d941a365fd1337c3b43f873338ff77605499",
            );
        }
    }

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
