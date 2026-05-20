use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use hal_simplicity::{
    bitcoin,
    simplicity::{
        ToXOnlyPubkey,
        elements::{
            self, SchnorrSig,
            encode::{deserialize, serialize},
            hashes::Hash,
            pset::PartiallySignedTransaction,
            secp256k1_zkp::{Message, Secp256k1, SecretKey},
            sighash::{SchnorrSighashType, SighashCache},
            taproot::{LeafVersion, TaprootBuilder},
        },
    },
};
use serde_json::json;
use simplicity_unchained_core::{
    ElementsNetwork,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_elements},
};

pub fn execute(
    pset_hex: &str,
    secret_key_hex: &str,
    input_index: usize,
    cosigner_pubkey_hex: &str,
    user_leaf_hash_hex: &str,
    network: &str,
) -> Result<()> {
    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let mut pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    if input_index >= pset.inputs().len() {
        return Err(anyhow::anyhow!(
            "Input index {} out of bounds (PSET has {} inputs)",
            input_index,
            pset.inputs().len()
        ));
    }

    let secret_key_bytes =
        hex::decode(secret_key_hex).context("Failed to decode secret key hex")?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).context("Invalid secret key")?;

    let genesis_hash = ElementsNetwork::from_str(network)
        .map_err(|e| anyhow!(e))?
        .genesis_hash();

    let secp = Secp256k1::new();

    let public_key = bitcoin::PublicKey::from_private_key(
        &secp,
        &hal_simplicity::simplicity::elements::bitcoin::PrivateKey {
            compressed: true,
            network: hal_simplicity::simplicity::elements::bitcoin::NetworkKind::Main,
            inner: secret_key,
        },
    );

    let cosigner_pubkey_bytes =
        hex::decode(cosigner_pubkey_hex).context("Failed to decode cosigner pubkey hex")?;
    let cosigner_pubkey = bitcoin::PublicKey::from_slice(&cosigner_pubkey_bytes)
        .context("Invalid cosigner pubkey")?;

    let multisig_leaf = p2tr_multisig_leaf_elements(&cosigner_pubkey, &public_key);

    let user_leaf = elements::hashes::sha256::Hash::from_slice(
        &hex::decode(user_leaf_hash_hex).context("Failed to decode user leaf hash hex")?,
    )
    .context("Invalid user leaf hash")?;

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf.clone())
        .context("Failed to add multisig leaf")?
        .add_hidden(1, user_leaf)
        .context("Failed to add user leaf")?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot"))?;

    let control_block = spend_info
        .control_block(&(multisig_leaf.clone(), LeafVersion::default()))
        .ok_or_else(|| anyhow::anyhow!("Failed to get control block"))?;

    let tx = pset.extract_tx().context("Failed to extract transaction")?;

    let prevouts: Vec<_> = pset
        .inputs()
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))
        })
        .collect::<Result<_>>()?;

    let mut sighash_cache = SighashCache::new(&tx);

    let leaf_hash = elements::sighash::ScriptPath::with_defaults(&multisig_leaf).leaf_hash();

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &elements::sighash::Prevouts::All(&prevouts),
            elements::sighash::ScriptPath::with_defaults(&multisig_leaf),
            SchnorrSighashType::Default,
            genesis_hash,
        )
        .context("Failed to compute sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let user_xonly = public_key.to_x_only_pubkey();

    let input = &mut pset.inputs_mut()[input_index];
    input.tap_script_sigs.insert(
        (user_xonly, leaf_hash),
        SchnorrSig {
            sig: signature,
            hash_ty: SchnorrSighashType::Default,
        },
    );
    input
        .tap_scripts
        .insert(control_block, (multisig_leaf, LeafVersion::default()));

    let partial_sigs_count = pset.inputs()[input_index].tap_script_sigs.len();

    let output = json!({
        "pset": hex::encode(serialize(&pset)),
        "signature_hex": hex::encode(signature.as_ref()),
        "public_key_hex": hex::encode(public_key.to_bytes()),
        "input_index": input_index,
        "partial_sigs_count": partial_sigs_count,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
