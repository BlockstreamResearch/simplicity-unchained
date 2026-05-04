use anyhow::{Context, Result, anyhow};
use hal_simplicity::{
    bitcoin::{self, key::UntweakedKeypair},
    simplicity::elements::{
        self, SchnorrSig,
        encode::{deserialize, serialize},
        hashes::Hash,
        pset::PartiallySignedTransaction,
        secp256k1_zkp::{Message, Secp256k1, SecretKey},
        sighash::{Prevouts, SchnorrSighashType, SighashCache},
        taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    },
};
use serde_json::json;
use simplicity_unchained_core::{
    ElementsNetwork,
    utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_elements},
};
use std::str::FromStr;

pub fn execute(
    pset_hex: &str,
    secret_key_hex: &str,
    user_leaf_script_hex: &str,
    cosigner_pubkey_hex: &str,
    input_index: usize,
    network: &str,
) -> Result<()> {
    let secp = Secp256k1::new();

    let pset_bytes = hex::decode(pset_hex).context("Failed to decode PSET hex")?;
    let mut pset: PartiallySignedTransaction =
        deserialize(&pset_bytes).context("Failed to deserialize PSET")?;

    let secret_key = SecretKey::from_str(secret_key_hex).context("Failed to parse secret key")?;
    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let (user_xonly, _) = keypair.x_only_public_key();
    let user_full_pk = bitcoin::PublicKey::new(keypair.public_key());

    let user_leaf_bytes =
        hex::decode(user_leaf_script_hex).context("Failed to decode user leaf script hex")?;
    let user_leaf_script = elements::script::Script::from(user_leaf_bytes);

    let cosigner_pubkey = bitcoin::PublicKey::from_str(cosigner_pubkey_hex)
        .context("Failed to parse cosigner pubkey")?;

    let genesis_hash = ElementsNetwork::from_str(network)
        .map_err(|e| anyhow!(e))?
        .genesis_hash();

    let multisig_leaf = p2tr_multisig_leaf_elements(&cosigner_pubkey, &user_full_pk);

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf)
        .context("Failed to add multisig leaf")?
        .add_leaf(1, user_leaf_script.clone())
        .context("Failed to add user leaf")?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot"))?;

    let control_block = spend_info
        .control_block(&(user_leaf_script.clone(), LeafVersion::default()))
        .ok_or_else(|| anyhow::anyhow!("Failed to get control block for user leaf"))?;

    let tx = pset.extract_tx().context("Failed to extract transaction")?;

    let prevouts = pset
        .inputs()
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            elements::sighash::ScriptPath::with_defaults(&user_leaf_script),
            SchnorrSighashType::Default,
            genesis_hash,
        )
        .context("Failed to compute sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);

    let leaf_hash = TapLeafHash::from_script(&user_leaf_script, LeafVersion::default());

    pset.inputs_mut()[input_index].tap_script_sigs.insert(
        (user_xonly, leaf_hash),
        SchnorrSig {
            sig: signature,
            hash_ty: SchnorrSighashType::Default,
        },
    );

    pset.inputs_mut()[input_index]
        .tap_scripts
        .insert(control_block, (user_leaf_script, LeafVersion::default()));

    let output = json!({
        "pset": hex::encode(serialize(&pset)),
        "signature": hex::encode(signature.as_ref()),
        "input_index": input_index,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
