use anyhow::{Context, Result};
use hal_simplicity::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use hal_simplicity::bitcoin::{self, TapNodeHash};
use hal_simplicity::simplicity::bitcoin::{
    PublicKey, hashes::Hash, psbt::Psbt, sighash::SighashCache,
};
use hal_simplicity::simplicity::elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use serde_json::json;
use simplicity_unchained_core::utils::{UNSPENDABLE_KEY_P2TR, p2tr_multisig_leaf_btc};

pub fn execute(
    psbt_hex: &str,
    secret_key_hex: &str,
    input_index: usize,
    cosigner_pubkey_hex: Option<&str>,
    user_leaf_hash: &str,
) -> Result<()> {
    let psbt_bytes = hex::decode(psbt_hex).context("Failed to decode PSBT hex")?;
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes).context("Failed to deserialize PSBT")?;

    if input_index >= psbt.inputs.len() {
        return Err(anyhow::anyhow!(
            "Input index {} out of bounds (PSBT has {} inputs)",
            input_index,
            psbt.inputs.len()
        ));
    }

    let secret_key_bytes =
        hex::decode(secret_key_hex).context("Failed to decode secret key hex")?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).context("Invalid secret key")?;

    let secp = Secp256k1::new();

    let public_key = PublicKey::from_private_key(
        &secp,
        &hal_simplicity::simplicity::elements::bitcoin::PrivateKey {
            compressed: true,
            network: hal_simplicity::simplicity::elements::bitcoin::NetworkKind::Main,
            inner: secret_key,
        },
    );

    let tx = psbt.clone().extract_tx()?;

    let mut sighash_cache = SighashCache::new(&tx);

    let cosigner_pubkey_bytes = hex::decode(
        cosigner_pubkey_hex
            .ok_or_else(|| anyhow::anyhow!("--cosigner-pubkey required for P2TR"))?,
    )
    .context("Failed to decode cosigner pubkey hex")?;
    let cosigner_pubkey =
        PublicKey::from_slice(&cosigner_pubkey_bytes).context("Invalid cosigner pubkey")?;

    let multisig_leaf = p2tr_multisig_leaf_btc(&cosigner_pubkey, &public_key);

    let user_leaf = TapNodeHash::from_slice(
        &hex::decode(user_leaf_hash).context("Failed to decode user leaf script hex")?,
    )?;

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, multisig_leaf.clone())
        .context("Failed to add multisig leaf")?
        .add_hidden_node(1, user_leaf)
        .context("Failed to add recovery leaf")?
        .finalize(&secp, *UNSPENDABLE_KEY_P2TR)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot"))?;

    let control_block = spend_info
        .control_block(&(multisig_leaf.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to get control block"))?;

    let prevouts: Vec<_> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))
        })
        .collect::<Result<_>>()?;

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::ScriptPath::with_defaults(&multisig_leaf),
            bitcoin::TapSighashType::Default,
        )
        .context("Failed to compute recovery sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let tap_sig = bitcoin::taproot::Signature {
        signature,
        sighash_type: bitcoin::TapSighashType::Default,
    };

    let leaf_hash = bitcoin::sighash::ScriptPath::with_defaults(&multisig_leaf).leaf_hash();
    let user_xonly = public_key.inner.x_only_public_key().0;

    let input = &mut psbt.inputs[input_index];
    input
        .tap_script_sigs
        .insert((user_xonly, leaf_hash), tap_sig);
    input
        .tap_scripts
        .insert(control_block, (multisig_leaf, LeafVersion::TapScript));

    let output = json!({
        "psbt": hex::encode(psbt.serialize()),
        "signature_hex": hex::encode(signature.as_ref()),
        "public_key_hex": hex::encode(public_key.to_bytes()),
        "input_index": input_index,
        "partial_sigs_count": 0,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
