//! Generate a public TEST-ONLY fixture. It contains known private keys; never fund it.
#[allow(dead_code)]
mod common {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/common/liquid.rs"
    ));
}
use common::*;
use serde_json::json;
use simplicity::base64::{Engine, engine::general_purpose::STANDARD};
use simplicity_unchained_policy::liquid::{
    self as policy,
    elements::{
        encode::serialize,
        secp256k1_zkp::{PublicKey, Secp256k1},
    },
};

fn main() {
    let mut f = Fixture::deterministic();
    let original = f.pset.clone();
    let contexts = (0..2)
        .map(|i| f.context(i).unwrap().summary())
        .collect::<Vec<_>>();
    let mut service_signatures = Vec::new();
    for index in 0..2 {
        let c = f.context(index).unwrap();
        let secret = f.service_secret();
        let sig = policy::add_signature(&c, &mut f.pset, secret, true).unwrap();
        service_signatures.push(json!({"input_index":index,"signature_hex":hex::encode(sig.sig.as_ref()),"public_key_hex":c.cooperative().service_pubkey.to_string()}));
    }
    let service_signed = hex::encode(serialize(&f.pset));
    let mut user_signatures = Vec::new();
    for index in 0..2 {
        let c = f.context(index).unwrap();
        let sig = policy::add_signature(&c, &mut f.pset, f.user_secret, false).unwrap();
        user_signatures.push(json!({"input_index":index,"signature_hex":hex::encode(sig.sig.as_ref()),"public_key_hex":f.user.to_string()}));
    }
    let tx = policy::finalize(&f.context(0).unwrap(), &f.pset).unwrap();
    let mut negative = serde_json::Map::new();
    for (name, mutation) in [
        ("input_amount", 0),
        ("input_asset", 1),
        ("missing_input_value_proof", 2),
        ("missing_input_asset_proof", 3),
        ("missing_parent", 4),
        ("output_amount", 5),
        ("output_asset", 6),
        ("missing_output_value_proof", 7),
        ("missing_output_asset_proof", 8),
        ("missing_output_rangeproof", 9),
        ("missing_output_surjection_proof", 10),
        ("wrong_input_value_proof", 11),
    ] {
        let mut p = original.clone();
        match mutation {
            0 => p.inputs_mut()[0].amount = Some(99_999),
            1 => p.inputs_mut()[0].asset = Some(f.other_asset),
            2 => p.inputs_mut()[0].blind_value_proof = None,
            3 => p.inputs_mut()[0].blind_asset_proof = None,
            4 => p.inputs_mut()[0].non_witness_utxo = None,
            5 => p.outputs_mut()[0].amount = Some(20_001),
            6 => p.outputs_mut()[0].asset = Some(f.other_asset),
            7 => p.outputs_mut()[0].blind_value_proof = None,
            8 => p.outputs_mut()[0].blind_asset_proof = None,
            9 => p.outputs_mut()[0].value_rangeproof = None,
            10 => p.outputs_mut()[0].asset_surjection_proof = None,
            _ => {
                p.inputs_mut()[0].blind_value_proof = original.inputs()[1].blind_value_proof.clone()
            }
        }
        assert!(f.context_for(&p, 0).is_err());
        negative.insert(name.into(), hex::encode(serialize(&p)).into());
    }
    let parent = original.inputs()[0].non_witness_utxo.as_ref().unwrap();
    let fixture = json!({
        "warning":"PUBLIC TEST-ONLY KNOWN PRIVATE KEYS; NEVER FUND; parents are synthetic content evidence, NOT chain inclusion/consensus-validity/unspentness.",
        "profile":"liquid-policy-v1","profile_hash":hex::encode(policy::profile_hash()),"network":"liquidtestnet",
        "source":"fn main() {}","program_base64":STANDARD.encode(&f.program),"witness_base64":"",
        "cmr_hex":hex::encode(f.cmr),"redeem_script_hex":hex::encode(&f.data),
        "recovery_script":format!("OP_5 OP_CSV OP_DROP OP_PUSHBYTES_32 {} OP_CHECKSIG",f.user),
        "user_leaf_hash_hex":hex::encode(f.recovery.to_byte_array()),
        "base_public_key_hex":f.base.to_string(),"user_pubkey":f.user.to_string(),
        "blinding_public_key_hex":PublicKey::from_secret_key(&Secp256k1::new(),&f.blinding_secret).to_string(),
        "test_only_secrets":{"base_secret_key_hex":hex::encode(f.base_secret.secret_bytes()),"user_secret_key_hex":hex::encode(f.user_secret.secret_bytes()),"blinding_secret_key_hex":hex::encode(f.blinding_secret.secret_bytes())},
        "parent_tx_hex":hex::encode(serialize(parent)),"parent_txid":parent.txid().to_string(),
        "source_parent_tx_hex":hex::encode(serialize(&f.source_parent)),
        "source_parent_txid":f.source_parent.txid().to_string(),
        "pset_hex":hex::encode(serialize(&original)),"contexts":contexts,
        "service_signed_pset_hex":service_signed,"service_signatures":service_signatures,
        "user_signatures":user_signatures,"fully_signed_pset_hex":hex::encode(serialize(&f.pset)),
        "transaction_hex":hex::encode(serialize(&tx)),"txid":tx.txid().to_string(),
        "negative_psets":negative,
    });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
