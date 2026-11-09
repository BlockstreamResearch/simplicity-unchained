use anyhow::Result;
use serde_json::json;
use simplicity_unchained_core::utils::generate_keypair;

pub fn execute() -> Result<()> {
    let (secret_key, public_key) = generate_keypair();

    let output = json!({
        "secret_key": hex::encode(secret_key.secret_bytes()),
        "public_key": hex::encode(public_key.to_bytes()),
        "compressed": public_key.compressed
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
