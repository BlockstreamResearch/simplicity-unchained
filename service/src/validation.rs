use hal_simplicity::bitcoin;
use validator::ValidationError;

pub fn validate_hex(hex: &str) -> Result<(), ValidationError> {
    if hex.trim().is_empty() {
        return Err(ValidationError::new("hex_empty"));
    }
    if !hex.len().is_multiple_of(2) {
        return Err(ValidationError::new("hex_odd_length"));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::new("hex_invalid_chars"));
    }
    Ok(())
}
pub fn validate_redeem_script(value: &str) -> Result<(), ValidationError> {
    let bytes = hex::decode(value).map_err(|_| ValidationError::new("invalid hex"))?;

    let script = bitcoin::script::ScriptBuf::from(bytes);
    for instruction in script.instructions() {
        instruction.map_err(|_| ValidationError::new("invalid script encoding"))?;
    }

    Ok(())
}
