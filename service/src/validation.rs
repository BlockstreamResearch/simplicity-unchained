use validator::ValidationError;

use hal_simplicity::simplicity::elements;

use elements::{
    opcodes::all::OP_CHECKMULTISIG,
    script::{Instruction, Script},
};

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

pub fn validate_redeem_script(hex: &str) -> Result<(), ValidationError> {
    validate_hex(hex)?;

    let script_bytes =
        hex::decode(hex).map_err(|_| ValidationError::new("script_decode_failed"))?;
    let script = Script::from(script_bytes);

    validate_2of2_multisig_script(&script).map_err(|e| {
        let mut err: ValidationError = ValidationError::new("invalid_multisig_script");
        err.message = Some(std::borrow::Cow::Owned(e));
        err
    })?;

    Ok(())
}

pub fn validate_2of2_multisig_script(script: &Script) -> Result<(), String> {
    let instructions: Vec<Instruction> = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse script instructions: {}", e))?;

    // 2-of-2 multisig script should have exactly 5 instructions:
    // OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    if instructions.len() != 5 {
        return Err(format!(
            "Invalid 2-of-2 multisig script: expected 5 instructions (OP_2, pubkey1, pubkey2, OP_2, OP_CHECKMULTISIG), got {} instructions",
            instructions.len()
        ));
    }

    // Check OP_2
    if !matches!(instructions[0], Instruction::Op(op) if op.into_u8() == 0x52) {
        let actual = match &instructions[0] {
            Instruction::Op(op) => format!("opcode 0x{:02x}", op.into_u8()),
            Instruction::PushBytes(bytes) => format!("{} bytes of data", bytes.len()),
        };
        return Err(format!(
            "Invalid 2-of-2 multisig script: expected OP_2 (0x52) at position 0, found {}",
            actual
        ));
    }

    // Check two public keys
    for idx in [1, 2].iter() {
        match &instructions[*idx] {
            Instruction::PushBytes(bytes) if bytes.len() == 33 || bytes.len() == 65 => {
                // Valid compressed (33) or uncompressed (65) public key
            }
            Instruction::PushBytes(bytes) => {
                return Err(format!(
                    "Invalid 2-of-2 multisig script: expected public key (33 or 65 bytes) at position {}, found {} bytes of data",
                    idx,
                    bytes.len()
                ));
            }
            Instruction::Op(op) => {
                return Err(format!(
                    "Invalid 2-of-2 multisig script: expected public key at position {}, found opcode 0x{:02x}",
                    idx,
                    op.into_u8()
                ));
            }
        }
    }

    // Check OP_2
    if !matches!(instructions[3], Instruction::Op(op) if op.into_u8() == 0x52) {
        let actual = match &instructions[3] {
            Instruction::Op(op) => format!("opcode 0x{:02x}", op.into_u8()),
            Instruction::PushBytes(bytes) => format!("{} bytes of data", bytes.len()),
        };
        return Err(format!(
            "Invalid 2-of-2 multisig script: expected OP_2 (0x52) at position 3, found {}",
            actual
        ));
    }

    // Check OP_CHECKMULTISIG
    if !matches!(instructions[4], Instruction::Op(op) if op == OP_CHECKMULTISIG) {
        let actual = match &instructions[4] {
            Instruction::Op(op) => format!("opcode 0x{:02x}", op.into_u8()),
            Instruction::PushBytes(bytes) => format!("{} bytes of data", bytes.len()),
        };
        return Err(format!(
            "Invalid 2-of-2 multisig script: expected OP_CHECKMULTISIG (0xae) at position 4, found {}",
            actual
        ));
    }

    Ok(())
}
