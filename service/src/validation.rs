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

    validate_script_ending_with_multisig(&script).map_err(|e| {
        let mut err: ValidationError = ValidationError::new("invalid_multisig_script");
        err.message = Some(std::borrow::Cow::Owned(e));
        err
    })?;

    Ok(())
}

/// Validates that a script (of any length/structure) ends with a valid M-of-N multisig tail:
///   ```... <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG```
/// The M value (required signers) is read from the opcode just before the pubkeys.
/// The N value (total keys) is read from the opcode just before OP_CHECKMULTISIG.
pub fn validate_script_ending_with_multisig(script: &Script) -> Result<(), String> {
    let instructions: Vec<Instruction> = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse script instructions: {}", e))?;

    let len = instructions.len();

    if len < 4 {
        return Err(format!(
            "Script too short to end with a multisig: need at least 4 instructions, got {}",
            len
        ));
    }

    if !matches!(instructions.last().expect("script is non-empty"), Instruction::Op(op) if op == &OP_CHECKMULTISIG)
    {
        let actual = format_instruction(&instructions[len - 1]);
        return Err(format!(
            "Script does not end with OP_CHECKMULTISIG: found {}",
            actual
        ));
    }

    let n = read_op_num(&instructions[len - 2]).ok_or_else(|| {
        format!(
            "Expected OP_N (total key count) before OP_CHECKMULTISIG, found {}",
            format_instruction(&instructions[len - 2])
        )
    })?;

    if !(1..=16).contains(&n) {
        return Err(format!(
            "Invalid total key count N={}: must be between 1 and 16",
            n
        ));
    }

    let pubkeys_start = len
        .checked_sub(2 + n as usize + 1) // OP_CHECKMULTISIG + OP_N + N keys + OP_M
        .ok_or_else(|| {
            format!(
                "Script too short: need {} pubkeys before OP_{} OP_CHECKMULTISIG, but script only has {} instructions",
                n, n, len
            )
        })?;

    // The instruction at pubkeys_start is OP_M (required signers)
    let m = read_op_num(&instructions[pubkeys_start]).ok_or_else(|| {
        format!(
            "Expected OP_M (required signer count) before pubkeys, found {}",
            format_instruction(&instructions[pubkeys_start])
        )
    })?;

    if !(1..=16).contains(&m) {
        return Err(format!(
            "Invalid required signer count M={}: must be between 1 and 16",
            m
        ));
    }

    if m > n {
        return Err(format!(
            "Invalid multisig: M={} cannot be greater than N={}",
            m, n
        ));
    }

    for i in 0..n as usize {
        let idx = pubkeys_start + 1 + i;
        match &instructions[idx] {
            Instruction::PushBytes(bytes) if bytes.len() == 33 || bytes.len() == 65 => {}
            Instruction::PushBytes(bytes) => {
                return Err(format!(
                    "Expected public key (33 or 65 bytes) at pubkey position {} (instruction {}), found {} bytes",
                    i + 1,
                    idx,
                    bytes.len()
                ));
            }
            Instruction::Op(op) => {
                return Err(format!(
                    "Expected public key at pubkey position {} (instruction {}), found opcode 0x{:02x}",
                    i + 1,
                    idx,
                    op.into_u8()
                ));
            }
        }
    }

    Ok(())
}

/// Reads a small integer (1–16) from an OP_1..OP_16 opcode (0x51..0x60).
/// OP_1 = 0x51, OP_2 = 0x52, ..., OP_16 = 0x60
fn read_op_num(instruction: &Instruction) -> Option<u8> {
    match instruction {
        Instruction::Op(op) => {
            let byte = op.into_u8();
            if (0x51..=0x60).contains(&byte) {
                Some(byte - 0x50)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn format_instruction(instruction: &Instruction) -> String {
    match instruction {
        Instruction::Op(op) => format!("opcode 0x{:02x}", op.into_u8()),
        Instruction::PushBytes(bytes) => format!("{} bytes of data", bytes.len()),
    }
}

#[cfg(test)]
mod test {
    use hal_simplicity::simplicity::elements::opcodes;

    use super::*;

    #[test]
    fn test_read_op_num() {
        let instructions = [
            Instruction::Op(opcodes::all::OP_PUSHNUM_1),
            Instruction::Op(opcodes::all::OP_PUSHNUM_2),
            Instruction::Op(opcodes::all::OP_PUSHNUM_3),
            Instruction::Op(opcodes::all::OP_PUSHNUM_4),
            Instruction::Op(opcodes::all::OP_PUSHNUM_5),
            Instruction::Op(opcodes::all::OP_PUSHNUM_6),
            Instruction::Op(opcodes::all::OP_PUSHNUM_7),
            Instruction::Op(opcodes::all::OP_PUSHNUM_8),
            Instruction::Op(opcodes::all::OP_PUSHNUM_9),
            Instruction::Op(opcodes::all::OP_PUSHNUM_10),
            Instruction::Op(opcodes::all::OP_PUSHNUM_11),
            Instruction::Op(opcodes::all::OP_PUSHNUM_12),
            Instruction::Op(opcodes::all::OP_PUSHNUM_13),
            Instruction::Op(opcodes::all::OP_PUSHNUM_14),
            Instruction::Op(opcodes::all::OP_PUSHNUM_15),
            Instruction::Op(opcodes::all::OP_PUSHNUM_16),
        ];

        for (i, op) in instructions.iter().enumerate() {
            assert_eq!(read_op_num(op), Some((i + 1) as u8));
        }
    }

    /// OP_2
    /// OP_PUSHBYTES_65
    /// OP_PUSHBYTES_65
    /// OP_PUSHBYTES_65
    /// OP_3
    /// OP_CHECKMULTISIG
    /// <https://learnmeabitcoin.com/explorer/tx/cc11ca9e9dc188663c41eb23b15370f68eded56b7ec54dd5bc4f2d2ae93addb2#input-0>
    #[test]
    fn test_validate_multisig() {
        let hex = "524104f3d35132084eb1b99b6506178c20adb42d26296012e452e392689bdb6553db33ba24b900000892805de1646821c7b0fb50b3d879c26e2b493b7041e6215356a04104ab4ecc9e8ea2da0562af25bcaede00c4d5a00db60edc17672376decf0a35a34fdc9f1ffad1fb74fd7b1b198b9231c25df88e0769bec49975649b4b3f40adafb04104f7149f270717c00f6cc09b9ce3c22791c4aab1af40a5107aacca85b6f644cc0d84459e308f998d801b8d9d355f8ec33b0e41866841e2870754cf667a9821703d53ae";

        assert!(validate_redeem_script(hex).is_ok());
    }
}
