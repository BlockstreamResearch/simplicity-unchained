use anyhow::{Context, Result, anyhow, ensure};
use simplicity::bitcoin::{
    Script, Sequence, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP},
    relative::LockTime,
    script::{Builder, Instruction},
};

pub(crate) fn validate_sequence(
    script: &[u8],
    version: i64,
    sequence: u32,
    input_index: usize,
) -> Result<()> {
    // Bitcoin and Elements use the same encoding for this recovery script.
    let instructions = Script::from_bytes(script)
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Input {input_index}: failed to parse recovery script"))?;
    if !instructions.contains(&Instruction::Op(OP_CSV)) {
        return Ok(());
    }

    let unsupported = || {
        anyhow!(
            "Input {input_index}: unsupported CSV recovery script; expected \
             <blocks: 0..65535> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG"
        )
    };
    let [
        delay,
        Instruction::Op(OP_CSV),
        Instruction::Op(OP_DROP),
        Instruction::PushBytes(key),
        Instruction::Op(OP_CHECKSIG),
    ] = instructions.as_slice()
    else {
        return Err(unsupported());
    };
    let blocks = delay
        .script_num()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(unsupported)?;
    let key = XOnlyPublicKey::from_slice(key.as_bytes())
        .with_context(|| format!("Input {input_index}: invalid CSV recovery public key"))?;
    let canonical = Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ensure!(script == canonical.as_bytes(), "{}", unsupported());
    ensure!(
        version >= 2,
        "Input {input_index}: CSV recovery requires transaction version >= 2"
    );
    ensure!(
        LockTime::from_height(blocks).is_implied_by_sequence(Sequence::from_consensus(sequence)),
        "Input {input_index}: CSV recovery requires a block-based sequence of at least \
         {blocks} with the disable flag clear (got {sequence:#010x}); \
         set --sequence before signing"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use simplicity::bitcoin::opcodes::all::{OP_ENDIF, OP_IF};
    use simplicity_unchained_core::utils::UNSPENDABLE_KEY_P2TR;

    fn leaf(blocks: i64) -> simplicity::bitcoin::ScriptBuf {
        Builder::new()
            .push_int(blocks)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&UNSPENDABLE_KEY_P2TR)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    #[test]
    fn validates_block_delays_and_bip68_flags() {
        for blocks in [0, 1, 16, 17, 127, 128, 144, u16::MAX] {
            let script = leaf(i64::from(blocks));
            for sequence in [
                u32::from(blocks),
                u32::from(u16::MAX),
                0x2000_0000 | u32::from(blocks),
            ] {
                validate_sequence(script.as_bytes(), 2, sequence, 1).unwrap();
                validate_sequence(script.as_bytes(), 3, sequence, 1).unwrap();
            }
            for sequence in [
                u32::MAX,
                0x8000_0000 | u32::from(blocks),
                Sequence::from_512_second_intervals(blocks).0,
            ] {
                let error = validate_sequence(script.as_bytes(), 2, sequence, 1).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("Input 1: CSV recovery requires a block-based")
                );
            }
            if blocks > 0 {
                assert!(validate_sequence(script.as_bytes(), 2, u32::from(blocks - 1), 0).is_err());
            }
            for version in [-1, 0, 1] {
                assert!(
                    validate_sequence(script.as_bytes(), version, u32::from(blocks), 0).is_err()
                );
            }
        }
    }

    #[test]
    fn rejects_unsupported_csv_scripts_but_preserves_non_csv_leaves() {
        for blocks in [-1, 65_536, 1 << 22, 1 << 31] {
            let error = validate_sequence(leaf(blocks).as_bytes(), 2, u32::MAX, 0).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported CSV recovery script")
            );
        }
        let conditional = Builder::new()
            .push_opcode(OP_IF)
            .push_int(144)
            .push_opcode(OP_CSV)
            .push_opcode(OP_ENDIF)
            .into_script();
        assert!(validate_sequence(conditional.as_bytes(), 2, 144, 0).is_err());
        let script = leaf(144).into_bytes();
        let mut nonminimal = vec![0x4c, script[0]];
        nonminimal.extend_from_slice(&script[1..]);
        assert!(validate_sequence(&nonminimal, 2, 144, 0).is_err());
        let mut nonminimal_number = leaf(0).into_bytes();
        nonminimal_number.splice(..1, [1, 0]);
        assert!(validate_sequence(&nonminimal_number, 2, 0, 0).is_err());
        for script in [
            Builder::new().push_int(1).into_script(),
            Builder::new().push_slice([OP_CSV.to_u8()]).into_script(),
        ] {
            validate_sequence(script.as_bytes(), 1, u32::MAX, 0).unwrap();
        }
    }
}
