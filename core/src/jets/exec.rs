use simplicity::{
    elements::{Transaction, opcodes::all::OP_PUSHBYTES_33},
    ffi::CFrameItem,
    ffi::c_jets::frame_ffi::{c_readBit, c_writeBit},
};

use crate::jets::environments::ElementsUnchainedEnv;

use super::environments::UnchainedEnv;

/// Reads a big-endian `n`-bit value from a C read frame.
fn read_bits(src: &mut CFrameItem, n: u32) -> u64 {
    let mut value = 0;
    for _ in 0..n {
        value = (value << 1) | u64::from(unsafe { c_readBit(src) });
    }
    value
}

/// Writes the low `n` bits of `value`, big-endian, to a C write frame.
fn write_bits(dst: &mut CFrameItem, value: u64, n: u32) {
    for i in (0..n).rev() {
        unsafe { c_writeBit(dst, (value >> i) & 1 == 1) };
    }
}

/// 2^8 |- 2^8
///
/// Returns the opcode at the given index in the redeem script, each opcode is one byte.
pub fn get_opcode_from_script<E>(
    dst: &mut CFrameItem,
    mut src: CFrameItem,
    env: &UnchainedEnv<E>,
) -> bool {
    let index = read_bits(&mut src, 8) as usize;
    if index >= env.redeem_script.len() {
        return false;
    }

    let opcode = env.redeem_script.as_bytes()[index];

    write_bits(dst, opcode.into(), 8);

    true
}
/// 2^8 |- 2^256
///
/// Each pubkey is encoded as: [OP_PUSHBYTES_33][0x02 or 0x03][32 bytes X coordinate]
pub fn get_pubkey_from_script<E>(
    dst: &mut CFrameItem,
    mut src: CFrameItem,
    env: &UnchainedEnv<E>,
) -> bool {
    let start_index = read_bits(&mut src, 8) as usize;
    if start_index + 34 > env.redeem_script.len() {
        return false;
    }

    let push_bytes_opcode = env.redeem_script.as_bytes()[start_index];
    if push_bytes_opcode != OP_PUSHBYTES_33.into_u8() {
        return false;
    }

    let prefix = env.redeem_script.as_bytes()[start_index + 1];
    if prefix != 0x02 && prefix != 0x03 {
        return false;
    }

    let x_only_pubkey_start = start_index + 2;

    let pubkey_bytes = &env.redeem_script.as_bytes()[x_only_pubkey_start..x_only_pubkey_start + 32];

    let words: Vec<u32> = pubkey_bytes
        .chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("Chunk with incorrect length")))
        .collect::<Vec<u32>>();

    for word in words.iter() {
        write_bits(dst, (*word).into(), 32);
    }

    true
}

// Changes ported from <https://github.com/BlockstreamResearch/simplicity/pull/326/changes/a97e57cd96f1ae110d75429043393fca10702a3e>

/// 2^16 |- ONE
pub fn check_lock_duration(
    _dst: &mut CFrameItem,
    mut src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    let req_duration = read_bits(&mut src, 16) as u16;
    req_duration <= lock_duration(tx, ix)
}

/// 2^16 |- ONE
pub fn check_lock_distance(
    _dst: &mut CFrameItem,
    mut src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    let req_distance = read_bits(&mut src, 16) as u16;
    req_distance <= lock_distance(tx, ix)
}

/// ONE |- 2^16
pub fn tx_lock_duration(
    dst: &mut CFrameItem,
    _src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    write_bits(dst, lock_duration(tx, ix).into(), 16);
    true
}

/// ONE |- 2^16
pub fn tx_lock_distance(
    dst: &mut CFrameItem,
    _src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    write_bits(dst, lock_distance(tx, ix).into(), 16);
    true
}

fn lock_duration(tx: &Transaction, ix: u32) -> u16 {
    assert!((ix as usize) < tx.input.len());

    if (2 <= tx.version)
        && (tx.input[ix as usize].sequence.0 < 0x80000000)
        && (tx.input[ix as usize].sequence.0 & (1 << 22) != 0)
    {
        return (tx.input[ix as usize].sequence.0 & 0xFFFF) as u16;
    }

    0
}

fn lock_distance(tx: &Transaction, ix: u32) -> u16 {
    assert!((ix as usize) < tx.input.len());

    if (2 <= tx.version)
        && (tx.input[ix as usize].sequence.0 < 0x80000000)
        && (tx.input[ix as usize].sequence.0 & (1 << 22) == 0)
    {
        return (tx.input[ix as usize].sequence.0 & 0xFFFF) as u16;
    }
    0
}
