use hal_simplicity::simplicity::{
    elements::{Transaction, opcodes::all::OP_PUSHBYTES_33},
    ffi::CFrameItem,
};

use crate::jets::environments::ElementsUnchainedEnv;

use super::environments::UnchainedEnv;

#[allow(unused)]
unsafe extern "C" {
    fn rustsimplicity_0_6_write8(dst: *mut CFrameItem, n: u64);
    fn rustsimplicity_0_6_write16(dst: *mut CFrameItem, n: u16);
    fn rustsimplicity_0_6_write32(dst: *mut CFrameItem, n: u32);
    fn rustsimplicity_0_6_write64(dst: *mut CFrameItem, n: u64);

    fn rustsimplicity_0_6_read8(src: *const CFrameItem) -> u64;
    fn rustsimplicity_0_6_read16(src: *const CFrameItem) -> u16;
    fn rustsimplicity_0_6_read32(src: *const CFrameItem) -> u32;
    fn rustsimplicity_0_6_read64(src: *const CFrameItem) -> u64;
}

/// 2^8 |- 2^8
///
/// Returns the opcode at the given index in the redeem script, each opcode is one byte.
pub fn get_opcode_from_script<E>(
    dst: &mut CFrameItem,
    src: CFrameItem,
    env: &UnchainedEnv<E>,
) -> bool {
    let index = unsafe { rustsimplicity_0_6_read8(&src as *const CFrameItem) } as usize;
    if index >= env.redeem_script.len() {
        return false;
    }

    let opcode = env.redeem_script.as_bytes()[index];

    unsafe {
        rustsimplicity_0_6_write8(dst as *mut CFrameItem, opcode as u64);
    }

    true
}
/// 2^8 |- 2^256
///
/// Each pubkey is encoded as: [OP_PUSHBYTES_33][0x02 or 0x03][32 bytes X coordinate]
pub fn get_pubkey_from_script<E>(
    dst: &mut CFrameItem,
    src: CFrameItem,
    env: &UnchainedEnv<E>,
) -> bool {
    let start_index = unsafe { rustsimplicity_0_6_read8(&src as *const CFrameItem) } as usize;
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
        unsafe {
            rustsimplicity_0_6_write32(dst as *mut CFrameItem, *word);
        }
    }

    true
}

// Changes ported from <https://github.com/BlockstreamResearch/simplicity/pull/326/changes/a97e57cd96f1ae110d75429043393fca10702a3e>

/// 2^16 |- ONE
pub fn check_lock_duration(
    _dst: &mut CFrameItem,
    src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    let req_duration = unsafe { rustsimplicity_0_6_read16(&src as *const CFrameItem) };
    req_duration <= lock_duration(tx, ix)
}

/// 2^16 |- ONE
pub fn check_lock_distance(
    _dst: &mut CFrameItem,
    src: CFrameItem,
    env: &ElementsUnchainedEnv,
) -> bool {
    let (tx, ix) = (env.env.tx(), env.env.ix());

    if tx.input.len() <= ix as usize {
        return false;
    }

    let req_distance = unsafe { rustsimplicity_0_6_read16(&src as *const CFrameItem) };
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

    unsafe { rustsimplicity_0_6_write16(dst, lock_duration(tx, ix)) };
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

    unsafe { rustsimplicity_0_6_write16(dst, lock_distance(tx, ix)) };
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
