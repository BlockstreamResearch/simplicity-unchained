//! Test plugin extending the Elements jets with jets reading the redeem script.
use jet_plugin_abi::{CFrameItem, JetEnv, read_bits, write_bits};

/// 1 |- 2^16: length of the redeem script.
unsafe extern "C" fn script_len(
    dst: *mut CFrameItem,
    _src: CFrameItem,
    env: *const JetEnv,
) -> bool {
    let len = unsafe { &*env }.redeem_script.len;
    let Ok(len) = u16::try_from(len) else {
        return false;
    };
    unsafe { write_bits(&mut *dst, len.into(), 16) };
    true
}

/// 2^8 |- 2^8: byte of the redeem script at the given index.
unsafe extern "C" fn opcode_at(
    dst: *mut CFrameItem,
    mut src: CFrameItem,
    env: *const JetEnv,
) -> bool {
    let script = unsafe { (*env).redeem_script.as_slice() };
    let index = unsafe { read_bits(&mut src, 8) } as usize;
    let Some(&opcode) = script.get(index) else {
        return false;
    };
    unsafe { write_bits(&mut *dst, opcode.into(), 8) };
    true
}

jet_plugin_abi::register_jets! {
    base: Elements,
    jets: {
        script_len: "1" -> "s" {
            cost_milliweight: 100,
            code: 0b1111_1110,
            code_len: 8,
            cmr: [0x11; 32],
        },
        opcode_at: "c" -> "c" {
            cost_milliweight: 100,
            code: 0b1_1111_1110,
            code_len: 9,
            cmr: [0x22; 32],
        },
    },
}
