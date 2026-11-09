//! C ABI between the simplicity-unchained host and custom jet plugins.
//!
//! A plugin is a dynamic library holding a static [`PluginDescriptor`], returned by the function it
//! exports as [`DESCRIPTOR_SYMBOL`] (see [`DescriptorFn`]). The descriptor is plain data: the host
//! owns every Simplicity type and only calls back into the plugin through [`JetFn`].
//!
//! Jets receive the bit machine's frames as [`CFrameItem`]s, so host and plugin must link the
//! same `simplicity-sys`; the host checks [`SIMPLICITY_SYS_VERSION`] at load time.
//
// TODO: drop the `simplicity-sys` dependency by passing opaque frames plus host read/write
// callbacks. That decouples plugins from the host's C library version and lets the host
// bounds-check frame access.
mod macros;
pub mod utils;

use simplicity_sys::c_jets::frame_ffi::{c_readBit, c_writeBit};

pub use simplicity_sys::c_jets::frame_ffi::CFrameItem;

use utils::Bytes;

/// Version of this ABI. The host refuses plugins built against a different one.
pub const ABI_VERSION: u32 = 1;

/// Version of `simplicity-sys` this crate is pinned to; keep in sync with `Cargo.toml`.
pub const SIMPLICITY_SYS_VERSION: &str = "0.8.0";

/// Name of the symbol every plugin exports.
pub const DESCRIPTOR_SYMBOL: &str = "unchained_jet_plugin";

/// Base jet set extended by a plugin.
///
/// Crosses the ABI as a raw `u32` (see [`PluginDescriptor::base_set`]).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseSet {
    /// The host's Bitcoin jets.
    Bitcoin = 0,
    /// The host's Elements jets.
    Elements = 1,
}

impl TryFrom<u32> for BaseSet {
    /// The unknown value.
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, u32> {
        match value {
            0 => Ok(Self::Bitcoin),
            1 => Ok(Self::Elements),
            _ => Err(value),
        }
    }
}

/// Signature of [`DESCRIPTOR_SYMBOL`].
pub type DescriptorFn = unsafe extern "C" fn() -> *const PluginDescriptor;

/// Implementation of a custom jet: reads its input from `src`, writes its output to `dst`.
/// Returns `false` when the jet fails.
///
/// The frames are not bounds-checked: a jet must read and write exactly as many bits as its
/// source and target types have.
pub type JetFn =
    unsafe extern "C" fn(dst: *mut CFrameItem, src: CFrameItem, env: *const JetEnv) -> bool;

/// Everything the host needs to know about a plugin.
#[repr(C)]
#[derive(Debug)]
pub struct PluginDescriptor {
    pub abi_version: u32,
    /// Must be [`SIMPLICITY_SYS_VERSION`].
    pub simplicity_sys_version: Bytes,
    /// A [`BaseSet`] discriminant.
    pub base_set: u32,
    pub jets: *const CustomJetDesc,
    pub jets_len: usize,
}

// SAFETY: descriptors are immutable data meant to live in plugin statics.
unsafe impl Sync for PluginDescriptor {}

/// A single custom jet.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CustomJetDesc {
    /// Jet name, `[a-z0-9_]+`.
    pub name: Bytes,
    // TODO: derive CMRs on the host from declared data instead of trusting the plugin
    pub cmr: [u8; 32],
    /// Source type in `TypeName` notation, e.g. `*ii`.
    pub source_ty: Bytes,
    /// Target type in `TypeName` notation.
    pub target_ty: Bytes,
    pub cost_milliweight: u64,
    /// Bit encoding of the jet, the low `code_len` bits of `code`, most significant first.
    pub code: u64,
    pub code_len: u8,
    pub func: Option<JetFn>,
}

// SAFETY: descriptors are immutable data meant to live in plugin statics.
unsafe impl Sync for CustomJetDesc {}

/// Data a custom jet may read about the spending transaction, valid during the jet call.
#[repr(C)]
#[derive(Debug)]
pub struct JetEnv {
    pub redeem_script: Bytes,
    pub tx: Bytes,
    pub input_index: u32,
}

/// Reads a big-endian `n`-bit value from a read frame.
///
/// # Safety
///
/// `src` must be a read frame with at least `n` bits left.
pub unsafe fn read_bits(src: &mut CFrameItem, n: u32) -> u64 {
    let mut value = 0;
    for _ in 0..n {
        value = (value << 1) | u64::from(unsafe { c_readBit(src) });
    }
    value
}

/// Writes the low `n` bits of `value`, big-endian, to a write frame.
///
/// # Safety
///
/// `dst` must be a write frame with room for at least `n` bits.
pub unsafe fn write_bits(dst: &mut CFrameItem, value: u64, n: u32) {
    for i in (0..n).rev() {
        unsafe { c_writeBit(dst, (value >> i) & 1 == 1) };
    }
}
