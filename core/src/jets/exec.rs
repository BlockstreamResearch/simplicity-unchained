use simplicity::ffi::CFrameItem;
use simplicity::ffi::c_jets::frame_ffi::rustsimplicity_0_6_writeHash;
use simplicity::ffi::ffi::sha256::CSha256Midstate;

use super::environments::UnchainedEnv;

/// 1 |- 2^256
pub fn wallet_id_hash(dst: &mut CFrameItem, _src: CFrameItem, env: &UnchainedEnv) -> bool {
    let hash = CSha256Midstate { s: env.wallet_id };
    unsafe {
        rustsimplicity_0_6_writeHash(dst as *mut CFrameItem, &hash);
    }
    true
}
