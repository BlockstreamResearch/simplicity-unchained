use hal_simplicity::simplicity::ffi::CFrameItem;
use jet_plugins::register_jets;

use simplicity_unchained_core::jets::environments::BitcoinUnchainedEnv;

pub fn custom_jet1_bitcoin(_dst: &mut CFrameItem, _: CFrameItem, _: &BitcoinUnchainedEnv) -> bool {
    false
}

pub fn custom_jet2_bitcoin(_dst: &mut CFrameItem, _: CFrameItem, _: &BitcoinUnchainedEnv) -> bool {
    false
}

register_jets!(
    hal_simplicity::simplicity::jet::Core,
    simplicity_unchained_core::jets::environments::BitcoinUnchainedEnv,
    "custom_jet_1" => custom_jet1_bitcoin, b"h", b"h",
    "custom_jet_2" => custom_jet2_bitcoin, b"h", b"h",
);
