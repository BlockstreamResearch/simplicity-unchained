use hal_simplicity::simplicity::ffi::CFrameItem;
use jet_plugins::register_jets;

use simplicity_unchained_core::jets::environments::ElementsUnchainedEnv;

pub fn custom_jet1_elements(
    _dst: &mut CFrameItem,
    _: CFrameItem,
    _: &ElementsUnchainedEnv,
) -> bool {
    false
}

pub fn custom_jet2_elements(
    _dst: &mut CFrameItem,
    _: CFrameItem,
    _: &ElementsUnchainedEnv,
) -> bool {
    false
}

register_jets!(
    hal_simplicity::simplicity::jet::Elements,
    simplicity_unchained_core::jets::environments::ElementsUnchainedEnv,
    "custom_jet_1" => custom_jet1_elements, b"h", b"h",
    "custom_jet_2" => custom_jet2_elements, b"h", b"h",
);
