//! One trampoline per custom jet position, see `PluginEnv::c_jet_ptr`.
//
// TODO: generate the table with a proc macro if plugins need more than 32 custom jets.
use super::MAX_CUSTOM_JETS;
use super::env::PluginEnv;
use crate::jets::base::JetFn;
use simplicity::ffi::CFrameItem;

/// Runs custom jet `IDX` of `Plugin`.
fn custom_jet_slot<Plugin: super::PluginTrait, const IDX: usize>(
    dst: &mut CFrameItem,
    src: CFrameItem,
    env: &PluginEnv<Plugin>,
) -> bool {
    match Plugin::get().and_then(|plugin| plugin.custom.get(IDX)) {
        Some(jet) => env.call(jet, dst, src),
        None => false,
    }
}

pub(super) struct CustomJetSlots<Plugin>(Plugin);

impl<Plugin: super::PluginTrait> CustomJetSlots<Plugin> {
    pub(super) const TABLE: [JetFn<PluginEnv<Plugin>>; MAX_CUSTOM_JETS] = [
        custom_jet_slot::<Plugin, 0>,
        custom_jet_slot::<Plugin, 1>,
        custom_jet_slot::<Plugin, 2>,
        custom_jet_slot::<Plugin, 3>,
        custom_jet_slot::<Plugin, 4>,
        custom_jet_slot::<Plugin, 5>,
        custom_jet_slot::<Plugin, 6>,
        custom_jet_slot::<Plugin, 7>,
        custom_jet_slot::<Plugin, 8>,
        custom_jet_slot::<Plugin, 9>,
        custom_jet_slot::<Plugin, 10>,
        custom_jet_slot::<Plugin, 11>,
        custom_jet_slot::<Plugin, 12>,
        custom_jet_slot::<Plugin, 13>,
        custom_jet_slot::<Plugin, 14>,
        custom_jet_slot::<Plugin, 15>,
        custom_jet_slot::<Plugin, 16>,
        custom_jet_slot::<Plugin, 17>,
        custom_jet_slot::<Plugin, 18>,
        custom_jet_slot::<Plugin, 19>,
        custom_jet_slot::<Plugin, 20>,
        custom_jet_slot::<Plugin, 21>,
        custom_jet_slot::<Plugin, 22>,
        custom_jet_slot::<Plugin, 23>,
        custom_jet_slot::<Plugin, 24>,
        custom_jet_slot::<Plugin, 25>,
        custom_jet_slot::<Plugin, 26>,
        custom_jet_slot::<Plugin, 27>,
        custom_jet_slot::<Plugin, 28>,
        custom_jet_slot::<Plugin, 29>,
        custom_jet_slot::<Plugin, 30>,
        custom_jet_slot::<Plugin, 31>,
    ];
}
