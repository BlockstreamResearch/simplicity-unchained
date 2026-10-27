use jet_plugin_abi::utils::Bytes;
use jet_plugin_abi::{BaseSet, JetEnv};
use simplicity::elements::encode::serialize;
use simplicity::ffi::CFrameItem;
use simplicity::jet::JetEnvironment;

use super::PluginTrait;
use super::jet::PluginJet;
use super::loaded::CustomJet;
use super::trampolines::CustomJetSlots;
use crate::jets::base::{AsBaseEnv, BaseJet, base_c_jet_ptr};
use crate::jets::bitcoin::CoreExtension;
use crate::jets::elements::ElementsExtension;

/// A base jet set plugins can extend, with the data custom jets get to see.
pub trait PluginBase: BaseJet {
    /// The ABI identifier of this set.
    const ABI_BASE_SET: BaseSet;

    fn redeem_script(env: &Self::Env) -> &[u8];

    /// Consensus-serialized spending transaction, empty if the environment has none.
    fn tx(env: &Self::Env) -> Vec<u8>;

    fn input_index(env: &Self::Env) -> u32;
}

impl PluginBase for CoreExtension {
    const ABI_BASE_SET: BaseSet = BaseSet::Bitcoin;

    fn redeem_script(env: &Self::Env) -> &[u8] {
        env.redeem_script.as_bytes()
    }

    fn tx(_env: &Self::Env) -> Vec<u8> {
        Vec::new()
    }

    fn input_index(_env: &Self::Env) -> u32 {
        0
    }
}

impl PluginBase for ElementsExtension {
    const ABI_BASE_SET: BaseSet = BaseSet::Elements;

    fn redeem_script(env: &Self::Env) -> &[u8] {
        env.redeem_script.as_bytes()
    }

    fn tx(env: &Self::Env) -> Vec<u8> {
        serialize(env.env.tx())
    }

    fn input_index(env: &Self::Env) -> u32 {
        env.env.ix()
    }
}

/// Environment for programs using the jets of plugin `S`.
pub struct PluginEnv<S: PluginTrait> {
    inner: <S::Base as BaseJet>::Env,
    tx: Vec<u8>,
}

impl<S: PluginTrait> PluginEnv<S> {
    pub fn new(inner: <S::Base as BaseJet>::Env) -> Self {
        let tx = S::Base::tx(&inner);
        Self { inner, tx }
    }

    pub fn inner(&self) -> &<S::Base as BaseJet>::Env {
        &self.inner
    }

    pub(super) fn call(&self, jet: &CustomJet, dst: &mut CFrameItem, src: CFrameItem) -> bool {
        let env = JetEnv {
            redeem_script: bytes(S::Base::redeem_script(&self.inner)),
            tx: bytes(&self.tx),
            input_index: S::Base::input_index(&self.inner),
        };

        // SAFETY: `env` outlives the call; plugins are operator-trusted to follow the ABI,
        // including staying within their frames.
        unsafe { (jet.func)(dst, src, &env) }
    }
}

impl<S: PluginTrait> AsBaseEnv<<S::Base as BaseJet>::Env> for PluginEnv<S> {
    fn base_env(&self) -> &<S::Base as BaseJet>::Env {
        &self.inner
    }
}

impl<S: PluginTrait> JetEnvironment for PluginEnv<S> {
    type Jet = PluginJet<S>;
    type CJetEnvironment = Self;

    fn c_jet_env(&self) -> &Self::CJetEnvironment {
        self
    }

    fn c_jet_ptr(
        jet: &Self::Jet,
    ) -> fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        let base = <S::Base as BaseJet>::ALL;
        match jet.index().checked_sub(base.len()) {
            None => base_c_jet_ptr::<S::Base, Self>(&base[jet.index()]),
            Some(k) => CustomJetSlots::<S>::TABLE[k],
        }
    }
}

fn bytes(slice: &[u8]) -> Bytes {
    Bytes {
        ptr: slice.as_ptr(),
        len: slice.len(),
    }
}
