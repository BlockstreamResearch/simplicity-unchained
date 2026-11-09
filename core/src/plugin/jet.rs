use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::marker::PhantomData;

use simplicity::jet::Jet;
use simplicity::jet::type_name::TypeName;
use simplicity::{BitIter, BitWriter, Cmr, Cost, decode};

use super::PluginTrait;
use super::loaded::{CustomJet, LoadedPlugin};
use crate::jets::base::BaseJet;

/// A jet of plugin `S`: a base jet of `S::Base` or one of the plugin's custom jets.
///
/// Values only exist once `S` is loaded: they are created by decoding, parsing or [`all`].
///
/// [`all`]: PluginJet::all
pub struct PluginJet<S> {
    /// Position in `S::Base::ALL`, followed by the custom jets in descriptor order.
    index: usize,
    _plugin: PhantomData<fn() -> S>,
}

enum Kind<B: 'static> {
    Base(&'static B),
    Custom(&'static CustomJet),
}

impl<S: PluginTrait> PluginJet<S> {
    fn new(index: usize) -> Self {
        Self {
            index,
            _plugin: PhantomData,
        }
    }

    fn loaded() -> &'static LoadedPlugin {
        S::get().expect("a PluginJet only exists once its plugin is loaded")
    }

    fn kind(&self) -> Kind<S::Base> {
        let base = <S::Base as BaseJet>::ALL;
        match self.index.checked_sub(base.len()) {
            None => Kind::Base(&base[self.index]),
            Some(k) => Kind::Custom(&Self::loaded().custom[k]),
        }
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    /// All base and custom jets of `S`, or nothing if `S` is not loaded.
    pub fn all() -> Vec<Self> {
        let Some(plugin) = S::get() else {
            return vec![];
        };
        (0..plugin.base_len() + plugin.custom.len())
            .map(Self::new)
            .collect()
    }
}

impl<S: PluginTrait> Jet for PluginJet<S> {
    fn cmr(&self) -> Cmr {
        match self.kind() {
            Kind::Base(jet) => jet.cmr(),
            Kind::Custom(jet) => jet.cmr,
        }
    }

    fn source_ty(&self) -> TypeName {
        match self.kind() {
            Kind::Base(jet) => jet.source_ty(),
            Kind::Custom(jet) => jet.source_ty.clone(),
        }
    }

    fn target_ty(&self) -> TypeName {
        match self.kind() {
            Kind::Base(jet) => jet.target_ty(),
            Kind::Custom(jet) => jet.target_ty.clone(),
        }
    }

    fn encode(&self, w: &mut BitWriter<&mut dyn Write>) -> std::io::Result<usize> {
        match self.kind() {
            Kind::Base(jet) => jet.encode(w),
            Kind::Custom(jet) => w.write_bits_be(jet.code, usize::from(jet.code_len)),
        }
    }

    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        let plugin = S::get().ok_or(decode::Error::InvalidJet)?;
        plugin.trie.decode(bits).map(Self::new)
    }

    fn cost(&self) -> Cost {
        match self.kind() {
            Kind::Base(jet) => jet.cost(),
            Kind::Custom(jet) => jet.cost,
        }
    }

    fn parse(s: &str) -> Result<Self, simplicity::Error> {
        S::get()
            .and_then(|plugin| plugin.names.get(s))
            .map(|&index| Self::new(index))
            .ok_or_else(|| simplicity::Error::InvalidJetName(s.into()))
    }
}

impl<S: PluginTrait> fmt::Display for PluginJet<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            Kind::Base(jet) => fmt::Display::fmt(jet, f),
            Kind::Custom(jet) => f.write_str(jet.name),
        }
    }
}

impl<S: PluginTrait> fmt::Debug for PluginJet<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PluginJet({self})")
    }
}

impl<S> Clone for PluginJet<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for PluginJet<S> {}

impl<S> PartialEq for PluginJet<S> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<S> Eq for PluginJet<S> {}

impl<S> PartialOrd for PluginJet<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S> Ord for PluginJet<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl<S> Hash for PluginJet<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state)
    }
}
