//! Custom jets loaded at runtime from dynamic libraries.
//!
//! A plugin extends one base jet set ([`CoreExtension`] or [`ElementsExtension`]) with custom
//! jets described by a [`jet_plugin_abi::PluginDescriptor`]. The host owns all Simplicity-facing
//! types: [`PluginJet`] and [`PluginEnv`] implement `Jet` and `JetEnvironment` for a plugin
//! declared with [`declare_plugin!`], base jets keep running through the host's own
//! implementation, and custom jets are called through the C ABI.
//!
//! [`CoreExtension`]: crate::jets::bitcoin::CoreExtension
//! [`ElementsExtension`]: crate::jets::elements::ElementsExtension
mod decode;
mod env;
mod jet;
mod loaded;
mod loader;
#[cfg(test)]
mod tests;
mod trampolines;

use std::fmt::Debug;
use std::hash::Hash;
use std::path::Path;
use std::sync::OnceLock;

pub use env::{PluginBase, PluginEnv};
pub use jet::PluginJet;
pub use loaded::{LoadError, LoadedPlugin, MAX_CUSTOM_JETS};

/// A plugin handle declared with [`declare_plugin!`].
///
/// Each handle holds at most one plugin for the lifetime of the process; plugins are never
/// unloaded.
pub trait PluginTrait: Copy + Ord + Hash + Debug + Send + Sync + 'static {
    /// The base jet set the plugin extends.
    type Base: PluginBase;

    #[doc(hidden)]
    fn cell() -> &'static OnceLock<LoadedPlugin>;

    /// The loaded plugin, if any.
    fn get() -> Option<&'static LoadedPlugin> {
        Self::cell().get()
    }

    /// Loads the dynamic library at `path` into this handle.
    ///
    /// When `sha256` is given, the file must hash to it; `None` skips the check and is meant for
    /// development only.
    fn load(path: impl AsRef<Path>, sha256: Option<[u8; 32]>) -> Result<(), LoadError> {
        if Self::get().is_some() {
            return Err(LoadError::AlreadyLoaded);
        }
        let plugin = loader::load::<Self::Base>(path.as_ref(), sha256)?;
        Self::install(plugin)
    }

    /// Installs an already validated plugin into this handle.
    fn install(plugin: LoadedPlugin) -> Result<(), LoadError> {
        let expected = <Self::Base as PluginBase>::ABI_BASE_SET;
        if plugin.base_set() != expected {
            return Err(LoadError::BaseSet {
                expected,
                found: plugin.base_set(),
            });
        }
        Self::cell()
            .set(plugin)
            .map_err(|_| LoadError::AlreadyLoaded)
    }
}

/// Declares a plugin handle type extending the given base jet set.
///
/// ```ignore
/// declare_plugin!(pub Foo: ElementsExtension);
/// Foo::load("libfoo.so", Some(sha256))?;
/// let program = Program::<PluginJet<Foo>>::from_str(program, witness)?;
/// ```
#[macro_export]
macro_rules! declare_plugin {
    ($vis:vis $name:ident : $base:ty) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis struct $name;

        impl $crate::plugin::PluginTrait for $name {
            type Base = $base;

            fn cell() -> &'static ::std::sync::OnceLock<$crate::plugin::LoadedPlugin> {
                static CELL: ::std::sync::OnceLock<$crate::plugin::LoadedPlugin> =
                    ::std::sync::OnceLock::new();
                &CELL
            }
        }
    };
}
