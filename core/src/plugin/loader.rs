use std::path::Path;

use dlopen2::raw::Library;
use jet_plugin_abi::{DESCRIPTOR_SYMBOL, DescriptorFn};
use simplicity::hashes::sha256;

use super::env::PluginBase;
use super::loaded::{LoadError, LoadedPlugin};

/// Opens the plugin at `path` and validates it as an extension of `B`.
///
/// The library is never closed: custom jet functions point into it.
pub(crate) fn load<B: PluginBase>(
    path: &Path,
    sha256: Option<[u8; 32]>,
) -> Result<LoadedPlugin, LoadError> {
    if let Some(expected) = sha256 {
        // TODO: the file can still change between hashing and opening; open from the hashed
        // bytes (e.g. a memfd) if plugins ever stop being operator-trusted.
        let found = sha256::Hash::hash(&std::fs::read(path)?).to_byte_array();
        if found != expected {
            return Err(LoadError::HashMismatch {
                expected: hex::encode(expected),
                found: hex::encode(found),
            });
        }
    }

    let library = Library::open(path)?;
    let describe: DescriptorFn = unsafe { library.symbol(DESCRIPTOR_SYMBOL) }?;
    // SAFETY: plugins are operator-trusted to follow the ABI.
    let plugin = unsafe { LoadedPlugin::from_descriptor::<B>(describe()) }?;
    std::mem::forget(library);
    Ok(plugin)
}
