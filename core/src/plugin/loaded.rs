//! Validation of plugin descriptors into owned, host-side jet tables.
use std::collections::{HashMap, HashSet};

use jet_plugin_abi::{
    ABI_VERSION, BaseSet, CustomJetDesc, JetFn, PluginDescriptor, SIMPLICITY_SYS_VERSION,
};
use simplicity::jet::Jet;
use simplicity::jet::type_name::TypeName;
use simplicity::{BitWriter, Cmr, Cost};

use super::decode::{DecodeTrie, code_bits};
use super::env::PluginBase;

/// Maximum number of custom jets in one plugin, see `trampolines::CustomTrampolines`.
pub const MAX_CUSTOM_JETS: usize = 32;

const MAX_NAME_LEN: usize = 64;
const MAX_TYPE_NAME_LEN: usize = 256;
const MAX_CODE_LEN: u8 = 64;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("failed to read plugin file: {0}")]
    Io(#[from] std::io::Error),

    #[error("plugin file hash {found} does not match pinned hash {expected}")]
    HashMismatch { expected: String, found: String },

    #[error("failed to open plugin: {0}")]
    Open(#[from] dlopen2::Error),

    #[error("plugin returned a null descriptor")]
    NullDescriptor,

    #[error("plugin ABI version {found}, host expects {expected}")]
    AbiVersion { expected: u32, found: u32 },

    #[error("plugin links simplicity-sys {found}, host links {expected}")]
    SimplicitySysVersion {
        expected: &'static str,
        found: String,
    },

    #[error("plugin extends unknown base set {0}")]
    UnknownBaseSet(u32),

    #[error("plugin extends base set {found:?}, host expects {expected:?}")]
    BaseSet { expected: BaseSet, found: BaseSet },

    #[error("plugin declares {found} jets, at most {max} are supported")]
    TooManyJets { max: usize, found: usize },

    #[error("plugin declares jets through a null pointer")]
    NullJets,

    #[error("custom jet #{index} has an invalid name")]
    InvalidName { index: usize },

    #[error("custom jet `{name}` is already defined")]
    DuplicateName { name: String },

    #[error("custom jet `{name}` has an invalid type `{ty}`")]
    InvalidType { name: String, ty: String },

    #[error("custom jet `{name}` has an invalid cost {cost}")]
    InvalidCost { name: String, cost: u64 },

    #[error("custom jet `{name}` has an invalid encoding")]
    InvalidCode { name: String },

    #[error("custom jet `{name}` encoding conflicts with `{other}`")]
    EncodingConflict { name: String, other: String },

    #[error("custom jet `{name}` CMR is already used by `{other}`")]
    DuplicateCmr { name: String, other: String },

    #[error("custom jet `{name}` has no implementation")]
    NullFunction { name: String },

    #[error("a plugin is already loaded into this handle")]
    AlreadyLoaded,
}

pub(crate) struct CustomJet {
    pub(crate) name: &'static str,
    pub(crate) cmr: Cmr,
    pub(crate) source_ty: TypeName,
    pub(crate) target_ty: TypeName,
    pub(crate) cost: Cost,
    pub(crate) code: u64,
    pub(crate) code_len: u8,
    pub(crate) func: JetFn,
}

/// A validated plugin: its custom jets plus lookup tables over the base and custom jets.
pub struct LoadedPlugin {
    base_set: BaseSet,
    base_len: usize,
    pub(crate) custom: Vec<CustomJet>,
    pub(crate) names: HashMap<String, usize>,
    pub(crate) trie: DecodeTrie,
}

impl LoadedPlugin {
    /// Validates `desc` as an extension of the base jet set `B`.
    ///
    /// Strings are copied and leaked, as plugins are never unloaded; `func` pointers stay
    /// pointing into the plugin.
    ///
    /// # Safety
    ///
    /// `desc` must be null or point to a descriptor whose pointers are valid for the lengths
    /// they are paired with, and whose functions follow the ABI for as long as the returned
    /// value lives.
    pub unsafe fn from_descriptor<B: PluginBase>(
        desc: *const PluginDescriptor,
    ) -> Result<Self, LoadError> {
        let desc = unsafe { desc.as_ref() }.ok_or(LoadError::NullDescriptor)?;

        if desc.abi_version != ABI_VERSION {
            return Err(LoadError::AbiVersion {
                expected: ABI_VERSION,
                found: desc.abi_version,
            });
        }
        let sys_version = unsafe { desc.simplicity_sys_version.as_slice() };
        if sys_version != SIMPLICITY_SYS_VERSION.as_bytes() {
            return Err(LoadError::SimplicitySysVersion {
                expected: SIMPLICITY_SYS_VERSION,
                found: String::from_utf8_lossy(sys_version).into_owned(),
            });
        }
        let base_set = BaseSet::try_from(desc.base_set).map_err(LoadError::UnknownBaseSet)?;
        if base_set != B::ABI_BASE_SET {
            return Err(LoadError::BaseSet {
                expected: B::ABI_BASE_SET,
                found: base_set,
            });
        }
        if desc.jets_len > MAX_CUSTOM_JETS {
            return Err(LoadError::TooManyJets {
                max: MAX_CUSTOM_JETS,
                found: desc.jets_len,
            });
        }
        let descs: &[CustomJetDesc] = if desc.jets_len == 0 {
            &[]
        } else if desc.jets.is_null() {
            return Err(LoadError::NullJets);
        } else {
            unsafe { std::slice::from_raw_parts(desc.jets, desc.jets_len) }
        };

        let base_len = B::ALL.len();
        let mut names = HashMap::new();
        let mut cmrs = HashMap::new();
        let mut trie = DecodeTrie::new();
        for (index, jet) in B::ALL.iter().enumerate() {
            names.insert(jet.to_string(), index);
            cmrs.insert(jet.cmr(), jet.to_string());
            trie.insert(encoding(jet), index)
                .expect("base jet encodings are prefix-free");
        }

        let mut custom: Vec<CustomJet> = Vec::with_capacity(descs.len());
        let mut seen = HashSet::new();
        for (k, jet) in descs.iter().enumerate() {
            let name = validate_name(unsafe { jet.name.as_slice() })
                .ok_or(LoadError::InvalidName { index: k })?;
            if !seen.insert(name) || names.contains_key(name) {
                return Err(LoadError::DuplicateName { name: name.into() });
            }

            let source_ty = validate_type(name, unsafe { jet.source_ty.as_slice() })?;
            let target_ty = validate_type(name, unsafe { jet.target_ty.as_slice() })?;

            let cost = u32::try_from(jet.cost_milliweight)
                .ok()
                .filter(|&cost| cost > 0)
                .map(Cost::from_milliweight)
                .ok_or(LoadError::InvalidCost {
                    name: name.into(),
                    cost: jet.cost_milliweight,
                })?;

            if jet.code_len == 0
                || jet.code_len > MAX_CODE_LEN
                || (jet.code_len < 64 && jet.code >> jet.code_len != 0)
            {
                return Err(LoadError::InvalidCode { name: name.into() });
            }

            let func = jet
                .func
                .ok_or(LoadError::NullFunction { name: name.into() })?;

            // TODO: once the host derives CMRs (see `CustomJetDesc::cmr`), compute it here
            // instead of trusting the plugin.
            let cmr = Cmr::from_byte_array(jet.cmr);
            if let Some(other) = cmrs.insert(cmr, name.to_string()) {
                return Err(LoadError::DuplicateCmr {
                    name: name.into(),
                    other,
                });
            }

            let index = base_len + k;
            trie.insert(code_bits(jet.code, jet.code_len), index)
                .map_err(|other| LoadError::EncodingConflict {
                    name: name.into(),
                    other: match other.checked_sub(base_len) {
                        None => B::ALL[other].to_string(),
                        Some(k) => custom[k].name.to_string(),
                    },
                })?;

            let name: &'static str = Box::leak(name.into());
            names.insert(name.to_string(), index);
            custom.push(CustomJet {
                name,
                cmr,
                source_ty,
                target_ty,
                cost,
                code: jet.code,
                code_len: jet.code_len,
                func,
            });
        }

        Ok(Self {
            base_set,
            base_len,
            custom,
            names,
            trie,
        })
    }

    /// The base jet set this plugin extends.
    pub fn base_set(&self) -> BaseSet {
        self.base_set
    }

    pub(crate) fn base_len(&self) -> usize {
        self.base_len
    }

    /// Names of the custom jets, in descriptor order.
    pub fn custom_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.custom.iter().map(|jet| jet.name)
    }
}

fn encoding<J: Jet>(jet: &J) -> Vec<bool> {
    let mut bytes: Vec<u8> = vec![];
    let mut writer = BitWriter::new(&mut bytes as &mut dyn std::io::Write);
    let len = jet
        .encode(&mut writer)
        .expect("writing to a Vec never fails");
    writer.flush_all().expect("writing to a Vec never fails");
    (0..len)
        .map(|i| (bytes[i / 8] & (0x80 >> (i % 8))) != 0)
        .collect()
}

fn validate_name(name: &[u8]) -> Option<&str> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    valid.then(|| std::str::from_utf8(name).expect("checked to be ASCII"))
}

/// Checks `ty` against the `TypeName` grammar, whose parser panics on bad input.
fn validate_type(name: &str, ty: &[u8]) -> Result<TypeName, LoadError> {
    let mut depth = 0usize;
    let mut valid = !ty.is_empty() && ty.len() <= MAX_TYPE_NAME_LEN;
    for &c in ty.iter().rev() {
        match c {
            b'1' | b'2' | b'c' | b's' | b'i' | b'l' | b'h' => depth += 1,
            b'+' | b'*' if depth >= 2 => depth -= 1,
            _ => valid = false,
        }
    }
    if !valid || depth != 1 {
        return Err(LoadError::InvalidType {
            name: name.into(),
            ty: String::from_utf8_lossy(ty).into_owned(),
        });
    }

    Ok(TypeName(Box::leak(ty.into())))
}
