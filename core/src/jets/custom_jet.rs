//! High level wrapper for loading custom jets from DLL.
use crate::jets::{
    environments::UnchainedEnv,
    jet_dyn::{CCustomJet, CustomJetApi},
};
use dlopen2::wrapper::Container;
use hal_simplicity::simplicity::jet::Jet;
use std::{marker::PhantomData, sync::LazyLock};

pub(crate) static JET_DLL: LazyLock<Option<Container<CustomJetApi>>> = LazyLock::new(|| {
    std::env::var("JET_DLL_PATH")
        .ok()
        .and_then(|path| unsafe { Container::<CustomJetApi>::load(&path) }.ok())
});

/// `simplicity_unchained_core::jets::jet_dyn::decode` copies input bits into a separate buffer to transfer them via FFI.
/// This constant controls how many bits will be read.
/// Not used right now because decode trees are hardcoded due to lack of BitIter rewind.
const MAX_JET_BIT_LEN: u32 = 30;

#[repr(transparent)]
/// Wrapper for interacting with Jet defined inside DLL.
/// Unless `Api` generic defined manually, loads DLL from path given by `std::env::var`
pub struct CustomJet<E: 'static, Api: 'static + JetApiProvider = DefaultApi> {
    inner: CCustomJet,
    _env: PhantomData<fn() -> E>,
    _dll: PhantomData<fn() -> Api>,
}

pub trait JetApiProvider {
    fn get() -> &'static Option<Container<CustomJetApi>>;
}

// Loads DLL from `std::env::var` by `JET_DLL_PATH` name
pub struct DefaultApi;

impl JetApiProvider for DefaultApi {
    fn get() -> &'static Option<Container<CustomJetApi>> {
        &JET_DLL
    }
}

impl<E, Api> From<CCustomJet> for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn from(value: CCustomJet) -> Self {
        Self {
            inner: value,
            _env: PhantomData,
            _dll: PhantomData,
        }
    }
}

impl<E, Api> CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    pub fn all() -> &'static [Self] {
        unsafe { std::mem::transmute(Api::get().as_ref().expect("DLL is not loaded").all_jets()) }
    }

    /// Tries to convert dynamic jet representation to instance of base type jet.
    /// Returns Some if given jet is from base jet set, None if custom.
    /// # Safety
    /// It's caller responsibility to guarantee that base type inside DLL is same
    /// as type provided as generic to this function.
    pub unsafe fn to_base_jet<T>(&self) -> Option<T> {
        unsafe {
            Api::get()
                .as_ref()
                .expect("DLL is not loaded")
                .to_base_jet(self.inner)
        }
    }

    /// Converts base type jet representation to instance of dynamic jet.
    /// # Safety
    /// It's caller responsibility to guarantee that base type inside DLL is same
    /// as type provided as generic to this function.
    pub unsafe fn from_base_jet<T>(jet: &T) -> Self {
        unsafe {
            Api::get()
                .as_ref()
                .expect("DLL is not loaded")
                .from_base_jet(jet)
                .into()
        }
    }
}

impl<E, Api> std::str::FromStr for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    type Err = hal_simplicity::simplicity::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Api::get().as_ref().expect("DLL is not loaded").from_str(s) {
            Ok(_jet) => Ok(_jet.into()),
            Err(err) => Err(err),
        }
    }
}
impl<E, Api> Copy for CustomJet<E, Api> where Api: JetApiProvider {}

impl<E, Api> Clone for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<E, Api> PartialEq for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<E, Api> Eq for CustomJet<E, Api> where Api: JetApiProvider {}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<E, Api> PartialOrd for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .partial_cmp(self.inner, other.inner)
    }
}

impl<E, Api> Ord for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .cmp(self.inner, other.inner)
    }
}

impl<E, Api> core::hash::Hash for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .hash(self.inner, state);
    }
}

impl<E, Api> std::fmt::Debug for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .debug_fmt(self.inner, f)
    }
}

impl<E, Api> std::fmt::Display for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .display_fmt(self.inner, f)
    }
}

impl<E, Api> Jet for CustomJet<E, Api>
where
    Api: JetApiProvider,
{
    type Environment = UnchainedEnv<E>;
    type CJetEnvironment = UnchainedEnv<E>;

    fn c_jet_env(env: &Self::Environment) -> &Self::CJetEnvironment {
        env
    }

    fn cmr(&self) -> hal_simplicity::simplicity::Cmr {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .cmr(self.inner)
    }

    fn source_ty(&self) -> hal_simplicity::simplicity::jet::type_name::TypeName {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .source_ty(self.inner)
    }

    fn target_ty(&self) -> hal_simplicity::simplicity::jet::type_name::TypeName {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .target_ty(self.inner)
    }

    fn encode<W: std::io::Write>(
        &self,
        w: &mut hal_simplicity::simplicity::BitWriter<W>,
    ) -> std::io::Result<usize> {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .encode(self.inner, w)
    }

    fn decode<I: Iterator<Item = u8>>(
        bits: &mut hal_simplicity::simplicity::BitIter<I>,
    ) -> Result<Self, hal_simplicity::simplicity::decode::Error> {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .decode(bits, MAX_JET_BIT_LEN)
            .map(|jet| jet.into())
    }

    fn c_jet_ptr(
        &self,
    ) -> &dyn Fn(
        &mut hal_simplicity::simplicity::ffi::CFrameItem,
        hal_simplicity::simplicity::ffi::CFrameItem,
        &Self::CJetEnvironment,
    ) -> bool {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .c_jet_ptr(self.inner)
    }

    fn cost(&self) -> hal_simplicity::simplicity::Cost {
        Api::get()
            .as_ref()
            .expect("DLL is not loaded")
            .cost(self.inner)
    }
}

#[cfg(test)]
mod test {
    use std::{
        hash::{Hash, Hasher},
        str::FromStr,
    };

    use hal_simplicity::simplicity::{BitIter, BitWriter};

    use crate::jets::environments::{BitcoinUnchainedEnv, ElementsUnchainedEnv};

    use super::*;

    // --- DLLs for tests ---
    // Use the cargo-built output from target/debug/ with the platform-appropriate extension
    // (dylib on macOS, so on Linux) instead of pre-built platform-specific binaries.
    static ELEMENTS_TEST_DLL: LazyLock<Option<Container<CustomJetApi>>> =
        LazyLock::new(|| unsafe {
            let path = format!(
                "{}/../target/debug/libelements.{}",
                env!("CARGO_MANIFEST_DIR"),
                std::env::consts::DLL_EXTENSION
            );
            Container::<CustomJetApi>::load(&path).ok()
        });

    static CORE_TEST_DLL: LazyLock<Option<Container<CustomJetApi>>> = LazyLock::new(|| unsafe {
        let path = format!(
            "{}/../target/debug/libbitcoin.{}",
            env!("CARGO_MANIFEST_DIR"),
            std::env::consts::DLL_EXTENSION
        );
        Container::<CustomJetApi>::load(&path).ok()
    });

    struct ElementsTestApi;
    impl JetApiProvider for ElementsTestApi {
        fn get() -> &'static Option<Container<CustomJetApi>> {
            &ELEMENTS_TEST_DLL
        }
    }

    struct CoreTestApi;
    impl JetApiProvider for CoreTestApi {
        fn get() -> &'static Option<Container<CustomJetApi>> {
            &CORE_TEST_DLL
        }
    }

    type CustomJetElements = CustomJet<ElementsUnchainedEnv, ElementsTestApi>;
    type CustomJetBitcoin = CustomJet<BitcoinUnchainedEnv, CoreTestApi>;

    // ---------------------
    #[test]
    fn test_dll_from_str_elements() {
        let jet = CustomJetElements::from_str("custom_jet_1");

        assert!(jet.is_ok());
        assert_eq!(jet.unwrap().to_string(), "custom_jet_1")
    }

    #[test]
    fn test_dll_hash_elements() {
        let jet = CustomJetElements::from_str("custom_jet_1").expect("Failed to load jet");

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        jet.hash(&mut hasher);

        let _ = hasher.finish();
    }

    #[test]
    fn test_dll_encode_elements() {
        let custom_jet = CustomJetElements::from_str("custom_jet_1").expect("Failed to load jet");
        let elements_jet = CustomJetElements::from_str("input_asset").expect("Failed to load jet");

        let mut buffer = Vec::new();
        let mut w = BitWriter::new(&mut buffer);

        let res1 = custom_jet.encode(&mut w);
        let res2 = elements_jet.encode(&mut w);

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        assert_eq!(res1.unwrap(), 20);
        assert_eq!(res2.unwrap(), 19);

        w.flush_all().unwrap();

        let mut bit_iter = BitIter::from(buffer);

        let mut read_code = |read_bits: u8| -> Option<u64> {
            let mut res = 0;
            let mut cursor = 1 << (read_bits - 1);

            for _ in 0..read_bits {
                match bit_iter.next() {
                    None => return None,
                    Some(true) => res |= cursor,
                    Some(false) => {}
                }
                cursor >>= 1;
            }
            Some(res)
        };

        let custom_jet_code = read_code(20);
        let elements_jet_code = read_code(19);

        assert!(custom_jet_code.is_some());
        assert!(elements_jet_code.is_some());

        assert_eq!(custom_jet_code.unwrap(), 1047454);
        assert_eq!(elements_jet_code.unwrap(), 462369);
    }

    #[test]
    fn test_dll_decode_elements() {
        let custom_jet = CustomJetElements::from_str("custom_jet_1").expect("Failed to load jet");
        let elements_jet = CustomJetElements::from_str("input_asset").expect("Failed to load jet");

        let mut buffer = Vec::new();
        let mut w = BitWriter::new(&mut buffer);

        let res1 = custom_jet.encode(&mut w);
        let res2 = elements_jet.encode(&mut w);

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        w.flush_all().unwrap();

        let mut bit_iter = BitIter::from(buffer.as_ref());

        let custom_decoded = CustomJetElements::decode(&mut bit_iter);
        assert!(custom_decoded.is_ok());

        assert_eq!(custom_decoded.unwrap().to_string(), "custom_jet_1");

        let elements_decoded = CustomJetElements::decode(&mut bit_iter);
        assert!(elements_decoded.is_ok());

        assert_eq!(elements_decoded.unwrap().to_string(), "input_asset");
    }

    #[test]
    fn test_dll_decode_bitcoin() {
        let custom_jet = CustomJetBitcoin::from_str("custom_jet_1").expect("Failed to load jet");
        let elements_jet = CustomJetBitcoin::from_str("leftmost_16_8").expect("Failed to load jet");

        let mut buffer = Vec::new();
        let mut w = BitWriter::new(&mut buffer);

        let res1 = custom_jet.encode(&mut w);
        let res2 = elements_jet.encode(&mut w);

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        w.flush_all().unwrap();

        let mut bit_iter = BitIter::from(buffer.as_ref());

        let custom_decoded = CustomJetBitcoin::decode(&mut bit_iter);
        assert!(custom_decoded.is_ok());

        assert_eq!(custom_decoded.unwrap().to_string(), "custom_jet_1");

        let elements_decoded = CustomJetBitcoin::decode(&mut bit_iter);
        assert!(elements_decoded.is_ok());

        assert_eq!(elements_decoded.unwrap().to_string(), "leftmost_16_8");
    }

    #[test]
    fn test_dll_c_jet_ptr_elements() {
        let custom_jet = CustomJetElements::from_str("custom_jet_1").expect("Failed to load jet");
        let elements_jet = CustomJetElements::from_str("input_asset").expect("Failed to load jet");

        let _ = custom_jet.c_jet_ptr();
        let _ = elements_jet.c_jet_ptr();
    }
}
