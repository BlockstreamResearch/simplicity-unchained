//! FFI layer for loading Jet trait from DLL using dlopen2.
//! See jet_plugins::c_wrappers for interface on other side.
#![allow(clippy::duplicate_underscore_argument)] // originates from `WrapperApi` macro
use dlopen2::wrapper::WrapperApi;
use hal_simplicity::simplicity::{
    BitIter, BitWriter, Cmr, Cost, ffi::CFrameItem, jet::type_name::TypeName,
};
use std::{fmt::Formatter, hash::Hasher, io::Write};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CCustomJet {
    // index of jet inside `ALL` constant
    pub index: usize,
}

#[repr(C)]
pub struct JetSelfHandle(());

#[repr(C)]
pub struct CmrHandle(());

#[repr(C)]
pub struct TypeNameHandle(());

#[repr(C)]
pub struct CostHandle(());

#[repr(C)]
pub struct HasherHandle<'a> {
    pub _hasher: &'a mut dyn Hasher,
}

#[repr(C)]
pub struct FmtHandle<'a, 'b> {
    pub _formatter: &'a mut core::fmt::Formatter<'b>,
}

#[repr(C)]
pub struct StrHandle<'a> {
    pub _str: &'a dyn AsRef<str>,
}

#[repr(i8)]
pub enum COrdering {
    Less = -1,
    Equal = 0,
    Greater = 1,
}

impl From<std::cmp::Ordering> for COrdering {
    fn from(o: std::cmp::Ordering) -> Self {
        match o {
            std::cmp::Ordering::Less => COrdering::Less,
            std::cmp::Ordering::Equal => COrdering::Equal,
            std::cmp::Ordering::Greater => COrdering::Greater,
        }
    }
}

impl From<COrdering> for std::cmp::Ordering {
    fn from(o: COrdering) -> Self {
        match o {
            COrdering::Less => std::cmp::Ordering::Less,
            COrdering::Equal => std::cmp::Ordering::Equal,
            COrdering::Greater => std::cmp::Ordering::Greater,
        }
    }
}

#[repr(i8)]
pub enum COptionOrdering {
    None = i8::MIN,
    Less = -1,
    Equal = 0,
    Greater = 1,
}

impl From<Option<std::cmp::Ordering>> for COptionOrdering {
    fn from(o: Option<std::cmp::Ordering>) -> Self {
        match o {
            None => COptionOrdering::None,
            Some(std::cmp::Ordering::Less) => COptionOrdering::Less,
            Some(std::cmp::Ordering::Equal) => COptionOrdering::Equal,
            Some(std::cmp::Ordering::Greater) => COptionOrdering::Greater,
        }
    }
}

impl From<COptionOrdering> for Option<std::cmp::Ordering> {
    fn from(o: COptionOrdering) -> Self {
        match o {
            COptionOrdering::None => None,
            COptionOrdering::Less => Some(std::cmp::Ordering::Less),
            COptionOrdering::Equal => Some(std::cmp::Ordering::Equal),
            COptionOrdering::Greater => Some(std::cmp::Ordering::Greater),
        }
    }
}

#[repr(C)]
pub struct BitIterHandle<'a> {
    pub data: &'a mut dyn Iterator<Item = bool>,
}

#[allow(unused)]
#[repr(C)]
/// Deprecated while issue with iterator rewind is not resolved
pub struct BitIterHandleDeprecated<'a> {
    pub data: &'a [u8],
}
#[repr(C)]
pub struct DecodeResHandle {
    pub jet: *const (), // *const Result<CCCustomJet, simplicity::decode::Error>
    pub bits_read: usize,
}

#[repr(C)]
pub struct BitWriterHandle<'a> {
    pub _writer: BitWriter<&'a mut Vec<u8>>,
}

#[repr(C)]
pub struct AllJetsHandle {
    pub jets: *const CCustomJet,
    pub len: usize,
}

#[derive(WrapperApi)]
pub struct CustomJetApi {
    _cmp: extern "C" fn(_self: CCustomJet, other: CCustomJet) -> COrdering,
    _partial_cmp: extern "C" fn(_self: CCustomJet, other: CCustomJet) -> COptionOrdering,
    _hash: extern "C" fn(_self: CCustomJet, hasher_handle: *mut HasherHandle),
    _debug_fmt: extern "C" fn(_self: CCustomJet, fmt_handle: *mut FmtHandle) -> *const (), // *const std::fmt::Result
    _display_fmt: extern "C" fn(_self: CCustomJet, fmt_handle: *mut FmtHandle) -> *const (), // *const std::fmt::Result
    _from_str: extern "C" fn(name: *const StrHandle) -> *const (), // *const Result<CCCustomJet, simplicity::Error>
    _all_jets: extern "C" fn() -> AllJetsHandle,
    _cmr: extern "C" fn(_self: CCustomJet) -> *const CmrHandle,
    _source_ty: extern "C" fn(_self: CCustomJet) -> *const TypeNameHandle,
    _target_ty: extern "C" fn(_self: CCustomJet) -> *const TypeNameHandle,
    _encode: extern "C" fn(_self: CCustomJet, w: *mut BitWriterHandle) -> *const (), // *std::io::Result<usize>
    _decode: extern "C" fn(w: *mut BitIterHandle) -> DecodeResHandle,
    _c_jet_ptr: extern "C" fn(_self: CCustomJet) -> *const (), // * &'static dyn Fn(&mut CFrameItem, CFrameItem, &T) -> bool
    _cost: extern "C" fn(_self: CCustomJet) -> *const CostHandle,
    _to_base_jet: extern "C" fn(_self: CCustomJet) -> *const (), // * Option<BaseJetType>
    _from_base_jet: extern "C" fn(jet: *const ()) -> CCustomJet, // * BaseJetType
}

impl CustomJetApi {
    pub fn from_str(&self, name: &str) -> Result<CCustomJet, hal_simplicity::simplicity::Error> {
        let str_handle = StrHandle { _str: &name };
        unsafe {
            *Box::from_raw((self._from_str)(&str_handle)
                as *mut Result<CCustomJet, hal_simplicity::simplicity::Error>)
        }
    }

    pub fn all_jets(&self) -> &'static [CCustomJet] {
        unsafe {
            let AllJetsHandle { jets, len } = (self._all_jets)();
            std::slice::from_raw_parts(jets, len)
        }
    }

    pub fn cmp(&self, lhs: CCustomJet, rhs: CCustomJet) -> std::cmp::Ordering {
        (self._cmp)(lhs, rhs).into()
    }

    pub fn partial_cmp(&self, lhs: CCustomJet, rhs: CCustomJet) -> Option<std::cmp::Ordering> {
        (self._partial_cmp)(lhs, rhs).into()
    }

    pub fn hash<H: core::hash::Hasher>(&self, jet: CCustomJet, hasher: &mut H) {
        let mut hasher_handle = HasherHandle { _hasher: hasher };
        (self._hash)(jet, &mut hasher_handle)
    }

    pub fn debug_fmt(&self, jet: CCustomJet, formatter: &mut Formatter) -> std::fmt::Result {
        let mut fmt_handle = FmtHandle {
            _formatter: formatter,
        };
        unsafe { *Box::from_raw((self._debug_fmt(jet, &mut fmt_handle)) as *mut std::fmt::Result) }
    }

    pub fn display_fmt(&self, jet: CCustomJet, formatter: &mut Formatter) -> std::fmt::Result {
        let mut fmt_handle = FmtHandle {
            _formatter: formatter,
        };
        unsafe {
            *Box::from_raw((self._display_fmt(jet, &mut fmt_handle)) as *mut std::fmt::Result)
        }
    }

    pub fn cmr(&self, jet: CCustomJet) -> Cmr {
        *unsafe { Box::from_raw((self._cmr)(jet) as *mut Cmr) }
    }

    pub fn source_ty(&self, jet: CCustomJet) -> TypeName {
        *unsafe { Box::from_raw((self._source_ty)(jet) as *mut TypeName) }
    }

    pub fn target_ty(&self, jet: CCustomJet) -> TypeName {
        *unsafe { Box::from_raw((self._target_ty)(jet) as *mut TypeName) }
    }

    pub fn encode<W: Write>(
        &self,
        jet: CCustomJet,
        w: &mut BitWriter<W>,
    ) -> std::io::Result<usize> {
        let mut buffer = Vec::new();
        let mut _writer = BitWriter::new(&mut buffer);

        let mut handle = BitWriterHandle { _writer };

        let res = unsafe {
            *Box::from_raw((self._encode)(jet, &mut handle) as *mut std::io::Result<usize>)
        };

        match res {
            Ok(bits_written) => {
                handle._writer.flush_all()?;

                let mut bit_iter = BitIter::from(buffer);
                for _ in 0..bits_written {
                    if let Some(bit) = bit_iter.next() {
                        w.write_bit(bit)?;
                    }
                }
                Ok(bits_written)
            }
            Err(err) => Err(err),
        }
    }

    pub fn decode<I: Iterator<Item = u8>>(
        &self,
        bits: &mut BitIter<I>,
        _: u32,
    ) -> Result<CCustomJet, hal_simplicity::simplicity::decode::Error> {
        let mut bit_iter_handle = BitIterHandle {
            data: bits as &mut dyn Iterator<Item = bool>,
        };

        let DecodeResHandle { jet, bits_read: _ } = (self._decode)(&mut bit_iter_handle);

        unsafe {
            *Box::from_raw(
                jet as *mut Result<CCustomJet, hal_simplicity::simplicity::decode::Error>,
            )
        }
    }

    /// Deprecated while issue with iterator rewind is not resolved
    #[allow(dead_code)]
    fn decode_deprecated<I: Iterator<Item = u8>>(
        &self,
        bits: &mut BitIter<I>,
        max_jet_len: u32,
    ) -> Result<CCustomJet, hal_simplicity::simplicity::decode::Error> {
        let mut bits_copy = unsafe { std::ptr::read(bits) };
        let mut buffer = Vec::with_capacity(max_jet_len.div_ceil(8) as usize);
        let mut writer = BitWriter::from(&mut buffer);

        let mut i = 0;
        while let Some(bit) = bits_copy.next()
            && i < max_jet_len
        {
            writer
                .write_bit(bit)
                .expect("Writing to vec should not fail");
            i += 1;
        }
        println!();
        writer.flush_all().expect("Writing to vec should not fail");

        let _handle = BitIterHandleDeprecated { data: &buffer };

        //let DecodeResHandle { jet, bits_read } = (self._decode)(&mut handle);
        let (jet, bits_read) = (std::ptr::null::<()>(), 0);

        let decoded = unsafe {
            *Box::from_raw(
                jet as *mut Result<CCustomJet, hal_simplicity::simplicity::decode::Error>,
            )
        };

        if decoded.is_ok() {
            for _ in 0..bits_read {
                bits.next();
            }
        }

        decoded
    }

    #[allow(clippy::type_complexity)]
    pub fn c_jet_ptr<T>(
        &self,
        jet: CCustomJet,
    ) -> &'static (dyn Fn(&mut CFrameItem, CFrameItem, &T) -> bool + Send + Sync) {
        unsafe {
            *Box::from_raw((self._c_jet_ptr)(jet)
                as *mut &'static (
                             dyn Fn(&mut CFrameItem, CFrameItem, &T) -> bool + Send + Sync
                         ))
        }
    }

    pub fn cost(&self, jet: CCustomJet) -> Cost {
        unsafe { *Box::from_raw(self._cost(jet) as *mut Cost) }
    }

    /// Tries to convert dynamic jet representation to instance of base type jet.
    /// Returns Some if given jet is from base jet set, None if custom.
    /// # Safety
    /// It's caller responsibility to guarantee that base type inside DLL is same
    /// as type provided as generic to this function.
    pub unsafe fn to_base_jet<T>(&self, jet: CCustomJet) -> Option<T> {
        *unsafe { Box::from_raw(self._to_base_jet(jet) as *mut Option<T>) }
    }

    /// Converts base type jet representation to instance of dynamic jet.
    /// # Safety
    /// It's caller responsibility to guarantee that base type inside DLL is same
    /// as type provided as generic to this function.
    pub unsafe fn from_base_jet<T>(&self, jet: *const T) -> CCustomJet {
        self._from_base_jet(jet as *const ())
    }
}
