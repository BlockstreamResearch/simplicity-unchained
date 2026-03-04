use std::collections::HashMap;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::LazyLock;

use hal_simplicity::simplicity::Cmr;
use hal_simplicity::simplicity::Cost;
use hal_simplicity::simplicity::ffi::CFrameItem;
use hal_simplicity::simplicity::jet::type_name::TypeName;
use hal_simplicity::simplicity::jet::{Elements, Jet};
use hal_simplicity::simplicity::{BitIter, BitWriter, decode};

use hal_simplicity::simplicity::elements::Transaction;
use hal_simplicity::simplicity::jet::elements::ElementsEnv;

use super::environments::UnchainedEnv;

static C_JET_PTRS: LazyLock<
    HashMap<
        ElementsExtension,
        &'static (
                     dyn Fn(
            &mut CFrameItem,
            CFrameItem,
            &UnchainedEnv<ElementsEnv<Arc<Transaction>>>,
        ) -> bool
                         + Send
                         + Sync
                 ),
    >,
> = LazyLock::new(|| build_c_jet_ptrs());

// Local version of decode_bits macro that accepts expressions instead of just paths
macro_rules! decode_bits {
    ($bits:ident, {}) => {
        Err(decode::Error::InvalidJet.into())
    };
    ($bits:ident, {$jet:expr}) => {
        Ok($jet)
    };
    ($bits:ident, { 0 => $false_branch:tt, 1 => $true_branch:tt }) => {
        match $bits.next() {
            None => Err(decode::Error::EndOfStream.into()),
            Some(false) => decode_bits!($bits, $false_branch),
            Some(true) => decode_bits!($bits, $true_branch),
        }
    };
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum ElementsExtension {
    Elements(Elements),
    GetOpcodeFromScript,
    GetPubkeyFromScript,
}

impl ElementsExtension {
    pub const ALL: [Self; Self::ALL_JETS_NUM] = Self::build_all_variants();

    const ALL_JETS_NUM: usize = Elements::ALL.len() + 2;

    const fn build_all_variants() -> [Self; Self::ALL_JETS_NUM] {
        struct AllVariantsBuilder {
            data: [MaybeUninit<ElementsExtension>; ElementsExtension::ALL_JETS_NUM],
            len: usize,
        }

        impl AllVariantsBuilder {
            const fn new() -> Self {
                Self {
                    data: [MaybeUninit::uninit(); ElementsExtension::ALL_JETS_NUM],
                    len: 0,
                }
            }

            const fn push(&mut self, item: ElementsExtension) {
                assert!(self.len < self.data.len());

                self.data[self.len].write(item);
                self.len += 1;
            }

            const fn finalize(self) -> [ElementsExtension; ElementsExtension::ALL_JETS_NUM] {
                assert!(self.len == ElementsExtension::ALL_JETS_NUM);

                unsafe { std::mem::transmute(self.data) }
            }
        }

        let mut builder = AllVariantsBuilder::new();
        let mut i = 0;

        while i < Elements::ALL.len() {
            builder.push(ElementsExtension::Elements(Elements::ALL[i]));
            i += 1;
        }

        builder.push(ElementsExtension::GetOpcodeFromScript);
        builder.push(ElementsExtension::GetPubkeyFromScript);

        builder.finalize()
    }
}

fn build_c_jet_ptrs() -> HashMap<
    ElementsExtension,
    &'static (
                 dyn Fn(
        &mut CFrameItem,
        CFrameItem,
        &UnchainedEnv<ElementsEnv<Arc<Transaction>>>,
    ) -> bool
                     + Send
                     + Sync
             ),
> {
    ElementsExtension::ALL
        .iter()
        .map(|jet| {
            let boxed: Box<
                dyn Fn(
                        &mut CFrameItem,
                        CFrameItem,
                        &UnchainedEnv<ElementsEnv<Arc<Transaction>>>,
                    ) -> bool
                    + Send
                    + Sync,
            > = match jet {
                // hijacked elements jets
                ElementsExtension::Elements(Elements::CheckLockDuration) => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::check_lock_duration(dst, src, env)
                    },
                ),
                ElementsExtension::Elements(Elements::CheckLockDistance) => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::check_lock_distance(dst, src, env)
                    },
                ),
                ElementsExtension::Elements(Elements::TxLockDuration) => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::tx_lock_duration(dst, src, env)
                    },
                ),
                ElementsExtension::Elements(Elements::TxLockDistance) => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::tx_lock_distance(dst, src, env)
                    },
                ),
                // rest of elements jets
                ElementsExtension::Elements(inner_jet) => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        inner_jet.c_jet_ptr()(dst, src, env.env.c_tx_env())
                    },
                ),
                // custom jets
                ElementsExtension::GetOpcodeFromScript => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::get_opcode_from_script(dst, src, env)
                    },
                ),
                ElementsExtension::GetPubkeyFromScript => Box::new(
                    move |dst: &mut CFrameItem,
                          src: CFrameItem,
                          env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>|
                          -> bool {
                        super::exec::get_pubkey_from_script(dst, src, env)
                    },
                ),
            };
            let leaked: &'static (
                         dyn Fn(
                &mut CFrameItem,
                CFrameItem,
                &UnchainedEnv<ElementsEnv<Arc<Transaction>>>,
            ) -> bool
                             + Send
                             + Sync
                     ) = Box::leak(boxed);
            (*jet, leaked)
        })
        .collect()
}

impl Jet for ElementsExtension {
    type Environment = UnchainedEnv<ElementsEnv<Arc<Transaction>>>;
    type CJetEnvironment = UnchainedEnv<ElementsEnv<Arc<Transaction>>>;

    fn c_jet_env(env: &Self::Environment) -> &Self::CJetEnvironment {
        // For the time being, we are goint to use the initial environment for unchained jets,
        // as we are going to implement them in rust.
        env
    }

    fn cmr(&self) -> Cmr {
        if let ElementsExtension::Elements(inner_jet) = self {
            return inner_jet.cmr();
        }

        let bytes = match self {
            ElementsExtension::GetOpcodeFromScript => [
                0xdc, 0xcc, 0xd2, 0x89, 0x59, 0x22, 0xe7, 0x5b, 0x01, 0x8b, 0x08, 0x46, 0xe5, 0xcd,
                0x49, 0x63, 0x80, 0x8b, 0xbf, 0xd4, 0x8b, 0x47, 0x23, 0x44, 0x75, 0x60, 0x7f, 0x90,
                0xe7, 0x0e, 0xe0, 0x32,
            ],
            ElementsExtension::GetPubkeyFromScript => [
                0x27, 0xea, 0xb0, 0x90, 0x68, 0xb0, 0x35, 0xaf, 0x61, 0x97, 0x13, 0x33, 0x5b, 0x73,
                0xd2, 0x52, 0x0e, 0xcc, 0x02, 0x09, 0x00, 0x67, 0xc8, 0xfc, 0xca, 0xbb, 0x4d, 0x72,
                0xa6, 0x55, 0xcd, 0xcb,
            ],
            _ => unreachable!(),
        };

        Cmr::from_byte_array(bytes)
    }

    fn source_ty(&self) -> TypeName {
        if let ElementsExtension::Elements(inner_jet) = self {
            return inner_jet.source_ty();
        }

        let name = match self {
            ElementsExtension::GetOpcodeFromScript => b"c",
            ElementsExtension::GetPubkeyFromScript => b"c",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn target_ty(&self) -> TypeName {
        if let ElementsExtension::Elements(inner_jet) = self {
            return inner_jet.target_ty();
        }

        let name = match self {
            ElementsExtension::GetOpcodeFromScript => b"c",
            ElementsExtension::GetPubkeyFromScript => b"h",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn encode<W: Write>(&self, w: &mut BitWriter<W>) -> std::io::Result<usize> {
        if let ElementsExtension::Elements(inner_jet) = self {
            return inner_jet.encode(w);
        }

        let (n, len) = match self {
            ElementsExtension::GetOpcodeFromScript => (62, 6),
            ElementsExtension::GetPubkeyFromScript => (126, 7),
            _ => unreachable!(),
        };

        w.write_bits_be(n, len)
    }

    /// # Safety
    ///
    /// Due to the lack of a `Clone` bound on `I`, the underlying implementation uses
    /// `ptr::read` to create bitwise copies of the iterator. This is unsafe and may cause
    /// undefined behavior if `I` contains types that manage unique resources.
    /// This works correctly for common slice-based iterators like `Copied<Iter<u8>>`.
    ///
    /// See <https://github.com/BlockstreamResearch/rust-simplicity/issues/342> for details.
    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        let (mut elements_iter, mut custom_iter) =
            unsafe { (std::ptr::read(bits), std::ptr::read(bits)) };

        let bits_read = bits.n_total_read();

        let try_elements = Elements::decode(&mut elements_iter);

        if let Ok(jet) = try_elements {
            for _ in 0..(elements_iter.n_total_read() - bits_read) {
                bits.next();
            }

            std::mem::forget(elements_iter);
            std::mem::forget(custom_iter);

            return Ok(ElementsExtension::Elements(jet));
        }

        let custom_iter_ref = &mut custom_iter;
        let try_custom = decode_bits!(custom_iter_ref, {
            0 => {},
            1 => {
                0 => {},
                1 => {
                    0 => {},
                    1 => {
                        0 => {},
                        1 => {
                            0 => {}, // Free path
                            1 => {
                                0 => {ElementsExtension::GetOpcodeFromScript},
                                1 => {
                                    0 => {ElementsExtension::GetPubkeyFromScript},
                                    1 => {}
                                }
                            }
                        }
                    }
                }
            }
        });

        if try_custom.is_ok() {
            for _ in 0..(custom_iter.n_total_read() - bits_read) {
                bits.next();
            }
        }

        std::mem::forget(elements_iter);
        std::mem::forget(custom_iter);

        try_custom
    }

    fn c_jet_ptr(&self) -> &dyn Fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        C_JET_PTRS
            .get(self)
            .expect("All enum variants should be initialized")
    }

    fn cost(&self) -> Cost {
        if let ElementsExtension::Elements(inner_jet) = self {
            return inner_jet.cost();
        }

        // TODO(ivanlele): Calculate accurate costs for unchained jets.
        match self {
            ElementsExtension::GetOpcodeFromScript => Cost::from_milliweight(100),
            ElementsExtension::GetPubkeyFromScript => Cost::from_milliweight(100),
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for ElementsExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElementsExtension::Elements(inner_jet) => f.write_str(&inner_jet.to_string()),
            ElementsExtension::GetOpcodeFromScript => f.write_str("get_opcode_from_script"),
            ElementsExtension::GetPubkeyFromScript => f.write_str("get_pubkey_from_script"),
        }
    }
}

impl std::str::FromStr for ElementsExtension {
    type Err = hal_simplicity::simplicity::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "get_opcode_from_script" => Ok(ElementsExtension::GetOpcodeFromScript),
            "get_pubkey_from_script" => Ok(ElementsExtension::GetPubkeyFromScript),
            _ => {
                let inner_jet = s.parse::<Elements>()?;
                Ok(ElementsExtension::Elements(inner_jet))
            }
        }
    }
}
