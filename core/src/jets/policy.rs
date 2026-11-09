//! Explicit, built-in-only Bitcoin policy jet namespace.

use std::io::Write;
use std::str::FromStr;

use simplicity::ffi::CFrameItem;
use simplicity::ffi::c_jets::frame_ffi::{c_readBit, c_writeBit};
use simplicity::jet::type_name::TypeName;
use simplicity::jet::{CoreEnv, Jet, JetEnvironment};
use simplicity::{BitIter, BitWriter, Cmr, Cost, decode};
use simplicity_unchained_policy::{BitValue, Builtin, Context};

use super::base::{AsBaseEnv, BaseJet, JetFn, base_c_jet_ptr};
use super::bitcoin::CoreExtension;
use super::environments::{BitcoinTxEnv, BitcoinUnchainedEnv, UnchainedEnv};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum PolicyJet {
    Legacy(CoreExtension),
    Builtin(Builtin),
}

impl PolicyJet {
    pub const ALL: [Self; CoreExtension::ALL.len() + Builtin::ALL.len()] = {
        let mut jets = [Self::Legacy(CoreExtension::TxApprovalHash);
            CoreExtension::ALL.len() + Builtin::ALL.len()];
        let mut index = 0;
        while index < CoreExtension::ALL.len() {
            jets[index] = Self::Legacy(CoreExtension::ALL[index]);
            index += 1;
        }
        let mut builtin = 0;
        while builtin < Builtin::ALL.len() {
            jets[index] = Self::Builtin(Builtin::ALL[builtin]);
            index += 1;
            builtin += 1;
        }
        jets
    };

    /// Enumeration position, independent of the legacy/base trampoline table.
    pub fn index(self) -> usize {
        match self {
            Self::Legacy(jet) => jet.index(),
            Self::Builtin(jet) => CoreExtension::ALL.len() + usize::from(jet.id()),
        }
    }
}

/// A validated immutable policy context and a compatibility view for legacy jets.
pub struct PolicyEnv {
    context: Context,
    legacy: BitcoinUnchainedEnv,
}

impl PolicyEnv {
    pub fn new(context: Context) -> Self {
        let legacy = UnchainedEnv::new(
            simplicity::elements::Script::from(context.script_data().to_vec()),
            BitcoinTxEnv {
                tx: context.tx().clone(),
                input_index: context.input_index() as u32,
                approval_hash: context.legacy_approval_hash(),
                core_env: CoreEnv::new(),
            },
        );
        Self { context, legacy }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }
}

impl AsBaseEnv<CoreEnv> for PolicyEnv {
    fn base_env(&self) -> &CoreEnv {
        &self.legacy.env.core_env
    }
}

impl JetEnvironment for PolicyEnv {
    type Jet = PolicyJet;
    type CJetEnvironment = Self;

    fn c_jet_env(&self) -> &Self {
        self
    }

    fn c_jet_ptr(jet: &PolicyJet) -> JetFn<Self> {
        match jet {
            PolicyJet::Legacy(CoreExtension::Core(core)) => base_c_jet_ptr(core),
            PolicyJet::Legacy(CoreExtension::GetOpcodeFromScript) => legacy_opcode,
            PolicyJet::Legacy(CoreExtension::GetPubkeyFromScript) => legacy_pubkey,
            PolicyJet::Legacy(CoreExtension::TxApprovalHash) => legacy_approval,
            PolicyJet::Builtin(jet) => BUILTIN_FNS[usize::from(jet.id())],
        }
    }
}

fn legacy_opcode(dst: &mut CFrameItem, src: CFrameItem, env: &PolicyEnv) -> bool {
    super::exec::get_opcode_from_script(dst, src, &env.legacy)
}

fn legacy_pubkey(dst: &mut CFrameItem, src: CFrameItem, env: &PolicyEnv) -> bool {
    super::exec::get_pubkey_from_script(dst, src, &env.legacy)
}

fn legacy_approval(dst: &mut CFrameItem, src: CFrameItem, env: &PolicyEnv) -> bool {
    super::exec::bitcoin_tx_approval_hash(dst, src, &env.legacy)
}

fn builtin<const ID: u8>(dst: &mut CFrameItem, mut src: CFrameItem, env: &PolicyEnv) -> bool {
    let jet = Builtin::from_id(ID).expect("fixed built-in dispatch index");
    let bit_len = jet.source_bits();
    let mut input = BitValue {
        bytes: vec![0; bit_len.div_ceil(8)],
        bit_len,
    };
    for bit in 0..bit_len {
        if unsafe { c_readBit(&mut src) } {
            input.bytes[bit / 8] |= 1 << (7 - bit % 8);
        }
    }
    let Ok(output) = env.context.evaluate(jet, &input) else {
        return false;
    };
    if output.validate(jet.target_bits()).is_err() {
        return false;
    }
    // Write sum padding too: a None result must not expose stale frame contents.
    for bit in 0..output.bit_len {
        unsafe { c_writeBit(dst, output.bytes[bit / 8] & (1 << (7 - bit % 8)) != 0) };
    }
    true
}

macro_rules! builtin_functions {
    ($($id:literal),* $(,)?) => {
        [$(builtin::<$id> as JetFn<PolicyEnv>),*]
    };
}

const BUILTIN_FNS: [JetFn<PolicyEnv>; 55] = builtin_functions![
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54,
];

impl Jet for PolicyJet {
    fn cmr(&self) -> Cmr {
        match self {
            Self::Legacy(jet) => jet.cmr(),
            Self::Builtin(jet) => Cmr::from_byte_array(jet.cmr()),
        }
    }

    fn source_ty(&self) -> TypeName {
        match self {
            Self::Legacy(jet) => jet.source_ty(),
            Self::Builtin(jet) => jet.source_type(),
        }
    }

    fn target_ty(&self) -> TypeName {
        match self {
            Self::Legacy(jet) => jet.target_ty(),
            Self::Builtin(jet) => jet.target_type(),
        }
    }

    fn encode(&self, writer: &mut BitWriter<&mut dyn Write>) -> std::io::Result<usize> {
        match self {
            Self::Legacy(jet) => {
                writer.write_bit(false)?;
                jet.encode(writer).map(|bits| 1 + bits)
            }
            Self::Builtin(jet) => writer.write_bits_be(64 | u64::from(jet.id()), 7),
        }
    }

    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        match bits.next().ok_or(decode::Error::EndOfStream)? {
            false => CoreExtension::decode(bits).map(Self::Legacy),
            true => {
                let mut id = 0;
                for _ in 0..6 {
                    id = (id << 1) | u8::from(bits.next().ok_or(decode::Error::EndOfStream)?);
                }
                Builtin::from_id(id)
                    .map(Self::Builtin)
                    .ok_or(decode::Error::InvalidJet)
            }
        }
    }

    fn cost(&self) -> Cost {
        match self {
            Self::Legacy(jet) => jet.cost(),
            Self::Builtin(jet) => Cost::from_milliweight(jet.cost_milliweight()),
        }
    }

    fn parse(name: &str) -> Result<Self, simplicity::Error> {
        name.parse()
    }
}

impl std::fmt::Display for PolicyJet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy(jet) => jet.fmt(formatter),
            Self::Builtin(jet) => jet.fmt(formatter),
        }
    }
}

impl FromStr for PolicyJet {
    type Err = simplicity::Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if let Ok(jet) = name.parse::<Builtin>() {
            Ok(Self::Builtin(jet))
        } else {
            name.parse().map(Self::Legacy)
        }
    }
}

#[cfg(test)]
mod tests;
