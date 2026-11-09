//! Portable bounded VM; host-specific filesystem/dynamic loading is not involved.
use super::{Builtin, Context, Error, Network, require};
use crate::BitValue;
use elements::{
    pset::PartiallySignedTransaction as Pset, secp256k1_zkp::XOnlyPublicKey, taproot::TapNodeHash,
};
use simplicity::{
    BitIter, BitMachine, BitWriter, Cmr, CommitNode, Cost, RedeemNode, decode,
    ffi::{
        CFrameItem,
        c_jets::frame_ffi::{c_readBit, c_writeBit},
    },
    jet::{Core, CoreEnv, Jet, JetEnvironment, type_name::TypeName},
};
use std::{io::Write, str::FromStr, sync::Arc};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyJet {
    Core(Core),
    Builtin(Builtin),
}
impl Jet for PolicyJet {
    fn cmr(&self) -> Cmr {
        match self {
            Self::Core(j) => j.cmr(),
            Self::Builtin(j) => Cmr::from_byte_array(j.cmr()),
        }
    }
    fn source_ty(&self) -> TypeName {
        match self {
            Self::Core(j) => j.source_ty(),
            Self::Builtin(j) => j.source_type(),
        }
    }
    fn target_ty(&self) -> TypeName {
        match self {
            Self::Core(j) => j.target_ty(),
            Self::Builtin(j) => j.target_type(),
        }
    }
    fn cost(&self) -> Cost {
        match self {
            Self::Core(j) => j.cost(),
            Self::Builtin(j) => Cost::from_milliweight(j.cost_milliweight()),
        }
    }
    fn encode(&self, w: &mut BitWriter<&mut dyn Write>) -> std::io::Result<usize> {
        match self {
            Self::Core(j) => {
                w.write_bit(false)?;
                j.encode(w).map(|n| n + 1)
            }
            Self::Builtin(j) => w.write_bits_be(128 | u64::from(j.id()), 8),
        }
    }
    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        if !bits.next().ok_or(decode::Error::EndOfStream)? {
            return Core::decode(bits).map(Self::Core);
        }
        let mut id = 0;
        for _ in 0..7 {
            id = (id << 1) | u8::from(bits.next().ok_or(decode::Error::EndOfStream)?);
        }
        Builtin::from_id(id)
            .map(Self::Builtin)
            .ok_or(decode::Error::InvalidJet)
    }
    fn parse(name: &str) -> Result<Self, simplicity::Error> {
        name.parse()
    }
}
impl std::fmt::Display for PolicyJet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(j) => j.fmt(f),
            Self::Builtin(j) => j.fmt(f),
        }
    }
}
impl FromStr for PolicyJet {
    type Err = simplicity::Error;
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if let Ok(j) = name.parse::<Builtin>() {
            Ok(Self::Builtin(j))
        } else {
            name.parse().map(Self::Core)
        }
    }
}

struct Env {
    context: Context,
    core: CoreEnv,
}
type JetFn = fn(&mut CFrameItem, CFrameItem, &Env) -> bool;
fn core<const ID: usize>(dst: &mut CFrameItem, src: CFrameItem, env: &Env) -> bool {
    CoreEnv::c_jet_ptr(&Core::ALL[ID])(dst, src, env.core.c_jet_env())
}
macro_rules! core_functions {
    (@c $a:literal; $b:literal; $($c:literal)*) => { [$(core::<{ $a * 64 + $b * 8 + $c }> as JetFn),*] };
    (@b $a:literal; $($b:literal)*) => { [$(core_functions!(@c $a; $b; 0 1 2 3 4 5 6 7)),*] };
    ($($a:literal)*) => { [$(core_functions!(@b $a; 0 1 2 3 4 5 6 7)),*] };
}
const CORE: [[[JetFn; 8]; 8]; 8] = core_functions!(0 1 2 3 4 5 6 7);
fn builtin<const ID: u8>(dst: &mut CFrameItem, mut src: CFrameItem, env: &Env) -> bool {
    let jet = Builtin::from_id(ID).expect("static dispatch");
    let bit_len = jet.source_bits();
    let mut input = BitValue {
        bytes: vec![0; bit_len.div_ceil(8)],
        bit_len,
    };
    for i in 0..bit_len {
        if unsafe { c_readBit(&mut src) } {
            input.bytes[i / 8] |= 1 << (7 - i % 8);
        }
    }
    let Ok(output) = env.context.evaluate(jet, &input) else {
        return false;
    };
    for i in 0..output.bit_len {
        unsafe { c_writeBit(dst, output.bit(i).expect("validated output")) };
    }
    true
}
macro_rules! functions { ($($id:literal),*) => { [$(builtin::<$id> as JetFn),*] }; }
const FUNCTIONS: [JetFn; 66] = functions![
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65
];
impl JetEnvironment for Env {
    type Jet = PolicyJet;
    type CJetEnvironment = Self;
    fn c_jet_env(&self) -> &Self {
        self
    }
    fn c_jet_ptr(jet: &PolicyJet) -> JetFn {
        match jet {
            PolicyJet::Core(j) => CORE.as_flattened().as_flattened()[*j as usize],
            PolicyJet::Builtin(j) => FUNCTIONS[j.id() as usize],
        }
    }
}
pub fn policy_cmr(program: &[u8]) -> Result<Cmr, Error> {
    require(
        program.len() <= crate::MAX_REQUEST_BYTES,
        "program exceeds profile limit",
    )?;
    CommitNode::decode::<_, PolicyJet>(BitIter::from(program))
        .map(|p| p.cmr())
        .map_err(|e| Error::Invalid(format!("invalid Liquid program: {e}")))
}
pub struct PreparedPolicy {
    program: Arc<[u8]>,
    cmr: Cmr,
    env: Env,
}
impl PreparedPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program: &[u8],
        pset: &Pset,
        index: usize,
        data: &[u8],
        network: Network,
        base: XOnlyPublicKey,
        user: XOnlyPublicKey,
        recovery: TapNodeHash,
    ) -> Result<Self, Error> {
        let cmr = policy_cmr(program)?;
        let context = Context::new(
            pset,
            index,
            cmr.to_byte_array(),
            data,
            network,
            base,
            user,
            recovery,
        )?;
        Ok(Self {
            program: program.into(),
            cmr,
            env: Env {
                context,
                core: CoreEnv::new(),
            },
        })
    }
    pub fn context(&self) -> &Context {
        &self.env.context
    }
    pub fn cmr(&self) -> Cmr {
        self.cmr
    }
    pub fn summary(&self) -> super::ContextSummary {
        self.context().summary()
    }
    pub fn evaluate_default(&self, witness: &[u8]) -> Result<u32, Error> {
        require(
            witness.len() <= crate::MAX_REQUEST_BYTES,
            "witness exceeds profile limit",
        )?;
        let program = RedeemNode::decode::<_, _, PolicyJet>(
            BitIter::from(self.program.as_ref()),
            BitIter::from(witness),
        )
        .map_err(|e| Error::Invalid(format!("invalid Liquid witness/program: {e}")))?;
        require(program.cmr() == self.cmr, "witnessed policy CMR mismatch")?;
        let cost = program.bounds().cost;
        require(
            cost <= Cost::from_milliweight(crate::MAX_EXECUTION_COST_MILLIWEIGHT),
            "policy execution cost exceeded",
        )?;
        BitMachine::for_program(&program)
            .map_err(|e| Error::Invalid(e.to_string()))?
            .exec(&program, &self.env)
            .map_err(|e| Error::Invalid(format!("policy rejected: {e}")))?;
        Ok(cost.to_string().parse().expect("Cost displays u32"))
    }
}
