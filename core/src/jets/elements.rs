use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;

use hal_simplicity::simplicity::Cmr;
use hal_simplicity::simplicity::Cost;
use hal_simplicity::simplicity::ffi::CFrameItem;
use hal_simplicity::simplicity::jet::type_name::TypeName;
use hal_simplicity::simplicity::jet::{Elements, Jet};
use hal_simplicity::simplicity::{BitIter, BitWriter, decode};

use hal_simplicity::simplicity::elements::Transaction;
use hal_simplicity::simplicity::jet::elements::ElementsEnv;

use super::environments::UnchainedEnv;

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
        // Maybe worth adding Uninit field to enum or use one of available enum variants to avoid unsafe code
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
        match self {
            ElementsExtension::Elements(Elements::CheckLockDuration) => {
                &super::exec::check_lock_duration
            }
            ElementsExtension::Elements(Elements::CheckLockDistance) => {
                &super::exec::check_lock_distance
            }
            ElementsExtension::Elements(Elements::TxLockDuration) => &super::exec::tx_lock_duration,
            ElementsExtension::Elements(Elements::TxLockDistance) => &super::exec::tx_lock_distance,
            ElementsExtension::Elements(inner_jet) => jet_wrapper(*inner_jet),
            ElementsExtension::GetOpcodeFromScript => &super::exec::get_opcode_from_script,
            ElementsExtension::GetPubkeyFromScript => &super::exec::get_pubkey_from_script,
        }
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

// Macro to generate static wrapper functions AND dispatcher for Elements jets
// This macro generates both the wrapper functions and the match statement in one go,
// so we only need to list each Elements variant once.
macro_rules! jet_wrappers {
    ($($variant:ident),* $(,)?) => {
        // Generate individual wrapper functions for each variant
        $(
            #[allow(non_snake_case)]
            fn $variant(frame: &mut CFrameItem, arg: CFrameItem, env: &UnchainedEnv<ElementsEnv<Arc<Transaction>>>) -> bool {
                Elements::$variant.c_jet_ptr()(frame, arg, env.env.c_tx_env())
            }
        )*

        // Generate the dispatcher function that returns the appropriate wrapper
        fn jet_wrapper(jet: Elements) -> &'static dyn Fn(&mut CFrameItem, CFrameItem, &UnchainedEnv<ElementsEnv<Arc<Transaction>>>) -> bool {
            match jet {
                $(
                    Elements::$variant => &$variant,
                )*
            }
        }
    };
}

// Generate wrapper functions and dispatcher for all Elements jet variants
// If Elements enum changes, only update this list to keep wrappers in sync
//
// TODO(ivanlele): This is extremly ungly solution, will need to open an issue
// for `rust-simplicity` to better interface for jet trait that
// does not require this boilerplate
jet_wrappers! {
    Add16,
    Add32,
    Add64,
    Add8,
    All16,
    All32,
    All64,
    All8,
    And1,
    And16,
    And32,
    And64,
    And8,
    AnnexHash,
    AssetAmountHash,
    Bip0340Verify,
    BuildTapbranch,
    BuildTapleafSimplicity,
    BuildTaptweak,
    CalculateAsset,
    CalculateConfidentialToken,
    CalculateExplicitToken,
    CalculateIssuanceEntropy,
    Ch1,
    Ch16,
    Ch32,
    Ch64,
    Ch8,
    CheckLockDistance,
    CheckLockDuration,
    CheckLockHeight,
    CheckLockTime,
    CheckSigVerify,
    Complement1,
    Complement16,
    Complement32,
    Complement64,
    Complement8,
    CurrentAmount,
    CurrentAnnexHash,
    CurrentAsset,
    CurrentIndex,
    CurrentIssuanceAssetAmount,
    CurrentIssuanceAssetProof,
    CurrentIssuanceTokenAmount,
    CurrentIssuanceTokenProof,
    CurrentNewIssuanceContract,
    CurrentPegin,
    CurrentPrevOutpoint,
    CurrentReissuanceBlinding,
    CurrentReissuanceEntropy,
    CurrentScriptHash,
    CurrentScriptSigHash,
    CurrentSequence,
    Decompress,
    Decrement16,
    Decrement32,
    Decrement64,
    Decrement8,
    DivMod128_64,
    DivMod16,
    DivMod32,
    DivMod64,
    DivMod8,
    Divide16,
    Divide32,
    Divide64,
    Divide8,
    Divides16,
    Divides32,
    Divides64,
    Divides8,
    Eq1,
    Eq16,
    Eq256,
    Eq32,
    Eq64,
    Eq8,
    FeAdd,
    FeInvert,
    FeIsOdd,
    FeIsZero,
    FeMultiply,
    FeMultiplyBeta,
    FeNegate,
    FeNormalize,
    FeSquare,
    FeSquareRoot,
    FullAdd16,
    FullAdd32,
    FullAdd64,
    FullAdd8,
    FullDecrement16,
    FullDecrement32,
    FullDecrement64,
    FullDecrement8,
    FullIncrement16,
    FullIncrement32,
    FullIncrement64,
    FullIncrement8,
    FullLeftShift16_1,
    FullLeftShift16_2,
    FullLeftShift16_4,
    FullLeftShift16_8,
    FullLeftShift32_1,
    FullLeftShift32_16,
    FullLeftShift32_2,
    FullLeftShift32_4,
    FullLeftShift32_8,
    FullLeftShift64_1,
    FullLeftShift64_16,
    FullLeftShift64_2,
    FullLeftShift64_32,
    FullLeftShift64_4,
    FullLeftShift64_8,
    FullLeftShift8_1,
    FullLeftShift8_2,
    FullLeftShift8_4,
    FullMultiply16,
    FullMultiply32,
    FullMultiply64,
    FullMultiply8,
    FullRightShift16_1,
    FullRightShift16_2,
    FullRightShift16_4,
    FullRightShift16_8,
    FullRightShift32_1,
    FullRightShift32_16,
    FullRightShift32_2,
    FullRightShift32_4,
    FullRightShift32_8,
    FullRightShift64_1,
    FullRightShift64_16,
    FullRightShift64_2,
    FullRightShift64_32,
    FullRightShift64_4,
    FullRightShift64_8,
    FullRightShift8_1,
    FullRightShift8_2,
    FullRightShift8_4,
    FullSubtract16,
    FullSubtract32,
    FullSubtract64,
    FullSubtract8,
    GeIsOnCurve,
    GeNegate,
    GejAdd,
    GejDouble,
    GejEquiv,
    GejGeAdd,
    GejGeAddEx,
    GejGeEquiv,
    GejInfinity,
    GejIsInfinity,
    GejIsOnCurve,
    GejNegate,
    GejNormalize,
    GejRescale,
    GejXEquiv,
    GejYIsOdd,
    Generate,
    GenesisBlockHash,
    HashToCurve,
    High1,
    High16,
    High32,
    High64,
    High8,
    Increment16,
    Increment32,
    Increment64,
    Increment8,
    InputAmount,
    InputAmountsHash,
    InputAnnexHash,
    InputAnnexesHash,
    InputAsset,
    InputHash,
    InputOutpointsHash,
    InputPegin,
    InputPrevOutpoint,
    InputScriptHash,
    InputScriptSigHash,
    InputScriptSigsHash,
    InputScriptsHash,
    InputSequence,
    InputSequencesHash,
    InputUtxoHash,
    InputUtxosHash,
    InputsHash,
    InternalKey,
    IsOne16,
    IsOne32,
    IsOne64,
    IsOne8,
    IsZero16,
    IsZero32,
    IsZero64,
    IsZero8,
    Issuance,
    IssuanceAsset,
    IssuanceAssetAmount,
    IssuanceAssetAmountsHash,
    IssuanceAssetProof,
    IssuanceBlindingEntropyHash,
    IssuanceEntropy,
    IssuanceHash,
    IssuanceRangeProofsHash,
    IssuanceToken,
    IssuanceTokenAmount,
    IssuanceTokenAmountsHash,
    IssuanceTokenProof,
    IssuancesHash,
    LbtcAsset,
    Le16,
    Le32,
    Le64,
    Le8,
    LeftExtend16_32,
    LeftExtend16_64,
    LeftExtend1_16,
    LeftExtend1_32,
    LeftExtend1_64,
    LeftExtend1_8,
    LeftExtend32_64,
    LeftExtend8_16,
    LeftExtend8_32,
    LeftExtend8_64,
    LeftPadHigh16_32,
    LeftPadHigh16_64,
    LeftPadHigh1_16,
    LeftPadHigh1_32,
    LeftPadHigh1_64,
    LeftPadHigh1_8,
    LeftPadHigh32_64,
    LeftPadHigh8_16,
    LeftPadHigh8_32,
    LeftPadHigh8_64,
    LeftPadLow16_32,
    LeftPadLow16_64,
    LeftPadLow1_16,
    LeftPadLow1_32,
    LeftPadLow1_64,
    LeftPadLow1_8,
    LeftPadLow32_64,
    LeftPadLow8_16,
    LeftPadLow8_32,
    LeftPadLow8_64,
    LeftRotate16,
    LeftRotate32,
    LeftRotate64,
    LeftRotate8,
    LeftShift16,
    LeftShift32,
    LeftShift64,
    LeftShift8,
    LeftShiftWith16,
    LeftShiftWith32,
    LeftShiftWith64,
    LeftShiftWith8,
    Leftmost16_1,
    Leftmost16_2,
    Leftmost16_4,
    Leftmost16_8,
    Leftmost32_1,
    Leftmost32_16,
    Leftmost32_2,
    Leftmost32_4,
    Leftmost32_8,
    Leftmost64_1,
    Leftmost64_16,
    Leftmost64_2,
    Leftmost64_32,
    Leftmost64_4,
    Leftmost64_8,
    Leftmost8_1,
    Leftmost8_2,
    Leftmost8_4,
    LinearCombination1,
    LinearVerify1,
    LockTime,
    Low1,
    Low16,
    Low32,
    Low64,
    Low8,
    Lt16,
    Lt32,
    Lt64,
    Lt8,
    Maj1,
    Maj16,
    Maj32,
    Maj64,
    Maj8,
    Max16,
    Max32,
    Max64,
    Max8,
    Median16,
    Median32,
    Median64,
    Median8,
    Min16,
    Min32,
    Min64,
    Min8,
    Modulo16,
    Modulo32,
    Modulo64,
    Modulo8,
    Multiply16,
    Multiply32,
    Multiply64,
    Multiply8,
    Negate16,
    Negate32,
    Negate64,
    Negate8,
    NewIssuanceContract,
    NonceHash,
    NumInputs,
    NumOutputs,
    One16,
    One32,
    One64,
    One8,
    Or1,
    Or16,
    Or32,
    Or64,
    Or8,
    OutpointHash,
    OutputAmount,
    OutputAmountsHash,
    OutputAsset,
    OutputHash,
    OutputIsFee,
    OutputNonce,
    OutputNoncesHash,
    OutputNullDatum,
    OutputRangeProof,
    OutputRangeProofsHash,
    OutputScriptHash,
    OutputScriptsHash,
    OutputSurjectionProof,
    OutputSurjectionProofsHash,
    OutputsHash,
    ParseLock,
    ParseSequence,
    PointVerify1,
    ReissuanceBlinding,
    ReissuanceEntropy,
    RightExtend16_32,
    RightExtend16_64,
    RightExtend32_64,
    RightExtend8_16,
    RightExtend8_32,
    RightExtend8_64,
    RightPadHigh16_32,
    RightPadHigh16_64,
    RightPadHigh1_16,
    RightPadHigh1_32,
    RightPadHigh1_64,
    RightPadHigh1_8,
    RightPadHigh32_64,
    RightPadHigh8_16,
    RightPadHigh8_32,
    RightPadHigh8_64,
    RightPadLow16_32,
    RightPadLow16_64,
    RightPadLow1_16,
    RightPadLow1_32,
    RightPadLow1_64,
    RightPadLow1_8,
    RightPadLow32_64,
    RightPadLow8_16,
    RightPadLow8_32,
    RightPadLow8_64,
    RightRotate16,
    RightRotate32,
    RightRotate64,
    RightRotate8,
    RightShift16,
    RightShift32,
    RightShift64,
    RightShift8,
    RightShiftWith16,
    RightShiftWith32,
    RightShiftWith64,
    RightShiftWith8,
    Rightmost16_1,
    Rightmost16_2,
    Rightmost16_4,
    Rightmost16_8,
    Rightmost32_1,
    Rightmost32_16,
    Rightmost32_2,
    Rightmost32_4,
    Rightmost32_8,
    Rightmost64_1,
    Rightmost64_16,
    Rightmost64_2,
    Rightmost64_32,
    Rightmost64_4,
    Rightmost64_8,
    Rightmost8_1,
    Rightmost8_2,
    Rightmost8_4,
    ScalarAdd,
    ScalarInvert,
    ScalarIsZero,
    ScalarMultiply,
    ScalarMultiplyLambda,
    ScalarNegate,
    ScalarNormalize,
    ScalarSquare,
    Scale,
    ScriptCMR,
    Sha256Block,
    Sha256Ctx8Add1,
    Sha256Ctx8Add128,
    Sha256Ctx8Add16,
    Sha256Ctx8Add2,
    Sha256Ctx8Add256,
    Sha256Ctx8Add32,
    Sha256Ctx8Add4,
    Sha256Ctx8Add512,
    Sha256Ctx8Add64,
    Sha256Ctx8Add8,
    Sha256Ctx8AddBuffer511,
    Sha256Ctx8Finalize,
    Sha256Ctx8Init,
    Sha256Iv,
    SigAllHash,
    Some1,
    Some16,
    Some32,
    Some64,
    Some8,
    Subtract16,
    Subtract32,
    Subtract64,
    Subtract8,
    Swu,
    TapEnvHash,
    TapdataInit,
    TapleafHash,
    TapleafVersion,
    Tappath,
    TappathHash,
    TotalFee,
    TransactionId,
    TxHash,
    TxIsFinal,
    TxLockDistance,
    TxLockDuration,
    TxLockHeight,
    TxLockTime,
    Verify,
    Version,
    Xor1,
    Xor16,
    Xor32,
    Xor64,
    Xor8,
    XorXor1,
    XorXor16,
    XorXor32,
    XorXor64,
    XorXor8,
}
