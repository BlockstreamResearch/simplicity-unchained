use std::io::Write;

use simplicity::Cmr;
use simplicity::analysis::Cost;
use simplicity::ffi::CFrameItem;
use simplicity::jet::type_name::TypeName;
use simplicity::jet::{Core, Jet};
use simplicity::{BitIter, BitWriter, decode, decode_bits};

use super::environments::UnchainedEnv;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum CoreExtension {
    Core(Core),
    WalletIDHash,
}

impl Jet for CoreExtension {
    type Environment = UnchainedEnv;
    type CJetEnvironment = UnchainedEnv;

    fn c_jet_env(env: &Self::Environment) -> &Self::CJetEnvironment {
        // For the time being, we are goint to use the initial environment for unchained jets,
        // as we are going to implement them in rust.
        env
    }

    fn cmr(&self) -> Cmr {
        if let CoreExtension::Core(core_jet) = self {
            return core_jet.cmr();
        }

        let bytes = match self {
            CoreExtension::WalletIDHash => [
                0x65, 0x61, 0xed, 0xaf, 0xdf, 0x5b, 0x74, 0x93, 0x91, 0x70, 0x41, 0x50, 0xe0, 0xa6,
                0x0d, 0x5c, 0x1f, 0x7d, 0x0e, 0x5e, 0xc6, 0xaf, 0xd8, 0x17, 0x7d, 0xe2, 0xd2, 0x10,
                0x6f, 0x8f, 0xa9, 0x14,
            ],
            _ => unreachable!(),
        };

        Cmr::from_byte_array(bytes)
    }

    fn source_ty(&self) -> TypeName {
        if let CoreExtension::Core(core_jet) = self {
            return core_jet.source_ty();
        }

        let name = match self {
            CoreExtension::WalletIDHash => b"1",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn target_ty(&self) -> TypeName {
        if let CoreExtension::Core(core_jet) = self {
            return core_jet.target_ty();
        }

        let name = match self {
            CoreExtension::WalletIDHash => b"h",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn encode<W: Write>(&self, w: &mut BitWriter<W>) -> std::io::Result<usize> {
        if let CoreExtension::Core(core_jet) = self {
            return core_jet.encode(w);
        }

        let (n, len) = match self {
            CoreExtension::WalletIDHash => (14, 4),
            _ => unreachable!(),
        };

        w.write_bits_be(n, len)
    }

    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        // Revert the iterator back to bytes to create two separate iterators for trying to decode
        // as Core jet first, and if that fails, as an unchained extension jet. We need this because
        // Core::decode consumes bits from the iterator
        let bytes = bits
            .map(u8::from)
            .collect::<Vec<u8>>()
            .chunks(u8::BITS as usize)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &bit| (acc << 1) | bit))
            .collect::<Vec<u8>>();

        let core_bits = &mut BitIter::from(&bytes[..]);
        let extension_bits = &mut BitIter::from(&bytes[..]);

        if let Ok(core_jet) = Core::decode(core_bits) {
            return Ok(CoreExtension::Core(core_jet));
        }

        decode_bits!(extension_bits, {
            0 => {},
            1 => {
                0 => {},
                1 => {
                    0 => {},
                    1 => {
                        0 => {CoreExtension::WalletIDHash},
                        1 => {}
                    }
                }
            }
        })
    }

    fn c_jet_ptr(&self) -> &dyn Fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        match self {
            CoreExtension::Core(core_jet) => core_jet_wrapper(*core_jet),
            CoreExtension::WalletIDHash => &super::exec::wallet_id_hash,
        }
    }

    fn cost(&self) -> Cost {
        if let CoreExtension::Core(core_jet) = self {
            return core_jet.cost();
        }

        // TODO(ivanlele): Calculate accurate costs for unchained jets.
        match self {
            CoreExtension::WalletIDHash => Cost::from_milliweight(100),
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for CoreExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreExtension::Core(core_jet) => f.write_str(&core_jet.to_string()),
            CoreExtension::WalletIDHash => f.write_str("wallet_id_hash"),
        }
    }
}

impl std::str::FromStr for CoreExtension {
    type Err = simplicity::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "wallet_id_hash" => Ok(CoreExtension::WalletIDHash),
            _ => {
                let core_jet = s.parse::<Core>()?;
                Ok(CoreExtension::Core(core_jet))
            }
        }
    }
}

// Macro to generate static wrapper functions AND dispatcher for Core jets
// This macro generates both the wrapper functions and the match statement in one go,
// so we only need to list each Core variant once.
macro_rules! core_jet_wrappers {
    ($($variant:ident),* $(,)?) => {
        // Generate individual wrapper functions for each variant
        $(
            #[allow(non_snake_case)]
            fn $variant(frame: &mut CFrameItem, arg: CFrameItem, _env: &UnchainedEnv) -> bool {
                Core::$variant.c_jet_ptr()(frame, arg, &())
            }
        )*

        // Generate the dispatcher function that returns the appropriate wrapper
        fn core_jet_wrapper(core: Core) -> &'static dyn Fn(&mut CFrameItem, CFrameItem, &UnchainedEnv) -> bool {
            match core {
                $(
                    Core::$variant => &$variant,
                )*
            }
        }
    };
}

// Generate wrapper functions and dispatcher for all Core jet variants
// If Core enum changes, only update this list to keep wrappers in sync
//
// TODO(ivanlele): This is extremly ungly solution, will need to open an issue
// for `rust-simplicity` to better interface for jet trait that
// does not require this boilerplate
core_jet_wrappers! {
    Add16, Add32, Add64, Add8,
    All16, All32, All64, All8,
    And1, And16, And32, And64, And8,
    Bip0340Verify,
    Ch1, Ch16, Ch32, Ch64, Ch8,
    CheckSigVerify,
    Complement1, Complement16, Complement32, Complement64, Complement8,
    Decompress,
    Decrement16, Decrement32, Decrement64, Decrement8,
    DivMod128_64, DivMod16, DivMod32, DivMod64, DivMod8,
    Divide16, Divide32, Divide64, Divide8,
    Divides16, Divides32, Divides64, Divides8,
    Eq1, Eq16, Eq256, Eq32, Eq64, Eq8,
    FeAdd, FeInvert, FeIsOdd, FeIsZero, FeMultiply, FeMultiplyBeta,
    FeNegate, FeNormalize, FeSquare, FeSquareRoot,
    FullAdd16, FullAdd32, FullAdd64, FullAdd8,
    FullDecrement16, FullDecrement32, FullDecrement64, FullDecrement8,
    FullIncrement16, FullIncrement32, FullIncrement64, FullIncrement8,
    FullLeftShift16_1, FullLeftShift16_2, FullLeftShift16_4, FullLeftShift16_8,
    FullLeftShift32_1, FullLeftShift32_2, FullLeftShift32_4, FullLeftShift32_8, FullLeftShift32_16,
    FullLeftShift64_1, FullLeftShift64_2, FullLeftShift64_4, FullLeftShift64_8, FullLeftShift64_16, FullLeftShift64_32,
    FullLeftShift8_1, FullLeftShift8_2, FullLeftShift8_4,
    FullMultiply16, FullMultiply32, FullMultiply64, FullMultiply8,
    FullRightShift16_1, FullRightShift16_2, FullRightShift16_4, FullRightShift16_8,
    FullRightShift32_1, FullRightShift32_2, FullRightShift32_4, FullRightShift32_8, FullRightShift32_16,
    FullRightShift64_1, FullRightShift64_2, FullRightShift64_4, FullRightShift64_8, FullRightShift64_16, FullRightShift64_32,
    FullRightShift8_1, FullRightShift8_2, FullRightShift8_4,
    FullSubtract16, FullSubtract32, FullSubtract64, FullSubtract8,
    GeIsOnCurve, GeNegate,
    GejAdd, GejDouble, GejEquiv, GejGeAdd, GejGeAddEx, GejGeEquiv,
    GejInfinity, GejIsInfinity, GejIsOnCurve, GejNegate, GejNormalize, GejRescale, GejXEquiv, GejYIsOdd,
    Generate, HashToCurve,
    High1, High16, High32, High64, High8,
    Increment16, Increment32, Increment64, Increment8,
    IsOne16, IsOne32, IsOne64, IsOne8,
    IsZero16, IsZero32, IsZero64, IsZero8,
    Le16, Le32, Le64, Le8,
    LeftExtend16_32, LeftExtend16_64, LeftExtend1_16, LeftExtend1_32, LeftExtend1_64, LeftExtend1_8,
    LeftExtend32_64, LeftExtend8_16, LeftExtend8_32, LeftExtend8_64,
    LeftPadHigh16_32, LeftPadHigh16_64, LeftPadHigh1_16, LeftPadHigh1_32, LeftPadHigh1_64, LeftPadHigh1_8,
    LeftPadHigh32_64, LeftPadHigh8_16, LeftPadHigh8_32, LeftPadHigh8_64,
    LeftPadLow16_32, LeftPadLow16_64, LeftPadLow1_16, LeftPadLow1_32, LeftPadLow1_64, LeftPadLow1_8,
    LeftPadLow32_64, LeftPadLow8_16, LeftPadLow8_32, LeftPadLow8_64,
    LeftRotate16, LeftRotate32, LeftRotate64, LeftRotate8,
    LeftShift16, LeftShift32, LeftShift64, LeftShift8,
    LeftShiftWith16, LeftShiftWith32, LeftShiftWith64, LeftShiftWith8,
    Leftmost16_1, Leftmost16_2, Leftmost16_4, Leftmost16_8,
    Leftmost32_1, Leftmost32_2, Leftmost32_4, Leftmost32_8, Leftmost32_16,
    Leftmost64_1, Leftmost64_2, Leftmost64_4, Leftmost64_8, Leftmost64_16, Leftmost64_32,
    Leftmost8_1, Leftmost8_2, Leftmost8_4,
    LinearCombination1, LinearVerify1,
    Low1, Low16, Low32, Low64, Low8,
    Lt16, Lt32, Lt64, Lt8,
    Maj1, Maj16, Maj32, Maj64, Maj8,
    Max16, Max32, Max64, Max8,
    Median16, Median32, Median64, Median8,
    Min16, Min32, Min64, Min8,
    Modulo16, Modulo32, Modulo64, Modulo8,
    Multiply16, Multiply32, Multiply64, Multiply8,
    Negate16, Negate32, Negate64, Negate8,
    One16, One32, One64, One8,
    Or1, Or16, Or32, Or64, Or8,
    ParseLock, ParseSequence, PointVerify1,
    RightExtend16_32, RightExtend16_64, RightExtend32_64, RightExtend8_16, RightExtend8_32, RightExtend8_64,
    RightPadHigh16_32, RightPadHigh16_64, RightPadHigh1_16, RightPadHigh1_32, RightPadHigh1_64, RightPadHigh1_8,
    RightPadHigh32_64, RightPadHigh8_16, RightPadHigh8_32, RightPadHigh8_64,
    RightPadLow16_32, RightPadLow16_64, RightPadLow1_16, RightPadLow1_32, RightPadLow1_64, RightPadLow1_8,
    RightPadLow32_64, RightPadLow8_16, RightPadLow8_32, RightPadLow8_64,
    RightRotate16, RightRotate32, RightRotate64, RightRotate8,
    RightShift16, RightShift32, RightShift64, RightShift8,
    RightShiftWith16, RightShiftWith32, RightShiftWith64, RightShiftWith8,
    Rightmost16_1, Rightmost16_2, Rightmost16_4, Rightmost16_8,
    Rightmost32_1, Rightmost32_2, Rightmost32_4, Rightmost32_8, Rightmost32_16,
    Rightmost64_1, Rightmost64_2, Rightmost64_4, Rightmost64_8, Rightmost64_16, Rightmost64_32,
    Rightmost8_1, Rightmost8_2, Rightmost8_4,
    ScalarAdd, ScalarInvert, ScalarIsZero, ScalarMultiply, ScalarMultiplyLambda,
    ScalarNegate, ScalarNormalize, ScalarSquare, Scale,
    Sha256Block, Sha256Ctx8Add1, Sha256Ctx8Add128, Sha256Ctx8Add16, Sha256Ctx8Add2,
    Sha256Ctx8Add256, Sha256Ctx8Add32, Sha256Ctx8Add4, Sha256Ctx8Add512,
    Sha256Ctx8Add64, Sha256Ctx8Add8, Sha256Ctx8AddBuffer511, Sha256Ctx8Finalize, Sha256Ctx8Init,
    Sha256Iv,
    Some1, Some16, Some32, Some64, Some8,
    Subtract16, Subtract32, Subtract64, Subtract8,
    Swu, TapdataInit, Verify,
    Xor1, Xor16, Xor32, Xor64, Xor8,
    XorXor1, XorXor16, XorXor32, XorXor64, XorXor8,
}
