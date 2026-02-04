use std::io::Write;
use std::sync::Arc;

use hal_simplicity::simplicity::Cmr;
use hal_simplicity::simplicity::Cost;
use hal_simplicity::simplicity::ffi::CFrameItem;
use hal_simplicity::simplicity::jet::type_name::TypeName;
use hal_simplicity::simplicity::jet::{Elements, Jet};
use hal_simplicity::simplicity::{BitIter, BitWriter, decode};

use hal_simplicity::simplicity::elements::Transaction;
use hal_simplicity::simplicity::jet::elements::ElementsEnv;

use crate::jets::environments::ElementsUnchainedEnv;

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
pub enum ElementsTimelockDeprJets {
    CheckLockDistance,
    CheckLockDuration,
    TxLockDistance,
    TxLockDuration,
}

impl ElementsTimelockDeprJets {
    fn cmr(&self) -> [u8; 32] {
        match self {
            Self::CheckLockDistance => [
                0x62, 0x6d, 0x83, 0xc1, 0xf3, 0xc8, 0xe4, 0xf3, 0x46, 0x85, 0x87, 0x2f, 0xec, 0x51,
                0x23, 0x06, 0x29, 0x52, 0x97, 0xe6, 0x5c, 0x96, 0x98, 0x9f, 0x97, 0xc0, 0xc1, 0xc3,
                0xda, 0x36, 0x01, 0x5c,
            ],
            Self::CheckLockDuration => [
                0xf3, 0x7a, 0x23, 0x84, 0x91, 0xd5, 0x80, 0xd5, 0x10, 0x76, 0x33, 0x11, 0xa2, 0x60,
                0x22, 0x65, 0xa6, 0xd1, 0x72, 0x4a, 0x85, 0x61, 0x83, 0xc5, 0xd1, 0xed, 0xe4, 0xd3,
                0xc8, 0xb3, 0x30, 0x0c,
            ],
            Self::TxLockDistance => [
                0xae, 0xf9, 0x71, 0x56, 0xd1, 0x9c, 0x70, 0x7b, 0x2f, 0x1a, 0x7a, 0x95, 0x00, 0xe2,
                0xee, 0x2d, 0x5a, 0x9b, 0x86, 0xc5, 0x84, 0xb3, 0xc1, 0x9e, 0x68, 0x48, 0x8c, 0x23,
                0x6d, 0x24, 0x5d, 0x1f,
            ],
            Self::TxLockDuration => [
                0xde, 0xee, 0x1a, 0xff, 0x56, 0xa3, 0x43, 0xa4, 0x89, 0x6e, 0xeb, 0x1d, 0x75, 0xed,
                0xe3, 0xdb, 0xf4, 0x5c, 0x5a, 0x0e, 0xce, 0xe9, 0xa3, 0xb8, 0xca, 0x2d, 0xa9, 0xcf,
                0xb8, 0x6c, 0x49, 0xba,
            ],
        }
    }

    fn source_ty(&self) -> TypeName {
        match self {
            Self::CheckLockDistance => Elements::CheckLockDistance.source_ty(),
            Self::CheckLockDuration => Elements::CheckLockDuration.source_ty(),
            Self::TxLockDistance => Elements::TxLockDistance.source_ty(),
            Self::TxLockDuration => Elements::TxLockDuration.source_ty(),
        }
    }

    fn target_ty(&self) -> TypeName {
        match self {
            Self::CheckLockDistance => Elements::CheckLockDistance.target_ty(),
            Self::CheckLockDuration => Elements::CheckLockDuration.target_ty(),
            Self::TxLockDistance => Elements::TxLockDistance.target_ty(),
            Self::TxLockDuration => Elements::TxLockDuration.target_ty(),
        }
    }
}

impl std::fmt::Display for ElementsTimelockDeprJets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CheckLockDistance => f.write_str(&Elements::CheckLockDistance.to_string()),
            Self::CheckLockDuration => f.write_str(&Elements::CheckLockDuration.to_string()),
            Self::TxLockDistance => f.write_str(&Elements::TxLockDistance.to_string()),
            Self::TxLockDuration => f.write_str(&Elements::TxLockDuration.to_string()),
        }
    }
}

impl ElementsTimelockDeprJets {
    fn c_jet_ptr(&self) -> &'static dyn Fn(&mut CFrameItem, CFrameItem, &ElementsUnchainedEnv) -> bool {
        match self {
            Self::CheckLockDistance => &super::exec::check_lock_distance,
            Self::CheckLockDuration => &super::exec::check_lock_duration,
            Self::TxLockDistance => &super::exec::tx_lock_distance,
            Self::TxLockDuration => &super::exec::tx_lock_duration,
        }
    }

    fn encode_bits(&self) -> (u64, usize) {
        match self {
            ElementsTimelockDeprJets::CheckLockDistance => {
                let val = 0b111100;
                (val, (val.ilog2() + 1) as usize)
            }
            ElementsTimelockDeprJets::CheckLockDuration => {
                let val = 0b1111010;
                (val, (val.ilog2() + 1) as usize)
            }
            ElementsTimelockDeprJets::TxLockDistance => {
                let val = 0b11110110;
                (val, (val.ilog2() + 1) as usize)
            }
            ElementsTimelockDeprJets::TxLockDuration => {
                let val = 0b111101110;
                (val, (val.ilog2() + 1) as usize)
            }
        }
    }
}

impl From<Elements> for ElementsTimelockDeprJets {
    fn from(value: Elements) -> Self {
        match value {
            Elements::CheckLockDistance => Self::CheckLockDistance,
            Elements::CheckLockDuration => Self::CheckLockDuration,
            Elements::TxLockDistance => Self::TxLockDistance,
            Elements::TxLockDuration => Self::TxLockDuration,
            _ => unreachable!(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum ElementsExtension {
    Elements(Elements),
    GetOpcodeFromScript,
    GetPubkeyFromScript,
    ElementsTimelockDeprJets(ElementsTimelockDeprJets),
}

impl ElementsExtension {
    pub const ALL: [Self; 473] = [
        Self::Elements(Elements::Add16),
        Self::Elements(Elements::Add32),
        Self::Elements(Elements::Add64),
        Self::Elements(Elements::Add8),
        Self::Elements(Elements::All16),
        Self::Elements(Elements::All32),
        Self::Elements(Elements::All64),
        Self::Elements(Elements::All8),
        Self::Elements(Elements::And1),
        Self::Elements(Elements::And16),
        Self::Elements(Elements::And32),
        Self::Elements(Elements::And64),
        Self::Elements(Elements::And8),
        Self::Elements(Elements::AnnexHash),
        Self::Elements(Elements::AssetAmountHash),
        Self::Elements(Elements::Bip0340Verify),
        Self::Elements(Elements::BuildTapbranch),
        Self::Elements(Elements::BuildTapleafSimplicity),
        Self::Elements(Elements::BuildTaptweak),
        Self::Elements(Elements::CalculateAsset),
        Self::Elements(Elements::CalculateConfidentialToken),
        Self::Elements(Elements::CalculateExplicitToken),
        Self::Elements(Elements::CalculateIssuanceEntropy),
        Self::Elements(Elements::Ch1),
        Self::Elements(Elements::Ch16),
        Self::Elements(Elements::Ch32),
        Self::Elements(Elements::Ch64),
        Self::Elements(Elements::Ch8),
        Self::Elements(Elements::CheckLockDistance),
        Self::Elements(Elements::CheckLockDuration),
        Self::Elements(Elements::CheckLockHeight),
        Self::Elements(Elements::CheckLockTime),
        Self::Elements(Elements::CheckSigVerify),
        Self::Elements(Elements::Complement1),
        Self::Elements(Elements::Complement16),
        Self::Elements(Elements::Complement32),
        Self::Elements(Elements::Complement64),
        Self::Elements(Elements::Complement8),
        Self::Elements(Elements::CurrentAmount),
        Self::Elements(Elements::CurrentAnnexHash),
        Self::Elements(Elements::CurrentAsset),
        Self::Elements(Elements::CurrentIndex),
        Self::Elements(Elements::CurrentIssuanceAssetAmount),
        Self::Elements(Elements::CurrentIssuanceAssetProof),
        Self::Elements(Elements::CurrentIssuanceTokenAmount),
        Self::Elements(Elements::CurrentIssuanceTokenProof),
        Self::Elements(Elements::CurrentNewIssuanceContract),
        Self::Elements(Elements::CurrentPegin),
        Self::Elements(Elements::CurrentPrevOutpoint),
        Self::Elements(Elements::CurrentReissuanceBlinding),
        Self::Elements(Elements::CurrentReissuanceEntropy),
        Self::Elements(Elements::CurrentScriptHash),
        Self::Elements(Elements::CurrentScriptSigHash),
        Self::Elements(Elements::CurrentSequence),
        Self::Elements(Elements::Decompress),
        Self::Elements(Elements::Decrement16),
        Self::Elements(Elements::Decrement32),
        Self::Elements(Elements::Decrement64),
        Self::Elements(Elements::Decrement8),
        Self::Elements(Elements::DivMod128_64),
        Self::Elements(Elements::DivMod16),
        Self::Elements(Elements::DivMod32),
        Self::Elements(Elements::DivMod64),
        Self::Elements(Elements::DivMod8),
        Self::Elements(Elements::Divide16),
        Self::Elements(Elements::Divide32),
        Self::Elements(Elements::Divide64),
        Self::Elements(Elements::Divide8),
        Self::Elements(Elements::Divides16),
        Self::Elements(Elements::Divides32),
        Self::Elements(Elements::Divides64),
        Self::Elements(Elements::Divides8),
        Self::Elements(Elements::Eq1),
        Self::Elements(Elements::Eq16),
        Self::Elements(Elements::Eq256),
        Self::Elements(Elements::Eq32),
        Self::Elements(Elements::Eq64),
        Self::Elements(Elements::Eq8),
        Self::Elements(Elements::FeAdd),
        Self::Elements(Elements::FeInvert),
        Self::Elements(Elements::FeIsOdd),
        Self::Elements(Elements::FeIsZero),
        Self::Elements(Elements::FeMultiply),
        Self::Elements(Elements::FeMultiplyBeta),
        Self::Elements(Elements::FeNegate),
        Self::Elements(Elements::FeNormalize),
        Self::Elements(Elements::FeSquare),
        Self::Elements(Elements::FeSquareRoot),
        Self::Elements(Elements::FullAdd16),
        Self::Elements(Elements::FullAdd32),
        Self::Elements(Elements::FullAdd64),
        Self::Elements(Elements::FullAdd8),
        Self::Elements(Elements::FullDecrement16),
        Self::Elements(Elements::FullDecrement32),
        Self::Elements(Elements::FullDecrement64),
        Self::Elements(Elements::FullDecrement8),
        Self::Elements(Elements::FullIncrement16),
        Self::Elements(Elements::FullIncrement32),
        Self::Elements(Elements::FullIncrement64),
        Self::Elements(Elements::FullIncrement8),
        Self::Elements(Elements::FullLeftShift16_1),
        Self::Elements(Elements::FullLeftShift16_2),
        Self::Elements(Elements::FullLeftShift16_4),
        Self::Elements(Elements::FullLeftShift16_8),
        Self::Elements(Elements::FullLeftShift32_1),
        Self::Elements(Elements::FullLeftShift32_16),
        Self::Elements(Elements::FullLeftShift32_2),
        Self::Elements(Elements::FullLeftShift32_4),
        Self::Elements(Elements::FullLeftShift32_8),
        Self::Elements(Elements::FullLeftShift64_1),
        Self::Elements(Elements::FullLeftShift64_16),
        Self::Elements(Elements::FullLeftShift64_2),
        Self::Elements(Elements::FullLeftShift64_32),
        Self::Elements(Elements::FullLeftShift64_4),
        Self::Elements(Elements::FullLeftShift64_8),
        Self::Elements(Elements::FullLeftShift8_1),
        Self::Elements(Elements::FullLeftShift8_2),
        Self::Elements(Elements::FullLeftShift8_4),
        Self::Elements(Elements::FullMultiply16),
        Self::Elements(Elements::FullMultiply32),
        Self::Elements(Elements::FullMultiply64),
        Self::Elements(Elements::FullMultiply8),
        Self::Elements(Elements::FullRightShift16_1),
        Self::Elements(Elements::FullRightShift16_2),
        Self::Elements(Elements::FullRightShift16_4),
        Self::Elements(Elements::FullRightShift16_8),
        Self::Elements(Elements::FullRightShift32_1),
        Self::Elements(Elements::FullRightShift32_16),
        Self::Elements(Elements::FullRightShift32_2),
        Self::Elements(Elements::FullRightShift32_4),
        Self::Elements(Elements::FullRightShift32_8),
        Self::Elements(Elements::FullRightShift64_1),
        Self::Elements(Elements::FullRightShift64_16),
        Self::Elements(Elements::FullRightShift64_2),
        Self::Elements(Elements::FullRightShift64_32),
        Self::Elements(Elements::FullRightShift64_4),
        Self::Elements(Elements::FullRightShift64_8),
        Self::Elements(Elements::FullRightShift8_1),
        Self::Elements(Elements::FullRightShift8_2),
        Self::Elements(Elements::FullRightShift8_4),
        Self::Elements(Elements::FullSubtract16),
        Self::Elements(Elements::FullSubtract32),
        Self::Elements(Elements::FullSubtract64),
        Self::Elements(Elements::FullSubtract8),
        Self::Elements(Elements::GeIsOnCurve),
        Self::Elements(Elements::GeNegate),
        Self::Elements(Elements::GejAdd),
        Self::Elements(Elements::GejDouble),
        Self::Elements(Elements::GejEquiv),
        Self::Elements(Elements::GejGeAdd),
        Self::Elements(Elements::GejGeAddEx),
        Self::Elements(Elements::GejGeEquiv),
        Self::Elements(Elements::GejInfinity),
        Self::Elements(Elements::GejIsInfinity),
        Self::Elements(Elements::GejIsOnCurve),
        Self::Elements(Elements::GejNegate),
        Self::Elements(Elements::GejNormalize),
        Self::Elements(Elements::GejRescale),
        Self::Elements(Elements::GejXEquiv),
        Self::Elements(Elements::GejYIsOdd),
        Self::Elements(Elements::Generate),
        Self::Elements(Elements::GenesisBlockHash),
        Self::Elements(Elements::HashToCurve),
        Self::Elements(Elements::High1),
        Self::Elements(Elements::High16),
        Self::Elements(Elements::High32),
        Self::Elements(Elements::High64),
        Self::Elements(Elements::High8),
        Self::Elements(Elements::Increment16),
        Self::Elements(Elements::Increment32),
        Self::Elements(Elements::Increment64),
        Self::Elements(Elements::Increment8),
        Self::Elements(Elements::InputAmount),
        Self::Elements(Elements::InputAmountsHash),
        Self::Elements(Elements::InputAnnexHash),
        Self::Elements(Elements::InputAnnexesHash),
        Self::Elements(Elements::InputAsset),
        Self::Elements(Elements::InputHash),
        Self::Elements(Elements::InputOutpointsHash),
        Self::Elements(Elements::InputPegin),
        Self::Elements(Elements::InputPrevOutpoint),
        Self::Elements(Elements::InputScriptHash),
        Self::Elements(Elements::InputScriptSigHash),
        Self::Elements(Elements::InputScriptSigsHash),
        Self::Elements(Elements::InputScriptsHash),
        Self::Elements(Elements::InputSequence),
        Self::Elements(Elements::InputSequencesHash),
        Self::Elements(Elements::InputUtxoHash),
        Self::Elements(Elements::InputUtxosHash),
        Self::Elements(Elements::InputsHash),
        Self::Elements(Elements::InternalKey),
        Self::Elements(Elements::IsOne16),
        Self::Elements(Elements::IsOne32),
        Self::Elements(Elements::IsOne64),
        Self::Elements(Elements::IsOne8),
        Self::Elements(Elements::IsZero16),
        Self::Elements(Elements::IsZero32),
        Self::Elements(Elements::IsZero64),
        Self::Elements(Elements::IsZero8),
        Self::Elements(Elements::Issuance),
        Self::Elements(Elements::IssuanceAsset),
        Self::Elements(Elements::IssuanceAssetAmount),
        Self::Elements(Elements::IssuanceAssetAmountsHash),
        Self::Elements(Elements::IssuanceAssetProof),
        Self::Elements(Elements::IssuanceBlindingEntropyHash),
        Self::Elements(Elements::IssuanceEntropy),
        Self::Elements(Elements::IssuanceHash),
        Self::Elements(Elements::IssuanceRangeProofsHash),
        Self::Elements(Elements::IssuanceToken),
        Self::Elements(Elements::IssuanceTokenAmount),
        Self::Elements(Elements::IssuanceTokenAmountsHash),
        Self::Elements(Elements::IssuanceTokenProof),
        Self::Elements(Elements::IssuancesHash),
        Self::Elements(Elements::LbtcAsset),
        Self::Elements(Elements::Le16),
        Self::Elements(Elements::Le32),
        Self::Elements(Elements::Le64),
        Self::Elements(Elements::Le8),
        Self::Elements(Elements::LeftExtend16_32),
        Self::Elements(Elements::LeftExtend16_64),
        Self::Elements(Elements::LeftExtend1_16),
        Self::Elements(Elements::LeftExtend1_32),
        Self::Elements(Elements::LeftExtend1_64),
        Self::Elements(Elements::LeftExtend1_8),
        Self::Elements(Elements::LeftExtend32_64),
        Self::Elements(Elements::LeftExtend8_16),
        Self::Elements(Elements::LeftExtend8_32),
        Self::Elements(Elements::LeftExtend8_64),
        Self::Elements(Elements::LeftPadHigh16_32),
        Self::Elements(Elements::LeftPadHigh16_64),
        Self::Elements(Elements::LeftPadHigh1_16),
        Self::Elements(Elements::LeftPadHigh1_32),
        Self::Elements(Elements::LeftPadHigh1_64),
        Self::Elements(Elements::LeftPadHigh1_8),
        Self::Elements(Elements::LeftPadHigh32_64),
        Self::Elements(Elements::LeftPadHigh8_16),
        Self::Elements(Elements::LeftPadHigh8_32),
        Self::Elements(Elements::LeftPadHigh8_64),
        Self::Elements(Elements::LeftPadLow16_32),
        Self::Elements(Elements::LeftPadLow16_64),
        Self::Elements(Elements::LeftPadLow1_16),
        Self::Elements(Elements::LeftPadLow1_32),
        Self::Elements(Elements::LeftPadLow1_64),
        Self::Elements(Elements::LeftPadLow1_8),
        Self::Elements(Elements::LeftPadLow32_64),
        Self::Elements(Elements::LeftPadLow8_16),
        Self::Elements(Elements::LeftPadLow8_32),
        Self::Elements(Elements::LeftPadLow8_64),
        Self::Elements(Elements::LeftRotate16),
        Self::Elements(Elements::LeftRotate32),
        Self::Elements(Elements::LeftRotate64),
        Self::Elements(Elements::LeftRotate8),
        Self::Elements(Elements::LeftShift16),
        Self::Elements(Elements::LeftShift32),
        Self::Elements(Elements::LeftShift64),
        Self::Elements(Elements::LeftShift8),
        Self::Elements(Elements::LeftShiftWith16),
        Self::Elements(Elements::LeftShiftWith32),
        Self::Elements(Elements::LeftShiftWith64),
        Self::Elements(Elements::LeftShiftWith8),
        Self::Elements(Elements::Leftmost16_1),
        Self::Elements(Elements::Leftmost16_2),
        Self::Elements(Elements::Leftmost16_4),
        Self::Elements(Elements::Leftmost16_8),
        Self::Elements(Elements::Leftmost32_1),
        Self::Elements(Elements::Leftmost32_16),
        Self::Elements(Elements::Leftmost32_2),
        Self::Elements(Elements::Leftmost32_4),
        Self::Elements(Elements::Leftmost32_8),
        Self::Elements(Elements::Leftmost64_1),
        Self::Elements(Elements::Leftmost64_16),
        Self::Elements(Elements::Leftmost64_2),
        Self::Elements(Elements::Leftmost64_32),
        Self::Elements(Elements::Leftmost64_4),
        Self::Elements(Elements::Leftmost64_8),
        Self::Elements(Elements::Leftmost8_1),
        Self::Elements(Elements::Leftmost8_2),
        Self::Elements(Elements::Leftmost8_4),
        Self::Elements(Elements::LinearCombination1),
        Self::Elements(Elements::LinearVerify1),
        Self::Elements(Elements::LockTime),
        Self::Elements(Elements::Low1),
        Self::Elements(Elements::Low16),
        Self::Elements(Elements::Low32),
        Self::Elements(Elements::Low64),
        Self::Elements(Elements::Low8),
        Self::Elements(Elements::Lt16),
        Self::Elements(Elements::Lt32),
        Self::Elements(Elements::Lt64),
        Self::Elements(Elements::Lt8),
        Self::Elements(Elements::Maj1),
        Self::Elements(Elements::Maj16),
        Self::Elements(Elements::Maj32),
        Self::Elements(Elements::Maj64),
        Self::Elements(Elements::Maj8),
        Self::Elements(Elements::Max16),
        Self::Elements(Elements::Max32),
        Self::Elements(Elements::Max64),
        Self::Elements(Elements::Max8),
        Self::Elements(Elements::Median16),
        Self::Elements(Elements::Median32),
        Self::Elements(Elements::Median64),
        Self::Elements(Elements::Median8),
        Self::Elements(Elements::Min16),
        Self::Elements(Elements::Min32),
        Self::Elements(Elements::Min64),
        Self::Elements(Elements::Min8),
        Self::Elements(Elements::Modulo16),
        Self::Elements(Elements::Modulo32),
        Self::Elements(Elements::Modulo64),
        Self::Elements(Elements::Modulo8),
        Self::Elements(Elements::Multiply16),
        Self::Elements(Elements::Multiply32),
        Self::Elements(Elements::Multiply64),
        Self::Elements(Elements::Multiply8),
        Self::Elements(Elements::Negate16),
        Self::Elements(Elements::Negate32),
        Self::Elements(Elements::Negate64),
        Self::Elements(Elements::Negate8),
        Self::Elements(Elements::NewIssuanceContract),
        Self::Elements(Elements::NonceHash),
        Self::Elements(Elements::NumInputs),
        Self::Elements(Elements::NumOutputs),
        Self::Elements(Elements::One16),
        Self::Elements(Elements::One32),
        Self::Elements(Elements::One64),
        Self::Elements(Elements::One8),
        Self::Elements(Elements::Or1),
        Self::Elements(Elements::Or16),
        Self::Elements(Elements::Or32),
        Self::Elements(Elements::Or64),
        Self::Elements(Elements::Or8),
        Self::Elements(Elements::OutpointHash),
        Self::Elements(Elements::OutputAmount),
        Self::Elements(Elements::OutputAmountsHash),
        Self::Elements(Elements::OutputAsset),
        Self::Elements(Elements::OutputHash),
        Self::Elements(Elements::OutputIsFee),
        Self::Elements(Elements::OutputNonce),
        Self::Elements(Elements::OutputNoncesHash),
        Self::Elements(Elements::OutputNullDatum),
        Self::Elements(Elements::OutputRangeProof),
        Self::Elements(Elements::OutputRangeProofsHash),
        Self::Elements(Elements::OutputScriptHash),
        Self::Elements(Elements::OutputScriptsHash),
        Self::Elements(Elements::OutputSurjectionProof),
        Self::Elements(Elements::OutputSurjectionProofsHash),
        Self::Elements(Elements::OutputsHash),
        Self::Elements(Elements::ParseLock),
        Self::Elements(Elements::ParseSequence),
        Self::Elements(Elements::PointVerify1),
        Self::Elements(Elements::ReissuanceBlinding),
        Self::Elements(Elements::ReissuanceEntropy),
        Self::Elements(Elements::RightExtend16_32),
        Self::Elements(Elements::RightExtend16_64),
        Self::Elements(Elements::RightExtend32_64),
        Self::Elements(Elements::RightExtend8_16),
        Self::Elements(Elements::RightExtend8_32),
        Self::Elements(Elements::RightExtend8_64),
        Self::Elements(Elements::RightPadHigh16_32),
        Self::Elements(Elements::RightPadHigh16_64),
        Self::Elements(Elements::RightPadHigh1_16),
        Self::Elements(Elements::RightPadHigh1_32),
        Self::Elements(Elements::RightPadHigh1_64),
        Self::Elements(Elements::RightPadHigh1_8),
        Self::Elements(Elements::RightPadHigh32_64),
        Self::Elements(Elements::RightPadHigh8_16),
        Self::Elements(Elements::RightPadHigh8_32),
        Self::Elements(Elements::RightPadHigh8_64),
        Self::Elements(Elements::RightPadLow16_32),
        Self::Elements(Elements::RightPadLow16_64),
        Self::Elements(Elements::RightPadLow1_16),
        Self::Elements(Elements::RightPadLow1_32),
        Self::Elements(Elements::RightPadLow1_64),
        Self::Elements(Elements::RightPadLow1_8),
        Self::Elements(Elements::RightPadLow32_64),
        Self::Elements(Elements::RightPadLow8_16),
        Self::Elements(Elements::RightPadLow8_32),
        Self::Elements(Elements::RightPadLow8_64),
        Self::Elements(Elements::RightRotate16),
        Self::Elements(Elements::RightRotate32),
        Self::Elements(Elements::RightRotate64),
        Self::Elements(Elements::RightRotate8),
        Self::Elements(Elements::RightShift16),
        Self::Elements(Elements::RightShift32),
        Self::Elements(Elements::RightShift64),
        Self::Elements(Elements::RightShift8),
        Self::Elements(Elements::RightShiftWith16),
        Self::Elements(Elements::RightShiftWith32),
        Self::Elements(Elements::RightShiftWith64),
        Self::Elements(Elements::RightShiftWith8),
        Self::Elements(Elements::Rightmost16_1),
        Self::Elements(Elements::Rightmost16_2),
        Self::Elements(Elements::Rightmost16_4),
        Self::Elements(Elements::Rightmost16_8),
        Self::Elements(Elements::Rightmost32_1),
        Self::Elements(Elements::Rightmost32_16),
        Self::Elements(Elements::Rightmost32_2),
        Self::Elements(Elements::Rightmost32_4),
        Self::Elements(Elements::Rightmost32_8),
        Self::Elements(Elements::Rightmost64_1),
        Self::Elements(Elements::Rightmost64_16),
        Self::Elements(Elements::Rightmost64_2),
        Self::Elements(Elements::Rightmost64_32),
        Self::Elements(Elements::Rightmost64_4),
        Self::Elements(Elements::Rightmost64_8),
        Self::Elements(Elements::Rightmost8_1),
        Self::Elements(Elements::Rightmost8_2),
        Self::Elements(Elements::Rightmost8_4),
        Self::Elements(Elements::ScalarAdd),
        Self::Elements(Elements::ScalarInvert),
        Self::Elements(Elements::ScalarIsZero),
        Self::Elements(Elements::ScalarMultiply),
        Self::Elements(Elements::ScalarMultiplyLambda),
        Self::Elements(Elements::ScalarNegate),
        Self::Elements(Elements::ScalarNormalize),
        Self::Elements(Elements::ScalarSquare),
        Self::Elements(Elements::Scale),
        Self::Elements(Elements::ScriptCMR),
        Self::Elements(Elements::Sha256Block),
        Self::Elements(Elements::Sha256Ctx8Add1),
        Self::Elements(Elements::Sha256Ctx8Add128),
        Self::Elements(Elements::Sha256Ctx8Add16),
        Self::Elements(Elements::Sha256Ctx8Add2),
        Self::Elements(Elements::Sha256Ctx8Add256),
        Self::Elements(Elements::Sha256Ctx8Add32),
        Self::Elements(Elements::Sha256Ctx8Add4),
        Self::Elements(Elements::Sha256Ctx8Add512),
        Self::Elements(Elements::Sha256Ctx8Add64),
        Self::Elements(Elements::Sha256Ctx8Add8),
        Self::Elements(Elements::Sha256Ctx8AddBuffer511),
        Self::Elements(Elements::Sha256Ctx8Finalize),
        Self::Elements(Elements::Sha256Ctx8Init),
        Self::Elements(Elements::Sha256Iv),
        Self::Elements(Elements::SigAllHash),
        Self::Elements(Elements::Some1),
        Self::Elements(Elements::Some16),
        Self::Elements(Elements::Some32),
        Self::Elements(Elements::Some64),
        Self::Elements(Elements::Some8),
        Self::Elements(Elements::Subtract16),
        Self::Elements(Elements::Subtract32),
        Self::Elements(Elements::Subtract64),
        Self::Elements(Elements::Subtract8),
        Self::Elements(Elements::Swu),
        Self::Elements(Elements::TapEnvHash),
        Self::Elements(Elements::TapdataInit),
        Self::Elements(Elements::TapleafHash),
        Self::Elements(Elements::TapleafVersion),
        Self::Elements(Elements::Tappath),
        Self::Elements(Elements::TappathHash),
        Self::Elements(Elements::TotalFee),
        Self::Elements(Elements::TransactionId),
        Self::Elements(Elements::TxHash),
        Self::Elements(Elements::TxIsFinal),
        Self::Elements(Elements::TxLockDistance),
        Self::Elements(Elements::TxLockDuration),
        Self::Elements(Elements::TxLockHeight),
        Self::Elements(Elements::TxLockTime),
        Self::Elements(Elements::Verify),
        Self::Elements(Elements::Version),
        Self::Elements(Elements::Xor1),
        Self::Elements(Elements::Xor16),
        Self::Elements(Elements::Xor32),
        Self::Elements(Elements::Xor64),
        Self::Elements(Elements::Xor8),
        Self::Elements(Elements::XorXor1),
        Self::Elements(Elements::XorXor16),
        Self::Elements(Elements::XorXor32),
        Self::Elements(Elements::XorXor64),
        Self::Elements(Elements::XorXor8),
        Self::GetOpcodeFromScript,
        Self::GetPubkeyFromScript,
    ];
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
        match self {
            ElementsExtension::Elements(
                inner_jet @ (Elements::CheckLockDistance
                | Elements::CheckLockDuration
                | Elements::TxLockDistance
                | Elements::TxLockDuration),
            ) => Cmr::from_byte_array(ElementsTimelockDeprJets::from(*inner_jet).cmr()),
            ElementsExtension::Elements(inner_jet) => inner_jet.cmr(),
            ElementsExtension::GetOpcodeFromScript => Cmr::from_byte_array([
                0xdc, 0xcc, 0xd2, 0x89, 0x59, 0x22, 0xe7, 0x5b, 0x01, 0x8b, 0x08, 0x46, 0xe5, 0xcd,
                0x49, 0x63, 0x80, 0x8b, 0xbf, 0xd4, 0x8b, 0x47, 0x23, 0x44, 0x75, 0x60, 0x7f, 0x90,
                0xe7, 0x0e, 0xe0, 0x32,
            ]),
            ElementsExtension::GetPubkeyFromScript => Cmr::from_byte_array([
                0x27, 0xea, 0xb0, 0x90, 0x68, 0xb0, 0x35, 0xaf, 0x61, 0x97, 0x13, 0x33, 0x5b, 0x73,
                0xd2, 0x52, 0x0e, 0xcc, 0x02, 0x09, 0x00, 0x67, 0xc8, 0xfc, 0xca, 0xbb, 0x4d, 0x72,
                0xa6, 0x55, 0xcd, 0xcb,
            ]),
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => {
                Cmr::from_byte_array(inner_jet.cmr())
            }
        }
    }

    fn source_ty(&self) -> TypeName {
        match self {
            ElementsExtension::Elements(inner_jet) => inner_jet.source_ty(),
            ElementsExtension::GetOpcodeFromScript => TypeName(b"c"),
            ElementsExtension::GetPubkeyFromScript => TypeName(b"c"),
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => inner_jet.source_ty(),
        }
    }

    fn target_ty(&self) -> TypeName {
        match self {
            ElementsExtension::Elements(inner_jet) => inner_jet.target_ty(),
            ElementsExtension::GetOpcodeFromScript => TypeName(b"c"),
            ElementsExtension::GetPubkeyFromScript => TypeName(b"h"),
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => inner_jet.target_ty(),
        }
    }

    fn encode<W: Write>(&self, w: &mut BitWriter<W>) -> std::io::Result<usize> {
        match self {
            ElementsExtension::Elements(inner_jet) => inner_jet.encode(w),
            ElementsExtension::GetOpcodeFromScript => w.write_bits_be(62, 6),
            ElementsExtension::GetPubkeyFromScript => w.write_bits_be(126, 7),
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => {
                let (n, len) = inner_jet.encode_bits();
                w.write_bits_be(n, len)
            }
        }
    }

    fn decode<I: Iterator<Item = u8>>(bits: &mut BitIter<I>) -> Result<Self, decode::Error> {
        decode_bits!(bits, {
            0 => {
                0 => {
                    0 => {ElementsExtension::Elements(Elements::Verify)},
                    1 => {
                        0 => {
                            0 => {
                                0 => {ElementsExtension::Elements(Elements::Low1)},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {ElementsExtension::Elements(Elements::Low8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::Low16)},
                                                    1 => {ElementsExtension::Elements(Elements::Low32)}
                                                },
                                                1 => {
                                                    0 => {ElementsExtension::Elements(Elements::Low64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {ElementsExtension::Elements(Elements::High1)},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {ElementsExtension::Elements(Elements::High8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::High16)},
                                                    1 => {ElementsExtension::Elements(Elements::High32)}
                                                },
                                                1 => {
                                                    0 => {ElementsExtension::Elements(Elements::High64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {ElementsExtension::Elements(Elements::Complement1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {ElementsExtension::Elements(Elements::Complement8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::Complement16)},
                                                                1 => {ElementsExtension::Elements(Elements::Complement32)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::Complement64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {ElementsExtension::Elements(Elements::And1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {ElementsExtension::Elements(Elements::And8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::And16)},
                                                                1 => {ElementsExtension::Elements(Elements::And32)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::And64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {ElementsExtension::Elements(Elements::Or1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {ElementsExtension::Elements(Elements::Or8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::Or16)},
                                                                1 => {ElementsExtension::Elements(Elements::Or32)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::Or64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {ElementsExtension::Elements(Elements::Xor1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {ElementsExtension::Elements(Elements::Xor8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::Xor16)},
                                                                1 => {ElementsExtension::Elements(Elements::Xor32)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::Xor64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::Maj1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::Maj8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Maj16)},
                                                                    1 => {ElementsExtension::Elements(Elements::Maj32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Maj64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {ElementsExtension::Elements(Elements::XorXor1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::XorXor8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::XorXor16)},
                                                                    1 => {ElementsExtension::Elements(Elements::XorXor32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::XorXor64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::Ch1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::Ch8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Ch16)},
                                                                    1 => {ElementsExtension::Elements(Elements::Ch32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Ch64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {ElementsExtension::Elements(Elements::Some1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::Some8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Some16)},
                                                                    1 => {ElementsExtension::Elements(Elements::Some32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Some64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::All8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::All16)},
                                                                    1 => {ElementsExtension::Elements(Elements::All32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::All64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {ElementsExtension::Elements(Elements::Eq1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {ElementsExtension::Elements(Elements::Eq8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Eq16)},
                                                                    1 => {ElementsExtension::Elements(Elements::Eq32)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Eq64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::Eq256)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {ElementsExtension::Elements(Elements::FullLeftShift8_1)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullLeftShift16_1)},
                                                                        1 => {ElementsExtension::Elements(Elements::FullLeftShift32_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullLeftShift64_1)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::FullLeftShift8_2)},
                                                                    1 => {ElementsExtension::Elements(Elements::FullLeftShift16_2)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullLeftShift32_2)},
                                                                                1 => {ElementsExtension::Elements(Elements::FullLeftShift64_2)}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::FullLeftShift8_4)},
                                                            1 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::FullLeftShift16_4)},
                                                                    1 => {ElementsExtension::Elements(Elements::FullLeftShift32_4)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullLeftShift64_4)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullLeftShift16_8)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullLeftShift32_8)},
                                                                                1 => {ElementsExtension::Elements(Elements::FullLeftShift64_8)}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullLeftShift32_16)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullLeftShift64_16)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullLeftShift64_32)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {ElementsExtension::Elements(Elements::FullRightShift8_1)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullRightShift16_1)},
                                                                        1 => {ElementsExtension::Elements(Elements::FullRightShift32_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullRightShift64_1)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::FullRightShift8_2)},
                                                                    1 => {ElementsExtension::Elements(Elements::FullRightShift16_2)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullRightShift32_2)},
                                                                                1 => {ElementsExtension::Elements(Elements::FullRightShift64_2)}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::FullRightShift8_4)},
                                                            1 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::FullRightShift16_4)},
                                                                    1 => {ElementsExtension::Elements(Elements::FullRightShift32_4)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullRightShift64_4)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullRightShift16_8)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullRightShift32_8)},
                                                                                1 => {ElementsExtension::Elements(Elements::FullRightShift64_8)}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullRightShift32_16)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::FullRightShift64_16)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullRightShift64_32)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::Leftmost8_1)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Leftmost16_1)},
                                                                                        1 => {ElementsExtension::Elements(Elements::Leftmost32_1)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Leftmost64_1)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::Leftmost8_2)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Leftmost16_2)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Leftmost32_2)},
                                                                                                1 => {ElementsExtension::Elements(Elements::Leftmost64_2)}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Leftmost8_4)},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::Leftmost16_4)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Leftmost32_4)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Leftmost64_4)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Leftmost16_8)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Leftmost32_8)},
                                                                                                1 => {ElementsExtension::Elements(Elements::Leftmost64_8)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Leftmost32_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Leftmost64_16)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Leftmost64_32)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::Rightmost8_1)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Rightmost16_1)},
                                                                                        1 => {ElementsExtension::Elements(Elements::Rightmost32_1)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Rightmost64_1)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::Rightmost8_2)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Rightmost16_2)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Rightmost32_2)},
                                                                                                1 => {ElementsExtension::Elements(Elements::Rightmost64_2)}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Rightmost8_4)},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::Rightmost16_4)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Rightmost32_4)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Rightmost64_4)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Rightmost16_8)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Rightmost32_8)},
                                                                                                1 => {ElementsExtension::Elements(Elements::Rightmost64_8)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Rightmost32_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::Rightmost64_16)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::Rightmost64_32)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::LeftPadLow1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadLow1_16)},
                                                                                        1 => {ElementsExtension::Elements(Elements::LeftPadLow1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadLow1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadLow8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftPadLow8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::LeftPadLow8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadLow16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftPadLow16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadLow32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::LeftPadHigh1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadHigh1_16)},
                                                                                        1 => {ElementsExtension::Elements(Elements::LeftPadHigh1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadHigh1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadHigh8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftPadHigh8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::LeftPadHigh8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadHigh16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftPadHigh16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftPadHigh32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::LeftExtend1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftExtend1_16)},
                                                                                        1 => {ElementsExtension::Elements(Elements::LeftExtend1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftExtend1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftExtend8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftExtend8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::LeftExtend8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftExtend16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::LeftExtend16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::LeftExtend32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::RightPadLow1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadLow1_16)},
                                                                                        1 => {ElementsExtension::Elements(Elements::RightPadLow1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadLow1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadLow8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightPadLow8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::RightPadLow8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadLow16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightPadLow16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadLow32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {ElementsExtension::Elements(Elements::RightPadHigh1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadHigh1_16)},
                                                                                        1 => {ElementsExtension::Elements(Elements::RightPadHigh1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadHigh1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadHigh8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightPadHigh8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::RightPadHigh8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadHigh16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightPadHigh16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightPadHigh32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightExtend8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightExtend8_32)},
                                                                                                1 => {ElementsExtension::Elements(Elements::RightExtend8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightExtend16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {ElementsExtension::Elements(Elements::RightExtend16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {ElementsExtension::Elements(Elements::RightExtend32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::LeftShiftWith8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftShiftWith16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::LeftShiftWith32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftShiftWith64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::RightShiftWith8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightShiftWith16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::RightShiftWith32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightShiftWith64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::LeftShift8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftShift16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::LeftShift32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftShift64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::RightShift8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightShift16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::RightShift32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightShift64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::LeftRotate8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftRotate16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::LeftRotate32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::LeftRotate64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {ElementsExtension::Elements(Elements::RightRotate8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightRotate16)},
                                                                                    1 => {ElementsExtension::Elements(Elements::RightRotate32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::RightRotate64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                },
                                1 => {}
                            }
                        }
                    }
                },
                1 => {
                    0 => {
                        0 => {
                            0 => {
                                0 => {},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {ElementsExtension::Elements(Elements::One8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::One16)},
                                                    1 => {ElementsExtension::Elements(Elements::One32)}
                                                },
                                                1 => {
                                                    0 => {ElementsExtension::Elements(Elements::One64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {ElementsExtension::Elements(Elements::FullAdd8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::FullAdd16)},
                                                            1 => {ElementsExtension::Elements(Elements::FullAdd32)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::FullAdd64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {ElementsExtension::Elements(Elements::Add8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::Add16)},
                                                            1 => {ElementsExtension::Elements(Elements::Add32)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::Add64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {ElementsExtension::Elements(Elements::FullIncrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullIncrement16)},
                                                                        1 => {ElementsExtension::Elements(Elements::FullIncrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullIncrement64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {ElementsExtension::Elements(Elements::Increment8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::Increment16)},
                                                                        1 => {ElementsExtension::Elements(Elements::Increment32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::Increment64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {},
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {ElementsExtension::Elements(Elements::FullSubtract8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullSubtract16)},
                                                                        1 => {ElementsExtension::Elements(Elements::FullSubtract32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {ElementsExtension::Elements(Elements::FullSubtract64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::Subtract8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Subtract16)},
                                                                            1 => {ElementsExtension::Elements(Elements::Subtract32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Subtract64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::Negate8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Negate16)},
                                                                            1 => {ElementsExtension::Elements(Elements::Negate32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Negate64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::FullDecrement8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::FullDecrement16)},
                                                                            1 => {ElementsExtension::Elements(Elements::FullDecrement32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::FullDecrement64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::Decrement8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Decrement16)},
                                                                            1 => {ElementsExtension::Elements(Elements::Decrement32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Decrement64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::FullMultiply8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::FullMultiply16)},
                                                                            1 => {ElementsExtension::Elements(Elements::FullMultiply32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::FullMultiply64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::Multiply8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Multiply16)},
                                                                            1 => {ElementsExtension::Elements(Elements::Multiply32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::Multiply64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::IsZero8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::IsZero16)},
                                                                            1 => {ElementsExtension::Elements(Elements::IsZero32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::IsZero64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {ElementsExtension::Elements(Elements::IsOne8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {ElementsExtension::Elements(Elements::IsOne16)},
                                                                            1 => {ElementsExtension::Elements(Elements::IsOne32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {ElementsExtension::Elements(Elements::IsOne64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Le8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Le16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Le32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Le64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Lt8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Lt16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Lt32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Lt64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Min8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Min16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Min32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Min64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Max8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Max16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Max32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Max64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Median8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Median16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Median32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Median64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {},
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::DivMod128_64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::DivMod8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::DivMod16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::DivMod32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::DivMod64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Divide8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Divide16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Divide32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Divide64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Modulo8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Modulo16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Modulo32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Modulo64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {ElementsExtension::Elements(Elements::Divides8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Divides16)},
                                                                                            1 => {ElementsExtension::Elements(Elements::Divides32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {ElementsExtension::Elements(Elements::Divides64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {ElementsExtension::Elements(Elements::Sha256Block)},
                                1 => {
                                    0 => {
                                        0 => {ElementsExtension::Elements(Elements::Sha256Iv)},
                                        1 => {
                                            0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add1)},
                                            1 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add2)},
                                                    1 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add4)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add8)},
                                                                1 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add16)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add32)},
                                                                1 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add64)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add128)},
                                                                    1 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add256)}
                                                                },
                                                                1 => {
                                                                    0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Add512)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::Sha256Ctx8AddBuffer511)},
                                                    1 => {ElementsExtension::Elements(Elements::Sha256Ctx8Finalize)}
                                                },
                                                1 => {
                                                    0 => {ElementsExtension::Elements(Elements::Sha256Ctx8Init)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {}
                        }
                    },
                    1 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {ElementsExtension::Elements(Elements::PointVerify1)},
                                            1 => {}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::Decompress)},
                                                1 => {
                                                    0 => {ElementsExtension::Elements(Elements::LinearVerify1)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::LinearCombination1)},
                                                                1 => {}
                                                            },
                                                            1 => {ElementsExtension::Elements(Elements::Scale)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::Generate)},
                                                            1 => {ElementsExtension::Elements(Elements::GejInfinity)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::GejNormalize)},
                                                                1 => {ElementsExtension::Elements(Elements::GejNegate)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::GeNegate)},
                                                                1 => {ElementsExtension::Elements(Elements::GejDouble)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::GejAdd)},
                                                                1 => {ElementsExtension::Elements(Elements::GejGeAddEx)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::GejGeAdd)},
                                                                1 => {ElementsExtension::Elements(Elements::GejRescale)}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::GejIsInfinity)},
                                                                                1 => {ElementsExtension::Elements(Elements::GejEquiv)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::GejGeEquiv)},
                                                                                1 => {ElementsExtension::Elements(Elements::GejXEquiv)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::GejYIsOdd)},
                                                                                1 => {ElementsExtension::Elements(Elements::GejIsOnCurve)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::GeIsOnCurve)},
                                                                                1 => {ElementsExtension::Elements(Elements::ScalarNormalize)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::ScalarNegate)},
                                                                                1 => {ElementsExtension::Elements(Elements::ScalarAdd)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::ScalarSquare)},
                                                                                1 => {ElementsExtension::Elements(Elements::ScalarMultiply)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::ScalarMultiplyLambda)},
                                                                                1 => {ElementsExtension::Elements(Elements::ScalarInvert)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::ScalarIsZero)},
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {
                                                                                    0 => {},
                                                                                    1 => {ElementsExtension::Elements(Elements::FeNormalize)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::FeNegate)},
                                                                                    1 => {ElementsExtension::Elements(Elements::FeAdd)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::FeSquare)},
                                                                                    1 => {ElementsExtension::Elements(Elements::FeMultiply)}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::FeMultiplyBeta)},
                                                                                    1 => {ElementsExtension::Elements(Elements::FeInvert)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::FeSquareRoot)},
                                                                                    1 => {ElementsExtension::Elements(Elements::FeIsZero)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::FeIsOdd)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::HashToCurve)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Swu)}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {ElementsExtension::Elements(Elements::CheckSigVerify)},
                                        1 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::Bip0340Verify)},
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    }
                                },
                                1 => {
                                    0 => {},
                                    1 => {
                                        0 => {ElementsExtension::Elements(Elements::ParseLock)},
                                        1 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::ParseSequence)},
                                                1 => {ElementsExtension::Elements(Elements::TapdataInit)}
                                            },
                                            1 => {}
                                        }
                                    }
                                }
                            },
                            1 => {}
                        },
                        1 => {}
                    }
                }
            },
            1 => {
                0 => {
                    0 => {ElementsExtension::Elements(Elements::SigAllHash)},
                    1 => {
                        0 => {
                            0 => {ElementsExtension::Elements(Elements::TxHash)},
                            1 => {ElementsExtension::Elements(Elements::TapEnvHash)}
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {ElementsExtension::Elements(Elements::OutputsHash)},
                                        1 => {ElementsExtension::Elements(Elements::InputsHash)}
                                    },
                                    1 => {
                                        0 => {ElementsExtension::Elements(Elements::IssuancesHash)},
                                        1 => {ElementsExtension::Elements(Elements::InputUtxosHash)}
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {ElementsExtension::Elements(Elements::OutputHash)},
                                            1 => {ElementsExtension::Elements(Elements::OutputAmountsHash)}
                                        },
                                        1 => {
                                            0 => {ElementsExtension::Elements(Elements::OutputScriptsHash)},
                                            1 => {ElementsExtension::Elements(Elements::OutputNoncesHash)}
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {ElementsExtension::Elements(Elements::OutputRangeProofsHash)},
                                            1 => {ElementsExtension::Elements(Elements::OutputSurjectionProofsHash)}
                                        },
                                        1 => {
                                            0 => {ElementsExtension::Elements(Elements::InputHash)},
                                            1 => {ElementsExtension::Elements(Elements::InputOutpointsHash)}
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::InputSequencesHash)},
                                                            1 => {ElementsExtension::Elements(Elements::InputAnnexesHash)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::InputScriptSigsHash)},
                                                            1 => {ElementsExtension::Elements(Elements::IssuanceHash)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::IssuanceAssetAmountsHash)},
                                                            1 => {ElementsExtension::Elements(Elements::IssuanceTokenAmountsHash)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::IssuanceRangeProofsHash)},
                                                            1 => {ElementsExtension::Elements(Elements::IssuanceBlindingEntropyHash)}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::InputUtxoHash)},
                                                            1 => {ElementsExtension::Elements(Elements::InputAmountsHash)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::InputScriptsHash)},
                                                            1 => {ElementsExtension::Elements(Elements::TapleafHash)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::TappathHash)},
                                                            1 => {ElementsExtension::Elements(Elements::OutpointHash)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::AssetAmountHash)},
                                                            1 => {ElementsExtension::Elements(Elements::NonceHash)}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::AnnexHash)},
                                                                1 => {ElementsExtension::Elements(Elements::BuildTapleafSimplicity)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::BuildTapbranch)},
                                                                1 => {ElementsExtension::Elements(Elements::BuildTaptweak)}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                },
                                1 => {}
                            }
                        }
                    }
                },
                1 => {
                    0 => {
                        0 => {
                            0 => {ElementsExtension::Elements(Elements::CheckLockHeight)},
                            1 => {
                                0 => {
                                    0 => {ElementsExtension::Elements(Elements::CheckLockTime)},
                                    1 => {ElementsExtension::Elements(Elements::CheckLockDistance)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::CheckLockDuration)},
                                                1 => {ElementsExtension::Elements(Elements::TxLockHeight)}
                                            },
                                            1 => {
                                                0 => {ElementsExtension::Elements(Elements::TxLockTime)},
                                                1 => {ElementsExtension::Elements(Elements::TxLockDistance)}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::TxLockDuration)},
                                                    1 => {ElementsExtension::Elements(Elements::TxIsFinal)}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    },
                                    1 => {}
                                }
                            }
                        },
                        1 => {
                            0 => {ElementsExtension::Elements(Elements::Issuance)},
                            1 => {
                                0 => {
                                    0 => {ElementsExtension::Elements(Elements::IssuanceAsset)},
                                    1 => {ElementsExtension::Elements(Elements::IssuanceToken)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::IssuanceEntropy)},
                                                1 => {ElementsExtension::Elements(Elements::CalculateIssuanceEntropy)}
                                            },
                                            1 => {
                                                0 => {ElementsExtension::Elements(Elements::CalculateAsset)},
                                                1 => {ElementsExtension::Elements(Elements::CalculateExplicitToken)}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {ElementsExtension::Elements(Elements::CalculateConfidentialToken)},
                                                    1 => {ElementsExtension::Elements(Elements::LbtcAsset)}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    },
                                    1 => {}
                                }
                            }
                        }
                    },
                    1 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {ElementsExtension::Elements(Elements::ScriptCMR)},
                                        1 => {
                                            0 => {
                                                0 => {ElementsExtension::Elements(Elements::InternalKey)},
                                                1 => {ElementsExtension::Elements(Elements::CurrentIndex)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {ElementsExtension::Elements(Elements::NumInputs)},
                                                            1 => {ElementsExtension::Elements(Elements::NumOutputs)}
                                                        },
                                                        1 => {
                                                            0 => {ElementsExtension::Elements(Elements::LockTime)},
                                                            1 => {ElementsExtension::Elements(Elements::OutputAsset)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::OutputAmount)},
                                                                1 => {ElementsExtension::Elements(Elements::OutputNonce)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::OutputScriptHash)},
                                                                1 => {ElementsExtension::Elements(Elements::OutputNullDatum)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {ElementsExtension::Elements(Elements::OutputIsFee)},
                                                                1 => {ElementsExtension::Elements(Elements::OutputSurjectionProof)}
                                                            },
                                                            1 => {
                                                                0 => {ElementsExtension::Elements(Elements::OutputRangeProof)},
                                                                1 => {ElementsExtension::Elements(Elements::TotalFee)}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentPegin)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentPrevOutpoint)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentAsset)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentAmount)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentScriptHash)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentSequence)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentAnnexHash)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentScriptSigHash)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentReissuanceBlinding)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentNewIssuanceContract)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentReissuanceEntropy)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentIssuanceAssetAmount)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentIssuanceTokenAmount)},
                                                                                1 => {ElementsExtension::Elements(Elements::CurrentIssuanceAssetProof)}
                                                                            },
                                                                            1 => {
                                                                                0 => {ElementsExtension::Elements(Elements::CurrentIssuanceTokenProof)},
                                                                                1 => {ElementsExtension::Elements(Elements::InputPegin)}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::InputPrevOutpoint)},
                                                                                    1 => {ElementsExtension::Elements(Elements::InputAsset)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::InputAmount)},
                                                                                    1 => {ElementsExtension::Elements(Elements::InputScriptHash)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::InputSequence)},
                                                                                    1 => {ElementsExtension::Elements(Elements::InputAnnexHash)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::InputScriptSigHash)},
                                                                                    1 => {ElementsExtension::Elements(Elements::ReissuanceBlinding)}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::NewIssuanceContract)},
                                                                                    1 => {ElementsExtension::Elements(Elements::ReissuanceEntropy)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::IssuanceAssetAmount)},
                                                                                    1 => {ElementsExtension::Elements(Elements::IssuanceTokenAmount)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::IssuanceAssetProof)},
                                                                                    1 => {ElementsExtension::Elements(Elements::IssuanceTokenProof)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::TapleafVersion)},
                                                                                    1 => {ElementsExtension::Elements(Elements::Tappath)}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::Version)},
                                                                                    1 => {ElementsExtension::Elements(Elements::GenesisBlockHash)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {ElementsExtension::Elements(Elements::TransactionId)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {}
                                },
                                1 => {}
                            },
                            1 => {}
                        },
                        1 => {
                            0 => {
                                0 => { ElementsExtension::ElementsTimelockDeprJets(ElementsTimelockDeprJets::CheckLockDistance) },
                                1 => {
                                    0 => { ElementsExtension::ElementsTimelockDeprJets(ElementsTimelockDeprJets::CheckLockDuration) },
                                    1 => {
                                        0 => { ElementsExtension::ElementsTimelockDeprJets(ElementsTimelockDeprJets::TxLockDistance) },
                                        1 => {
                                            0 => { ElementsExtension::ElementsTimelockDeprJets(ElementsTimelockDeprJets::TxLockDuration) },
                                            1 => { }
                                        }
                                    }
                                }
                            },
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
        })
    }

    fn c_jet_ptr(&self) -> &dyn Fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        match self {
            ElementsExtension::Elements(
                inner_jet @ (Elements::CheckLockDistance
                | Elements::CheckLockDuration
                | Elements::TxLockDistance
                | Elements::TxLockDuration),
            ) => {
                let tmp = ElementsTimelockDeprJets::from(*inner_jet);
                tmp.c_jet_ptr()
            }
            ElementsExtension::Elements(inner_jet) => jet_wrapper(*inner_jet),
            ElementsExtension::GetOpcodeFromScript => &super::exec::get_opcode_from_script,
            ElementsExtension::GetPubkeyFromScript => &super::exec::get_pubkey_from_script,
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => inner_jet.c_jet_ptr(),
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
            ElementsExtension::ElementsTimelockDeprJets(inner_jet) => inner_jet.fmt(f),
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
