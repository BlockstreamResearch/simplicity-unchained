use std::io::Write;

use hal_simplicity::simplicity::Cmr;
use hal_simplicity::simplicity::Cost;
use hal_simplicity::simplicity::ffi::CFrameItem;
use hal_simplicity::simplicity::jet::type_name::TypeName;
use hal_simplicity::simplicity::jet::{Core, Jet};
use hal_simplicity::simplicity::{BitIter, BitWriter, decode};

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
pub enum CoreExtension {
    Core(Core),
    GetOpcodeFromScript,
    GetPubkeyFromScript,
}

impl CoreExtension {
    pub const ALL: [Self; 370] = [
        CoreExtension::Core(Core::Add16),
        CoreExtension::Core(Core::Add32),
        CoreExtension::Core(Core::Add64),
        CoreExtension::Core(Core::Add8),
        CoreExtension::Core(Core::All16),
        CoreExtension::Core(Core::All32),
        CoreExtension::Core(Core::All64),
        CoreExtension::Core(Core::All8),
        CoreExtension::Core(Core::And1),
        CoreExtension::Core(Core::And16),
        CoreExtension::Core(Core::And32),
        CoreExtension::Core(Core::And64),
        CoreExtension::Core(Core::And8),
        CoreExtension::Core(Core::Bip0340Verify),
        CoreExtension::Core(Core::Ch1),
        CoreExtension::Core(Core::Ch16),
        CoreExtension::Core(Core::Ch32),
        CoreExtension::Core(Core::Ch64),
        CoreExtension::Core(Core::Ch8),
        CoreExtension::Core(Core::CheckSigVerify),
        CoreExtension::Core(Core::Complement1),
        CoreExtension::Core(Core::Complement16),
        CoreExtension::Core(Core::Complement32),
        CoreExtension::Core(Core::Complement64),
        CoreExtension::Core(Core::Complement8),
        CoreExtension::Core(Core::Decompress),
        CoreExtension::Core(Core::Decrement16),
        CoreExtension::Core(Core::Decrement32),
        CoreExtension::Core(Core::Decrement64),
        CoreExtension::Core(Core::Decrement8),
        CoreExtension::Core(Core::DivMod128_64),
        CoreExtension::Core(Core::DivMod16),
        CoreExtension::Core(Core::DivMod32),
        CoreExtension::Core(Core::DivMod64),
        CoreExtension::Core(Core::DivMod8),
        CoreExtension::Core(Core::Divide16),
        CoreExtension::Core(Core::Divide32),
        CoreExtension::Core(Core::Divide64),
        CoreExtension::Core(Core::Divide8),
        CoreExtension::Core(Core::Divides16),
        CoreExtension::Core(Core::Divides32),
        CoreExtension::Core(Core::Divides64),
        CoreExtension::Core(Core::Divides8),
        CoreExtension::Core(Core::Eq1),
        CoreExtension::Core(Core::Eq16),
        CoreExtension::Core(Core::Eq256),
        CoreExtension::Core(Core::Eq32),
        CoreExtension::Core(Core::Eq64),
        CoreExtension::Core(Core::Eq8),
        CoreExtension::Core(Core::FeAdd),
        CoreExtension::Core(Core::FeInvert),
        CoreExtension::Core(Core::FeIsOdd),
        CoreExtension::Core(Core::FeIsZero),
        CoreExtension::Core(Core::FeMultiply),
        CoreExtension::Core(Core::FeMultiplyBeta),
        CoreExtension::Core(Core::FeNegate),
        CoreExtension::Core(Core::FeNormalize),
        CoreExtension::Core(Core::FeSquare),
        CoreExtension::Core(Core::FeSquareRoot),
        CoreExtension::Core(Core::FullAdd16),
        CoreExtension::Core(Core::FullAdd32),
        CoreExtension::Core(Core::FullAdd64),
        CoreExtension::Core(Core::FullAdd8),
        CoreExtension::Core(Core::FullDecrement16),
        CoreExtension::Core(Core::FullDecrement32),
        CoreExtension::Core(Core::FullDecrement64),
        CoreExtension::Core(Core::FullDecrement8),
        CoreExtension::Core(Core::FullIncrement16),
        CoreExtension::Core(Core::FullIncrement32),
        CoreExtension::Core(Core::FullIncrement64),
        CoreExtension::Core(Core::FullIncrement8),
        CoreExtension::Core(Core::FullLeftShift16_1),
        CoreExtension::Core(Core::FullLeftShift16_2),
        CoreExtension::Core(Core::FullLeftShift16_4),
        CoreExtension::Core(Core::FullLeftShift16_8),
        CoreExtension::Core(Core::FullLeftShift32_1),
        CoreExtension::Core(Core::FullLeftShift32_16),
        CoreExtension::Core(Core::FullLeftShift32_2),
        CoreExtension::Core(Core::FullLeftShift32_4),
        CoreExtension::Core(Core::FullLeftShift32_8),
        CoreExtension::Core(Core::FullLeftShift64_1),
        CoreExtension::Core(Core::FullLeftShift64_16),
        CoreExtension::Core(Core::FullLeftShift64_2),
        CoreExtension::Core(Core::FullLeftShift64_32),
        CoreExtension::Core(Core::FullLeftShift64_4),
        CoreExtension::Core(Core::FullLeftShift64_8),
        CoreExtension::Core(Core::FullLeftShift8_1),
        CoreExtension::Core(Core::FullLeftShift8_2),
        CoreExtension::Core(Core::FullLeftShift8_4),
        CoreExtension::Core(Core::FullMultiply16),
        CoreExtension::Core(Core::FullMultiply32),
        CoreExtension::Core(Core::FullMultiply64),
        CoreExtension::Core(Core::FullMultiply8),
        CoreExtension::Core(Core::FullRightShift16_1),
        CoreExtension::Core(Core::FullRightShift16_2),
        CoreExtension::Core(Core::FullRightShift16_4),
        CoreExtension::Core(Core::FullRightShift16_8),
        CoreExtension::Core(Core::FullRightShift32_1),
        CoreExtension::Core(Core::FullRightShift32_16),
        CoreExtension::Core(Core::FullRightShift32_2),
        CoreExtension::Core(Core::FullRightShift32_4),
        CoreExtension::Core(Core::FullRightShift32_8),
        CoreExtension::Core(Core::FullRightShift64_1),
        CoreExtension::Core(Core::FullRightShift64_16),
        CoreExtension::Core(Core::FullRightShift64_2),
        CoreExtension::Core(Core::FullRightShift64_32),
        CoreExtension::Core(Core::FullRightShift64_4),
        CoreExtension::Core(Core::FullRightShift64_8),
        CoreExtension::Core(Core::FullRightShift8_1),
        CoreExtension::Core(Core::FullRightShift8_2),
        CoreExtension::Core(Core::FullRightShift8_4),
        CoreExtension::Core(Core::FullSubtract16),
        CoreExtension::Core(Core::FullSubtract32),
        CoreExtension::Core(Core::FullSubtract64),
        CoreExtension::Core(Core::FullSubtract8),
        CoreExtension::Core(Core::GeIsOnCurve),
        CoreExtension::Core(Core::GeNegate),
        CoreExtension::Core(Core::GejAdd),
        CoreExtension::Core(Core::GejDouble),
        CoreExtension::Core(Core::GejEquiv),
        CoreExtension::Core(Core::GejGeAdd),
        CoreExtension::Core(Core::GejGeAddEx),
        CoreExtension::Core(Core::GejGeEquiv),
        CoreExtension::Core(Core::GejInfinity),
        CoreExtension::Core(Core::GejIsInfinity),
        CoreExtension::Core(Core::GejIsOnCurve),
        CoreExtension::Core(Core::GejNegate),
        CoreExtension::Core(Core::GejNormalize),
        CoreExtension::Core(Core::GejRescale),
        CoreExtension::Core(Core::GejXEquiv),
        CoreExtension::Core(Core::GejYIsOdd),
        CoreExtension::Core(Core::Generate),
        CoreExtension::Core(Core::HashToCurve),
        CoreExtension::Core(Core::High1),
        CoreExtension::Core(Core::High16),
        CoreExtension::Core(Core::High32),
        CoreExtension::Core(Core::High64),
        CoreExtension::Core(Core::High8),
        CoreExtension::Core(Core::Increment16),
        CoreExtension::Core(Core::Increment32),
        CoreExtension::Core(Core::Increment64),
        CoreExtension::Core(Core::Increment8),
        CoreExtension::Core(Core::IsOne16),
        CoreExtension::Core(Core::IsOne32),
        CoreExtension::Core(Core::IsOne64),
        CoreExtension::Core(Core::IsOne8),
        CoreExtension::Core(Core::IsZero16),
        CoreExtension::Core(Core::IsZero32),
        CoreExtension::Core(Core::IsZero64),
        CoreExtension::Core(Core::IsZero8),
        CoreExtension::Core(Core::Le16),
        CoreExtension::Core(Core::Le32),
        CoreExtension::Core(Core::Le64),
        CoreExtension::Core(Core::Le8),
        CoreExtension::Core(Core::LeftExtend16_32),
        CoreExtension::Core(Core::LeftExtend16_64),
        CoreExtension::Core(Core::LeftExtend1_16),
        CoreExtension::Core(Core::LeftExtend1_32),
        CoreExtension::Core(Core::LeftExtend1_64),
        CoreExtension::Core(Core::LeftExtend1_8),
        CoreExtension::Core(Core::LeftExtend32_64),
        CoreExtension::Core(Core::LeftExtend8_16),
        CoreExtension::Core(Core::LeftExtend8_32),
        CoreExtension::Core(Core::LeftExtend8_64),
        CoreExtension::Core(Core::LeftPadHigh16_32),
        CoreExtension::Core(Core::LeftPadHigh16_64),
        CoreExtension::Core(Core::LeftPadHigh1_16),
        CoreExtension::Core(Core::LeftPadHigh1_32),
        CoreExtension::Core(Core::LeftPadHigh1_64),
        CoreExtension::Core(Core::LeftPadHigh1_8),
        CoreExtension::Core(Core::LeftPadHigh32_64),
        CoreExtension::Core(Core::LeftPadHigh8_16),
        CoreExtension::Core(Core::LeftPadHigh8_32),
        CoreExtension::Core(Core::LeftPadHigh8_64),
        CoreExtension::Core(Core::LeftPadLow16_32),
        CoreExtension::Core(Core::LeftPadLow16_64),
        CoreExtension::Core(Core::LeftPadLow1_16),
        CoreExtension::Core(Core::LeftPadLow1_32),
        CoreExtension::Core(Core::LeftPadLow1_64),
        CoreExtension::Core(Core::LeftPadLow1_8),
        CoreExtension::Core(Core::LeftPadLow32_64),
        CoreExtension::Core(Core::LeftPadLow8_16),
        CoreExtension::Core(Core::LeftPadLow8_32),
        CoreExtension::Core(Core::LeftPadLow8_64),
        CoreExtension::Core(Core::LeftRotate16),
        CoreExtension::Core(Core::LeftRotate32),
        CoreExtension::Core(Core::LeftRotate64),
        CoreExtension::Core(Core::LeftRotate8),
        CoreExtension::Core(Core::LeftShift16),
        CoreExtension::Core(Core::LeftShift32),
        CoreExtension::Core(Core::LeftShift64),
        CoreExtension::Core(Core::LeftShift8),
        CoreExtension::Core(Core::LeftShiftWith16),
        CoreExtension::Core(Core::LeftShiftWith32),
        CoreExtension::Core(Core::LeftShiftWith64),
        CoreExtension::Core(Core::LeftShiftWith8),
        CoreExtension::Core(Core::Leftmost16_1),
        CoreExtension::Core(Core::Leftmost16_2),
        CoreExtension::Core(Core::Leftmost16_4),
        CoreExtension::Core(Core::Leftmost16_8),
        CoreExtension::Core(Core::Leftmost32_1),
        CoreExtension::Core(Core::Leftmost32_16),
        CoreExtension::Core(Core::Leftmost32_2),
        CoreExtension::Core(Core::Leftmost32_4),
        CoreExtension::Core(Core::Leftmost32_8),
        CoreExtension::Core(Core::Leftmost64_1),
        CoreExtension::Core(Core::Leftmost64_16),
        CoreExtension::Core(Core::Leftmost64_2),
        CoreExtension::Core(Core::Leftmost64_32),
        CoreExtension::Core(Core::Leftmost64_4),
        CoreExtension::Core(Core::Leftmost64_8),
        CoreExtension::Core(Core::Leftmost8_1),
        CoreExtension::Core(Core::Leftmost8_2),
        CoreExtension::Core(Core::Leftmost8_4),
        CoreExtension::Core(Core::LinearCombination1),
        CoreExtension::Core(Core::LinearVerify1),
        CoreExtension::Core(Core::Low1),
        CoreExtension::Core(Core::Low16),
        CoreExtension::Core(Core::Low32),
        CoreExtension::Core(Core::Low64),
        CoreExtension::Core(Core::Low8),
        CoreExtension::Core(Core::Lt16),
        CoreExtension::Core(Core::Lt32),
        CoreExtension::Core(Core::Lt64),
        CoreExtension::Core(Core::Lt8),
        CoreExtension::Core(Core::Maj1),
        CoreExtension::Core(Core::Maj16),
        CoreExtension::Core(Core::Maj32),
        CoreExtension::Core(Core::Maj64),
        CoreExtension::Core(Core::Maj8),
        CoreExtension::Core(Core::Max16),
        CoreExtension::Core(Core::Max32),
        CoreExtension::Core(Core::Max64),
        CoreExtension::Core(Core::Max8),
        CoreExtension::Core(Core::Median16),
        CoreExtension::Core(Core::Median32),
        CoreExtension::Core(Core::Median64),
        CoreExtension::Core(Core::Median8),
        CoreExtension::Core(Core::Min16),
        CoreExtension::Core(Core::Min32),
        CoreExtension::Core(Core::Min64),
        CoreExtension::Core(Core::Min8),
        CoreExtension::Core(Core::Modulo16),
        CoreExtension::Core(Core::Modulo32),
        CoreExtension::Core(Core::Modulo64),
        CoreExtension::Core(Core::Modulo8),
        CoreExtension::Core(Core::Multiply16),
        CoreExtension::Core(Core::Multiply32),
        CoreExtension::Core(Core::Multiply64),
        CoreExtension::Core(Core::Multiply8),
        CoreExtension::Core(Core::Negate16),
        CoreExtension::Core(Core::Negate32),
        CoreExtension::Core(Core::Negate64),
        CoreExtension::Core(Core::Negate8),
        CoreExtension::Core(Core::One16),
        CoreExtension::Core(Core::One32),
        CoreExtension::Core(Core::One64),
        CoreExtension::Core(Core::One8),
        CoreExtension::Core(Core::Or1),
        CoreExtension::Core(Core::Or16),
        CoreExtension::Core(Core::Or32),
        CoreExtension::Core(Core::Or64),
        CoreExtension::Core(Core::Or8),
        CoreExtension::Core(Core::ParseLock),
        CoreExtension::Core(Core::ParseSequence),
        CoreExtension::Core(Core::PointVerify1),
        CoreExtension::Core(Core::RightExtend16_32),
        CoreExtension::Core(Core::RightExtend16_64),
        CoreExtension::Core(Core::RightExtend32_64),
        CoreExtension::Core(Core::RightExtend8_16),
        CoreExtension::Core(Core::RightExtend8_32),
        CoreExtension::Core(Core::RightExtend8_64),
        CoreExtension::Core(Core::RightPadHigh16_32),
        CoreExtension::Core(Core::RightPadHigh16_64),
        CoreExtension::Core(Core::RightPadHigh1_16),
        CoreExtension::Core(Core::RightPadHigh1_32),
        CoreExtension::Core(Core::RightPadHigh1_64),
        CoreExtension::Core(Core::RightPadHigh1_8),
        CoreExtension::Core(Core::RightPadHigh32_64),
        CoreExtension::Core(Core::RightPadHigh8_16),
        CoreExtension::Core(Core::RightPadHigh8_32),
        CoreExtension::Core(Core::RightPadHigh8_64),
        CoreExtension::Core(Core::RightPadLow16_32),
        CoreExtension::Core(Core::RightPadLow16_64),
        CoreExtension::Core(Core::RightPadLow1_16),
        CoreExtension::Core(Core::RightPadLow1_32),
        CoreExtension::Core(Core::RightPadLow1_64),
        CoreExtension::Core(Core::RightPadLow1_8),
        CoreExtension::Core(Core::RightPadLow32_64),
        CoreExtension::Core(Core::RightPadLow8_16),
        CoreExtension::Core(Core::RightPadLow8_32),
        CoreExtension::Core(Core::RightPadLow8_64),
        CoreExtension::Core(Core::RightRotate16),
        CoreExtension::Core(Core::RightRotate32),
        CoreExtension::Core(Core::RightRotate64),
        CoreExtension::Core(Core::RightRotate8),
        CoreExtension::Core(Core::RightShift16),
        CoreExtension::Core(Core::RightShift32),
        CoreExtension::Core(Core::RightShift64),
        CoreExtension::Core(Core::RightShift8),
        CoreExtension::Core(Core::RightShiftWith16),
        CoreExtension::Core(Core::RightShiftWith32),
        CoreExtension::Core(Core::RightShiftWith64),
        CoreExtension::Core(Core::RightShiftWith8),
        CoreExtension::Core(Core::Rightmost16_1),
        CoreExtension::Core(Core::Rightmost16_2),
        CoreExtension::Core(Core::Rightmost16_4),
        CoreExtension::Core(Core::Rightmost16_8),
        CoreExtension::Core(Core::Rightmost32_1),
        CoreExtension::Core(Core::Rightmost32_16),
        CoreExtension::Core(Core::Rightmost32_2),
        CoreExtension::Core(Core::Rightmost32_4),
        CoreExtension::Core(Core::Rightmost32_8),
        CoreExtension::Core(Core::Rightmost64_1),
        CoreExtension::Core(Core::Rightmost64_16),
        CoreExtension::Core(Core::Rightmost64_2),
        CoreExtension::Core(Core::Rightmost64_32),
        CoreExtension::Core(Core::Rightmost64_4),
        CoreExtension::Core(Core::Rightmost64_8),
        CoreExtension::Core(Core::Rightmost8_1),
        CoreExtension::Core(Core::Rightmost8_2),
        CoreExtension::Core(Core::Rightmost8_4),
        CoreExtension::Core(Core::ScalarAdd),
        CoreExtension::Core(Core::ScalarInvert),
        CoreExtension::Core(Core::ScalarIsZero),
        CoreExtension::Core(Core::ScalarMultiply),
        CoreExtension::Core(Core::ScalarMultiplyLambda),
        CoreExtension::Core(Core::ScalarNegate),
        CoreExtension::Core(Core::ScalarNormalize),
        CoreExtension::Core(Core::ScalarSquare),
        CoreExtension::Core(Core::Scale),
        CoreExtension::Core(Core::Sha256Block),
        CoreExtension::Core(Core::Sha256Ctx8Add1),
        CoreExtension::Core(Core::Sha256Ctx8Add128),
        CoreExtension::Core(Core::Sha256Ctx8Add16),
        CoreExtension::Core(Core::Sha256Ctx8Add2),
        CoreExtension::Core(Core::Sha256Ctx8Add256),
        CoreExtension::Core(Core::Sha256Ctx8Add32),
        CoreExtension::Core(Core::Sha256Ctx8Add4),
        CoreExtension::Core(Core::Sha256Ctx8Add512),
        CoreExtension::Core(Core::Sha256Ctx8Add64),
        CoreExtension::Core(Core::Sha256Ctx8Add8),
        CoreExtension::Core(Core::Sha256Ctx8AddBuffer511),
        CoreExtension::Core(Core::Sha256Ctx8Finalize),
        CoreExtension::Core(Core::Sha256Ctx8Init),
        CoreExtension::Core(Core::Sha256Iv),
        CoreExtension::Core(Core::Some1),
        CoreExtension::Core(Core::Some16),
        CoreExtension::Core(Core::Some32),
        CoreExtension::Core(Core::Some64),
        CoreExtension::Core(Core::Some8),
        CoreExtension::Core(Core::Subtract16),
        CoreExtension::Core(Core::Subtract32),
        CoreExtension::Core(Core::Subtract64),
        CoreExtension::Core(Core::Subtract8),
        CoreExtension::Core(Core::Swu),
        CoreExtension::Core(Core::TapdataInit),
        CoreExtension::Core(Core::Verify),
        CoreExtension::Core(Core::Xor1),
        CoreExtension::Core(Core::Xor16),
        CoreExtension::Core(Core::Xor32),
        CoreExtension::Core(Core::Xor64),
        CoreExtension::Core(Core::Xor8),
        CoreExtension::Core(Core::XorXor1),
        CoreExtension::Core(Core::XorXor16),
        CoreExtension::Core(Core::XorXor32),
        CoreExtension::Core(Core::XorXor64),
        CoreExtension::Core(Core::XorXor8),
        CoreExtension::GetOpcodeFromScript,
        CoreExtension::GetPubkeyFromScript,
    ];
}

impl Jet for CoreExtension {
    type Environment = UnchainedEnv<()>;
    type CJetEnvironment = UnchainedEnv<()>;

    fn c_jet_env(env: &Self::Environment) -> &Self::CJetEnvironment {
        // For the time being, we are goint to use the initial environment for unchained jets,
        // as we are going to implement them in rust.
        env
    }

    fn cmr(&self) -> Cmr {
        if let CoreExtension::Core(inner_jet) = self {
            return inner_jet.cmr();
        }

        let bytes = match self {
            CoreExtension::GetOpcodeFromScript => [
                0xdc, 0xcc, 0xd2, 0x89, 0x59, 0x22, 0xe7, 0x5b, 0x01, 0x8b, 0x08, 0x46, 0xe5, 0xcd,
                0x49, 0x63, 0x80, 0x8b, 0xbf, 0xd4, 0x8b, 0x47, 0x23, 0x44, 0x75, 0x60, 0x7f, 0x90,
                0xe7, 0x0e, 0xe0, 0x32,
            ],
            CoreExtension::GetPubkeyFromScript => [
                0x27, 0xea, 0xb0, 0x90, 0x68, 0xb0, 0x35, 0xaf, 0x61, 0x97, 0x13, 0x33, 0x5b, 0x73,
                0xd2, 0x52, 0x0e, 0xcc, 0x02, 0x09, 0x00, 0x67, 0xc8, 0xfc, 0xca, 0xbb, 0x4d, 0x72,
                0xa6, 0x55, 0xcd, 0xcb,
            ],
            _ => unreachable!(),
        };

        Cmr::from_byte_array(bytes)
    }

    fn source_ty(&self) -> TypeName {
        if let CoreExtension::Core(inner_jet) = self {
            return inner_jet.source_ty();
        }

        let name = match self {
            CoreExtension::GetOpcodeFromScript => b"c",
            CoreExtension::GetPubkeyFromScript => b"c",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn target_ty(&self) -> TypeName {
        if let CoreExtension::Core(inner_jet) = self {
            return inner_jet.target_ty();
        }

        let name = match self {
            CoreExtension::GetOpcodeFromScript => b"c",
            CoreExtension::GetPubkeyFromScript => b"h",
            _ => unreachable!(),
        };

        TypeName(name)
    }

    fn encode<W: Write>(&self, w: &mut BitWriter<W>) -> std::io::Result<usize> {
        if let CoreExtension::Core(inner_jet) = self {
            return inner_jet.encode(w);
        }

        let (n, len) = match self {
            CoreExtension::GetOpcodeFromScript => (30, 5),
            CoreExtension::GetPubkeyFromScript => (62, 6),
            _ => unreachable!(),
        };

        w.write_bits_be(n, len)
    }

    fn decode<I: Iterator<Item = u8> + Clone>(
        bits: &mut BitIter<I>,
    ) -> Result<Self, decode::Error> {
        decode_bits!(bits, {
            0 => {
                0 => {CoreExtension::Core(Core::Verify)},
                1 => {
                    0 => {
                        0 => {
                            0 => {CoreExtension::Core(Core::Low1)},
                            1 => {
                                0 => {
                                    0 => {},
                                    1 => {CoreExtension::Core(Core::Low8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {CoreExtension::Core(Core::Low16)},
                                                1 => {CoreExtension::Core(Core::Low32)}
                                            },
                                            1 => {
                                                0 => {CoreExtension::Core(Core::Low64)},
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
                            0 => {CoreExtension::Core(Core::High1)},
                            1 => {
                                0 => {
                                    0 => {},
                                    1 => {CoreExtension::Core(Core::High8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {CoreExtension::Core(Core::High16)},
                                                1 => {CoreExtension::Core(Core::High32)}
                                            },
                                            1 => {
                                                0 => {CoreExtension::Core(Core::High64)},
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
                                        0 => {CoreExtension::Core(Core::Complement1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {CoreExtension::Core(Core::Complement8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::Complement16)},
                                                            1 => {CoreExtension::Core(Core::Complement32)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::Complement64)},
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
                                        0 => {CoreExtension::Core(Core::And1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {CoreExtension::Core(Core::And8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::And16)},
                                                            1 => {CoreExtension::Core(Core::And32)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::And64)},
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
                                        0 => {CoreExtension::Core(Core::Or1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {CoreExtension::Core(Core::Or8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::Or16)},
                                                            1 => {CoreExtension::Core(Core::Or32)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::Or64)},
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
                                        0 => {CoreExtension::Core(Core::Xor1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {CoreExtension::Core(Core::Xor8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::Xor16)},
                                                            1 => {CoreExtension::Core(Core::Xor32)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::Xor64)},
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
                                            0 => {CoreExtension::Core(Core::Maj1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {CoreExtension::Core(Core::Maj8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::Maj16)},
                                                                1 => {CoreExtension::Core(Core::Maj32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::Maj64)},
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
                                            0 => {CoreExtension::Core(Core::XorXor1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {CoreExtension::Core(Core::XorXor8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::XorXor16)},
                                                                1 => {CoreExtension::Core(Core::XorXor32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::XorXor64)},
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
                                            0 => {CoreExtension::Core(Core::Ch1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {CoreExtension::Core(Core::Ch8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::Ch16)},
                                                                1 => {CoreExtension::Core(Core::Ch32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::Ch64)},
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
                                            0 => {CoreExtension::Core(Core::Some1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {CoreExtension::Core(Core::Some8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::Some16)},
                                                                1 => {CoreExtension::Core(Core::Some32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::Some64)},
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
                                                    1 => {CoreExtension::Core(Core::All8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::All16)},
                                                                1 => {CoreExtension::Core(Core::All32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::All64)},
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
                                            0 => {CoreExtension::Core(Core::Eq1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {CoreExtension::Core(Core::Eq8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::Eq16)},
                                                                1 => {CoreExtension::Core(Core::Eq32)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::Eq64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::Eq256)},
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
                                                        1 => {CoreExtension::Core(Core::FullLeftShift8_1)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullLeftShift16_1)},
                                                                    1 => {CoreExtension::Core(Core::FullLeftShift32_1)}
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullLeftShift64_1)},
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
                                                                0 => {CoreExtension::Core(Core::FullLeftShift8_2)},
                                                                1 => {CoreExtension::Core(Core::FullLeftShift16_2)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullLeftShift32_2)},
                                                                            1 => {CoreExtension::Core(Core::FullLeftShift64_2)}
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
                                                        0 => {CoreExtension::Core(Core::FullLeftShift8_4)},
                                                        1 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::FullLeftShift16_4)},
                                                                1 => {CoreExtension::Core(Core::FullLeftShift32_4)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullLeftShift64_4)},
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
                                                                    0 => {CoreExtension::Core(Core::FullLeftShift16_8)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullLeftShift32_8)},
                                                                            1 => {CoreExtension::Core(Core::FullLeftShift64_8)}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullLeftShift32_16)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullLeftShift64_16)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullLeftShift64_32)},
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
                                                        1 => {CoreExtension::Core(Core::FullRightShift8_1)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullRightShift16_1)},
                                                                    1 => {CoreExtension::Core(Core::FullRightShift32_1)}
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullRightShift64_1)},
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
                                                                0 => {CoreExtension::Core(Core::FullRightShift8_2)},
                                                                1 => {CoreExtension::Core(Core::FullRightShift16_2)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullRightShift32_2)},
                                                                            1 => {CoreExtension::Core(Core::FullRightShift64_2)}
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
                                                        0 => {CoreExtension::Core(Core::FullRightShift8_4)},
                                                        1 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::FullRightShift16_4)},
                                                                1 => {CoreExtension::Core(Core::FullRightShift32_4)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullRightShift64_4)},
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
                                                                    0 => {CoreExtension::Core(Core::FullRightShift16_8)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullRightShift32_8)},
                                                                            1 => {CoreExtension::Core(Core::FullRightShift64_8)}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullRightShift32_16)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::FullRightShift64_16)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullRightShift64_32)},
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
                                                                        1 => {CoreExtension::Core(Core::Leftmost8_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::Leftmost16_1)},
                                                                                    1 => {CoreExtension::Core(Core::Leftmost32_1)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::Leftmost64_1)},
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
                                                                                0 => {CoreExtension::Core(Core::Leftmost8_2)},
                                                                                1 => {CoreExtension::Core(Core::Leftmost16_2)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Leftmost32_2)},
                                                                                            1 => {CoreExtension::Core(Core::Leftmost64_2)}
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
                                                                        0 => {CoreExtension::Core(Core::Leftmost8_4)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::Leftmost16_4)},
                                                                                1 => {CoreExtension::Core(Core::Leftmost32_4)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Leftmost64_4)},
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
                                                                                    0 => {CoreExtension::Core(Core::Leftmost16_8)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Leftmost32_8)},
                                                                                            1 => {CoreExtension::Core(Core::Leftmost64_8)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::Leftmost32_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Leftmost64_16)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::Leftmost64_32)},
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
                                                                        1 => {CoreExtension::Core(Core::Rightmost8_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::Rightmost16_1)},
                                                                                    1 => {CoreExtension::Core(Core::Rightmost32_1)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::Rightmost64_1)},
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
                                                                                0 => {CoreExtension::Core(Core::Rightmost8_2)},
                                                                                1 => {CoreExtension::Core(Core::Rightmost16_2)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Rightmost32_2)},
                                                                                            1 => {CoreExtension::Core(Core::Rightmost64_2)}
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
                                                                        0 => {CoreExtension::Core(Core::Rightmost8_4)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::Rightmost16_4)},
                                                                                1 => {CoreExtension::Core(Core::Rightmost32_4)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Rightmost64_4)},
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
                                                                                    0 => {CoreExtension::Core(Core::Rightmost16_8)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Rightmost32_8)},
                                                                                            1 => {CoreExtension::Core(Core::Rightmost64_8)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::Rightmost32_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::Rightmost64_16)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::Rightmost64_32)},
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
                                                                        1 => {CoreExtension::Core(Core::LeftPadLow1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadLow1_16)},
                                                                                    1 => {CoreExtension::Core(Core::LeftPadLow1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadLow1_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::LeftPadLow8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftPadLow8_32)},
                                                                                            1 => {CoreExtension::Core(Core::LeftPadLow8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadLow16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftPadLow16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadLow32_64)},
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
                                                                        1 => {CoreExtension::Core(Core::LeftPadHigh1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadHigh1_16)},
                                                                                    1 => {CoreExtension::Core(Core::LeftPadHigh1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadHigh1_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::LeftPadHigh8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftPadHigh8_32)},
                                                                                            1 => {CoreExtension::Core(Core::LeftPadHigh8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadHigh16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftPadHigh16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftPadHigh32_64)},
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
                                                                        1 => {CoreExtension::Core(Core::LeftExtend1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftExtend1_16)},
                                                                                    1 => {CoreExtension::Core(Core::LeftExtend1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftExtend1_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::LeftExtend8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftExtend8_32)},
                                                                                            1 => {CoreExtension::Core(Core::LeftExtend8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftExtend16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::LeftExtend16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::LeftExtend32_64)},
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
                                                                        1 => {CoreExtension::Core(Core::RightPadLow1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadLow1_16)},
                                                                                    1 => {CoreExtension::Core(Core::RightPadLow1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadLow1_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::RightPadLow8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightPadLow8_32)},
                                                                                            1 => {CoreExtension::Core(Core::RightPadLow8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadLow16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightPadLow16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadLow32_64)},
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
                                                                        1 => {CoreExtension::Core(Core::RightPadHigh1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadHigh1_16)},
                                                                                    1 => {CoreExtension::Core(Core::RightPadHigh1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadHigh1_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::RightPadHigh8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightPadHigh8_32)},
                                                                                            1 => {CoreExtension::Core(Core::RightPadHigh8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadHigh16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightPadHigh16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::RightPadHigh32_64)},
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
                                                                                    0 => {CoreExtension::Core(Core::RightExtend8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightExtend8_32)},
                                                                                            1 => {CoreExtension::Core(Core::RightExtend8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {CoreExtension::Core(Core::RightExtend16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {CoreExtension::Core(Core::RightExtend16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {CoreExtension::Core(Core::RightExtend32_64)},
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
                                                                    1 => {CoreExtension::Core(Core::LeftShiftWith8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::LeftShiftWith16)},
                                                                                1 => {CoreExtension::Core(Core::LeftShiftWith32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::LeftShiftWith64)},
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
                                                                    1 => {CoreExtension::Core(Core::RightShiftWith8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::RightShiftWith16)},
                                                                                1 => {CoreExtension::Core(Core::RightShiftWith32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::RightShiftWith64)},
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
                                                                    1 => {CoreExtension::Core(Core::LeftShift8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::LeftShift16)},
                                                                                1 => {CoreExtension::Core(Core::LeftShift32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::LeftShift64)},
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
                                                                    1 => {CoreExtension::Core(Core::RightShift8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::RightShift16)},
                                                                                1 => {CoreExtension::Core(Core::RightShift32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::RightShift64)},
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
                                                                    1 => {CoreExtension::Core(Core::LeftRotate8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::LeftRotate16)},
                                                                                1 => {CoreExtension::Core(Core::LeftRotate32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::LeftRotate64)},
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
                                                                    1 => {CoreExtension::Core(Core::RightRotate8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::RightRotate16)},
                                                                                1 => {CoreExtension::Core(Core::RightRotate32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::RightRotate64)},
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
                                    1 => {CoreExtension::Core(Core::One8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {CoreExtension::Core(Core::One16)},
                                                1 => {CoreExtension::Core(Core::One32)}
                                            },
                                            1 => {
                                                0 => {CoreExtension::Core(Core::One64)},
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
                                            1 => {CoreExtension::Core(Core::FullAdd8)}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {CoreExtension::Core(Core::FullAdd16)},
                                                        1 => {CoreExtension::Core(Core::FullAdd32)}
                                                    },
                                                    1 => {
                                                        0 => {CoreExtension::Core(Core::FullAdd64)},
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
                                            1 => {CoreExtension::Core(Core::Add8)}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {CoreExtension::Core(Core::Add16)},
                                                        1 => {CoreExtension::Core(Core::Add32)}
                                                    },
                                                    1 => {
                                                        0 => {CoreExtension::Core(Core::Add64)},
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
                                                        1 => {CoreExtension::Core(Core::FullIncrement8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullIncrement16)},
                                                                    1 => {CoreExtension::Core(Core::FullIncrement32)}
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullIncrement64)},
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
                                                        1 => {CoreExtension::Core(Core::Increment8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::Increment16)},
                                                                    1 => {CoreExtension::Core(Core::Increment32)}
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::Increment64)},
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
                                                        1 => {CoreExtension::Core(Core::FullSubtract8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {CoreExtension::Core(Core::FullSubtract16)},
                                                                    1 => {CoreExtension::Core(Core::FullSubtract32)}
                                                                },
                                                                1 => {
                                                                    0 => {CoreExtension::Core(Core::FullSubtract64)},
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
                                                            1 => {CoreExtension::Core(Core::Subtract8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::Subtract16)},
                                                                        1 => {CoreExtension::Core(Core::Subtract32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::Subtract64)},
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
                                                            1 => {CoreExtension::Core(Core::Negate8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::Negate16)},
                                                                        1 => {CoreExtension::Core(Core::Negate32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::Negate64)},
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
                                                            1 => {CoreExtension::Core(Core::FullDecrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::FullDecrement16)},
                                                                        1 => {CoreExtension::Core(Core::FullDecrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::FullDecrement64)},
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
                                                            1 => {CoreExtension::Core(Core::Decrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::Decrement16)},
                                                                        1 => {CoreExtension::Core(Core::Decrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::Decrement64)},
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
                                                            1 => {CoreExtension::Core(Core::FullMultiply8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::FullMultiply16)},
                                                                        1 => {CoreExtension::Core(Core::FullMultiply32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::FullMultiply64)},
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
                                                            1 => {CoreExtension::Core(Core::Multiply8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::Multiply16)},
                                                                        1 => {CoreExtension::Core(Core::Multiply32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::Multiply64)},
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
                                                            1 => {CoreExtension::Core(Core::IsZero8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::IsZero16)},
                                                                        1 => {CoreExtension::Core(Core::IsZero32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::IsZero64)},
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
                                                            1 => {CoreExtension::Core(Core::IsOne8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {CoreExtension::Core(Core::IsOne16)},
                                                                        1 => {CoreExtension::Core(Core::IsOne32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {CoreExtension::Core(Core::IsOne64)},
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
                                                                            1 => {CoreExtension::Core(Core::Le8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Le16)},
                                                                                        1 => {CoreExtension::Core(Core::Le32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Le64)},
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
                                                                            1 => {CoreExtension::Core(Core::Lt8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Lt16)},
                                                                                        1 => {CoreExtension::Core(Core::Lt32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Lt64)},
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
                                                                            1 => {CoreExtension::Core(Core::Min8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Min16)},
                                                                                        1 => {CoreExtension::Core(Core::Min32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Min64)},
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
                                                                            1 => {CoreExtension::Core(Core::Max8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Max16)},
                                                                                        1 => {CoreExtension::Core(Core::Max32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Max64)},
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
                                                                            1 => {CoreExtension::Core(Core::Median8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Median16)},
                                                                                        1 => {CoreExtension::Core(Core::Median32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Median64)},
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
                                                                                        0 => {CoreExtension::Core(Core::DivMod128_64)},
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
                                                                            1 => {CoreExtension::Core(Core::DivMod8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::DivMod16)},
                                                                                        1 => {CoreExtension::Core(Core::DivMod32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::DivMod64)},
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
                                                                            1 => {CoreExtension::Core(Core::Divide8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Divide16)},
                                                                                        1 => {CoreExtension::Core(Core::Divide32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Divide64)},
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
                                                                            1 => {CoreExtension::Core(Core::Modulo8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Modulo16)},
                                                                                        1 => {CoreExtension::Core(Core::Modulo32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Modulo64)},
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
                                                                            1 => {CoreExtension::Core(Core::Divides8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {CoreExtension::Core(Core::Divides16)},
                                                                                        1 => {CoreExtension::Core(Core::Divides32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {CoreExtension::Core(Core::Divides64)},
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
                            0 => {CoreExtension::Core(Core::Sha256Block)},
                            1 => {
                                0 => {
                                    0 => {CoreExtension::Core(Core::Sha256Iv)},
                                    1 => {
                                        0 => {CoreExtension::Core(Core::Sha256Ctx8Add1)},
                                        1 => {
                                            0 => {
                                                0 => {CoreExtension::Core(Core::Sha256Ctx8Add2)},
                                                1 => {CoreExtension::Core(Core::Sha256Ctx8Add4)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::Sha256Ctx8Add8)},
                                                            1 => {CoreExtension::Core(Core::Sha256Ctx8Add16)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::Sha256Ctx8Add32)},
                                                            1 => {CoreExtension::Core(Core::Sha256Ctx8Add64)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {CoreExtension::Core(Core::Sha256Ctx8Add128)},
                                                                1 => {CoreExtension::Core(Core::Sha256Ctx8Add256)}
                                                            },
                                                            1 => {
                                                                0 => {CoreExtension::Core(Core::Sha256Ctx8Add512)},
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
                                                0 => {CoreExtension::Core(Core::Sha256Ctx8AddBuffer511)},
                                                1 => {CoreExtension::Core(Core::Sha256Ctx8Finalize)}
                                            },
                                            1 => {
                                                0 => {CoreExtension::Core(Core::Sha256Ctx8Init)},
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
                                        0 => {CoreExtension::Core(Core::PointVerify1)},
                                        1 => {}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {CoreExtension::Core(Core::Decompress)},
                                            1 => {
                                                0 => {CoreExtension::Core(Core::LinearVerify1)},
                                                1 => {}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::LinearCombination1)},
                                                            1 => {}
                                                        },
                                                        1 => {CoreExtension::Core(Core::Scale)}
                                                    },
                                                    1 => {
                                                        0 => {CoreExtension::Core(Core::Generate)},
                                                        1 => {CoreExtension::Core(Core::GejInfinity)}
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::GejNormalize)},
                                                            1 => {CoreExtension::Core(Core::GejNegate)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::GeNegate)},
                                                            1 => {CoreExtension::Core(Core::GejDouble)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {CoreExtension::Core(Core::GejAdd)},
                                                            1 => {CoreExtension::Core(Core::GejGeAddEx)}
                                                        },
                                                        1 => {
                                                            0 => {CoreExtension::Core(Core::GejGeAdd)},
                                                            1 => {CoreExtension::Core(Core::GejRescale)}
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
                                                                            0 => {CoreExtension::Core(Core::GejIsInfinity)},
                                                                            1 => {CoreExtension::Core(Core::GejEquiv)}
                                                                        },
                                                                        1 => {
                                                                            0 => {CoreExtension::Core(Core::GejGeEquiv)},
                                                                            1 => {CoreExtension::Core(Core::GejXEquiv)}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::GejYIsOdd)},
                                                                            1 => {CoreExtension::Core(Core::GejIsOnCurve)}
                                                                        },
                                                                        1 => {
                                                                            0 => {CoreExtension::Core(Core::GeIsOnCurve)},
                                                                            1 => {CoreExtension::Core(Core::ScalarNormalize)}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::ScalarNegate)},
                                                                            1 => {CoreExtension::Core(Core::ScalarAdd)}
                                                                        },
                                                                        1 => {
                                                                            0 => {CoreExtension::Core(Core::ScalarSquare)},
                                                                            1 => {CoreExtension::Core(Core::ScalarMultiply)}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {CoreExtension::Core(Core::ScalarMultiplyLambda)},
                                                                            1 => {CoreExtension::Core(Core::ScalarInvert)}
                                                                        },
                                                                        1 => {
                                                                            0 => {CoreExtension::Core(Core::ScalarIsZero)},
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
                                                                                1 => {CoreExtension::Core(Core::FeNormalize)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::FeNegate)},
                                                                                1 => {CoreExtension::Core(Core::FeAdd)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::FeSquare)},
                                                                                1 => {CoreExtension::Core(Core::FeMultiply)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::FeMultiplyBeta)},
                                                                                1 => {CoreExtension::Core(Core::FeInvert)}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::FeSquareRoot)},
                                                                                1 => {CoreExtension::Core(Core::FeIsZero)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {CoreExtension::Core(Core::FeIsOdd)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {
                                                                                0 => {CoreExtension::Core(Core::HashToCurve)},
                                                                                1 => {CoreExtension::Core(Core::Swu)}
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
                                    0 => {CoreExtension::Core(Core::CheckSigVerify)},
                                    1 => {
                                        0 => {
                                            0 => {CoreExtension::Core(Core::Bip0340Verify)},
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {},
                                1 => {
                                    0 => {CoreExtension::Core(Core::ParseLock)},
                                    1 => {
                                        0 => {
                                            0 => {CoreExtension::Core(Core::ParseSequence)},
                                            1 => {CoreExtension::Core(Core::TapdataInit)}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {}
                    },
                    1 => {
                        0 => {}, // Free path
                        1 => {
                            0 => {CoreExtension::GetOpcodeFromScript},
                            1 => {
                                0 => {CoreExtension::GetPubkeyFromScript},
                                1 => {}
                            }
                        }
                    }
                }
            }
        })
    }

    fn c_jet_ptr(&self) -> &dyn Fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool {
        match self {
            CoreExtension::Core(inner_jet) => jet_wrapper(*inner_jet),
            CoreExtension::GetOpcodeFromScript => &super::exec::get_opcode_from_script,
            CoreExtension::GetPubkeyFromScript => &super::exec::get_pubkey_from_script,
        }
    }

    fn cost(&self) -> Cost {
        if let CoreExtension::Core(inner_jet) = self {
            return inner_jet.cost();
        }

        // TODO(ivanlele): Calculate accurate costs for unchained jets.
        match self {
            CoreExtension::GetOpcodeFromScript => Cost::from_milliweight(100),
            CoreExtension::GetPubkeyFromScript => Cost::from_milliweight(100),
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for CoreExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreExtension::Core(inner_jet) => f.write_str(&inner_jet.to_string()),
            CoreExtension::GetOpcodeFromScript => f.write_str("get_opcode_from_script"),
            CoreExtension::GetPubkeyFromScript => f.write_str("get_pubkey_from_script"),
        }
    }
}

impl std::str::FromStr for CoreExtension {
    type Err = hal_simplicity::simplicity::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "get_opcode_from_script" => Ok(CoreExtension::GetOpcodeFromScript),
            "get_pubkey_from_script" => Ok(CoreExtension::GetPubkeyFromScript),
            _ => {
                let inner_jet = s.parse::<Core>()?;
                Ok(CoreExtension::Core(inner_jet))
            }
        }
    }
}

// Macro to generate static wrapper functions AND dispatcher for Core jets
// This macro generates both the wrapper functions and the match statement in one go,
// so we only need to list each Core variant once.
macro_rules! jet_wrappers {
    ($($variant:ident),* $(,)?) => {
        // Generate individual wrapper functions for each variant
        $(
            #[allow(non_snake_case)]
            fn $variant(frame: &mut CFrameItem, arg: CFrameItem, _env: &UnchainedEnv<()>) -> bool {
                Core::$variant.c_jet_ptr()(frame, arg, &())
            }
        )*

        // Generate the dispatcher function that returns the appropriate wrapper
        fn jet_wrapper(jet: Core) -> &'static dyn Fn(&mut CFrameItem, CFrameItem, &UnchainedEnv<()>) -> bool {
            match jet {
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
    Bip0340Verify,
    Ch1,
    Ch16,
    Ch32,
    Ch64,
    Ch8,
    CheckSigVerify,
    Complement1,
    Complement16,
    Complement32,
    Complement64,
    Complement8,
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
    IsOne16,
    IsOne32,
    IsOne64,
    IsOne8,
    IsZero16,
    IsZero32,
    IsZero64,
    IsZero8,
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
    One16,
    One32,
    One64,
    One8,
    Or1,
    Or16,
    Or32,
    Or64,
    Or8,
    ParseLock,
    ParseSequence,
    PointVerify1,
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
    TapdataInit,
    Verify,
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
