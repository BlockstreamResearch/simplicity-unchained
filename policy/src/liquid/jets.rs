use super::{Context, Error, profile_hash, require};
use crate::BitValue;
use elements::hashes::sha256;
use simplicity::jet::type_name::TypeName;
use std::{fmt, str::FromStr};

/// Shared operation names do not imply shared identities or Bitcoin amount semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Builtin {
    Policy(crate::Builtin),
    InputAsset,
    OutputAsset,
    CurrentAsset,
    FeeAsset,
    AssetTotalInputValue,
    AssetTotalOutputValue,
    AssetFee,
    AssetCurrentScriptDebit,
    DisclosuresHash,
    InputValueAsset,
    OutputValueAsset,
}

impl Builtin {
    pub const COUNT: usize = 66;
    pub fn all() -> impl Iterator<Item = Self> {
        crate::Builtin::ALL.into_iter().map(Self::Policy).chain([
            Self::InputAsset,
            Self::OutputAsset,
            Self::CurrentAsset,
            Self::FeeAsset,
            Self::AssetTotalInputValue,
            Self::AssetTotalOutputValue,
            Self::AssetFee,
            Self::AssetCurrentScriptDebit,
            Self::DisclosuresHash,
            Self::InputValueAsset,
            Self::OutputValueAsset,
        ])
    }
    pub fn from_id(id: u8) -> Option<Self> {
        Self::all().nth(id as usize)
    }
    pub fn id(self) -> u8 {
        match self {
            Self::Policy(j) => j.id(),
            Self::InputAsset => 55,
            Self::OutputAsset => 56,
            Self::CurrentAsset => 57,
            Self::FeeAsset => 58,
            Self::AssetTotalInputValue => 59,
            Self::AssetTotalOutputValue => 60,
            Self::AssetFee => 61,
            Self::AssetCurrentScriptDebit => 62,
            Self::DisclosuresHash => 63,
            Self::InputValueAsset => 64,
            Self::OutputValueAsset => 65,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Policy(j) => j.name(),
            Self::InputAsset => "input_asset",
            Self::OutputAsset => "output_asset",
            Self::CurrentAsset => "current_asset",
            Self::FeeAsset => "fee_asset",
            Self::AssetTotalInputValue => "asset_total_input_value",
            Self::AssetTotalOutputValue => "asset_total_output_value",
            Self::AssetFee => "asset_fee",
            Self::AssetCurrentScriptDebit => "asset_current_script_debit",
            Self::DisclosuresHash => "disclosures_hash",
            Self::InputValueAsset => "input_value_asset",
            Self::OutputValueAsset => "output_value_asset",
        }
    }
    pub fn source_type(self) -> TypeName {
        TypeName(match self {
            Self::Policy(j) => return j.source_type(),
            Self::InputAsset
            | Self::OutputAsset
            | Self::InputValueAsset
            | Self::OutputValueAsset => b"i",
            Self::AssetTotalInputValue
            | Self::AssetTotalOutputValue
            | Self::AssetFee
            | Self::AssetCurrentScriptDebit => b"h",
            _ => b"1",
        })
    }
    pub fn target_type(self) -> TypeName {
        TypeName(match self {
            Self::Policy(j) => return j.target_type(),
            Self::InputAsset | Self::OutputAsset => b"+1h",
            Self::InputValueAsset | Self::OutputValueAsset => b"+1*hl",
            Self::AssetTotalInputValue
            | Self::AssetTotalOutputValue
            | Self::AssetFee
            | Self::AssetCurrentScriptDebit => b"l",
            _ => b"h",
        })
    }
    pub fn source_bits(self) -> usize {
        self.source_type().to_bit_width()
    }
    pub fn target_bits(self) -> usize {
        self.target_type().to_bit_width()
    }
    pub fn cmr(self) -> [u8; 32] {
        super::manifest::identity(self)
    }
    pub fn cost_milliweight(self) -> u32 {
        10_000
    }
}

impl fmt::Display for Builtin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
impl FromStr for Builtin {
    type Err = Error;
    fn from_str(name: &str) -> Result<Self, Error> {
        Self::all()
            .find(|j| j.name() == name)
            .ok_or_else(|| Error::Invalid(format!("unknown Liquid policy jet: {name}")))
    }
}

impl Context {
    pub fn evaluate(&self, jet: Builtin, src: &BitValue) -> Result<BitValue, Error> {
        use crate::Builtin::*;
        src.validate(jet.source_bits())?;
        let index = || src.uint(0, 32) as usize;
        let hash = BitValue::hash;
        let u32v = |v: u32| BitValue::word(v as u64, 32);
        let u64v = |v: u64| BitValue::word(v, 64);
        let asset_hash = |d: &super::Disclosure| hash(d.asset().to_byte_array());
        let script_hash = |o: &elements::TxOut| {
            hash(sha256::Hash::hash(o.script_pubkey.as_bytes()).to_byte_array())
        };
        let current = &self.tx.input[self.index];
        let asset = self.inputs[self.index].asset();
        let totals = &self.accounting[&asset];
        let requested_asset = || {
            elements::AssetId::from_byte_array(
                src.bytes.as_slice().try_into().expect("validated hash"),
            )
        };
        let outpoint = |i: &elements::TxIn| {
            hash(i.previous_output.txid.to_byte_array()).concat(&u32v(i.previous_output.vout))
        };
        let read_hash = || -> [u8; 32] { src.bytes.as_slice().try_into().expect("validated hash") };
        let same_asset_value = |d: &super::Disclosure| (d.asset() == asset).then(|| u64v(d.value));
        let result = match jet {
            Builtin::InputAsset => BitValue::option(self.inputs.get(index()).map(asset_hash), 256),
            Builtin::OutputAsset => {
                BitValue::option(self.outputs.get(index()).map(asset_hash), 256)
            }
            Builtin::CurrentAsset => asset_hash(&self.inputs[self.index]),
            Builtin::FeeAsset => hash(self.network.fee_asset().to_byte_array()),
            Builtin::DisclosuresHash => hash(self.disclosures_hash),
            Builtin::InputValueAsset => BitValue::option(
                self.inputs
                    .get(index())
                    .map(|d| asset_hash(d).concat(&u64v(d.value))),
                320,
            ),
            Builtin::OutputValueAsset => BitValue::option(
                self.outputs
                    .get(index())
                    .map(|d| asset_hash(d).concat(&u64v(d.value))),
                320,
            ),
            Builtin::AssetTotalInputValue
            | Builtin::AssetTotalOutputValue
            | Builtin::AssetFee
            | Builtin::AssetCurrentScriptDebit => {
                let a = self.accounting.get(&requested_asset());
                u64v(a.map_or(0, |a| match jet {
                    Builtin::AssetTotalInputValue => a.total_input_value,
                    Builtin::AssetTotalOutputValue => a.total_output_value,
                    Builtin::AssetFee => a.fee,
                    _ => a.debit,
                }))
            }
            Builtin::Policy(j) => match j {
                PolicyProfileHash => hash(profile_hash()),
                PolicyCmr => hash(self.cmr),
                SigningCommitmentHash => hash(super::signing_commitment(
                    self.cmr,
                    &self.data,
                    self.network,
                )?),
                RedeemScriptHash => hash(sha256::Hash::hash(&self.data).to_byte_array()),
                NetworkGenesisHash => hash(self.network.genesis_hash().to_byte_array()),
                CurrentIndex => u32v(self.index as u32),
                Version => u32v(self.tx.version),
                TxLockTime => u32v(self.tx.lock_time.to_consensus_u32()),
                NumInputs => u32v(self.inputs.len() as u32),
                NumOutputs => u32v(self.outputs.len() as u32),
                InputPrevOutpoint => {
                    BitValue::option(self.tx.input.get(index()).map(outpoint), 288)
                }
                InputValue => {
                    BitValue::option(self.inputs.get(index()).and_then(same_asset_value), 64)
                }
                OutputValue => {
                    BitValue::option(self.outputs.get(index()).and_then(same_asset_value), 64)
                }
                CurrentPrevOutpoint => outpoint(current),
                CurrentValue => u64v(self.inputs[self.index].value),
                InputScriptHash => {
                    BitValue::option(self.prevouts.get(index()).map(script_hash), 256)
                }
                CurrentScriptHash => script_hash(&self.prevouts[self.index]),
                OutputScriptHash => {
                    BitValue::option(self.tx.output.get(index()).map(script_hash), 256)
                }
                InputScriptSize => BitValue::option(
                    self.prevouts
                        .get(index())
                        .map(|o| u32v(o.script_pubkey.len() as u32)),
                    32,
                ),
                OutputScriptSize => BitValue::option(
                    self.tx
                        .output
                        .get(index())
                        .map(|o| u32v(o.script_pubkey.len() as u32)),
                    32,
                ),
                InputScriptByte | OutputScriptByte => {
                    let outputs = if j == InputScriptByte {
                        &self.prevouts
                    } else {
                        &self.tx.output
                    };
                    BitValue::option(
                        outputs
                            .get(index())
                            .and_then(|o| o.script_pubkey.as_bytes().get(src.uint(32, 32) as usize))
                            .map(|b| BitValue::word(*b as u64, 8)),
                        8,
                    )
                }
                InputSequence => {
                    BitValue::option(self.tx.input.get(index()).map(|i| u32v(i.sequence.0)), 32)
                }
                CurrentSequence => u32v(current.sequence.0),
                OutputScriptClass => BitValue::option(
                    self.tx.output.get(index()).map(|o| {
                        BitValue::word(
                            crate::context::script_class(crate::bitcoin::Script::from_bytes(
                                o.script_pubkey.as_bytes(),
                            )) as u64,
                            8,
                        )
                    }),
                    8,
                ),
                TotalInputValue => u64v(totals.total_input_value),
                TotalOutputValue => u64v(totals.total_output_value),
                TxFee => u64v(
                    self.accounting
                        .get(&self.network.fee_asset())
                        .map_or(0, |a| a.fee),
                ),
                ValueReturnedToCurrentScript => u64v(totals.returned_value),
                CurrentScriptDebit => u64v(totals.debit),
                InputValueForScript | OutputValueForScript | OutputCountForScript => {
                    let (outs, ds) = if j == InputValueForScript {
                        (&self.prevouts, &self.inputs)
                    } else {
                        (&self.tx.output, &self.outputs)
                    };
                    let wanted = read_hash();
                    let matching = outs.iter().zip(ds).filter(|(o, d)| {
                        d.asset() == asset
                            && sha256::Hash::hash(o.script_pubkey.as_bytes()).to_byte_array()
                                == wanted
                    });
                    if j == OutputCountForScript {
                        u32v(matching.count() as u32)
                    } else {
                        u64v(matching.map(|(_, d)| d.value).sum())
                    }
                }
                IsRbfSignaled => BitValue::word(
                    self.tx.input.iter().any(|i| i.sequence.0 < 0xffff_fffe) as u64,
                    1,
                ),
                HasEffectiveLockTime => BitValue::word(
                    (self.tx.lock_time.to_consensus_u32() != 0
                        && self.tx.input.iter().any(|i| i.sequence.0 != u32::MAX))
                        as u64,
                    1,
                ),
                InputLockBlocks | InputLockIntervals | CurrentLockBlocks | CurrentLockIntervals => {
                    let i = if matches!(j, CurrentLockBlocks | CurrentLockIntervals) {
                        self.index
                    } else {
                        index()
                    };
                    BitValue::option(
                        self.relative_lock(
                            i,
                            matches!(j, InputLockIntervals | CurrentLockIntervals),
                        )
                        .map(|v| BitValue::word(v as u64, 16)),
                        16,
                    )
                }
                CheckCsvBlocks | CheckCsvIntervals => {
                    require(
                        self.relative_lock(self.index, j == CheckCsvIntervals)
                            .is_some_and(|v| v as u64 >= src.uint(0, 16)),
                        "CSV check failed",
                    )?;
                    BitValue::unit()
                }
                CheckCltvHeight | CheckCltvTime => {
                    let requested = src.uint(0, 32) as u32;
                    let actual = self.tx.lock_time.to_consensus_u32();
                    require(
                        (requested >= 500_000_000) == (j == CheckCltvTime)
                            && (actual >= 500_000_000) == (j == CheckCltvTime)
                            && actual >= requested
                            && current.sequence.0 != u32::MAX,
                        "CLTV check failed",
                    )?;
                    BitValue::unit()
                }
                UnsignedTxHash => hash(self.tx_hash),
                PrevoutsHash => hash(self.prevouts_hash),
                TxInputsHash => hash(
                    sha256::Hash::hash(&elements::encode::serialize(&self.tx.input))
                        .to_byte_array(),
                ),
                TxOutputsHash => hash(
                    sha256::Hash::hash(&elements::encode::serialize(&self.tx.output))
                        .to_byte_array(),
                ),
                CooperativeLeafHash => hash(self.cooperative.leaf_hash.to_byte_array()),
                CooperativeSighashDefault => hash(self.sighash),
                CooperativeUserPubkey => hash(self.user.serialize()),
                CooperativeServicePubkey => hash(self.cooperative.service_pubkey.serialize()),
                RecoveryLeafHash => hash(self.recovery.to_byte_array()),
                PolicyApprovalHash => hash(self.approval),
                PolicyTransactionApprovalHash => hash(self.transaction_approval),
                TxVsizeLowerBound => u32v(self.vsize_lower_bound()),
            },
        };
        result.validate(jet.target_bits())?;
        Ok(result)
    }

    fn relative_lock(&self, index: usize, time: bool) -> Option<u16> {
        let seq = self.tx.input.get(index)?.sequence.0;
        (seq & 0x8000_0000 == 0 && (seq & 0x0040_0000 != 0) == time).then_some(seq as u16)
    }

    pub fn vsize_lower_bound(&self) -> u32 {
        let mut stripped = self.tx.clone();
        for o in &mut stripped.output {
            o.witness = Default::default();
        }
        for i in &mut stripped.input {
            i.witness = Default::default();
        }
        elements::encode::serialize(&stripped).len() as u32
    }
}
