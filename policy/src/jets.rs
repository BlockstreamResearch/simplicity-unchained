use std::{fmt, str::FromStr};

use simplicity::jet::type_name::TypeName;

use crate::{BitValue, Context, Error, profile_hash};

macro_rules! catalogue {
    ($( $variant:ident, $name:literal, $source:literal, $target:literal, $contract:literal; )*) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum Builtin { $( $variant, )* }

        impl Builtin {
            pub const ALL: [Self; 55] = [$( Self::$variant, )*];

            pub fn from_id(id: u8) -> Option<Self> {
                Self::ALL.get(usize::from(id)).copied()
            }

            pub const fn id(self) -> u8 { self as u8 }

            pub const fn name(self) -> &'static str {
                match self { $( Self::$variant => $name, )* }
            }

            pub const fn source_type(self) -> TypeName {
                TypeName(match self { $( Self::$variant => $source, )* })
            }

            pub const fn target_type(self) -> TypeName {
                TypeName(match self { $( Self::$variant => $target, )* })
            }

            pub const fn semantic_contract(self) -> &'static str {
                match self { $( Self::$variant => $contract, )* }
            }
        }
    };
}

catalogue! {
    PolicyProfileHash, "policy_profile_hash", b"1", b"h",
        "Return the single-SHA256 fingerprint of the ordered canonical manifest body, excluding only its profile_hash field. No jet identity includes this resulting hash, avoiding circular hashing.";
    PolicyCmr, "policy_cmr", b"1", b"h",
        "Return the 32-byte CMR of the exact policy program being evaluated, supplied before context reconstruction.";
    SigningCommitmentHash, "signing_commitment_hash", b"1", b"h",
        "Return TaggedHash('SimplicityUnchained/PolicySigningCommitment/v1', profile_hash || configured genesis_hash || program_cmr || SHA256(exact script_data)). All four fields are 32 bytes.";
    RedeemScriptHash, "redeem_script_hash", b"1", b"h",
        "Return single SHA256 of exact script_data bytes, including an empty script. This does not claim that script_data is the hidden recovery script.";
    NetworkGenesisHash, "network_genesis_hash", b"1", b"h",
        "Return the configured Bitcoin/Testnet/Testnet4 genesis block hash using Hash::to_byte_array, never explorer-display byte reversal. No caller network label or chain state is read.";
    CurrentIndex, "current_index", b"1", b"i",
        "Return the validated zero-based input index being authorized as a big-endian unsigned 32-bit word.";
    Version, "version", b"1", b"i",
        "Return the transaction version's raw 32-bit bits, big-endian. Context construction requires version exactly 2.";
    TxLockTime, "tx_lock_time", b"1", b"i",
        "Return raw transaction nLockTime as a big-endian unsigned 32-bit word. This is not the current time or height.";
    NumInputs, "num_inputs", b"1", b"i",
        "Return the actual transaction input count, never a truncated or padded count. Valid contexts have 1..=8.";
    NumOutputs, "num_outputs", b"1", b"i",
        "Return the actual transaction output count, never a truncated or padded count. Valid contexts have 1..=8.";
    InputPrevOutpoint, "input_prev_outpoint", b"i", b"+1*hi",
        "For an in-range zero-based input index return Some(parent txid Hash::to_byte_array || vout:u32 big-endian); otherwise None. The hash is not explorer-display hex order.";
    InputValue, "input_value", b"i", b"+1l",
        "Return Some(content-verified parent TxOut value in integer satoshis) at an in-range input index; otherwise None. Required parent/witness proof absence is a construction error.";
    InputScriptHash, "input_script_hash", b"i", b"+1h",
        "Return Some(single SHA256 of the verified parent's raw scriptPubKey) at an in-range input index; otherwise None.";
    InputScriptSize, "input_script_size", b"i", b"+1i",
        "Return Some(verified parent scriptPubKey byte length as u32) at an in-range input index; otherwise None.";
    InputScriptByte, "input_script_byte", b"*ii", b"+1c",
        "Read (input_index:u32, byte_offset:u32). Return Some(raw verified parent scriptPubKey byte), including pushed data, or None if either index is out of bounds. This is not an instruction parser.";
    InputSequence, "input_sequence", b"i", b"+1i",
        "Return Some(raw nSequence:u32 including all flags) at an in-range input index; otherwise None.";
    CurrentPrevOutpoint, "current_prev_outpoint", b"1", b"*hi",
        "Return input_prev_outpoint at the validated current input index without an option tag. It is an error to construct a missing current input.";
    CurrentValue, "current_value", b"1", b"l",
        "Return input_value at the validated current input index without an option tag.";
    CurrentScriptHash, "current_script_hash", b"1", b"h",
        "Return input_script_hash at the validated current input index without an option tag.";
    CurrentSequence, "current_sequence", b"1", b"i",
        "Return input_sequence at the validated current input index without an option tag.";
    OutputValue, "output_value", b"i", b"+1l",
        "Return Some(output value in integer satoshis) at an in-range output index; otherwise None.";
    OutputScriptHash, "output_script_hash", b"i", b"+1h",
        "Return Some(single SHA256 of raw output scriptPubKey) at an in-range output index; otherwise None.";
    OutputScriptSize, "output_script_size", b"i", b"+1i",
        "Return Some(output scriptPubKey byte length as u32) at an in-range output index; otherwise None.";
    OutputScriptByte, "output_script_byte", b"*ii", b"+1c",
        "Read (output_index:u32, byte_offset:u32). Return Some(raw scriptPubKey byte), including pushed data, or None if either index is out of bounds. This is not an instruction parser.";
    OutputScriptClass, "output_script_class", b"i", b"+1c",
        "Return Some(u8 class) at an in-range output index, else None. Exact standard byte patterns: Other=0; P2PKH=1 (76 a9 14 [20] 88 ac); P2SH=2 (a9 14 [20] 87); P2WPKH=3 (00 14 [20]); P2WSH=4 (00 20 [32]); P2TR=5 (51 20 [32]); leading 6a OP_RETURN=6. Unknown witness versions/program lengths are Other. Classes do not establish spendability.";
    TotalInputValue, "total_input_value", b"1", b"l",
        "Return the checked sum of all content-verified input values. Individual values and the total must be within 0..=2100000000000000 satoshis.";
    TotalOutputValue, "total_output_value", b"1", b"l",
        "Return the checked sum of all output values. Individual values and the total must be within 0..=2100000000000000 satoshis.";
    TxFee, "tx_fee", b"1", b"l",
        "Return checked total_input_value minus total_output_value, in satoshis. Overspend is a context-construction error, never a wrapped or clamped fee.";
    InputValueForScript, "input_value_for_script", b"h", b"l",
        "Return the checked sum of verified input values whose raw scriptPubKey single-SHA256 equals the supplied 256-bit hash. Scan at most 8 inputs. No matches returns zero.";
    OutputValueForScript, "output_value_for_script", b"h", b"l",
        "Return the checked sum of output values whose raw scriptPubKey single-SHA256 equals the supplied 256-bit hash. Scan at most 8 outputs. No matches returns zero.";
    OutputCountForScript, "output_count_for_script", b"h", b"i",
        "Return the number of outputs whose raw scriptPubKey single-SHA256 equals the supplied 256-bit hash, as u32. Scan at most 8 outputs. No matches returns zero.";
    ValueReturnedToCurrentScript, "value_returned_to_current_script", b"1", b"l",
        "Return the checked sum of outputs with exact byte-for-byte scriptPubKey equality to the current verified prevout. Never use change labels, PSBT metadata, or hash equality as an ownership assertion.";
    CurrentScriptDebit, "current_script_debit", b"1", b"l",
        "Return checked sum of ALL funding inputs with the current exact script minus value_returned_to_current_script, including fees. All funding inputs must spend this same reconstructed output. This is not current_value minus change and is not mixed-wallet accounting.";
    IsRbfSignaled, "is_rbf_signaled", b"1", b"2",
        "Return one actual bit, true iff any input nSequence is strictly below 0xfffffffe. This reports explicit BIP-125 signaling only, not mempool replacement acceptance.";
    HasEffectiveLockTime, "has_effective_lock_time", b"1", b"2",
        "Return one actual bit, true iff raw nLockTime is nonzero and at least one input nSequence differs from 0xffffffff. This is not a current-input CLTV check or a maturity proof.";
    InputLockBlocks, "input_lock_blocks", b"i", b"+1s",
        "For an in-range input, return Some(nSequence & 0x0000ffff) iff transaction version >=2, disable bit0x80000000 is unset and type bit0x00400000 is unset; otherwise None, including out-of-range. Unrelated reserved sequence bits are ignored.";
    InputLockIntervals, "input_lock_intervals", b"i", b"+1s",
        "For an in-range input, return Some(nSequence & 0x0000ffff) iff transaction version >=2, disable bit0x80000000 is unset and type bit0x00400000 is set; otherwise None, including out-of-range. Units are 512-second intervals. Reserved bits are ignored.";
    CurrentLockBlocks, "current_lock_blocks", b"1", b"+1s",
        "Return input_lock_blocks at the validated current index, with the same None behavior for disabled or wrong-unit relative locks.";
    CurrentLockIntervals, "current_lock_intervals", b"1", b"+1s",
        "Return input_lock_intervals at the validated current index, with the same None behavior for disabled or wrong-unit relative locks.";
    CheckCsvBlocks, "check_csv_blocks", b"s", b"1",
        "Succeed with unit iff current input has an enabled version>=2 block-relative sequence and (nSequence & 0xffff) >= requested u16 block delay. Otherwise explicitly fail. Disable flag fails even for requested zero; time units fail. Does not prove maturity.";
    CheckCsvIntervals, "check_csv_intervals", b"s", b"1",
        "Succeed with unit iff current input has an enabled version>=2 time-relative sequence and (nSequence & 0xffff) >= requested u16 512-second delay. Otherwise explicitly fail. Disable flag fails even for requested zero; block units fail. Does not prove maturity.";
    CheckCltvHeight, "check_cltv_height", b"i", b"1",
        "Succeed with unit iff requested u32 <500000000, transaction nLockTime <500000000 and >=request, and CURRENT input nSequence !=0xffffffff. Otherwise explicitly fail. Other nonfinal inputs do not satisfy the current-input condition. No live height is read.";
    CheckCltvTime, "check_cltv_time", b"i", b"1",
        "Succeed with unit iff requested u32 >=500000000, transaction nLockTime >=500000000 and >=request, and CURRENT input nSequence !=0xffffffff. Otherwise explicitly fail. No live time is read.";
    UnsignedTxHash, "unsigned_tx_hash", b"1", b"h",
        "Return single SHA256 of Bitcoin consensus encoding: version:i32 little-endian || CompactSize(input_count) || each outpoint(txid Hash::to_byte_array,vout:u32 little-endian), empty scriptSig CompactSize0, sequence:u32 little-endian || CompactSize(output_count) || each value:u64 little-endian, CompactSize(script length), raw scriptPubKey || nLockTime:u32 little-endian. No segwit marker, flag, or witnesses.";
    PrevoutsHash, "prevouts_hash", b"1", b"h",
        "Return single SHA256 of consensus-encoded TxOut vector in input order: CompactSize(input_count) || each verified value:u64 little-endian, CompactSize(script length), raw scriptPubKey. This is not a BIP-341 component hash.";
    TxInputsHash, "tx_inputs_hash", b"1", b"h",
        "Return single SHA256 of consensus-encoded unsigned input vector: CompactSize(input_count) || each txid Hash::to_byte_array, vout:u32 little-endian, CompactSize0 empty scriptSig, sequence:u32 little-endian. No witness/marker/flag. This is not BIP-341 sha_prevouts/sha_sequences.";
    TxOutputsHash, "tx_outputs_hash", b"1", b"h",
        "Return single SHA256 of consensus-encoded output vector: CompactSize(output_count) || each value:u64 little-endian, CompactSize(script length), raw scriptPubKey. The count is included, unlike BIP-341 sha_outputs.";
    CooperativeLeafHash, "cooperative_leaf_hash", b"1", b"h",
        "Return actual BIP-341 TapLeafHash of canonical tapscript <profile-tweaked service xonly32> CHECKSIG <validated user xonly32> CHECKSIGADD 2 EQUAL, with leaf version0xc0. Not a dummy Simplicity execution leaf.";
    CooperativeSighashDefault, "cooperative_sighash_default", b"1", b"h",
        "Return actual BIP-341 script-path SIGHASH_DEFAULT for the selected input, unsigned transaction, ALL parent-verified prevouts and canonical cooperative leaf. No annex; code-separator position0xffffffff; key version0. This exact digest is signed after policy success.";
    CooperativeUserPubkey, "cooperative_user_pubkey", b"1", b"h",
        "Return the validated 32-byte x-only user public key embedded in the reconstructed cooperative leaf.";
    CooperativeServicePubkey, "cooperative_service_pubkey", b"1", b"h",
        "Return the profile-tweaked 32-byte x-only service public key embedded in the reconstructed cooperative leaf. No secret key is present in the context or a jet.";
    RecoveryLeafHash, "recovery_leaf_hash", b"1", b"h",
        "Return the supplied 32-byte hidden recovery TapNodeHash, authenticated by reconstructing the two-depth1-leaf tree and requiring ALL funding scriptPubKeys to equal that output. It does not reveal the recovery script.";
    PolicyApprovalHash, "policy_approval_hash", b"1", b"h",
        "Return TaggedHash('SimplicityUnchained/PolicyInputApproval/v1', policy_transaction_approval_hash || input_index:u32 big-endian || cooperative_sighash_default). Fields are32+4+32 bytes. Excludes approval signatures; differs across inputs.";
    PolicyTransactionApprovalHash, "policy_transaction_approval_hash", b"1", b"h",
        "Return TaggedHash('SimplicityUnchained/PolicyTransactionApproval/v1', profile_hash || genesis_hash || signing_commitment_hash || unsigned_tx_hash || prevouts_hash || cooperative_leaf_hash || recovery_leaf_hash), seven32-byte fields in that order. Excludes input index and approval signatures; deliberately reusable across same-contract inputs of this exact transaction.";
    TxVsizeLowerBound, "tx_vsize_lower_bound", b"1", b"i",
        "Return stripped unsigned transaction consensus byte length as u32. This is a conservative lower bound on final virtual size, not an upper estimate or final fee rate. A conservative rate cap uses checked fee <= rate*lower_bound.";
}

impl Builtin {
    pub fn source_bits(self) -> usize {
        self.source_type().to_bit_width()
    }

    pub fn target_bits(self) -> usize {
        self.target_type().to_bit_width()
    }

    pub fn cmr(self) -> [u8; 32] {
        crate::manifest::builtin_identity(self)
    }

    pub const fn cost_milliweight(self) -> u32 {
        10_000
    }

    pub fn encoding(self) -> String {
        format!("1{:06b}", self.id())
    }
}

impl fmt::Display for Builtin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Builtin {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|jet| jet.name() == name)
            .ok_or_else(|| Error::UnknownJet(name.to_owned()))
    }
}

impl Context {
    /// Evaluate a pure policy extension on the immutable validated context.
    pub fn evaluate(&self, jet: Builtin, source: &BitValue) -> Result<BitValue, Error> {
        use Builtin::*;
        source.validate(jet.source_bits())?;
        let index = || source.uint(0, 32) as usize;
        let offset = || source.uint(32, 32) as usize;
        let word32 = |value: u32| BitValue::word(u64::from(value), 32);
        let word64 = |value: u64| BitValue::word(value, 64);
        let hash = BitValue::hash;
        let input = || self.tx().input.get(index());
        let prevout = || self.prevouts().get(index());
        let output = || self.tx().output.get(index());
        let outpoint = |input: &simplicity::bitcoin::TxIn| {
            use simplicity::bitcoin::hashes::Hash;
            hash(input.previous_output.txid.to_byte_array())
                .concat(&word32(input.previous_output.vout))
        };
        let current = &self.tx().input[self.input_index()];
        let read_hash = || {
            source
                .bytes
                .as_slice()
                .try_into()
                .expect("validated 256-bit frame")
        };
        let check = |success| {
            if success {
                Ok(BitValue::unit())
            } else {
                Err(Error::CheckFailed)
            }
        };
        let result = match jet {
            PolicyProfileHash => hash(profile_hash()),
            PolicyCmr => hash(self.cmr()),
            SigningCommitmentHash => hash(self.signing_commitment()),
            RedeemScriptHash => hash(self.script_data_hash),
            NetworkGenesisHash => hash(self.genesis_hash),
            CurrentIndex => word32(self.input_index() as u32),
            Version => word32(self.tx().version.0 as u32),
            TxLockTime => word32(self.tx().lock_time.to_consensus_u32()),
            NumInputs => word32(self.tx().input.len() as u32),
            NumOutputs => word32(self.tx().output.len() as u32),
            InputPrevOutpoint => BitValue::option(input().map(outpoint), 288),
            InputValue => BitValue::option(prevout().map(|o| word64(o.value.to_sat())), 64),
            InputScriptHash => BitValue::option(
                self.input_script_hashes.get(index()).copied().map(hash),
                256,
            ),
            InputScriptSize => {
                BitValue::option(prevout().map(|o| word32(o.script_pubkey.len() as u32)), 32)
            }
            InputScriptByte => BitValue::option(
                prevout()
                    .and_then(|o| o.script_pubkey.as_bytes().get(offset()))
                    .map(|&b| BitValue::word(u64::from(b), 8)),
                8,
            ),
            InputSequence => BitValue::option(input().map(|i| word32(i.sequence.0)), 32),
            CurrentPrevOutpoint => outpoint(current),
            CurrentValue => word64(self.prevouts()[self.input_index()].value.to_sat()),
            CurrentScriptHash => hash(self.input_script_hashes[self.input_index()]),
            CurrentSequence => word32(current.sequence.0),
            OutputValue => BitValue::option(output().map(|o| word64(o.value.to_sat())), 64),
            OutputScriptHash => BitValue::option(
                self.output_script_hashes.get(index()).copied().map(hash),
                256,
            ),
            OutputScriptSize => {
                BitValue::option(output().map(|o| word32(o.script_pubkey.len() as u32)), 32)
            }
            OutputScriptByte => BitValue::option(
                output()
                    .and_then(|o| o.script_pubkey.as_bytes().get(offset()))
                    .map(|&b| BitValue::word(u64::from(b), 8)),
                8,
            ),
            OutputScriptClass => BitValue::option(
                output().map(|o| {
                    BitValue::word(u64::from(crate::context::script_class(&o.script_pubkey)), 8)
                }),
                8,
            ),
            TotalInputValue => word64(self.total_input_value),
            TotalOutputValue => word64(self.total_output_value),
            TxFee => word64(self.fee),
            InputValueForScript => word64(self.value_for_script(true, read_hash())?),
            OutputValueForScript => word64(self.value_for_script(false, read_hash())?),
            OutputCountForScript => {
                let wanted = read_hash();
                word32(
                    self.output_script_hashes
                        .iter()
                        .filter(|&&h| h == wanted)
                        .count() as u32,
                )
            }
            ValueReturnedToCurrentScript => word64(self.returned_value),
            CurrentScriptDebit => word64(self.debit),
            IsRbfSignaled => BitValue::word(
                u64::from(self.tx().input.iter().any(|i| i.sequence.0 < 0xffff_fffe)),
                1,
            ),
            HasEffectiveLockTime => BitValue::word(
                u64::from(
                    self.tx().lock_time.to_consensus_u32() != 0
                        && self.tx().input.iter().any(|i| i.sequence.0 != u32::MAX),
                ),
                1,
            ),
            InputLockBlocks | InputLockIntervals => BitValue::option(
                self.relative_lock(index(), jet == InputLockIntervals)
                    .map(|v| BitValue::word(u64::from(v), 16)),
                16,
            ),
            CurrentLockBlocks | CurrentLockIntervals => BitValue::option(
                self.relative_lock(self.input_index(), jet == CurrentLockIntervals)
                    .map(|v| BitValue::word(u64::from(v), 16)),
                16,
            ),
            CheckCsvBlocks | CheckCsvIntervals => {
                return check(
                    self.relative_lock(self.input_index(), jet == CheckCsvIntervals)
                        .is_some_and(|delay| u64::from(delay) >= source.uint(0, 16)),
                );
            }
            CheckCltvHeight | CheckCltvTime => {
                let requested = source.uint(0, 32) as u32;
                let actual = self.tx().lock_time.to_consensus_u32();
                let time_units = jet == CheckCltvTime;
                return check(
                    (requested >= 500_000_000) == time_units
                        && (actual >= 500_000_000) == time_units
                        && actual >= requested
                        && current.sequence.0 != u32::MAX,
                );
            }
            UnsignedTxHash => hash(self.unsigned_tx_hash),
            PrevoutsHash => hash(self.prevouts_hash),
            TxInputsHash => hash(self.tx_inputs_hash),
            TxOutputsHash => hash(self.tx_outputs_hash),
            CooperativeLeafHash => {
                use simplicity::bitcoin::hashes::Hash;
                hash(self.cooperative_leaf_hash().to_byte_array())
            }
            CooperativeSighashDefault => hash(self.cooperative_sighash_default()),
            CooperativeUserPubkey => hash(self.user_pubkey().serialize()),
            CooperativeServicePubkey => hash(self.service_pubkey().serialize()),
            RecoveryLeafHash => {
                use simplicity::bitcoin::hashes::Hash;
                hash(self.recovery_hash.to_byte_array())
            }
            PolicyApprovalHash => hash(self.policy_approval_hash()),
            PolicyTransactionApprovalHash => hash(self.policy_transaction_approval_hash()),
            TxVsizeLowerBound => word32(self.vsize_lower_bound),
        };
        debug_assert_eq!(result.bit_len, jet.target_bits());
        Ok(result)
    }

    fn relative_lock(&self, index: usize, time_units: bool) -> Option<u16> {
        let seq = self.tx().input.get(index)?.sequence.0;
        (self.tx().version.0 >= 2
            && seq & 0x8000_0000 == 0
            && (seq & 0x0040_0000 != 0) == time_units)
            .then_some((seq & 0xffff) as u16)
    }

    fn value_for_script(&self, inputs: bool, wanted: [u8; 32]) -> Result<u64, Error> {
        let (hashes, outputs) = if inputs {
            (&self.input_script_hashes, self.prevouts())
        } else {
            (&self.output_script_hashes, self.tx().output.as_slice())
        };
        hashes
            .iter()
            .zip(outputs)
            .try_fold(0u64, |sum, (hash, output)| {
                if hash == &wanted {
                    sum.checked_add(output.value.to_sat())
                        .ok_or(Error::Arithmetic)
                } else {
                    Ok(sum)
                }
            })
    }
}
