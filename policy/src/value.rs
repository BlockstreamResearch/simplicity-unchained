use crate::Error;

/// A canonical Simplicity frame, packed most-significant bit first.
///
/// The byte length is exactly `ceil(bit_len/8)`; unused low bits of the final byte
/// are zero. Products concatenate. Sums contain a tag, left padding to the wider
/// branch, then the active value. Thus `Either<(), T>` is `0 || zeroes` or `1 || T`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitValue {
    pub bytes: Vec<u8>,
    pub bit_len: usize,
}

impl BitValue {
    pub fn unit() -> Self {
        Self::default()
    }

    pub fn from_bytes(bytes: Vec<u8>, bit_len: usize) -> Result<Self, Error> {
        let value = Self { bytes, bit_len };
        value.validate(bit_len)?;
        Ok(value)
    }

    pub fn validate(&self, expected: usize) -> Result<(), Error> {
        if self.bit_len != expected
            || self.bytes.len() != expected.div_ceil(8)
            || (!expected.is_multiple_of(8)
                && self
                    .bytes
                    .last()
                    .is_some_and(|last| last & ((1u8 << (8 - expected % 8)) - 1) != 0))
        {
            return Err(Error::SourceShape { expected });
        }
        Ok(())
    }

    pub fn bit(&self, index: usize) -> Option<bool> {
        (index < self.bit_len).then(|| self.bytes[index / 8] >> (7 - index % 8) & 1 != 0)
    }

    pub(crate) fn zero(bits: usize) -> Self {
        Self {
            bytes: vec![0; bits.div_ceil(8)],
            bit_len: bits,
        }
    }

    pub(crate) fn word(value: u64, bits: usize) -> Self {
        let mut result = Self::zero(bits);
        for i in 0..bits {
            result.set(i, value >> (bits - 1 - i) & 1 != 0);
        }
        result
    }

    pub(crate) fn hash(value: [u8; 32]) -> Self {
        Self {
            bytes: value.to_vec(),
            bit_len: 256,
        }
    }

    pub(crate) fn set(&mut self, index: usize, bit: bool) {
        if bit {
            self.bytes[index / 8] |= 1 << (7 - index % 8);
        }
    }

    pub(crate) fn uint(&self, offset: usize, bits: usize) -> u64 {
        (offset..offset + bits).fold(0, |value, index| {
            value << 1 | u64::from(self.bit(index).unwrap())
        })
    }

    pub(crate) fn concat(&self, other: &Self) -> Self {
        let mut result = Self::zero(self.bit_len + other.bit_len);
        for (start, value) in [(0, self), (self.bit_len, other)] {
            for i in 0..value.bit_len {
                result.set(start + i, value.bit(i).unwrap());
            }
        }
        result
    }

    pub(crate) fn option(value: Option<Self>, bits: usize) -> Self {
        match value {
            Some(value) => {
                debug_assert_eq!(value.bit_len, bits);
                Self::word(1, 1).concat(&value)
            }
            None => Self::zero(1 + bits),
        }
    }
}
