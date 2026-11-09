use std::marker::PhantomData;
use std::sync::Arc;

use simplicity::base64::prelude::{BASE64_STANDARD, Engine as _};
use simplicity::jet::Jet;
use simplicity::{BitIter, Cmr, CommitNode, ParseError, RedeemNode};

/// A Simplicity program decoded with jets of type `J`.
///
/// Port of `hal_simplicity::Program`.
pub struct Program<J: Jet> {
    commit_prog: Arc<CommitNode>,
    redeem_prog: Option<Arc<RedeemNode>>,
    _jet: PhantomData<fn() -> J>,
}

impl<J: Jet> Program<J> {
    /// Decodes a program and an optional witness, each given as hex or base64.
    pub fn from_str(prog: &str, witness: Option<&str>) -> Result<Self, ParseError> {
        let prog_bytes = hex_or_base64(prog)?;
        let commit_prog = CommitNode::decode::<_, J>(BitIter::new(prog_bytes.iter().copied()))
            .map_err(ParseError::Decode)?;

        let redeem_prog = witness
            .map(|witness| {
                let wit_bytes = hex_or_base64(witness)?;
                RedeemNode::decode::<_, _, J>(
                    BitIter::new(prog_bytes.into_iter()),
                    BitIter::new(wit_bytes.into_iter()),
                )
                .map_err(ParseError::Decode)
            })
            .transpose()?;

        Ok(Self {
            commit_prog,
            redeem_prog,
            _jet: PhantomData,
        })
    }

    /// The CMR of the program.
    pub fn cmr(&self) -> Cmr {
        self.commit_prog.cmr()
    }

    /// The commitment-time program.
    pub fn commit_prog(&self) -> &CommitNode {
        &self.commit_prog
    }

    /// The redemption-time program, if a witness was given.
    pub fn redeem_node(&self) -> Option<&Arc<RedeemNode>> {
        self.redeem_prog.as_ref()
    }
}

/// Same detection as `hal_simplicity::hex_or_base64`, kept so that existing inputs decode to the
/// same programs: hex only when every char is a lowercase hex letter, base64 otherwise.
fn hex_or_base64(s: &str) -> Result<Vec<u8>, ParseError> {
    if s.len().is_multiple_of(2)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && b.is_ascii_lowercase())
    {
        simplicity::hex::decode_to_vec(s).map_err(ParseError::Hex)
    } else {
        BASE64_STANDARD.decode(s).map_err(ParseError::Base64)
    }
}
