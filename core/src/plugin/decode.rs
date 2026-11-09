//! Prefix tree over jet bit encodings.
//!
//! Built once at load from the base jets' encodings and the plugin's codes, so decoding never
//! needs to rewind the bit iterator and encoding conflicts are found while inserting.
use simplicity::{BitIter, decode};

/// Position of a node in `DecodeTrie::nodes`.
#[derive(Clone, Copy)]
struct NodeIdx(usize);

const ROOT: NodeIdx = NodeIdx(0);

#[derive(Default)]
struct Node {
    /// Next node after reading bit 0.
    zero: Option<NodeIdx>,
    /// Next node after reading bit 1.
    one: Option<NodeIdx>,
    jet: Option<usize>,
}

impl Node {
    fn child(&self, bit: bool) -> Option<NodeIdx> {
        if bit { self.one } else { self.zero }
    }

    fn child_mut(&mut self, bit: bool) -> &mut Option<NodeIdx> {
        if bit { &mut self.one } else { &mut self.zero }
    }
}

pub(crate) struct DecodeTrie {
    nodes: Vec<Node>,
}

impl DecodeTrie {
    pub(crate) fn new() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }

    fn node(&self, idx: NodeIdx) -> &Node {
        &self.nodes[idx.0]
    }

    fn node_mut(&mut self, idx: NodeIdx) -> &mut Node {
        &mut self.nodes[idx.0]
    }

    /// Inserts `jet` under `bits`. On conflict returns a jet whose encoding is a prefix of
    /// `bits` or has `bits` as a prefix.
    pub(crate) fn insert(
        &mut self,
        bits: impl IntoIterator<Item = bool>,
        jet: usize,
    ) -> Result<(), usize> {
        let mut node = ROOT;
        for bit in bits {
            if let Some(other) = self.node(node).jet {
                return Err(other);
            }
            node = match self.node(node).child(bit) {
                Some(child) => child,
                None => {
                    let child = NodeIdx(self.nodes.len());
                    self.nodes.push(Node::default());
                    *self.node_mut(node).child_mut(bit) = Some(child);
                    child
                }
            };
        }
        if let Some(other) = self.node(node).jet {
            return Err(other);
        }
        if let Some(other) = self.any_jet_below(node) {
            return Err(other);
        }
        self.node_mut(node).jet = Some(jet);
        Ok(())
    }

    fn any_jet_below(&self, node: NodeIdx) -> Option<usize> {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if let Some(jet) = self.node(node).jet {
                return Some(jet);
            }
            let node = self.node(node);
            stack.extend(node.zero);
            stack.extend(node.one);
        }
        None
    }

    /// Reads one jet encoding from `bits`.
    pub(crate) fn decode<I: Iterator<Item = u8>>(
        &self,
        bits: &mut BitIter<I>,
    ) -> Result<usize, decode::Error> {
        let mut node = ROOT;
        loop {
            if let Some(jet) = self.node(node).jet {
                return Ok(jet);
            }
            let bit = bits.next().ok_or(decode::Error::EndOfStream)?;
            node = self
                .node(node)
                .child(bit)
                .ok_or(decode::Error::InvalidJet)?;
        }
    }
}

/// The low `len` bits of `code`, most significant first.
pub(crate) fn code_bits(code: u64, len: u8) -> impl Iterator<Item = bool> {
    (0..len).rev().map(move |i| (code >> i) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_prefix_conflicts() {
        let mut trie = DecodeTrie::new();
        trie.insert(code_bits(0b10, 2), 0).unwrap();
        assert_eq!(trie.insert(code_bits(0b101, 3), 1), Err(0));
        assert_eq!(trie.insert(code_bits(0b1, 1), 2), Err(0));
        assert_eq!(trie.insert(code_bits(0b10, 2), 3), Err(0));
        trie.insert(code_bits(0b11, 2), 4).unwrap();
    }

    #[test]
    fn decodes_inserted_codes() {
        let mut trie = DecodeTrie::new();
        trie.insert(code_bits(0b0, 1), 0).unwrap();
        trie.insert(code_bits(0b10, 2), 1).unwrap();

        let bytes = [0b1000_0000];
        let mut bits = BitIter::from(&bytes[..]);
        assert_eq!(trie.decode(&mut bits).unwrap(), 1);
        assert_eq!(trie.decode(&mut bits).unwrap(), 0);
    }
}
