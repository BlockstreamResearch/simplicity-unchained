//! Helper functions for implementing CMR and `decode_bits!` macro tree.
use bitcoin_hashes::{Hash, HashEngine, sha256};
use quote::quote;

const SIMPLICITY_TAG_PREFIX: &[u8] = b"Simplicity\x1fCommitment\x1f";
const JETIV: sha256::Midstate = sha256::Midstate([
    0x95, 0x32, 0xee, 0x28, 0xcd, 0xca, 0x69, 0xde, 0xc8, 0xa0, 0xa2, 0x18, 0xb7, 0x9b, 0xe3, 0x62,
    0xf7, 0x40, 0xce, 0xaf, 0x64, 0x7f, 0x15, 0xb3, 0x8a, 0xed, 0x91, 0x68, 0x16, 0x3f, 0x92, 0x1b,
]);
/// Empty while issue with iterator inside decode is not resolved.
/// Prefix is hardcoded by tree
pub const ENCODE_PREFIX: &[u8] = &[];
pub type JetCodeBits = u32;
pub const JET_ENC_BITLEN: usize = 16 + 4; // + ENCODE_PREFIX.len();
// `Jet::encode` uses `write_bits_be` which is bounded to u64
const _: () = {
    let _ = 0 as JetCodeBits;
    if std::mem::size_of::<JetCodeBits>() > std::mem::size_of::<u64>() {
        panic!("JetCodeBits type should not exceed u64")
    }
};

// Warning: The CMRs generated here does not follow the proper Simplicity specification.
//
// TODO(ivanlele): Build valid Simplicity in Haskell from which we can extract the true CMRs.
// Taken from core::utils
#[allow(unused)]
pub fn cmr(name: &str) -> [u8; 32] {
    let name = SIMPLICITY_TAG_PREFIX
        .iter()
        .chain(name.as_bytes().iter())
        .copied()
        .collect::<Vec<u8>>();

    let right_state = sha256::Hash::hash(&name).as_byte_array().to_owned();

    let mut engine = sha256::HashEngine::from_midstate(JETIV, 0);
    engine.input(&right_state);

    right_state
}

/// Helper structure for converting jet bit encoding to `decode_bits!` macro input format
/// By construction ensures that token and left/right can not be Some() simultaneously
pub struct JetDecodeTree {
    left: Option<Box<JetDecodeTree>>,
    right: Option<Box<JetDecodeTree>>,
    token: Option<proc_macro2::Ident>,
}

// Stores bit pattern starting from most significant bit to be able to input patterns in BE order i.e.
// 0b111 ->
// 0 => {}
// 1 => {
//     0 => {}
//     1 => {
//         0 => {}
//         1 => {
//            Ident
//         }
//     }
// }
#[derive(Clone)]
pub struct JetBranchCode {
    pub bits: JetCodeBits,
    pub len: usize,
    pub token: proc_macro2::Ident,
}

impl JetBranchCode {
    /// Hashes identifier string and takes `JET_ENC_BITLEN - ENCODE_PREFIX.len()` bits of that hash
    /// as jet's encoding alongside with `ENCODE_PREFIX`
    pub fn from_ident_fixed(token: proc_macro2::Ident) -> Self {
        let mut bits = 0 as JetCodeBits;
        let mut cursor = 1 << (JET_ENC_BITLEN - 1 - 4);

        for &bit in ENCODE_PREFIX {
            if bit == 1 {
                bits |= cursor;
            }
            cursor >>= 1;
        }

        let mut token_branch = [0; std::mem::size_of::<JetCodeBits>()];
        token_branch.copy_from_slice(
            &sha256::Hash::hash(token.to_string().as_bytes()).to_byte_array()
                [0..std::mem::size_of::<JetCodeBits>()],
        );
        let mut token_bits = JetCodeBits::from_le_bytes(token_branch);

        // -4 because prefix is empty. remove when issue resolved
        for _ in 0..(JET_ENC_BITLEN - ENCODE_PREFIX.len() - 4) {
            if token_bits & 1 == 1 {
                bits |= cursor;
            }
            cursor >>= 1;
            token_bits >>= 1;
        }

        Self {
            bits,
            len: JET_ENC_BITLEN - 4, // -4 because prefix is empty. remove when issue resolved
            token,
        }
    }
}

impl JetDecodeTree {
    fn new() -> Self {
        Self {
            left: None,
            right: None,
            token: None,
        }
    }
    /// Constructs `JetDecodeTree` from branches.
    /// ## Panics
    /// Panics if some branches bit patterns collide or some bit pattern is prefix of another
    pub fn from_branches(branches: Vec<JetBranchCode>) -> Self {
        // check for pattern collision
        for i in 0..branches.len() {
            for j in (i + 1)..branches.len() {
                assert!(
                    branches[i].bits != branches[j].bits,
                    "Idents {}, {} collide",
                    branches[i].token,
                    branches[j].token
                )
            }
        }

        let mut res = Self::new();

        for JetBranchCode { bits, len, token } in branches {
            let mut curr = &mut res;
            let mut cursor = 1 << (len - 1);

            for _ in 0..len {
                if curr.token.is_some() {
                    panic!(
                        "Existing branch is a prefix of the new branch {:b} being added",
                        bits
                    );
                }
                let bit = (bits & cursor) != 0;

                match bit {
                    false => {
                        if curr.left.is_none() {
                            curr.left = Some(Box::new(JetDecodeTree::new()));
                        }
                        curr = curr.left.as_mut().expect("Visited branch cannot be empty");
                    }
                    true => {
                        if curr.right.is_none() {
                            curr.right = Some(Box::new(JetDecodeTree::new()));
                        }
                        curr = curr.right.as_mut().expect("Visited branch cannot be empty");
                    }
                }
                cursor >>= 1;
            }

            if curr.left.is_some() || curr.right.is_some() {
                panic!("{:b} branch is prefix of some other branch", bits);
            }
            curr.token = Some(token)
        }

        res
    }
}

impl From<JetDecodeTree> for proc_macro2::TokenStream {
    fn from(value: JetDecodeTree) -> Self {
        let (left_branch, right_branch, token) = (value.left, value.right, value.token);

        let (left, right, val) = match (left_branch, right_branch, token) {
            (Some(left_branch), Some(right_branch), _) => {
                (Self::from(*left_branch), Self::from(*right_branch), None)
            }
            (Some(left_branch), None, _) => (Self::from(*left_branch), quote! {}, None),
            (None, Some(right_branch), _) => (quote! {}, Self::from(*right_branch), None),
            (None, None, Some(ident)) => (quote! {}, quote! {}, Some(ident)),
            _ => unreachable!("Non null ident implifies null left/right branches by construction"),
        };

        if let Some(ident) = val {
            return quote! {Self::#ident};
        }
        quote! {
            0 => {
                #left
            },
            1 => {
                #right
            }
        }
    }
}

pub fn snake_to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}
pub fn pascal_to_snake_case(s: &str) -> String {
    let mut snake = String::new();
    let chars = s.chars().collect::<Vec<_>>();

    chars.windows(2).for_each(|pair| {
        if let [curr, next] = pair {
            snake.extend(pair[0].to_lowercase());
            if curr.is_lowercase() && !next.is_lowercase() {
                snake.push('_');
            }
        }
    });

    if let Some(c) = chars.last() {
        snake.extend(c.to_lowercase());
    }

    snake
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_pascal_case() {
        let snake = "valid_str";
        let single = "single";
        let empty = "";

        assert_eq!(snake_to_pascal_case(snake), "ValidStr");
        assert_eq!(snake_to_pascal_case(single), "Single");
        assert_eq!(snake_to_pascal_case(empty), "");
    }

    #[test]
    fn test_to_snake_case() {
        let pascal = "PascalCase";
        let single = "Single";
        let acronym = "PAScalCase";
        let empty = "";

        assert_eq!(pascal_to_snake_case(pascal), "pascal_case");
        assert_eq!(pascal_to_snake_case(single), "single");
        assert_eq!(pascal_to_snake_case(acronym), "pascal_case");
        assert_eq!(pascal_to_snake_case(empty), "");
    }

    fn format_arms(ts: proc_macro2::TokenStream) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut indent = 0usize;
        let mut line: Vec<&str> = Vec::new();

        let s = ts.to_string();

        let flush = |line: &mut Vec<&str>, indent: usize, lines: &mut Vec<String>| {
            if !line.is_empty() {
                lines.push(format!("{}{}", "    ".repeat(indent), line.join(" ")));
                line.clear();
            }
        };

        for token in s.split_whitespace() {
            match token {
                "{" => {
                    line.push("{");
                    flush(&mut line, indent, &mut lines);
                    indent += 1;
                }
                "}" => {
                    flush(&mut line, indent, &mut lines);
                    indent = indent.saturating_sub(1);
                    lines.push(format!("{}}}", "    ".repeat(indent)));
                }
                "," => {
                    flush(&mut line, indent, &mut lines);
                }
                t => line.push(t),
            }
        }

        flush(&mut line, indent, &mut lines);
        lines.join("\n")
    }

    #[test]
    fn test_decode_tree() {
        let branches = vec![
            JetBranchCode::from_ident_fixed(quote::format_ident!("CustomJet1")),
            JetBranchCode::from_ident_fixed(quote::format_ident!("CustomJet2")),
        ];
        println!("jet1 bits {:b} {}", branches[0].bits, branches[0].bits);

        let tree = JetDecodeTree::from_branches(branches);
        let tree_tokens: proc_macro2::TokenStream = tree.into();

        let formatted = format_arms(tree_tokens);

        println!("{}", formatted);
    }
}
