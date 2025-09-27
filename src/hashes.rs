// SPDX-License-Identifier: LGPL-3.0-or-later

use p2c_s2c::{TweakHash, PubkeyTweakHash, XOnly};
use p2c_s2c::bitcoin_hashes::{hash_newtype, sha256t, sha256t_tag};

sha256t_tag! {
    /// Tag used for in tagged hash for key tweaking.
    pub struct SimplicityUnchainedTag = hash_str("SimplicityUnchainedDemo/P2C/0.1");
}

sha256t_tag! {
    /// Tag used for in tagged hash for signaturetweaking.
    pub struct SimplicityUnchainedSigningTag = hash_str("SimplicityUnchainedDemo/S2C/0.1");
}

hash_newtype! {
    /// Tagged hash used for key tweaking.
    #[derive(Debug)]
    pub struct SimplicityUnchainedHash(sha256t::Hash<SimplicityUnchainedTag>);

    /// Tagged hash used for key tweaking.
    #[derive(Debug)]
    pub struct SimplicityUnchainedSigningHash(sha256t::Hash<SimplicityUnchainedSigningTag>);
}

impl TweakHash for SimplicityUnchainedHash {
    type HashTag = SimplicityUnchainedTag;
    type AllowedKeys = XOnly;
}

impl TweakHash for SimplicityUnchainedSigningHash {
    type HashTag = SimplicityUnchainedSigningTag;
    type AllowedKeys = XOnly;
}

impl PubkeyTweakHash for SimplicityUnchainedHash {
    type SignatureTweakHash = SimplicityUnchainedSigningHash;
}
