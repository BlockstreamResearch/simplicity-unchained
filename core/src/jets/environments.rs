use simplicity::elements::script::Script;
use simplicity::jet::{CoreEnv, ElementsTxEnv};

pub type BitcoinUnchainedEnv = UnchainedEnv<BitcoinTxEnv>;
pub type ElementsUnchainedEnv = UnchainedEnv<ElementsTxEnv>;

/// Transaction context exposed to Bitcoin custom jets and plugins.
pub struct BitcoinTxEnv {
    /// Unsigned spending transaction, without PSBT signature metadata.
    pub tx: simplicity::bitcoin::Transaction,
    /// Input being authorized.
    pub input_index: u32,
    /// Versioned per-spend approval digest, distinct from the Taproot signing sighash.
    pub approval_hash: [u8; 32],
    pub(crate) core_env: CoreEnv,
}

pub struct UnchainedEnv<E> {
    pub redeem_script: Script,
    pub env: E,
}

impl<E> UnchainedEnv<E> {
    pub fn new(redeem_script: Script, env: E) -> Self {
        Self { redeem_script, env }
    }
}
