use simplicity::elements::script::Script;
use simplicity::jet::{CoreEnv, ElementsTxEnv};

pub type BitcoinUnchainedEnv = UnchainedEnv<CoreEnv>;
pub type ElementsUnchainedEnv = UnchainedEnv<ElementsTxEnv>;

pub struct UnchainedEnv<E> {
    pub redeem_script: Script,
    pub env: E,
}

impl<E> UnchainedEnv<E> {
    pub fn new(redeem_script: Script, env: E) -> Self {
        Self { redeem_script, env }
    }
}
