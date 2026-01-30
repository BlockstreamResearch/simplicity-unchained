use std::sync::Arc;

use hal_simplicity::simplicity::jet::elements::ElementsEnv;

use hal_simplicity::simplicity::elements::{Transaction, script::Script};

pub type BitcoinUnchainedEnv = UnchainedEnv<()>;
pub type ElementsUnchainedEnv = UnchainedEnv<ElementsEnv<Arc<Transaction>>>;

pub struct UnchainedEnv<E> {
    pub redeem_script: Script,
    pub env: E,
}

impl<E> UnchainedEnv<E> {
    pub fn new(redeem_script: Script, env: E) -> Self {
        Self { redeem_script, env }
    }
}
