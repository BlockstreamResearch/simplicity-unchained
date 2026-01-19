use std::sync::Arc;

use hal_simplicity::simplicity::elements::Transaction;
use hal_simplicity::simplicity::{elements::script::Script, jet::elements::ElementsEnv};

pub struct UnchainedEnv {
    pub redeem_script: Script,
    pub elements_env: ElementsEnv<Arc<Transaction>>,
}

impl UnchainedEnv {
    pub fn new(redeem_script: Script, elements_env: ElementsEnv<Arc<Transaction>>) -> Self {
        Self {
            redeem_script,
            elements_env,
        }
    }
}
