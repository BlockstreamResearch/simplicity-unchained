pub struct UnchainedEnv {
    pub wallet_id: [u32; 8],
}

impl UnchainedEnv {
    pub fn new(wallet_id: [u32; 8]) -> Self {
        Self { wallet_id }
    }
}
