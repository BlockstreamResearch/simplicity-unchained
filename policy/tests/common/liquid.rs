use simplicity::{ConstructNode, node::CoreConstructible, types};
use simplicity_unchained_policy::liquid::{
    self as liquid,
    elements::{
        Address, AssetId, LockTime, Transaction, TxIn, TxOut,
        confidential::{Asset, Nonce, Value},
        encode::serialize,
        pset::PartiallySignedTransaction as Pset,
        secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
        taproot::TapNodeHash,
    },
};
use std::sync::Arc;

pub fn unit_program() -> Vec<u8> {
    types::Context::with_context(|ctx| {
        Arc::<ConstructNode>::unit(&ctx)
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    })
}
pub struct Fixture {
    pub pset: Pset,
    pub program: Vec<u8>,
    pub cmr: [u8; 32],
    pub data: Vec<u8>,
    pub network: liquid::Network,
    pub base_secret: SecretKey,
    pub user_secret: SecretKey,
    pub blinding_secret: SecretKey,
    pub base: XOnlyPublicKey,
    pub user: XOnlyPublicKey,
    pub recovery: TapNodeHash,
    pub other_asset: AssetId,
    pub source_parent: Transaction,
}
impl Fixture {
    pub fn new() -> Self {
        Self::with_program(unit_program())
    }
    pub fn with_program(program: Vec<u8>) -> Self {
        Self::with_program_rng(
            program,
            &mut liquid::elements::secp256k1_zkp::rand::rngs::OsRng,
        )
    }
    pub fn deterministic() -> Self {
        use liquid::elements::secp256k1_zkp::rand::{SeedableRng, rngs::StdRng};
        Self::with_program_rng(
            unit_program(),
            &mut StdRng::seed_from_u64(0x53555f4c49515549),
        )
    }
    fn with_program_rng<
        R: liquid::elements::secp256k1_zkp::rand::RngCore
            + liquid::elements::secp256k1_zkp::rand::CryptoRng,
    >(
        program: Vec<u8>,
        rng: &mut R,
    ) -> Self {
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let user_secret = SecretKey::from_slice(&[2; 32]).unwrap();
        let blinding_secret = SecretKey::from_slice(&[3; 32]).unwrap();
        let base = Keypair::from_secret_key(&secp, &base_secret)
            .x_only_public_key()
            .0;
        let user = Keypair::from_secret_key(&secp, &user_secret)
            .x_only_public_key()
            .0;
        let network = liquid::Network::LiquidTestnet;
        let recovery_script = liquid::elements::script::Builder::new()
            .push_int(5)
            .push_opcode(liquid::elements::opcodes::all::OP_CSV)
            .push_opcode(liquid::elements::opcodes::all::OP_DROP)
            .push_slice(&user.serialize())
            .push_opcode(liquid::elements::opcodes::all::OP_CHECKSIG)
            .into_script();
        let recovery = TapNodeHash::from_byte_array(
            liquid::elements::taproot::TapLeafHash::from_script(
                &recovery_script,
                liquid::elements::taproot::LeafVersion::default(),
            )
            .to_byte_array(),
        );
        let data = recovery_script.to_bytes();
        let cmr = liquid::policy_cmr(&program).unwrap().to_byte_array();
        let cooperative =
            liquid::cooperative_output(base, cmr, &data, network, user, recovery).unwrap();
        let blind_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let funding = Address::from_script(
            &cooperative.script_pubkey,
            Some(blind_key),
            network.address_params(),
        )
        .unwrap();
        let recipient = Address::p2wpkh(
            &liquid::elements::bitcoin::PublicKey::new(PublicKey::from_secret_key(
                &secp,
                &user_secret,
            )),
            Some(blind_key),
            network.address_params(),
        );
        let other_asset = AssetId::from_byte_array([0x51; 32]);
        let source = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(network.fee_asset()),
                    value: Value::Explicit(100_001),
                    nonce: Nonce::Null,
                    script_pubkey: recipient.script_pubkey(),
                    witness: Default::default(),
                },
                TxOut {
                    asset: Asset::Explicit(other_asset),
                    value: Value::Explicit(70_000),
                    nonce: Nonce::Null,
                    script_pubkey: recipient.script_pubkey(),
                    witness: Default::default(),
                },
            ],
        };
        let source_inputs = (0..2)
            .map(|vout| liquid::ProvenInput {
                txid: source.txid().to_string(),
                vout,
                parent_tx_hex: hex::encode(serialize(&source)),
                blinding_secret_key_hex: None,
                sequence: 10,
            })
            .collect();
        let parent_pset = liquid::create_pset_with_rng(
            &liquid::CreateRequest {
                inputs: source_inputs,
                outputs: vec![
                    liquid::Output {
                        address: funding.to_string(),
                        asset_id: network.fee_asset().to_string(),
                        value_sat: 100_000,
                    },
                    liquid::Output {
                        address: funding.to_string(),
                        asset_id: other_asset.to_string(),
                        value_sat: 70_000,
                    },
                    liquid::Output {
                        address: "fee".into(),
                        asset_id: network.fee_asset().to_string(),
                        value_sat: 1,
                    },
                ],
                network,
                lock_time: 0,
            },
            rng,
        )
        .unwrap();
        let parent = parent_pset.extract_tx().unwrap();
        let inputs = (0..2)
            .map(|vout| liquid::ProvenInput {
                txid: parent.txid().to_string(),
                vout,
                parent_tx_hex: hex::encode(serialize(&parent)),
                blinding_secret_key_hex: Some(hex::encode(blinding_secret.secret_bytes())),
                sequence: 10,
            })
            .collect();
        let pset = liquid::create_pset_with_rng(
            &liquid::CreateRequest {
                inputs,
                outputs: vec![
                    liquid::Output {
                        address: recipient.to_string(),
                        asset_id: network.fee_asset().to_string(),
                        value_sat: 20_000,
                    },
                    liquid::Output {
                        address: funding.to_string(),
                        asset_id: network.fee_asset().to_string(),
                        value_sat: 79_000,
                    },
                    liquid::Output {
                        address: recipient.to_string(),
                        asset_id: other_asset.to_string(),
                        value_sat: 15_000,
                    },
                    liquid::Output {
                        address: funding.to_string(),
                        asset_id: other_asset.to_string(),
                        value_sat: 55_000,
                    },
                    liquid::Output {
                        address: "fee".into(),
                        asset_id: network.fee_asset().to_string(),
                        value_sat: 1_000,
                    },
                ],
                network,
                lock_time: 500,
            },
            rng,
        )
        .unwrap();
        Self {
            pset,
            program,
            cmr,
            data,
            network,
            base_secret,
            user_secret,
            blinding_secret,
            base,
            user,
            recovery,
            other_asset,
            source_parent: source,
        }
    }
    pub fn context(&self, index: usize) -> Result<liquid::Context, liquid::Error> {
        self.context_for(&self.pset, index)
    }
    pub fn context_for(&self, p: &Pset, index: usize) -> Result<liquid::Context, liquid::Error> {
        liquid::Context::new(
            p,
            index,
            self.cmr,
            &self.data,
            self.network,
            self.base,
            self.user,
            self.recovery,
        )
    }
    pub fn service_secret(&self) -> SecretKey {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &self.base_secret)
            .add_xonly_tweak(
                &secp,
                &liquid::service_tweak(self.base, self.cmr, &self.data, self.network).unwrap(),
            )
            .unwrap()
            .secret_key()
    }
    pub fn sign_all(&mut self) {
        for index in 0..self.pset.inputs().len() {
            let context = self.context(index).unwrap();
            let secret = self.service_secret();
            liquid::add_signature(&context, &mut self.pset, secret, true).unwrap();
            liquid::add_signature(&context, &mut self.pset, self.user_secret, false).unwrap();
        }
    }
}
