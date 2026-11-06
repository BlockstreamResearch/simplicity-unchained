//! New, proof-verified Liquid policy CLI. No legacy command alias.
use anyhow::{Context as _, Result, ensure};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::{Value, json};
use simplicity::base64::{Engine, engine::general_purpose::STANDARD};
use simplicity_unchained_policy::liquid::{
    self as policy,
    elements::{
        Address,
        encode::{deserialize, serialize},
        pset::PartiallySignedTransaction as Pset,
        secp256k1_zkp::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, rand::rngs::OsRng},
        taproot::TapNodeHash,
    },
};
use std::{fs, io::Read, path::PathBuf, str::FromStr, time::Duration};

#[derive(Subcommand)]
pub enum Command {
    /// Print this binary's canonical liquid-policy-v1 registry
    Registry,
    /// Check service profile/network/base-key identity against a local request
    Capabilities {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:30431")]
        service: String,
    },
    /// Derive a Liquid profile-bound service key locally
    Tweak {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Reconstruct the cooperative funding address, optionally confidential
    Address {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Generate a local receiving blinding key; protect the private output
    GenerateBlindingKey,
    /// Build/blind a PSET with full parents and browser/local unblinding keys
    Create {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Verify all evidence/proofs/signatures and prepare a local context
    Prepare {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Compute input-specific and transaction-wide approval hashes locally
    ApprovalHash {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Execute a witnessed policy locally without signing
    Evaluate {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Request service signing and independently verify the returned PSET/signature
    Sign {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:30431")]
        service: String,
    },
    /// Reverify disclosures/service signature and add a local user signature
    UserSign {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long)]
        secret_key_file: PathBuf,
    },
    /// Reverify disclosures and both signatures for every input, then finalize
    Finalize {
        #[arg(long)]
        request_file: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default = "profile")]
    profile: String,
    #[serde(default)]
    profile_hash: Option<String>,
    #[serde(default)]
    network: policy::Network,
    program: String,
    #[serde(default)]
    redeem_script_hex: String,
    base_public_key_hex: String,
    #[serde(default)]
    pset_hex: Option<String>,
    #[serde(default)]
    input_index: usize,
    #[serde(default)]
    user_pubkey: Option<String>,
    #[serde(default)]
    user_leaf_hash_hex: Option<String>,
    #[serde(default)]
    blinding_public_key_hex: Option<String>,
    #[serde(default)]
    witness: Option<String>,
}
fn profile() -> String {
    policy::PROFILE_NAME.into()
}
fn read<T: serde::de::DeserializeOwned>(path: PathBuf) -> Result<T> {
    let size = fs::metadata(&path)?.len();
    ensure!(
        size <= (simplicity_unchained_policy::MAX_REQUEST_BYTES * 2) as u64,
        "request exceeds evidence limit"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn key(s: &str) -> Result<XOnlyPublicKey> {
    match s.len() {
        64 => Ok(XOnlyPublicKey::from_str(s)?),
        66 => Ok(PublicKey::from_str(s)?.x_only_public_key().0),
        _ => anyhow::bail!("expected compressed/x-only public key"),
    }
}
impl Request {
    fn binding(&self) -> Result<(Vec<u8>, Vec<u8>, XOnlyPublicKey)> {
        ensure!(
            self.profile == policy::PROFILE_NAME,
            "explicit Liquid profile mismatch"
        );
        ensure!(
            self.profile_hash
                .as_ref()
                .is_none_or(|h| *h == hex::encode(policy::profile_hash())),
            "Liquid fingerprint mismatch"
        );
        Ok((
            STANDARD.decode(&self.program)?,
            hex::decode(&self.redeem_script_hex)?,
            key(&self.base_public_key_hex)?,
        ))
    }
    fn recovery(&self) -> Result<TapNodeHash> {
        let bytes: [u8; 32] = hex::decode(
            self.user_leaf_hash_hex
                .as_ref()
                .context("missing user_leaf_hash_hex")?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("recovery hash must be 32 bytes"))?;
        Ok(TapNodeHash::from_byte_array(bytes))
    }
    fn prepare(&self) -> Result<(Pset, policy::PreparedPolicy)> {
        let (program, data, base) = self.binding()?;
        let pset_hex = self.pset_hex.as_ref().context("missing pset_hex")?;
        ensure!(
            pset_hex.len() <= simplicity_unchained_policy::MAX_REQUEST_BYTES * 2,
            "PSET exceeds profile limit"
        );
        let pset: Pset = deserialize(&hex::decode(pset_hex)?)?;
        let prepared = policy::PreparedPolicy::new(
            &program,
            &pset,
            self.input_index,
            &data,
            self.network,
            base,
            key(self.user_pubkey.as_ref().context("missing user_pubkey")?)?,
            self.recovery()?,
        )?;
        Ok((pset, prepared))
    }
    fn witness(&self) -> Result<Vec<u8>> {
        Ok(STANDARD.decode(
            self.witness
                .as_ref()
                .context("witness required; use empty string for no witness")?,
        )?)
    }
    fn remote(&self) -> Value {
        json!({"profile_hash":hex::encode(policy::profile_hash()),"network":self.network.name(),"program":self.program,"redeem_script_hex":self.redeem_script_hex,"pset_hex":self.pset_hex,"input_index":self.input_index,"user_pubkey":self.user_pubkey,"user_leaf_hash_hex":self.user_leaf_hash_hex,"witness":self.witness})
    }
}
fn http(service: &str, operation: &str, body: Option<Value>) -> Result<Value> {
    let origin = reqwest::Url::parse(service)?;
    ensure!(
        matches!(origin.scheme(), "http" | "https")
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.path() == "/",
        "service must be a bare HTTP(S) origin without credentials/query"
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!(
        "{}/simplicity-unchained/policy/liquid/{operation}",
        service.trim_end_matches('/')
    );
    let response = if let Some(body) = body {
        client.post(url).json(&body).send()?
    } else {
        client.get(url).send()?
    };
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take((simplicity_unchained_policy::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= simplicity_unchained_policy::MAX_REQUEST_BYTES,
        "service response exceeds limit"
    );
    ensure!(
        status.is_success(),
        "service failed ({status}): {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn capabilities(r: &Request, service: &str) -> Result<Value> {
    let (_, _, base) = r.binding()?;
    let v = http(service, "capabilities", None)?;
    ensure!(
        v["profile"] == policy::PROFILE_NAME
            && v["profile_hash"] == hex::encode(policy::profile_hash()),
        "service profile/fingerprint mismatch"
    );
    ensure!(
        v["network"] == r.network.name()
            && v["genesis_hash"] == hex::encode(r.network.genesis_hash().to_byte_array()),
        "service network/genesis mismatch"
    );
    ensure!(
        v["base_public_key_hex"] == base.to_string() && v["manifest"] == policy::manifest(),
        "service base key/manifest mismatch"
    );
    Ok(v)
}

pub fn execute(command: Command) -> Result<()> {
    let value = match command {
        Command::Registry => {
            json!({"profile":policy::PROFILE_NAME,"profile_hash":hex::encode(policy::profile_hash()),"manifest":policy::manifest()})
        }
        Command::GenerateBlindingKey => {
            let secret = SecretKey::new(&mut OsRng);
            json!({"blinding_secret_key_hex":hex::encode(secret.secret_bytes()),"blinding_public_key_hex":PublicKey::from_secret_key(&Secp256k1::new(),&secret).to_string()})
        }
        Command::Create { request_file } => {
            let request: policy::CreateRequest = read(request_file)?;
            let pset = policy::create_pset(&request)?;
            json!({"pset_hex":hex::encode(serialize(&pset)),"network":request.network.name(),"inputs":pset.inputs().len(),"outputs":pset.outputs().len()})
        }
        Command::Capabilities {
            request_file,
            service,
        } => capabilities(&read(request_file)?, &service)?,
        Command::Tweak { request_file } => {
            let r: Request = read(request_file)?;
            let (program, data, base) = r.binding()?;
            let cmr = policy::policy_cmr(&program)?.to_byte_array();
            json!({"profile":policy::PROFILE_NAME,"profile_hash":hex::encode(policy::profile_hash()),"network":r.network.name(),"genesis_hash":hex::encode(r.network.genesis_hash().to_byte_array()),"cmr":hex::encode(cmr),"signing_commitment":hex::encode(policy::signing_commitment(cmr,&data,r.network)?),"public_key_hex":policy::tweak_public_key(base,cmr,&data,r.network)?.to_string(),"base_public_key_hex":base.to_string()})
        }
        Command::Address { request_file } => {
            let r: Request = read(request_file)?;
            let (program, data, base) = r.binding()?;
            let output = policy::cooperative_output(
                base,
                policy::policy_cmr(&program)?.to_byte_array(),
                &data,
                r.network,
                key(r.user_pubkey.as_ref().context("missing user_pubkey")?)?,
                r.recovery()?,
            )?;
            let blinding = r
                .blinding_public_key_hex
                .as_deref()
                .map(PublicKey::from_str)
                .transpose()?;
            let address =
                Address::from_script(&output.script_pubkey, blinding, r.network.address_params())
                    .context("cannot encode funding address")?;
            json!({"address":address.to_string(),"script_pubkey_hex":hex::encode(output.script_pubkey.as_bytes()),"profile":policy::PROFILE_NAME,"profile_hash":hex::encode(policy::profile_hash()),"network":r.network.name()})
        }
        Command::Prepare { request_file } | Command::ApprovalHash { request_file } => {
            let r: Request = read(request_file)?;
            json!({"context":r.prepare()?.1.summary()})
        }
        Command::Evaluate { request_file } => {
            let r: Request = read(request_file)?;
            let (_, prepared) = r.prepare()?;
            json!({"accepted":true,"context":prepared.summary(),"execution_cost_milliweight":prepared.evaluate_default(&r.witness()?)?})
        }
        Command::Sign {
            request_file,
            service,
        } => {
            let r: Request = read(request_file)?;
            let (_, before) = r.prepare()?;
            let cost = before.evaluate_default(&r.witness()?)?;
            capabilities(&r, &service)?;
            let response = http(&service, "sign", Some(r.remote()))?;
            let encoded = response["pset_hex"]
                .as_str()
                .context("missing signed PSET")?;
            ensure!(
                encoded.len() <= simplicity_unchained_policy::MAX_REQUEST_BYTES * 2,
                "signed PSET exceeds limit"
            );
            let signed: Pset = deserialize(&hex::decode(encoded)?)?;
            before.context().revalidate(&signed)?;
            ensure!(
                response["context"] == serde_json::to_value(before.summary())?,
                "service context changed"
            );
            ensure!(
                response["execution_cost_milliweight"] == cost,
                "service execution cost changed"
            );
            ensure!(
                response["public_key_hex"]
                    == before.context().cooperative().service_pubkey.to_string()
                    && response["input_index"] == r.input_index,
                "service signer/index changed"
            );
            let sig = signed.inputs()[r.input_index]
                .tap_script_sigs
                .get(&(
                    before.context().cooperative().service_pubkey,
                    before.context().cooperative().leaf_hash,
                ))
                .context("missing verified service signature")?;
            ensure!(
                response["signature_hex"] == hex::encode(sig.sig.as_ref()),
                "service signature response mismatch"
            );
            response
        }
        Command::UserSign {
            request_file,
            secret_key_file,
        } => {
            let r: Request = read(request_file)?;
            let (mut pset, prepared) = r.prepare()?;
            ensure!(
                pset.inputs()[r.input_index].tap_script_sigs.contains_key(&(
                    prepared.context().cooperative().service_pubkey,
                    prepared.context().cooperative().leaf_hash
                )),
                "missing verified service signature"
            );
            let secret = SecretKey::from_str(fs::read_to_string(secret_key_file)?.trim())?;
            let sig = policy::add_signature(prepared.context(), &mut pset, secret, false)?;
            json!({"pset_hex":hex::encode(serialize(&pset)),"signature_hex":hex::encode(sig.sig.as_ref()),"public_key_hex":prepared.context().user_pubkey().to_string(),"input_index":r.input_index,"context":prepared.summary()})
        }
        Command::Finalize { request_file } => {
            let r: Request = read(request_file)?;
            let (pset, prepared) = r.prepare()?;
            let tx = policy::finalize(prepared.context(), &pset)?;
            json!({"transaction_hex":hex::encode(serialize(&tx)),"txid":tx.txid().to_string(),"finalized":true,"inputs":tx.input.len(),"outputs":tx.output.len()})
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
