mod finalize;

use std::{collections::HashMap, io::Read, path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand};
use reqwest::{
    Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use simplicity::{
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bitcoin::{
        Address, Network, Psbt, PublicKey, TapLeafHash, TapNodeHash, Transaction, XOnlyPublicKey,
        consensus::{deserialize, serialize},
        hashes::Hash,
        secp256k1::{Keypair, Message, Secp256k1, SecretKey, schnorr},
        taproot::LeafVersion,
    },
};
use simplicity_unchained_core::policy::{PreparedPolicy, policy_cmr};
use simplicity_unchained_policy::{
    ContextSummary, Limits, MAX_EXECUTION_COST_MILLIWEIGHT, MAX_INPUTS, MAX_OUTPUTS,
    MAX_REQUEST_BYTES, PROFILE_NAME, cooperative_output, genesis_hash, manifest, profile_hash,
    signing_commitment, tweak_public_key,
};

const POLICY_PATH: &str = "/simplicity-unchained/policy/bitcoin";
const MAX_BODY_BYTES: usize = MAX_REQUEST_BYTES;

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Derive the exact policy-bound funding address locally before funding
    Address {
        #[command(flatten)]
        policy: ProgramArgs,
        #[arg(long)]
        base_public_key: String,
        #[arg(long)]
        user_pubkey: String,
        #[arg(long)]
        user_leaf_hash_hex: String,
    },
    /// Build a canonical Bitcoin CSV recovery leaf before deriving the address
    BuildCsvLeaf {
        #[arg(long)]
        user_pubkey: String,
        #[arg(long)]
        timelock: u16,
    },
    /// Check the exact compiled profile, manifest and configured service network
    Capabilities {
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        service: ServiceArgs,
    },
    /// Derive the profile-bound service key before funding
    Tweak {
        #[command(flatten)]
        policy: ProgramArgs,
        #[command(flatten)]
        service: ServiceArgs,
        /// Optionally pin the service's known untweaked x-only or compressed key
        #[arg(long)]
        base_public_key: Option<String>,
    },
    /// Verify full parent evidence and compare the service's prepared context locally
    Prepare {
        #[command(flatten)]
        transaction: TransactionArgs,
        #[command(flatten)]
        service: ServiceArgs,
    },
    /// Evaluate a witnessed policy without requesting a transaction signature
    Evaluate {
        #[command(flatten)]
        transaction: TransactionArgs,
        #[command(flatten)]
        service: ServiceArgs,
        /// Standard-base64 encoded Simplicity witness (an empty string is allowed)
        #[arg(long)]
        witness: String,
    },
    /// Compute J53/J54 locally from verified parents and a known base service key
    ApprovalHash {
        #[command(flatten)]
        transaction: TransactionArgs,
    },
    /// Revalidate and evaluate the exact policy, then verify the service's signature
    Sign {
        #[command(flatten)]
        transaction: TransactionArgs,
        #[command(flatten)]
        service: ServiceArgs,
        /// Standard-base64 encoded Simplicity witness (an empty string is allowed)
        #[arg(long)]
        witness: String,
    },
    /// Add the user's cooperative signature after verifying the policy context
    UserSign {
        #[command(flatten)]
        transaction: TransactionArgs,
        /// File containing the user's 32-byte secret key as hex; keep it private
        #[arg(long)]
        secret_key_file: PathBuf,
    },
    /// Verify the policy binding and both signatures for every input, then finalize
    Finalize {
        #[command(flatten)]
        transaction: TransactionArgs,
    },
}

#[derive(Args)]
pub struct IdentityArgs {
    /// Explicit policy profile; no legacy/profile fallback is permitted
    #[arg(long, default_value = PROFILE_NAME)]
    profile: String,
    /// Expected registry fingerprint; defaults to this binary's compiled fingerprint
    #[arg(long)]
    profile_hash: Option<String>,
    /// Expected Bitcoin network; must exactly match the configured service
    #[arg(long, default_value = "testnet4")]
    network: String,
}

#[derive(Args)]
pub struct ServiceArgs {
    /// Service origin, without an endpoint path
    #[arg(long, default_value = "http://127.0.0.1:30431")]
    service: String,
}

#[derive(Args)]
pub struct ProgramArgs {
    #[command(flatten)]
    identity: IdentityArgs,
    /// Standard-base64 encoded program compiled for bitcoin-policy-v1, not legacy
    #[arg(long)]
    program: String,
    /// Exact committed script-data bytes; omission means an empty script
    #[arg(long, default_value = "")]
    redeem_script_hex: String,
}

#[derive(Args)]
pub struct TransactionArgs {
    #[command(flatten)]
    policy: ProgramArgs,
    /// Hex serialized PSBT; full parent transactions are required for every input
    #[arg(long)]
    psbt: String,
    #[arg(long)]
    input_index: usize,
    /// Cooperative user's compressed or x-only public key, in hex
    #[arg(long)]
    user_pubkey: String,
    /// Exact 32-byte recovery TapNodeHash, in raw-byte hex (not explorer byte order)
    #[arg(long)]
    user_leaf_hash_hex: String,
    /// Known untweaked service public key, compressed or x-only hex
    #[arg(long)]
    base_public_key: String,
    /// Explicit Esplora API base; fetch missing full parents from /tx/<txid>/raw
    #[arg(long, conflicts_with = "offline")]
    esplora_url: Option<String>,
    /// Forbid parent fetching; all non_witness_utxo evidence must already be present
    #[arg(long)]
    offline: bool,
}

#[derive(Serialize)]
struct ProgramRequest {
    profile_hash: String,
    network: String,
    program: String,
    redeem_script_hex: String,
}

#[derive(Serialize)]
struct TransactionRequest {
    #[serde(flatten)]
    policy: ProgramRequest,
    psbt_hex: String,
    input_index: usize,
    user_pubkey: String,
    user_leaf_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct CapabilitiesResponse {
    profile: String,
    profile_hash: String,
    network: String,
    genesis_hash: String,
    base_public_key_hex: String,
    manifest: Value,
    limits: Value,
    provenance: String,
}

#[derive(Deserialize, Serialize)]
struct TweakResponse {
    profile: String,
    profile_hash: String,
    network: String,
    genesis_hash: String,
    cmr: String,
    signing_commitment: String,
    public_key_hex: String,
    base_public_key_hex: String,
}

#[derive(Deserialize, Serialize)]
struct PrepareResponse {
    context: ContextSummary,
}

#[derive(Deserialize, Serialize)]
struct EvaluateResponse {
    accepted: bool,
    context: ContextSummary,
    execution_cost_milliweight: u64,
}

#[derive(Deserialize, Serialize)]
struct SignResponse {
    psbt_hex: String,
    signature_hex: String,
    public_key_hex: String,
    input_index: usize,
    context: ContextSummary,
    execution_cost_milliweight: u64,
}

struct ServiceClient {
    client: Client,
    base: String,
}

impl ServiceClient {
    fn new(args: &ServiceArgs) -> Result<Self> {
        let origin = validate_url(&args.service)?;
        ensure!(
            origin.path() == "/",
            "--service must be an origin without an endpoint path"
        );
        Ok(Self {
            client: http_client()?,
            base: format!("{}{}", origin.as_str().trim_end_matches('/'), POLICY_PATH),
        })
    }

    fn capabilities(
        &self,
        identity: &IdentityArgs,
        expected_key: Option<XOnlyPublicKey>,
    ) -> Result<CapabilitiesResponse> {
        let response = self
            .client
            .get(format!("{}/capabilities", self.base))
            .send()
            .context("Failed to fetch policy capabilities")?;
        let result: CapabilitiesResponse = decode_response(response)?;
        check_identity(
            identity,
            &result.profile,
            &result.profile_hash,
            &result.network,
            &result.genesis_hash,
        )?;
        let compiled_manifest = manifest();
        ensure!(
            result.manifest == serde_json::to_value(&compiled_manifest)?,
            "Service policy manifest differs from the compiled registry"
        );
        let limits: Limits = serde_json::from_value(result.limits.clone())
            .context("Invalid service policy limits")?;
        ensure!(
            limits == compiled_manifest.limits,
            "Service policy limits differ from the compiled profile"
        );
        ensure!(
            result.provenance == "parent-txid-verified",
            "Service policy verification provenance mismatch"
        );
        let base_key = parse_public_key(&result.base_public_key_hex)?;
        if let Some(expected_key) = expected_key {
            ensure!(
                base_key == expected_key,
                "Service base public key does not match --base-public-key"
            );
        }
        Ok(result)
    }

    fn post<T: Serialize, R: DeserializeOwned>(&self, operation: &str, body: &T) -> Result<R> {
        let body = serde_json::to_vec(body)?;
        ensure!(
            body.len() <= MAX_BODY_BYTES,
            "Policy request exceeds the 2 MiB body limit"
        );
        let response = self
            .client
            .post(format!("{}/{}", self.base, operation))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .with_context(|| format!("Policy {operation} request failed"))?;
        decode_response(response)
    }
}

pub fn execute(command: PolicyCommand) -> Result<()> {
    match run(command) {
        Ok(output) => {
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        Err(error) => {
            println!("{}", json!({ "error": format!("{error:#}") }));
            Err(error)
        }
    }
}

fn run(command: PolicyCommand) -> Result<Value> {
    match command {
        PolicyCommand::Address {
            policy,
            base_public_key,
            user_pubkey,
            user_leaf_hash_hex,
        } => {
            let (network, program, script) = policy.validate()?;
            let cmr = policy_cmr(&program)?;
            let output = cooperative_output(
                parse_public_key(&base_public_key)?,
                cmr.to_byte_array(),
                &script,
                network,
                parse_public_key(&user_pubkey)?,
                parse_recovery_hash(&user_leaf_hash_hex)?,
            )?;
            Ok(json!({
                "profile": PROFILE_NAME,
                "profile_hash": hex::encode(profile_hash()),
                "network": policy.identity.network,
                "genesis_hash": hex::encode(genesis_hash(network)?),
                "cmr": hex::encode(cmr.to_byte_array()),
                "signing_commitment": hex::encode(signing_commitment(cmr.to_byte_array(), &script, network)?),
                "address": Address::from_script(&output.script_pubkey, network)?.to_string(),
                "script_pubkey_hex": hex::encode(output.script_pubkey.as_bytes()),
            }))
        }
        PolicyCommand::BuildCsvLeaf {
            user_pubkey,
            timelock,
        } => {
            ensure!(timelock > 0, "Recovery timelock must be at least one block");
            let script = simplicity::bitcoin::script::Builder::new()
                .push_int(i64::from(timelock))
                .push_opcode(simplicity::bitcoin::opcodes::all::OP_CSV)
                .push_opcode(simplicity::bitcoin::opcodes::all::OP_DROP)
                .push_x_only_key(&parse_public_key(&user_pubkey)?)
                .push_opcode(simplicity::bitcoin::opcodes::all::OP_CHECKSIG)
                .into_script();
            Ok(json!({
                "script": hex::encode(script.as_bytes()),
                "leaf_hash": hex::encode(TapLeafHash::from_script(&script, LeafVersion::TapScript).to_byte_array()),
            }))
        }
        PolicyCommand::Capabilities { identity, service } => {
            identity.validate()?;
            let result = ServiceClient::new(&service)?.capabilities(&identity, None)?;
            Ok(serde_json::to_value(result)?)
        }
        PolicyCommand::Tweak {
            policy,
            service,
            base_public_key,
        } => {
            let (network, program, script) = policy.validate()?;
            let expected_key = base_public_key
                .as_deref()
                .map(parse_public_key)
                .transpose()?;
            let client = ServiceClient::new(&service)?;
            let capabilities = client.capabilities(&policy.identity, expected_key)?;
            let base_key = parse_public_key(&capabilities.base_public_key_hex)?;
            let cmr = policy_cmr(&program).context("Invalid policy-profile program")?;
            let cmr_bytes = cmr.to_byte_array();
            let expected_commitment = signing_commitment(cmr_bytes, &script, network)?;
            let expected_tweaked = tweak_public_key(base_key, cmr_bytes, &script, network)?;
            let result: TweakResponse = client.post("tweak", &policy.request())?;
            check_identity(
                &policy.identity,
                &result.profile,
                &result.profile_hash,
                &result.network,
                &result.genesis_hash,
            )?;
            ensure!(
                result.cmr == hex::encode(cmr_bytes)
                    && result.signing_commitment == hex::encode(expected_commitment)
                    && result.public_key_hex == expected_tweaked.to_string()
                    && parse_public_key(&result.base_public_key_hex)? == base_key,
                "Service tweak does not match the locally derived policy commitment/key"
            );
            Ok(serde_json::to_value(result)?)
        }
        PolicyCommand::ApprovalHash { transaction } => {
            let local = LocalTransaction::new(&transaction)?;
            Ok(serde_json::to_value(PrepareResponse {
                context: local.prepared.summary(),
            })?)
        }
        PolicyCommand::Prepare {
            transaction,
            service,
        } => {
            let local = LocalTransaction::new(&transaction)?;
            let client = checked_service(&service, &transaction, &local)?;
            let result: PrepareResponse =
                client.post("prepare", &local.request(&transaction, None))?;
            check_context(&result.context, &local.prepared.summary())?;
            Ok(serde_json::to_value(result)?)
        }
        PolicyCommand::Evaluate {
            transaction,
            service,
            witness,
        } => {
            let witness_bytes = decode_base64(&witness, "witness")?;
            let local = LocalTransaction::new(&transaction)?;
            let evaluated = local.prepared.evaluate_default(&witness_bytes)?;
            let client = checked_service(&service, &transaction, &local)?;
            let result: EvaluateResponse =
                client.post("evaluate", &local.request(&transaction, Some(witness)))?;
            ensure!(result.accepted, "Service did not accept the policy");
            check_context(&result.context, &local.prepared.summary())?;
            check_cost(result.execution_cost_milliweight)?;
            ensure!(
                result.execution_cost_milliweight == u64::from(evaluated.cost_milliweight),
                "Service execution cost differs from local policy evaluation"
            );
            Ok(serde_json::to_value(result)?)
        }
        PolicyCommand::Sign {
            transaction,
            service,
            witness,
        } => {
            let witness_bytes = decode_base64(&witness, "witness")?;
            let local = LocalTransaction::new(&transaction)?;
            let evaluated = local.prepared.evaluate_default(&witness_bytes)?;
            let client = checked_service(&service, &transaction, &local)?;
            let result: SignResponse =
                client.post("sign", &local.request(&transaction, Some(witness)))?;
            check_context(&result.context, &local.prepared.summary())?;
            check_cost(result.execution_cost_milliweight)?;
            ensure!(
                result.execution_cost_milliweight == u64::from(evaluated.cost_milliweight),
                "Service execution cost differs from local policy evaluation"
            );
            local.verify_signature(&transaction, &result)?;
            Ok(serde_json::to_value(result)?)
        }
        PolicyCommand::UserSign {
            transaction,
            secret_key_file,
        } => {
            let mut local = LocalTransaction::new(&transaction)?;
            let secret = std::fs::read_to_string(secret_key_file)
                .context("Failed to read user secret key file")?;
            let secret = hex::decode(secret.trim()).context("Invalid user secret key hex")?;
            let key = Keypair::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&secret).context("Invalid user secret key")?,
            );
            let context = local.prepared.context();
            ensure!(
                key.x_only_public_key().0 == context.user_pubkey(),
                "User secret key does not match the committed user public key"
            );
            let signature = Secp256k1::new().sign_schnorr(
                &Message::from_digest(context.cooperative_sighash_default()),
                &key,
            );
            let input = &mut local.psbt.inputs[transaction.input_index];
            input.tap_script_sigs.insert(
                (context.user_pubkey(), context.cooperative_leaf_hash()),
                simplicity::bitcoin::taproot::Signature {
                    signature,
                    sighash_type: simplicity::bitcoin::TapSighashType::Default,
                },
            );
            input.tap_scripts.insert(
                context.control_block().clone(),
                (context.cooperative_script().clone(), LeafVersion::TapScript),
            );
            Ok(json!({
                "psbt_hex": hex::encode(local.psbt.serialize()),
                "input_index": transaction.input_index,
                "context": local.prepared.summary(),
            }))
        }
        PolicyCommand::Finalize { transaction } => {
            let local = LocalTransaction::new(&transaction)?;
            let tx = finalize::finalize(&local.psbt)?;
            Ok(json!({
                "transaction_hex": hex::encode(serialize(&tx)),
                "txid": tx.compute_txid().to_string(),
                "inputs": tx.input.len(),
                "outputs": tx.output.len(),
                "finalized": true,
            }))
        }
    }
}

impl IdentityArgs {
    fn validate(&self) -> Result<Network> {
        ensure!(
            self.profile == PROFILE_NAME,
            "Unsupported policy profile '{}'; expected {PROFILE_NAME}",
            self.profile
        );
        if let Some(expected_hash) = &self.profile_hash {
            ensure!(
                hex::decode(expected_hash).context("Invalid profile fingerprint hex")?
                    == profile_hash(),
                "Policy fingerprint does not match this binary's compiled registry"
            );
        }
        match self.network.as_str() {
            "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "testnet4" => Ok(Network::Testnet4),
            _ => bail!("Unsupported policy network; expected bitcoin, testnet, or testnet4"),
        }
    }
}

impl ProgramArgs {
    fn validate(&self) -> Result<(Network, Vec<u8>, Vec<u8>)> {
        let network = self.identity.validate()?;
        let program = decode_base64(&self.program, "program")?;
        ensure!(!program.is_empty(), "Policy program cannot be empty");
        policy_cmr(&program).context("Invalid policy-profile program")?;
        let script = hex::decode(&self.redeem_script_hex).context("Invalid redeem script hex")?;
        Ok((network, program, script))
    }

    fn request(&self) -> ProgramRequest {
        ProgramRequest {
            profile_hash: hex::encode(profile_hash()),
            network: self.identity.network.clone(),
            program: self.program.clone(),
            redeem_script_hex: self.redeem_script_hex.clone(),
        }
    }
}

struct LocalTransaction {
    psbt: Psbt,
    prepared: PreparedPolicy,
    base_key: XOnlyPublicKey,
}

impl LocalTransaction {
    fn new(args: &TransactionArgs) -> Result<Self> {
        let (network, program, script) = args.policy.validate()?;
        let base_key = parse_public_key(&args.base_public_key)?;
        let user_key = parse_public_key(&args.user_pubkey)?;
        let recovery = parse_recovery_hash(&args.user_leaf_hash_hex)?;
        let mut psbt = parse_psbt(&args.psbt)?;
        let resolver = if args.offline {
            None
        } else {
            args.esplora_url.as_deref()
        };
        populate_parents(&mut psbt, resolver)?;
        let prepared = PreparedPolicy::new(
            &program,
            &psbt,
            args.input_index,
            &script,
            network,
            base_key,
            user_key,
            recovery,
        )
        .context("Failed to construct verified policy context")?;
        Ok(Self {
            psbt,
            prepared,
            base_key,
        })
    }

    fn request(&self, args: &TransactionArgs, witness: Option<String>) -> TransactionRequest {
        TransactionRequest {
            policy: args.policy.request(),
            psbt_hex: hex::encode(self.psbt.serialize()),
            input_index: args.input_index,
            user_pubkey: args.user_pubkey.clone(),
            user_leaf_hash_hex: args.user_leaf_hash_hex.clone(),
            witness,
        }
    }

    fn verify_signature(&self, args: &TransactionArgs, result: &SignResponse) -> Result<()> {
        ensure!(
            result.input_index == args.input_index,
            "Service signed an unexpected input index"
        );
        let context = self.prepared.context();
        ensure!(
            result.public_key_hex == context.service_pubkey().to_string(),
            "Service signature public key differs from the reconstructed policy key"
        );
        let signature = schnorr::Signature::from_slice(
            &hex::decode(&result.signature_hex).context("Invalid service signature hex")?,
        )
        .context("Service must return a 64-byte SIGHASH_DEFAULT signature")?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(context.cooperative_sighash_default()),
                &context.service_pubkey(),
            )
            .context("Service returned an invalid cooperative signature")?;
        let returned_psbt = parse_psbt(&result.psbt_hex)?;
        ensure!(
            returned_psbt.unsigned_tx == self.psbt.unsigned_tx
                && returned_psbt.inputs.len() == self.psbt.inputs.len(),
            "Service changed the transaction"
        );
        for (index, (returned, original)) in returned_psbt
            .inputs
            .iter()
            .zip(&self.psbt.inputs)
            .enumerate()
        {
            ensure!(
                returned.witness_utxo == original.witness_utxo
                    && returned.non_witness_utxo == original.non_witness_utxo,
                "Service changed parent evidence for input {index}"
            );
        }
        let input = &returned_psbt.inputs[args.input_index];
        let leaf_hash =
            TapLeafHash::from_script(context.cooperative_script(), LeafVersion::TapScript);
        let stored = input
            .tap_script_sigs
            .get(&(context.service_pubkey(), leaf_hash))
            .context("Returned PSBT does not contain the verified service signature")?;
        ensure!(
            stored.signature == signature
                && stored.sighash_type == simplicity::bitcoin::TapSighashType::Default,
            "Returned PSBT contains a different service signature/sighash type"
        );
        ensure!(
            input.tap_scripts.get(context.control_block())
                == Some(&(
                    context.cooperative_script().to_owned(),
                    LeafVersion::TapScript
                )),
            "Returned PSBT is missing the reconstructed cooperative leaf/control block"
        );
        Ok(())
    }
}

fn checked_service(
    service: &ServiceArgs,
    transaction: &TransactionArgs,
    local: &LocalTransaction,
) -> Result<ServiceClient> {
    let client = ServiceClient::new(service)?;
    client.capabilities(&transaction.policy.identity, Some(local.base_key))?;
    Ok(client)
}

fn check_identity(
    expected: &IdentityArgs,
    profile: &str,
    fingerprint: &str,
    network: &str,
    genesis: &str,
) -> Result<()> {
    let expected_network = expected.validate()?;
    ensure!(profile == PROFILE_NAME, "Service policy profile mismatch");
    ensure!(
        fingerprint == hex::encode(profile_hash()),
        "Service policy fingerprint mismatch"
    );
    ensure!(
        network == expected.network,
        "Service policy network mismatch"
    );
    ensure!(
        genesis == hex::encode(genesis_hash(expected_network)?),
        "Service genesis hash mismatch"
    );
    Ok(())
}

fn check_context(remote: &ContextSummary, local: &ContextSummary) -> Result<()> {
    ensure!(
        remote == local,
        "Service policy context/digests differ from the locally verified context"
    );
    Ok(())
}

fn check_cost(cost: u64) -> Result<()> {
    ensure!(
        cost <= u64::from(MAX_EXECUTION_COST_MILLIWEIGHT),
        "Service reported a cost above the policy execution limit"
    );
    Ok(())
}

fn parse_recovery_hash(encoded: &str) -> Result<TapNodeHash> {
    TapNodeHash::from_slice(&hex::decode(encoded).context("Invalid recovery leaf hash hex")?)
        .context("Recovery leaf hash must be exactly 32 bytes")
}

fn parse_public_key(encoded: &str) -> Result<XOnlyPublicKey> {
    let bytes = hex::decode(encoded).context("Invalid public key hex")?;
    match bytes.len() {
        32 => XOnlyPublicKey::from_slice(&bytes).context("Invalid x-only public key"),
        33 => PublicKey::from_slice(&bytes)
            .map(|key| key.inner.x_only_public_key().0)
            .context("Invalid compressed public key"),
        _ => bail!("Public key must be 32-byte x-only or 33-byte compressed hex"),
    }
}

fn parse_psbt(encoded: &str) -> Result<Psbt> {
    let bytes = hex::decode(encoded).context("Invalid PSBT hex")?;
    ensure!(
        bytes.len() <= MAX_BODY_BYTES,
        "PSBT exceeds the policy body limit"
    );
    Psbt::deserialize(&bytes).context("Invalid serialized PSBT")
}

fn decode_base64(encoded: &str, label: &str) -> Result<Vec<u8>> {
    ensure!(
        encoded.len() <= MAX_BODY_BYTES,
        "Policy {label} exceeds the body limit"
    );
    BASE64_STANDARD
        .decode(encoded)
        .with_context(|| format!("Invalid standard-base64 policy {label}"))
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .build()
        .context("Failed to create HTTP client")
}

fn validate_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("Invalid HTTP URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Expected an HTTP(S) URL without credentials, query, or fragment"
    );
    Ok(url)
}

fn read_body(response: Response) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    let status = response.status();
    let mut body = Vec::new();
    response
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .context("Failed to read HTTP response body")?;
    ensure!(
        body.len() <= MAX_BODY_BYTES,
        "HTTP response exceeds the 2 MiB policy limit (status {status})"
    );
    Ok((status, body))
}

fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T> {
    let (status, body) = read_body(response)?;
    ensure!(
        status.is_success(),
        "Policy service returned HTTP {status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).context("Invalid policy service response JSON/shape")
}

fn populate_parents(psbt: &mut Psbt, esplora: Option<&str>) -> Result<()> {
    ensure!(
        !psbt.inputs.is_empty() && psbt.inputs.len() == psbt.unsigned_tx.input.len(),
        "Invalid PSBT input count"
    );
    ensure!(
        psbt.inputs.len() <= MAX_INPUTS && psbt.unsigned_tx.output.len() <= MAX_OUTPUTS,
        "Policy profile accepts at most eight inputs and eight outputs"
    );
    let esplora = esplora.map(validate_url).transpose()?;
    let client = esplora.as_ref().map(|_| http_client()).transpose()?;
    let mut parents = HashMap::<_, Transaction>::new();
    for (index, (input, txin)) in psbt.inputs.iter().zip(&psbt.unsigned_tx.input).enumerate() {
        if let Some(parent) = &input.non_witness_utxo {
            ensure!(
                parent.compute_txid() == txin.previous_output.txid,
                "Input {index} parent transaction txid mismatch"
            );
            if let Some(known) = parents.insert(txin.previous_output.txid, parent.clone()) {
                ensure!(
                    known == *parent,
                    "Conflicting full parent transaction evidence"
                );
            }
        }
    }
    for (index, (input, txin)) in psbt
        .inputs
        .iter_mut()
        .zip(&psbt.unsigned_tx.input)
        .enumerate()
    {
        let outpoint = txin.previous_output;
        if input.non_witness_utxo.is_none() {
            if let Some(parent) = parents.get(&outpoint.txid) {
                input.non_witness_utxo = Some(parent.clone());
            } else if let (Some(esplora), Some(client)) = (&esplora, &client) {
                let url = format!(
                    "{}/tx/{}/raw",
                    esplora.as_str().trim_end_matches('/'),
                    outpoint.txid
                );
                let response = client
                    .get(url)
                    .send()
                    .with_context(|| format!("Failed to fetch parent for input {index}"))?;
                let (status, bytes) = read_body(response)?;
                ensure!(
                    status.is_success(),
                    "Esplora returned HTTP {status} for input {index}: {}",
                    String::from_utf8_lossy(&bytes)
                );
                input.non_witness_utxo =
                    Some(deserialize::<Transaction>(&bytes).with_context(|| {
                        format!("Invalid parent transaction for input {index}")
                    })?);
            } else {
                bail!(
                    "Input {index} missing non_witness_utxo full parent evidence in offline mode; provide --esplora-url or populate every parent"
                );
            }
        }
        let parent = input.non_witness_utxo.as_ref().unwrap();
        ensure!(
            parent.compute_txid() == outpoint.txid,
            "Input {index} parent transaction txid mismatch"
        );
        let prevout = parent
            .output
            .get(outpoint.vout as usize)
            .with_context(|| format!("Input {index} parent output index out of bounds"))?;
        if let Some(witness_utxo) = &input.witness_utxo {
            ensure!(
                witness_utxo == prevout,
                "Input {index} witness_utxo conflicts with verified parent output"
            );
        } else {
            input.witness_utxo = Some(prevout.clone());
        }
        parents.insert(outpoint.txid, parent.clone());
    }
    Ok(())
}
