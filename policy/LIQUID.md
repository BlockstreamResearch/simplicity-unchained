# liquid-policy-v1

New off-chain policy profile, **not** the removed legacy Liquid flow or Elements
consensus Simplicity. Never fund an old output expecting this profile to recognize
it. Bitcoin profile identities and semantics are unchanged.

## Cryptographic context

Every input requires its full parent transaction and matching `witness_utxo` base
fields. Parent txid/vout are checked. Parent content verification is not a chain
inclusion, consensus-validity, confirmation or unspentness proof.

Confidential inputs and outputs require standard PSET explicit `asset`/`amount`
fields **and** `blind_asset_proof`/`blind_value_proof`. The kernel calls Elements'
single-asset surjection disclosure verifier and exact-value range disclosure
verifier against the authenticated commitments. It also verifies original input
rangeproofs, transaction output range/surjection proofs and Pedersen balance.
Missing evidence, invalid labels, proofs, existing signatures, or checked
per-asset conservation failure abort preparation and signing. Disclosure proofs
are not a commitment-opening assertion supplied by the caller.

This profile requires disclosure of **every** input/output asset and value to
the co-signer and immutable summary; it does not preserve amount secrecy from
the service. On-chain asset/value commitments can remain confidential. Receiving
keys and blinding factors are never sent to the service. Partial/unknown
disclosures cannot produce a signable context.

Issuance/pegin, annex, code-separator overrides, key-path signatures and already
finalized PSET input witnesses are unsupported and rejected. Standard fully
confidential inputs and multiple assets are supported. Local unblinding handles
fully explicit or fully confidential outputs; mixed asset/value commitments can
be submitted with independently generated valid PSET disclosure proofs. They
never receive a trusted-label fallback.

All inputs spend the same reconstructed NUMS cooperative tree: Elements
tapscript version `0xc4`, service `CHECKSIG`, user `CHECKSIGADD`, `2 EQUAL`, hidden
recovery node at depth one. The new manifest fingerprint and configured Elements
genesis enter the service-key tweak. Elements' actual DEFAULT script-path sighash
uses that genesis too. The summary is immutable after construction.

## Asset semantics

Asset words in jets are `AssetId::to_byte_array()` (raw hash bytes). JSON
`asset_id` uses explorer/display order; reverse that hex before writing a `u256`
asset constant in a policy. Individual amount fields are integer smallest units
of their disclosed asset, **not Bitcoin satoshis across all assets**.

`input_value` and `output_value` return `None` for a different current-input asset.
Totals, script-hash sums/counts, returns and debit project on the current verified
input asset. There is no all-asset scalar total.

**Exception:** `tx_fee` always means the one explicit configured network-fee-asset
output's value. Its denomination is `fee_asset`, not `current_asset`; fee caps
cannot be bypassed by selecting an input of another asset. `total_output_value`
and `asset_total_output_value` include fee outputs. Each asset's input/output
totals must be equal; debit is all that asset's same-contract inputs minus
exact-script returns, including fees where applicable.

Additional jets (all fixed 10000 milliweight):

| Jet | Arguments | Return |
| --- | --- | --- |
| `input_asset`, `output_asset` | `u32` index | `Option<u256>` raw asset |
| `current_asset`, `fee_asset` | none | raw asset `u256` |
| `asset_total_input_value`, `asset_total_output_value` | raw asset `u256` | checked `u64` total |
| `asset_fee` | raw asset `u256` | `u64` fee (zero for nonfee asset) |
| `asset_current_script_debit` | raw asset `u256` | checked `u64` debit |
| `disclosures_hash` | none | `u256` |
| `input_value_asset`, `output_value_asset` | `u32` index | `Option<(u256,u64)>` |

Use an explicit constant asset in `asset_current_script_debit` for each budget,
independent of which input is being authorized. If intentionally using a scalar
budget, first assert `current_asset` equals the intended constant. A transaction
with multiple assets needs independently specified budgets, not a sum of unlike
units. Hash-keyed sums only assert script equality by hash, not ownership.

## Rust/WASM API

All WASM functions synchronously accept JS objects, return JSON-compatible objects,
and throw errors. No endpoint silently succeeds on invalid evidence.
`compile({environment:"elements",profile:"liquid-policy-v1",script,witness,
include_debug})` returns the existing compiler response.

```ts
type Binding = {
  network?: "liquidtestnet" | "liquid"; // default liquidtestnet
  cmr_hex: string; redeem_script_hex: string; base_public_key_hex: string;
};
type ContextRequest = Binding & {
  pset_hex: string; input_index: number;
  user_pubkey: string; user_leaf_hash_hex: string;
};
type Disclosure = {
  asset_id: string; value: number;
  confidential_asset: boolean; confidential_value: boolean;
};
type AssetAccounting = {
  asset_id: string; total_input_value: number; total_output_value: number;
  fee: number; returned_value: number; debit: number;
};
type ContextSummary = {
  profile: "liquid-policy-v1"; profile_hash: string;
  network: "liquidtestnet" | "liquid"; genesis_hash: string;
  cmr: string; signing_commitment: string; redeem_script_hash: string;
  input_index: number; input_count: number; output_count: number;
  unsigned_tx_hash: string; prevouts_hash: string; disclosures_hash: string;
  cooperative_leaf_hash: string; cooperative_sighash_default: string;
  policy_approval_hash: string; policy_transaction_approval_hash: string;
  service_pubkey: string; user_pubkey: string; recovery_leaf_hash: string;
  current_asset_id: string; fee_asset_id: string;
  assets: AssetAccounting[]; inputs: Disclosure[]; outputs: Disclosure[];
  output_scripts_hex: string[]; script_pubkey_hex: string;
  vsize_lower_bound: number; provenance: string; chain_status_verified: false;
};
```

Amounts cross the JS boundary only within `Number.MAX_SAFE_INTEGER`; larger
amounts/totals are supported natively but rejected by WASM rather than rounded.
Sign raw decoded 32-byte approval/sighash digest bytes, with no extra hash.

| WASM export | Request | Exact response |
| --- | --- | --- |
| `liquid_policy_registry` | none | `{profile,profile_hash,manifest}` |
| `liquid_policy_generate_blinding_key` | none | `{blinding_secret_key_hex,blinding_public_key_hex}` |
| `liquid_policy_recovery_script` | human-readable `string` | `{redeem_script_hex,user_leaf_hash_hex}` using Elements TapLeaf/default `0xc4` |
| `liquid_policy_local_tweak` | `Binding` | `{profile,profile_hash,network,genesis_hash,cmr,signing_commitment,public_key_hex,base_public_key_hex}` |
| `liquid_policy_address` | `{binding:Binding,user_pubkey,user_leaf_hash_hex,blinding_public_key_hex?:string}` | `{address,unconfidential_address,script_pubkey_hex,service_pubkey,cooperative_script_hex,control_block_hex,profile,profile_hash,network}` |
| `liquid_policy_unblind_output` | `{parent_tx_hex,txid,vout,blinding_secret_key_hex?:string}` | `{txid,vout,script_pubkey_hex,chain_status_verified:false,disclosure:{asset_id,value_sat,confidential,blind_asset_proof_hex:string|null,blind_value_proof_hex:string|null}}` |
| `liquid_policy_create_pset` | creation below | `{pset_hex,transaction_hex,txid,inputs:number,outputs:number,network}` (unsigned transaction for subsequent full-parent evidence) |
| `liquid_policy_context` | `ContextRequest` | `{context:ContextSummary}` |
| `liquid_policy_evaluate` | `{prepared:ContextRequest,program_base64,witness_base64}` | `{accepted:true,context,execution_cost_milliweight:number}` |
| `liquid_policy_verify_signed_pset` | `{prepared:ContextRequest,signed_pset_hex,signature_hex,public_key_hex}` | `{verified:true,context}` |
| `liquid_policy_user_sign` | `{prepared:ContextRequest,signed_pset_hex,secret_key_hex}` | `{pset_hex,signature_hex,public_key_hex,input_index,context}` |
| `liquid_policy_finalize_pset` | `{prepared:ContextRequest,signed_pset_hex,signatures:[{input_index,signature_hex,public_key_hex}]}` | `{transaction_hex,txid,finalized:true,inputs:number,outputs:number}` |

`signature_hex` is exactly 64 Schnorr signature bytes, without a DEFAULT suffix.
Public keys are x-only hex. All hash fields use raw bytes unless explicitly
named `txid`/`asset_id`, which use their display conventions. Optional keys can
be omitted/null. Unknown request fields are rejected.

Creation shape:

```ts
{
  network?: "liquidtestnet", lock_time?: number,
  inputs: [{
    txid: string, vout: number, parent_tx_hex: string,
    blinding_secret_key_hex?: string, sequence?: number // default 0xfffffffd
  }],
  outputs: [{address: string, asset_id: string, value_sat: number}]
}
```

Use `address:"fee"` exactly once with the network fee asset. Confidential
destination addresses trigger audited `Pset::blind_last`, which generates output
proofs and balances blinding factors. Fully confidential inputs normally require
at least one confidential destination to balance their factors. Unblinding secrets
are browser-local and never retained in the resulting PSET or service request.
Reuse the local funding blinding key to discover/unblind raw parent outputs.

## Service and restart

`/simplicity-unchained/policy/liquid/{capabilities,tweak,prepare,evaluate,sign}`.
Capabilities response:

```ts
{
  profile:"liquid-policy-v1", profile_hash:string,
  network:"liquidtestnet"|"liquid", genesis_hash:string,
  base_public_key_hex:string, manifest:object,
  limits:{max_body_bytes:number,max_blocking_jobs:number}, provenance:string
}
```

Tweak request: `{profile_hash,network,program,redeem_script_hex}`; `program` is
standard base64. Response matches local tweak. Transaction requests add
`{pset_hex,input_index,user_pubkey,user_leaf_hash_hex,witness?:string}`.
Prepare/evaluate responses match the local APIs.
Sign response:
`{pset_hex,signature_hex,public_key_hex,input_index,context,
execution_cost_milliweight}`. Both signers must independently reconstruct and
compare the complete context; signatures alone cannot authenticate disclosure
interpretation. Finalization rechecks all proofs and both signatures per input.

Service configuration gains optional `liquid_network="liquidtestnet"`. It is
independent from Bitcoin's configured network. The existing running binary
cannot expose these routes until rebuilt/restarted. No generated WASM package,
running PID, actual configuration or private key is modified by source work.

## Reproducible test fixture

[`tests/fixtures/liquid-policy-v1.json`](tests/fixtures/liquid-policy-v1.json)
contains deterministic, **public test-only** signing/blinding keys, synthetic
parent transactions, source/script/key bindings, fully confidential two-asset
PSET, all input summaries, real service/user signatures, final transaction and
12 negative PSET encodings (rejected during decoding or cryptographic context
verification). Never fund its known keys or unconditional test
program. Its parents are content evidence only, not mined/unspent outputs.

Exact fixture schema (all fields required; `ContextSummary` is defined above):

```ts
type FixtureSignature = {
  input_index: number; public_key_hex: string; signature_hex: string;
};
type LiquidPolicyFixture = Record<
  | "warning" | "profile" | "profile_hash" | "network" | "source"
  | "program_base64" | "witness_base64" | "cmr_hex" | "redeem_script_hex"
  | "recovery_script" | "user_leaf_hash_hex" | "base_public_key_hex"
  | "user_pubkey" | "blinding_public_key_hex" | "source_parent_tx_hex"
  | "source_parent_txid" | "parent_tx_hex" | "parent_txid" | "pset_hex"
  | "service_signed_pset_hex" | "fully_signed_pset_hex"
  | "transaction_hex" | "txid", string
> & {
  contexts: ContextSummary[]; // input-index aligned, exactly two
  service_signatures: FixtureSignature[]; // input-index aligned
  user_signatures: FixtureSignature[]; // input-index aligned
  test_only_secrets: {
    base_secret_key_hex: string; user_secret_key_hex: string;
    blinding_secret_key_hex: string;
  };
  negative_psets: Record<
    | "input_amount" | "input_asset" | "output_amount" | "output_asset"
    | "missing_parent" | "missing_input_asset_proof"
    | "missing_input_value_proof" | "wrong_input_value_proof"
    | "missing_output_asset_proof" | "missing_output_value_proof"
    | "missing_output_rangeproof" | "missing_output_surjection_proof", string
  >;
};
```

Regenerate with the fixed test seed (production creation uses `OsRng`):

```bash
cargo run --quiet -p simplicity-unchained-policy --example liquid_fixture \
  > policy/tests/fixtures/liquid-policy-v1.json
```

Fingerprint: `6097ac61cbd923269edaaed8cf14691cc8ba756e45949f7478f7f907f42d8ce2`.
The Bitcoin golden fingerprint remains
`0890429432ce3f797ae26e43ca6d47bdea6cd9369b32a48722a8b6385addd0c7`.

The fixture must not be submitted unchanged to a differently keyed live signer:
its funding output commits its test base key. For live-service tests derive a
fresh address from that signer's independently known base key and use the
fixture's explicit source parent to construct a new blinded synthetic funding
transaction, followed by the spending PSET. Creation now returns the unsigned
`transaction_hex` and `txid` for that full-parent construction. Do not substitute
PSET asset labels or wallet-provided values for local unblinding/disclosure proofs.

The Rust/WASM crate includes a Node-target release integration harness:

```bash
cargo build --manifest-path ../simplicity-unchained-web-demo/simplicity-lib/Cargo.toml \
  --target wasm32-unknown-unknown --release --locked
wasm-bindgen --target nodejs \
  --out-dir ../simplicity-unchained-web-demo/simplicity-lib/target/liquid-node-validation \
  ../simplicity-unchained-web-demo/simplicity-lib/target/wasm32-unknown-unknown/release/simplicity_lib.wasm
node ../simplicity-unchained-web-demo/simplicity-lib/tests/liquid-policy-node.cjs \
  ../simplicity-unchained-web-demo/simplicity-lib/target/liquid-node-validation/simplicity_lib.js
```

If the surrounding Node package is ESM, place `{"type":"commonjs"}` in the isolated
binding directory's `package.json`; do not replace the browser's generated `pkg`.
This executes all 12 real Liquid WASM exports, rechecks both native fixture
signatures, co-signs/finalizes, blinds a fresh two-asset PSET, and rejects the
negative encodings/network/profile/signature mutations.

## Recorded implementation validation

Executed from the native repository root; all commands below passed. The four
native and three browser ignored cases are pre-existing.

| Exact command | Result |
|---|---|
| `cargo test -p cli --test liquid_policy --quiet` | 2 passed; real CLI creation, user co-signing and finalization, independent remote response verification |
| `cargo test -p simplicity-unchained-policy --test liquid bitcoin_profile_funding_script_is_not_reinterpreted_as_liquid_contract --quiet` | 1 passed; Bitcoin-profile funding scripts rejected |
| `TMPDIR="$PWD/target" cargo test --workspace --quiet` | 121 passed, 4 ignored; includes confidential multi-asset kernel, HTTP and CLI roundtrips and proof/value/asset/evidence/signature/approval replay rejection |
| `cargo clippy -p simplicity-unchained-policy -p core -p cli -p service --all-targets --quiet -- -D warnings` | Passed without warnings |
| `cargo check -p simplicity-unchained-policy --target wasm32-unknown-unknown --quiet` | Portable kernel standalone WASM target passed |
| `cargo build -p service --release --locked --quiet` | Release service built |
| `cargo test --manifest-path /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/Cargo.toml --quiet` | 22 passed, 3 ignored; all 66 compiler jets and explicit two-asset budgets covered |
| `cargo clippy --manifest-path /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/Cargo.toml --all-targets --quiet -- -D warnings` | Passed without warnings |
| `cargo build --manifest-path /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/Cargo.toml --target wasm32-unknown-unknown --release --locked --quiet` | Release WASM built |
| `wasm-bindgen --target nodejs --out-dir /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/target/liquid-node-validation /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/target/wasm32-unknown-unknown/release/simplicity_lib.wasm` | Isolated Node bindings generated, browser `pkg` untouched |
| `node /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/tests/liquid-policy-node.cjs /Users/user/Documents/Projects/blockstream/simplicity-unchained-web-demo/simplicity-lib/target/liquid-node-validation/simplicity_lib.js` | All 12 Liquid exports; genuine confidential two-asset roundtrip; all 12 negative proof/label/evidence encodings; signature/network/profile failures; both canonical fingerprints matched |
| `git --no-pager diff --check` | Passed |

The actual HTTP handlers were exercised in-process; the existing old external
service was not restarted or claimed to support these routes. Once authorized,
the coordinator can preserve its exact existing working directory/configuration
and signing key with:

```bash
cd /Users/user/Documents/Projects/blockstream/simplicity-unchained/service
kill -TERM 49509
../target/release/service start --config config.toml
```

Run the last command under the coordinator's managed long-lived process facility,
then verify the Liquid capabilities route and its `liquidtestnet` network and
canonical fingerprint before enabling live signing. Regenerate the browser WASM
package from final Rust sources separately; source validation does not modify it.
