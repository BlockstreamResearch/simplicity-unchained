# Simplicity Unchained CLI

Command-line interface for communicating with the Simplicity Unchained service and preparing, signing and finalizing policy transactions.

## Commands

Run from the repository root with `cargo run --quiet -p cli -- <command>`, or use the built `simplicity-unchained` binary. Use `--help` with any command or subcommand for its arguments.

```plaintext
Usage: simplicity-unchained <COMMAND>

Commands:
  liquid-policy  Confidential multi-asset Liquid policy utilities
  policy         Bitcoin policy funding, evaluation and signing
  keypair        Keypair operations
  help           Print this message or the help of the given subcommand(s)
```

### keypair

- `keypair generate` — Generate a new secp256k1 keypair.

## Bitcoin policy workflow

Compile programs for `bitcoin-policy-v1`. See the [policy examples](../examples/policy/README.md) for recipient allowlists, debit and fee caps, threshold approvals and source/locktime restrictions.

| `policy` operation | Behavior |
|---|---|
| `capabilities` | Check the service's registry, fingerprint, network and genesis hash. |
| `tweak` | Derive and verify the service's policy-bound cooperative key before funding. |
| `build-csv-leaf` | Build a Bitcoin recovery script from `--user-pubkey` and `--timelock` (1–65535 blocks). Retain this script privately. |
| `address` | Derive the funding address locally from the program, network, base service key, user key and recovery hash. |
| `prepare` | Compare the service's context with locally verified full parent evidence, without approval signatures. |
| `evaluate` | Locally evaluate the witnessed policy and compare the service context and bounded cost; no transaction signature. |
| `approval-hash` | Locally compute J53/J54 from verified parents; no signing-service contact. |
| `sign` | Evaluate the policy, request the service signature and verify the returned signature and PSBT. |
| `user-sign` | Verify the context and service signature, then add the user's signature locally using `--secret-key-file`. |
| `finalize` | Verify the policy binding, parent evidence and both signatures for **every** input before producing transaction hex. No broadcast. |

`--profile` defaults to `bitcoin-policy-v1`; `--profile-hash` can pin the compiled fingerprint. `--network` defaults to **`testnet4`** and must match the service. Accepted networks are `bitcoin`, `testnet` and `testnet4`.

`--service` defaults to `http://127.0.0.1:30431`. Supply an HTTP(S) origin without an endpoint path, credentials, query or fragment. Use TLS for remote deployments. Remote Bitcoin calls use `/simplicity-unchained/policy/bitcoin`.

### Before funding

Choose the reviewed program, exact script data, independently known base signing
key and user/recovery keys first. `tweak` returns `public_key_hex` as an **x-only**
cooperative leaf key, not the Taproot internal key.

```bash
SERVICE_ORIGIN=http://127.0.0.1:30431
cargo run --quiet -p cli -- policy capabilities \
  --network testnet4 --service "$SERVICE_ORIGIN"
cargo run --quiet -p cli -- policy build-csv-leaf \
  --user-pubkey "$USER_PUBLIC_KEY_HEX" --timelock 144
# Retain its script and use its raw leaf_hash as RECOVERY_LEAF_HASH_HEX.
POLICY_ARGS=(
  --network testnet4
  --program "$POLICY_PROGRAM_BASE64"
  --redeem-script-hex "$REDEEM_SCRIPT_HEX"
)
cargo run --quiet -p cli -- policy tweak "${POLICY_ARGS[@]}" \
  --base-public-key "$BASE_SERVICE_PUBLIC_KEY_HEX" --service "$SERVICE_ORIGIN"
cargo run --quiet -p cli -- policy address "${POLICY_ARGS[@]}" \
  --base-public-key "$BASE_SERVICE_PUBLIC_KEY_HEX" \
  --user-pubkey "$USER_PUBLIC_KEY_HEX" \
  --user-leaf-hash-hex "$RECOVERY_LEAF_HASH_HEX"
```

`--program` takes standard base64. `--redeem-script-hex` commits exact bytes
(empty by default); changing them changes the address. `address` works offline
with the known base key and compiled profile. Check service capabilities and a
key-pinned `tweak` before funding.

### Prepare, approve and co-sign

Construct an unsigned version-2 PSBT using your Bitcoin wallet or PSBT tooling.
All inputs must spend the same policy-bound P2TR output, with one to eight inputs
and outputs. Provide full `non_witness_utxo` parents for **every** input.

Parent verification is offline unless a resolver is configured, and fails if
evidence is missing. Use `--offline` to forbid fetching, or set
`--esplora-url https://mempool.space/testnet4/api` (or your own network-matching
Esplora API). Missing parents are fetched from `/tx/<txid>/raw`, deduplicated and
checked against the outpoints. Missing `witness_utxo` is populated from the
verified parent; conflicting values/scripts fail. Context is validated **before
contacting the signing service**. There are no automatic signing retries.

```bash
TX_ARGS=(
  "${POLICY_ARGS[@]}"
  --psbt "$PSBT_HEX" --input-index 0
  --user-pubkey "$USER_PUBLIC_KEY_HEX"
  --user-leaf-hash-hex "$RECOVERY_LEAF_HASH_HEX"
  --base-public-key "$BASE_SERVICE_PUBLIC_KEY_HEX"
  --offline
)
cargo run --quiet -p cli -- policy approval-hash "${TX_ARGS[@]}"
cargo run --quiet -p cli -- policy prepare "${TX_ARGS[@]}" --service "$SERVICE_ORIGIN"
# Review the context, sign the decoded J54 or J53 bytes, and encode the witness.
cargo run --quiet -p cli -- policy evaluate "${TX_ARGS[@]}" \
  --witness "$APPROVAL_WITNESS_BASE64" --service "$SERVICE_ORIGIN"
cargo run --quiet -p cli -- policy sign "${TX_ARGS[@]}" \
  --witness "$APPROVAL_WITNESS_BASE64" --service "$SERVICE_ORIGIN"
```

`prepare` needs no witness. `evaluate`/`sign` require standard-base64 `--witness`;
use `--witness ''` only for a witness-free program. The returned `context` includes
amounts, fees, debit, output scripts, keys and verification provenance for review:

- `policy_approval_hash` (J53) binds the selected input and actual signing digest.
- `policy_transaction_approval_hash` (J54) can deliberately authorize all
  same-contract inputs in this transaction.
- Sign the **decoded 32-byte digest** directly with BIP-340, not ASCII hex or
  another SHA256. Any approved transaction/context change requires fresh approvals.
- Static hashlocks and fixed-message signatures are replayable; caps apply per transaction.

Repeat `sign` and `user-sign` for every input, using the latest `psbt_hex` each
time. `user-sign` takes all the same transaction arguments and a file containing
only the user's 64-character private-key hex (surrounding whitespace is allowed).
Keep this file private, never commit it, and never send it to the service.
The CLI checks the secret against the committed user key.

```bash
# Rebuild TX_ARGS with the service-returned PSBT_HEX before each invocation.
cargo run --quiet -p cli -- policy user-sign "${TX_ARGS[@]}" \
  --secret-key-file "$USER_SECRET_KEY_FILE"
# Rebuild TX_ARGS with user-sign's psbt_hex; repeat for all remaining inputs.
cargo run --quiet -p cli -- policy finalize "${TX_ARGS[@]}"
```

Finalization verifies the committed canonical leaf/control block and both
SIGHASH_DEFAULT signatures; missing signatures or tampered metadata fail.
Broadcast the resulting `transaction_hex` using your wallet only after separately
checking chain status, fee rate and transaction acceptance.

Bitcoin policy commands print JSON. Failures after argument parsing print
`{"error":"..."}`, diagnostic stderr and a nonzero exit. Clap usage errors print
normal stderr usage. `parent-txid-verified` proves parent **content**, not active
chain membership, confirmation, consensus validity or unspentness;
`chain_status_verified` is always false.

## Liquid policy workflow

Compile programs for `liquid-policy-v1`. The network defaults to `liquidtestnet`;
`liquid` is also supported. See the [Liquid profile](../policy/LIQUID.md) for
disclosure proofs, asset semantics and creation schemas.

`liquid-policy registry` prints the manifest. Other operations, except
`generate-blinding-key`, accept `--request-file path.json`. A transaction request
has this shape:

```json
{
  "profile": "liquid-policy-v1",
  "network": "liquidtestnet",
  "program": "<standard-base64 compiled Liquid policy>",
  "redeem_script_hex": "<exact committed bytes>",
  "base_public_key_hex": "<known base x-only key>",
  "pset_hex": "<PSET with full parents and disclosure proofs>",
  "input_index": 0,
  "user_pubkey": "<user x-only key>",
  "user_leaf_hash_hex": "<raw Elements recovery leaf hash>",
  "witness": "<standard-base64 witness; empty for a witness-free program>"
}
```

Optional `profile_hash` pins the compiled fingerprint. `address` can add
`blinding_public_key_hex` for a confidential address. `create` uses a separate
request shape with full parents and optional local blinding secrets; keep these
creation files private. Receiving secrets are not sent to the service.

| `liquid-policy` operation | Behavior |
| --- | --- |
| `registry` | Print the local registry and fingerprint. |
| `generate-blinding-key` | Generate a receiving keypair locally; keep the secret private. |
| `address`, `tweak` | Derive the funding address or service key locally. |
| `capabilities` | Check the remote manifest, network, genesis hash and known base key. |
| `create` | Build and blind a multi-asset PSET with disclosure proofs. |
| `prepare`, `approval-hash` | Verify evidence and produce the local context or approval hashes. |
| `evaluate` | Evaluate the witnessed policy locally. |
| `sign` | Evaluate locally, request a service signature and verify the returned PSET and signature. |
| `user-sign` | Verify the service signature and add the user's signature using `--secret-key-file`. |
| `finalize` | Verify proofs and both signatures for every input, then produce transaction hex. |

Only `capabilities` and `sign` contact the service. They accept `--service`,
defaulting to `http://127.0.0.1:30431`.

```bash
cargo run --quiet -p cli -- liquid-policy registry
cargo run --quiet -p cli -- liquid-policy capabilities --request-file request.json
cargo run --quiet -p cli -- liquid-policy prepare --request-file request.json
cargo run --quiet -p cli -- liquid-policy evaluate --request-file request.json
cargo run --quiet -p cli -- liquid-policy sign --request-file request.json
```

Update `pset_hex` with each returned PSET and repeat `sign` and `user-sign` for
every input before `finalize`. Approval signatures use decoded J53/J54 digest
bytes, as in the Bitcoin workflow.

## Demo

Provision a unique private service key following the
[startup instructions](../service/README.md#starting-the-service), then run:

```bash
cd service
cargo run --quiet -- start
# In another terminal, from the repository root:
./cli/scripts/demo_btc.sh --help
```

The Bitcoin script requires `cargo` and `jq`. It defaults to Testnet4 and has
three modes: `address`, `review` (default) and `sign`. Its `--help` lists the
required environment variables for the program, script data, base service key,
user key and recovery hash. `review` and `sign` also require a PSBT and witness;
`sign` requires a private user key file.

The script handles one input. It does not fetch faucet funds or broadcast, and
`review` does not request a signature. Use the commands above for multi-input
spends or Liquid.

## Licence

See the [LICENCE](../LICENCE) file for details.
