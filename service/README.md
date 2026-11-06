# Simplicity Unchained Service

Simplicity Unchained Service evaluates committed policies and co-signs Bitcoin and Liquid transactions. It exposes `bitcoin-policy-v1` and `liquid-policy-v1` through separate API paths.

## Starting the Service

For a new service, provision a configuration with a unique, persistent signing
key. Reuse the existing private configuration when restarting a funded service.

```bash
umask 077
cd service
cp config.example.toml config.toml
```

Set `service.private_key` in the local `config.toml` to a newly generated
32-byte secp256k1 private key (64 hex characters). Use a cryptographically secure
generator, for example `openssl rand -hex 32`, and edit the file locally without
putting the key in command-line arguments. Keep the file private and backed up;
do not commit it or put it in a Docker build context. The example's empty key
cannot start the service.

Then start the service:

```bash
cargo run --quiet -- start
```

You can specify a custom configuration file using `--config`:

```bash
cargo run --quiet -- start --config path/to/your/config.toml
```

By default, the service looks for `config.toml` in the current directory. Invalid
configuration exits with a nonzero status.

## Configuration

```toml
[service]
# Port on which the service will run
port = 30431
# Required: provision a unique, persistent 32-byte private key.
private_key = ""
# Bitcoin network: bitcoin, testnet, testnet4
bitcoin_network = "testnet4"
# Liquid network: liquid or liquidtestnet (default)
liquid_network = "liquidtestnet"
```

`bitcoin_network` is required. `liquid_network` is optional and defaults to
Liquid Testnet. Requests must match the configured network for their profile.

### Docker

To run the prebuilt release image without compiling, follow
[Run your own SU service](../README.md#run-your-own-su-service).
The instructions below build an image from the local checkout.

The image contains the service binary but no active configuration or signing key.
Provision a configuration outside the build context using the example above,
then mount it read-only:

```bash
docker build -t simplicity-unchained-service .
docker run --rm -p 30431:30431 \
  --mount type=bind,src=/absolute/path/to/service-config.toml,dst=/app/config.toml,readonly \
  simplicity-unchained-service
```

Run these commands from the repository root. The host file must exist and be
readable by the container's service user (UID/GID 1000), without making the key
world-readable. Adjust the published port if you change `service.port`.

## Endpoints

### 1. Version Endpoint

`GET /simplicity-unchained/version` returns the service package version:

```json
{
  "version": "0.1.0"
}
```

### 2. Policy Endpoints

Bitcoin operations use `/simplicity-unchained/policy/bitcoin`; Liquid operations
use `/simplicity-unchained/policy/liquid`.

| Method | Path suffix | Operation |
|---|---|---|
| GET | `/capabilities` | Return the profile fingerprint, manifest, network, genesis hash, base public key and limits. |
| POST | `/tweak` | Derive the policy-bound cooperative key before funding. |
| POST | `/prepare` | Verify transaction evidence and return the context without requiring approval witnesses. |
| POST | `/evaluate` | Evaluate the witnessed policy without signing. |
| POST | `/sign` | Prepare and evaluate again, then co-sign the selected input. |

The [CLI](../cli/README.md) checks the service manifest, network and known base
key, reconstructs the context locally and verifies returned signatures.

**Program binding**

All POST operations require these fields. This example is for Bitcoin:

```json
{
  "profile_hash": "<compiled manifest fingerprint>",
  "network": "testnet4",
  "program": "<standard-base64 bitcoin-policy-v1 program>",
  "redeem_script_hex": ""
}
```

For Liquid, use its fingerprint, compiled program and configured network.
`redeem_script_hex` is required; `""` commits zero script-data bytes.

`/tweak` returns `profile`, `profile_hash`, `network`, `genesis_hash`, `cmr`,
`signing_commitment`, `public_key_hex` and `base_public_key_hex`.
`public_key_hex` is the 32-byte x-only cooperative leaf key, not the Taproot
internal key. The commitment binds the profile, genesis hash, CMR and script
data; see the [kernel specification](../policy/README.md).

**Transaction requests**

`prepare`, `evaluate` and `sign` add these fields to the binding:

```json
{
  "psbt_hex": "<hex serialized PSBT>",
  "input_index": 0,
  "user_pubkey": "<compressed or x-only public key hex>",
  "user_leaf_hash_hex": "<32-byte raw recovery leaf hash>",
  "witness": "<standard-base64 witness>"
}
```

Liquid uses `pset_hex` instead of `psbt_hex`. `/prepare` does not require
`witness`; `/evaluate` and `/sign` require it, with `""` for a witness-free
program. Unknown fields are rejected.

Every input requires a full `non_witness_utxo` parent and matching
`witness_utxo`. The service verifies parent txids and referenced outputs; it
does not fetch parents. The Bitcoin CLI can populate missing evidence using an
explicit Esplora resolver before sending the request.

Both profiles accept version 2, one to eight same-contract P2TR inputs and one
to eight outputs, with SIGHASH_DEFAULT script-path signing. Duplicates,
conflicting evidence, invalid accounting and finalized input witnesses are
rejected. Liquid also verifies asset/value disclosures, range and surjection
proofs, and commitment balance. See the [Liquid profile](../policy/LIQUID.md) for
required PSET fields and per-asset rules.

**Responses**

- `/prepare`: `{"context": ...}`.
- `/evaluate`: `{"accepted":true,"context":...,"execution_cost_milliweight":...}`.
- `/sign`: `psbt_hex` (or `pset_hex`), `signature_hex`, `public_key_hex`,
  `input_index`, `context` and `execution_cost_milliweight`.

The context includes verified prevouts, output scripts, accounting, the signing
digest and approval hashes. J53 `policy_approval_hash` binds the selected input;
J54 `policy_transaction_approval_hash` can approve all same-contract inputs of
one transaction. Approvers review the context locally and sign decoded 32-byte
digests directly with BIP-340, without another SHA256.

The service does not finalize or broadcast. Add the user's signature with
`policy user-sign` or `liquid-policy user-sign`, repeat for every input, then
finalize locally.

### Limits and Errors

Requests are limited to 2 MiB, two concurrent CPU workers, a five-second response
deadline and 10,000,000 milliweight per evaluation. A timed-out worker retains
its slot until it exits. Busy requests return 503; timeouts return 504.

Invalid fields, context, proofs or policy execution return non-success HTTP
responses. Operation errors contain `error` and `code`; request-decoding
errors can return framework-generated responses.

Parent verification establishes content, not confirmation, chain membership,
unspentness or maturity. Bitcoin context reports
`provenance: "parent-txid-verified"`; Liquid provenance also lists the verified
disclosure and transaction proofs. Both report `chain_status_verified: false`.
Check live chain status separately.

## Licence

See the [LICENCE](../LICENCE) file for details.
