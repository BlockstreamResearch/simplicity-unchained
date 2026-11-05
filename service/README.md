# Simplicity Unchained Service

Simplicity Unchained Service is a web service that provides endpoints to interact with the Simplicity Unchained oracle. It currently supports a 2-of-2 multisig side effect triggered by the execution of Simplicity programs.

## Starting the Service

First provision a configuration with a unique, persistent signing key:

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
deliberately cannot start the service.

Then start the service:

```bash
cargo run --quiet -- start
```

You can optionally specify a custom configuration file using the `--config` flag:

```bash
cargo run --quiet -- start --config path/to/your/config.toml
```

By default, service configuration looks for a `config.toml` file in the current directory.

## Configuration

```toml
[service]
# Port on which the service will run
port = 30431
# Required: replace locally with a unique, persistent 32-byte private key.
private_key = ""
# Network to get metadata from: liquid or liquidtestnet
elements_network = "liquidtestnet"
# Bitcoin network for signature computation: bitcoin, testnet, testnet4
bitcoin_network = "testnet4"
```

### Docker

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
Starting the image without provisioning fails closed with a nonzero exit.

## Endpoints

The service exposes the following endpoints:

### 1. Version Endpoint

`GET /simplicity-unchained/version`: Returns the current version of the service.

**Success Response**:

```json
{
  "version": "0.1.0"
}
```

### 2. Sign PSBT Endpoint

`POST /simplicity-unchained/sign/psbt`: Accepts a Simplicity program and its inputs, executes it, and if successful, co-signs a 2-of-2 multisig Bitcoin transaction.

For per-spend authorization, the program must verify an approver signature over
`jet::tx_approval_hash()`. The runner derives this digest from the PSBT, all
prevouts, input index, configured Bitcoin network, and program/script commitment.
Use the [local approval workflow](../cli/README.md#bitcoin-transaction-approvals)
before requesting the signature. All inputs need `witness_utxo`; the approver
must verify those prevouts independently.

A fixed-message signature, hash preimage, or other static condition is still
replayable across transactions. Merely providing a PSBT or using the new runner
does not convert such a policy into per-spend approval. Existing static contracts
need a new program/address to adopt the new condition. See the
[digest definition and compatibility rules](../core/README.md#bitcoin-per-spend-approvals).

**Request Body**:

```json
{
  "psbt_hex": "70736274ff...",
  "input_index": 0,
  "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
  "user_pubkey": "02...",
  "user_leaf_hash_hex": "a1b2c3...",
  "witness": null,
  "redeem_script_hex": null
}
```

**Request Fields**:

- `psbt_hex`: The PSBT (Partially Signed Bitcoin Transaction) encoded as a hexadecimal string
- `input_index`: The index of the transaction input to sign (must be between 0 and 65535)
- `program`: The Simplicity program to execute for validation before signing
- `user_pubkey`: The user's compressed public key in hexadecimal format
- `user_leaf_hash_hex`: The user leaf hash in hexadecimal format, used to reconstruct the taproot tree
- `witness`: The witness data required by the Simplicity program (optional)
- `redeem_script_hex`: Script bytes exposed to script-reading jets (optional; null or omitted means empty). Must exactly match the script supplied to `/tweak` before funding.

**Success Response**:

```json
{
  "psbt_hex": "70736274ff...",
  "signature_hex": "3045022100...",
  "public_key_hex": "02...",
  "input_index": 0,
  "partial_sigs_count": 1
}
```

**Error Response**:

```json
{
  "error": "Validation failed: ..."
}
```

### 3. Sign PSET Endpoint

`POST /simplicity-unchained/sign/pset`: Accepts a Simplicity program and its inputs, executes it, and if successful, co-signs a 2-of-2 multisig transaction.
**Request Body**:

```json
{
  "pset_hex": "70736574ff...",
  "input_index": 0,
  "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
  "user_pubkey": "02...",
  "user_leaf_hash_hex": "a1b2c3...",
  "witness": null,
  "redeem_script_hex": null
}
```

**Request Fields**:

- `pset_hex`: The PSET (Partially Signed Elements Transaction) encoded as a hexadecimal string
- `input_index`: The index of the transaction input to sign (must be between 0 and 65535)
- `program`: The Simplicity program to execute for validation before signing
- `user_pubkey`: The user's compressed public key in hexadecimal format
- `user_leaf_hash_hex`: The user leaf hash in hexadecimal format, used to reconstruct the taproot tree
- `witness`: The witness data required by the Simplicity program (optional)
- `redeem_script_hex`: Script bytes exposed to script-reading jets (optional; null or omitted means empty). Must exactly match the script supplied to `/tweak` before funding.

**Success Response**:

```json
{
  "pset_hex": "70736574ff...",
  "signature_hex": "3045022100...",
  "public_key_hex": "02...",
  "input_index": 0,
  "partial_sigs_count": 1
}
```

**Error Response**:

```json
{
  "error": "Validation failed: ..."
}
```

### 4. Tweak Endpoint

`POST /simplicity-unchained/tweak`: Accepts a Simplicity program and script data, computes its CMR (commitment Merkle root), and returns the public key tweaked with a commitment to both.

### **Note**

The tweaked key is used in the cooperative multisig leaf, not as the P2TR internal key.

**Request Body**:

```json
{
  "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
  "jet_env": "elements",
  "redeem_script_hex": null
}
```

**Request Fields**:

- `program`: The Simplicity program to compute the CMR from (must be a non-empty string)
- `jet_env`: The jet environment to use, either `elements` or `bitcoin` (optional, defaults to `elements`)
- `redeem_script_hex`: Exact script bytes to commit to and later expose to script-reading jets (optional; null, omitted, or `""` means empty).

**Success Response**:

```json
{
  "cmr_hex": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
  "tweaked_public_key_hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

**Response Fields**:

- `cmr_hex`: The 32-byte commitment Merkle root (CMR) of the program, encoded as a 64-character hexadecimal string
- `tweaked_public_key_hex`: The 33-byte compressed tweaked public key, encoded as a 66-character hexadecimal string

**Error Response**:

```json
{
  "error": "Failed to parse program: ..."
}
```

## Licence

See the [LICENCE](../LICENCE) file for details.
