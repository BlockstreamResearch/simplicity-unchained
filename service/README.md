# Simplicity Unchained Service

Simplicity Unchained Service is a web service that provides endpoints to interact with the Simplicity Unchained oracle. It currently supports a 2-of-2 multisig side effect triggered by the execution of Simplicity programs.

## Starting the Service

To start the Simplicity Unchained Servic navigate to the `service` directory and run the following command:

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
port = 8080
# secpr256k1 32-byte hex-encoded private key, used for signing
# this is a demo key, do not use it anywhere else
private_key = "804622cda0d8e634317a12651d91751ceff5c081f2b5f63ef7912725c7275e5d"
# Network to get metadata from: liquid or liquidtestnet
network = "liquidtestnet"
```

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

### 2. Sign PSET Endpoint

`POST /simplicity-unchained/sign/pset`: Accepts a Simplicity program and its inputs, executes it, and if successful, co-signs a 2-of-2 multisig transaction.
**Request Body**:

```json
{
  "pset_hex": "70736574ff...",
  "input_index": 0,
  "redeem_script_hex": "5221...",
  "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA",
  "witness": ""
}
```

**Request Fields**:
- `pset_hex`: The PSET (Partially Signed Elements Transaction) encoded as a hexadecimal string
- `input_index`: The index of the transaction input to sign (must be between 0 and 65535)
- `redeem_script_hex`: The redeem script in hexadecimal format, used for SegWit v0 signature computation
- `program`: The Simplicity program to execute for validation before signing
- `witness`: The witness data required by the Simplicity program (can be an empty string)

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

### 3. Tweak Endpoint

`POST /simplicity-unchained/tweak`: Accepts a Simplicity program, computes its CMR (commitment Merkle root), and returns the tweaked public key using taproot key tweaking.

**Request Body**:

```json
{
  "program": "zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
}
```

**Request Fields**:
- `program`: The Simplicity program to compute the CMR from (must be a non-empty string)

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
