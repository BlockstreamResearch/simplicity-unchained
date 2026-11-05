# Simplicity Unchained CLI

Command-line interface for communicating with the Simplicity Unchained service and accessing various ecosystem utilities.

## Commands

Use the `--help` flag with any command or subcommand for the full list of arguments.

```plaintext
Usage: simplicity-unchained <COMMAND>

Commands:
  address   Address operations
  keypair   Keypair operations
  tx        Transaction operations (Elements / Liquid)
  btc-tx    Transaction operations (Bitcoin)
  help      Print this message or the help of the given subcommand(s)
```

### address

- `address multisig` — Generate a P2TR 2-of-2 multisig address from two public keys and a user leaf hash.

Pass the updated service `/tweak` response's `tweaked_public_key_hex` as
`--pubkey1`, not the untweaked service key or an old CMR-only tweaked key.
When using script-reading jets, include the intended `redeem_script_hex` in the
`/tweak` request before funding and supply the identical bytes to `/sign/psbt`
or `/sign/pset`. Use that same tweaked key for `--cosigner-pubkey` when signing
or spending the recovery leaf. The demo scripts omit the script in both
requests, consistently committing to an empty script.

### keypair

- `keypair generate` — Generate a new secp256k1 keypair.

### tx (Elements / Liquid)

- `tx create` — Create a PSET from UTXOs.
- `tx sign` — Sign a PSET with one secret key (for local co-signing).
- `tx finalize` — Finalize a PSET into a broadcastable transaction.
- `tx build-csv-leaf` — Build a CSV recovery leaf script from a user pubkey and timelock.
- `tx spend-user-leaf` — Spend the user leaf (Leaf 1) of a P2TR output independently.
- `tx finalize-user-leaf` — Finalize a user leaf PSET into a broadcastable transaction.

### btc-tx (Bitcoin)

- `btc-tx create` — Create a PSBT from UTXOs.
- `btc-tx approval-hash` — Compute the digest an approver must sign for a Bitcoin `tx_approval_hash` policy.
- `btc-tx sign` — Sign a PSBT with one secret key (for local co-signing).
- `btc-tx finalize` — Finalize a PSBT into a broadcastable transaction.
- `btc-tx build-csv-leaf` — Build a CSV recovery leaf script from a user pubkey and timelock.
- `btc-tx spend-user-leaf` — Spend the user leaf (Leaf 1) of a P2TR output independently.
- `btc-tx finalize-user-leaf` — Finalize a user leaf PSBT into a broadcastable transaction.

### Bitcoin Transaction Approvals

Use a program that explicitly verifies the approver's BIP-340 signature against
`jet::tx_approval_hash()`. Build it with the updated core `CoreExtension` jet table.
Choose the approver public key and script data before generating and funding the
address.

For each spend, populate `witness_utxo` for **every** PSBT input, independently
verify the prevouts, review the transaction, and calculate its approval digest:

```bash
cargo run --quiet -- btc-tx approval-hash \
  --psbt "$PSBT_HEX" \
  --input-index 0 \
  --program "$PROGRAM" \
  --redeem-script-hex "$REDEEM_SCRIPT_HEX" \
  --network testnet4
```

Run this from the `cli` directory. Omit `--redeem-script-hex` for an empty script.
`--network` is required and must match the service's configured `bitcoin_network`
(`bitcoin`, `testnet`, or `testnet4`), even for a local test deployment.

The JSON response contains `approval_hash_hex` and `cmr_hex`, both 64-character
hex strings. Have the approver sign the **32 decoded approval-hash bytes**, not
the ASCII hex text, using BIP-340. Encode the signature into the program's witness
and submit the same PSBT, input, program and script to `/sign/psbt`. Recompute and
obtain a fresh approval after changing the transaction or prevouts.

The approval digest is not the co-signer's Taproot sighash. See the
[versioned digest definition](../core/README.md#bitcoin-per-spend-approvals).
Static hashlocks and fixed-message signature policies retain their intentionally
replayable behavior; existing funded static policies are not upgraded by this
command.

## Demo

First, provision a private configuration and unique signing key following the
service's [startup instructions](../service/README.md#starting-the-service).
Then ensure the Simplicity Unchained service is running:

```bash
cd service
cargo run --quiet -- start
```

Then, in a separate terminal, navigate to the `cli` directory and run one of the demo scripts:

### Bitcoin (regtest)

Requires a running `bitcoind` in regtest mode and `bitcoin-cli` in your `PATH`:

```bash
bitcoind -regtest -fallbackfee=0.0002 -txindex=1 -daemon
bitcoin-cli -regtest loadwallet <wallet>
```

```bash
cd cli
./scripts/demo_btc.sh            # 2-of-2 co-signing via Simplicity program
./scripts/demo_btc_user_leaf.sh  # CSV recovery leaf spend
```

### Elements / Liquid Testnet

Requires `curl` and `jq` in your `PATH`. Transactions are broadcast to Liquid Testnet via the Blockstream API.

```bash
cd cli
./scripts/demo_elements.sh            # 2-of-2 co-signing via Simplicity program
./scripts/demo_elements_user_leaf.sh  # CSV recovery leaf spend
```

> ⚠️ **Warning: Liquid Testnet Faucet rate limit**
>
> The Elements demo scripts interact with the Liquid Testnet Faucet, which imposes a rate limit. If the script fails due to rate limiting, wait at least one minute before retrying.

## Licence

See the [LICENCE](../LICENCE) file for details.
