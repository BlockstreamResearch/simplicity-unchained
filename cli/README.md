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
- `btc-tx sign` — Sign a PSBT with one secret key (for local co-signing).
- `btc-tx finalize` — Finalize a PSBT into a broadcastable transaction.
- `btc-tx build-csv-leaf` — Build a CSV recovery leaf script from a user pubkey and timelock.
- `btc-tx spend-user-leaf` — Spend the user leaf (Leaf 1) of a P2TR output independently.
- `btc-tx finalize-user-leaf` — Finalize a user leaf PSBT into a broadcastable transaction.

## Demo

First, ensure the Simplicity Unchained service is running:

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
