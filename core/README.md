# Simplicity Unchained Core

Contains the fundamental logic for executing Simplicity programs and interacting with the Elements blockchain.

## Capabilities

- Execute Simplicity programs with provided data and environment.
- Utilities for interacting with Elements and Simplicity environments.
- Custom execution environment supporting the injection of custom jets.
- Provides API for loading custom Jet trait implementation derived via jet_plugins crate via dynamic library.

## How It Works

### The Unchained Model

The core idea is to bind a Simplicity program to a co-signer's key using taproot key tweaking, without requiring Simplicity to be a consensus rule on-chain. The oracle commits to a specific program at address-generation time; it can only produce a valid signature if that exact program executes successfully.

1. The user writes a Simplicity program encoding the conditions they want enforced (e.g. a signature check, a hash preimage, an oracle assertion).
2. The service computes the **CMR** (Commitment Merkle Root) of the program — a 32-byte hash that uniquely identifies the program's structure and semantics.
3. The service tweaks its own internal key with the CMR using the standard taproot tweak: `tweaked_key = tap_tweak(service_key, CMR)`. This binds the co-signer's key irrevocably to that program.
4. A P2TR address is constructed using the tweaked co-signer key and the user's key (see below). Funds sent to this address can only move with the oracle's cooperation — and the oracle will only cooperate if the Simplicity program passes.

### Taproot Tree Structure

Each P2TR address produced by Simplicity Unchained has the following structure:

```plaintext
P2TR output
├── Internal key: unspendable key
└── Script tree
    ├── Leaf 0 — Co-signing leaf (2-of-2 multisig)
    │     <cosigner_tweaked_xonly> OP_CHECKSIG
    │     <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
    └── Leaf 1 — User recovery leaf (CSV + user key, hidden from the service)
```

**Internal key**: A provably unspendable key is used as the internal key.

**Leaf 0 — Co-signing leaf**: A 2-of-2 Schnorr multisig script. Both the co-signer and the user must sign. The co-signer's x-only key embedded here is the CMR-tweaked service key, so this leaf is only spendable with signatures from a service that has already executed the matching Simplicity program successfully.

**Leaf 1 — User recovery leaf**: A user-controlled script (example is a CSV timelock + user key) that allows the user to recover funds unilaterally after the timelock expires, with no involvement from the service. The service receives only the *hash* of this leaf (`user_leaf_hash`) and never sees the script itself, preserving the user's privacy for the recovery path.

### Co-signing Flow

When a user wants to spend from the address:

1. The user constructs a PSBT/PSET spending transaction and submits it to the service along with the Simplicity program, any required witness data, their public key, and the user leaf hash.
2. The service executes the Simplicity program against the transaction environment.
3. If execution succeeds, the service re-derives the tweaked co-signer key from the CMR, reconstructs the taproot tree (co-signing leaf + hidden user leaf), computes the script-path sighash for Leaf 0, and returns a Schnorr signature.
4. The user adds their own signature for the same leaf and finalizes the transaction.

If the Simplicity program fails, the service refuses to sign and the funds remain locked.

## Licence

See the [LICENCE](../LICENCE) file for details.
