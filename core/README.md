# Simplicity Unchained Core

Contains the fundamental logic for executing Simplicity programs with Bitcoin and Elements environments.

## Capabilities

- Execute Simplicity programs with provided data and environment.
- Utilities for interacting with Elements and Simplicity environments.
- Custom execution environment extending the Bitcoin and Elements jet sets with additional jets.

## How It Works

### The Unchained Model

The core idea is to bind a Simplicity program to a co-signer's key using taproot key tweaking, without requiring Simplicity to be a consensus rule on-chain. The oracle commits to a specific program at address-generation time; it can only produce a valid signature if that exact program executes successfully.

1. The user writes a Simplicity program encoding the conditions they want enforced (e.g. a signature check, a hash preimage, an oracle assertion).
2. The service computes the **CMR** (Commitment Merkle Root) of the program — a 32-byte hash that uniquely identifies the program's structure and semantics.
3. The service commits to both the CMR and the exact script bytes exposed to script-reading jets, then applies the standard taproot tweak: `tweaked_key = tap_tweak(service_key, signing_commitment(CMR, redeem_script))`. This binds the co-signer's key to that program and its script data.
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

**Leaf 0 — Co-signing leaf**: A 2-of-2 Schnorr multisig script. Both the co-signer and the user must sign. The co-signer's x-only key embedded here commits to the program and script data, so this leaf is only spendable with signatures from a service that has already executed the matching Simplicity program with the matching script successfully.

**Leaf 1 — User recovery leaf**: A user-controlled script (example is a CSV timelock + user key) that allows the user to recover funds unilaterally after the timelock expires, with no involvement from the service. The service receives only the *hash* of this leaf (`user_leaf_hash`) and never sees the script itself, preserving the user's privacy for the recovery path.

### Co-signing Flow

When a user wants to spend from the address:

1. The user constructs a PSBT/PSET spending transaction and submits it to the service along with the Simplicity program, the same `redeem_script_hex` used at address generation, any required witness data, their public key, and the user leaf hash.
2. The service executes the Simplicity program against the transaction environment. Per-spend authorization requires the program to actually verify a transaction-dependent condition; a hash preimage or signature over a fixed message remains reusable.
3. If execution succeeds, the service re-derives the tweaked co-signer key from the CMR and script, reconstructs the taproot tree (co-signing leaf + hidden user leaf), checks that it matches the input's `witness_utxo.script_pubkey`, computes the script-path sighash for Leaf 0, and returns a Schnorr signature.
4. The user adds their own signature for the same leaf and finalizes the transaction.

If the Simplicity program fails, the service refuses to sign and the funds remain locked.

### Bitcoin Per-Spend Approvals

The Bitcoin extension exposes `tx_approval_hash: ONE -> 2^256`. A policy requiring
an approver's authorization for each spend must verify a BIP-340 signature over
this digest, not a constant message or a requester-supplied digest:

```text
approval_hash = jet::tx_approval_hash()
jet::bip_0340_verify((committed_approver_pubkey, approval_hash), witness_signature)
```

The approver can calculate the exact digest locally using
`bitcoin_execution_environment` or the CLI's
[`btc-tx approval-hash`](../cli/README.md#bitcoin-transaction-approvals) command.
All inputs must have `witness_utxo` populated. The approver must independently
verify those prevouts and review the transaction before signing the digest.

The version 1 digest is a single SHA256 hash of this concatenation:

```text
tag_hash || tag_hash || network_id || input_index_be32 ||
signing_commitment(CMR, redeem_script) ||
SHA256(bitcoin_consensus_encode(unsigned_transaction)) ||
SHA256(bitcoin_consensus_encode(prevouts_vector))
```

`tag_hash = SHA256("SimplicityUnchained/BitcoinApproval/v1")`.
`network_id` is one byte: `0` for `bitcoin`, `1` for `testnet`, `2` for `testnet4`.
The input index is four bytes, big-endian. The prevouts vector contains each
input's `witness_utxo` in transaction order, including its value and script; its
Bitcoin consensus encoding includes the CompactSize vector length. All hashes
here are single SHA256, not SHA256d. The program/script commitment is defined
below.

Changing outputs, input outpoints, sequences, amounts, scripts, locktime, version,
selected input, network, or program/script commitment changes the digest. PSBT
signatures and other non-transaction metadata are not included. Repeating an
identical approved transaction is allowed; this is not a one-use-token registry.

This is a dedicated off-chain **approval hash**, not a BIP-341 signing sighash and
not the Elements `sig_all_hash` jet. The service still produces its cooperative
Taproot signature over the actual BIP-341 sighash. The dependency's native
Bitcoin transaction jets are not implemented; programs must use the updated
`CoreExtension` jet table. The new custom jet uses encoding `1111111` and CMR
`SHA256("SimplicityUnchained/Jet/tx_approval_hash/v1")`.

**Compatibility:** existing jet encodings, CMRs and static-policy addresses are
unchanged. Static Bitcoin policies remain intentionally replayable. Adding this
jet to an existing policy changes its CMR and address; already-funded static
contracts do not gain per-spend approval automatically. Deploy the new policy
and migrate funds using an available original spending path.

### Script Commitment and Migration

`signing_commitment` is the 32-byte tagged SHA256 hash
`SHA256(tag_hash || tag_hash || CMR || SHA256(redeem_script))`, where
`tag_hash = SHA256("SimplicityUnchained/SigningCommitment/v1")`.
The original program CMR is unchanged. Omitted, null, and empty scripts all mean
the same zero-length byte string, which is also committed.

## Licence

See the [LICENCE](../LICENCE) file for details.
