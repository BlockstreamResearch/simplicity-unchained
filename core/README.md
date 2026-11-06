# Simplicity Unchained Core

Contains the fundamental logic for executing Simplicity policies with Bitcoin and Elements environments.

## Capabilities

- Execute `bitcoin-policy-v1` policies against verified PSBT context.
- Execute [`liquid-policy-v1`](../policy/LIQUID.md) policies using the portable VM and proof-verified PSET context.
- Provide cryptographic, Taproot and transaction-environment utilities.
- Load [custom jet plugins](src/plugin/README.md) for native callers. The policy profiles use fixed registries.

## How It Works

### The Unchained Model

The service commits to a Simplicity policy through its Taproot key tweak, without requiring Simplicity as an on-chain consensus rule.

1. The user writes and compiles a policy for the intended profile, choosing its keys and script data before funding.
2. The service computes the program's **CMR** (Commitment Merkle Root).
3. The service derives a cooperative key that commits to the profile fingerprint, network genesis hash, CMR and exact script-data bytes.
4. The user constructs a P2TR address from that key, their own key and a recovery leaf hash.

Keep the base signing key and published profile available for funded outputs. Enforcement is off-chain: someone holding the signing key can bypass policy evaluation.

### Taproot Tree Structure

```plaintext
P2TR output
├── Internal key: standard NUMS (unspendable)
└── Script tree
    ├── Leaf 0 — Co-signing leaf (2-of-2 multisig)
    │     <policy_service_xonly> OP_CHECKSIG
    │     <user_xonly> OP_CHECKSIGADD OP_2 OP_EQUAL
    └── Leaf 1 — User recovery leaf (hidden from the service)
```

**Leaf 0 — Co-signing leaf**: Both the service and user must sign. The service key commits to the policy; the service checks that each input spends the reconstructed output before signing.

**Leaf 1 — User recovery leaf**: The user chooses a recovery script, such as a CSV timelock and user key, and keeps the full script privately. The service needs only its hash. A valid recovery spend does not require service cooperation or policy evaluation.

### Co-signing Flow

1. The user prepares a PSBT/PSET with full parent transactions, the committed program and script data, their public key and the recovery hash.
2. The service verifies parent txids, referenced outputs and `witness_utxo` data, then reconstructs every input's policy-bound output. Liquid also requires verified asset/value disclosures and transaction proofs.
3. The user reviews the transaction context and obtains any approvals required by the policy.
4. The service evaluates the witnessed program and, if it passes, returns a cooperative script-path signature for the selected input.
5. The user verifies the service signature, adds their own signature and finalizes after both signatures are present for every input.

Parent verification proves transaction content, not confirmation or unspentness. Both profiles report `chain_status_verified: false`; check live chain status separately.

### Bitcoin Per-Spend Approvals

The 55 Bitcoin policy jets expose transaction amounts, output scripts, debit including fees, declared locktime conditions and approval hashes:

- J53 `policy_approval_hash` binds the transaction context, selected input and its cooperative sighash.
- J54 `policy_transaction_approval_hash` permits one approval across all same-contract inputs of the same transaction.

Use [`policy approval-hash`](../cli/README.md#prepare-approve-and-co-sign) to reconstruct the context locally from full parents and a known base service key. Sign the decoded 32-byte digest directly with BIP-340 and compile the signatures into the policy witness. Changing the approved transaction or context requires fresh approvals.

A policy must verify a transaction-dependent condition to authorize individual spends. Static hashlocks and fixed-message signatures are replayable; debit and fee caps apply per transaction, not per day. See the [policy templates](../examples/policy/README.md) and [approval preimages](../policy/README.md#commitments-and-approval-preimages).

### Script Commitment

For Bitcoin, the cooperative key is derived as follows:

```text
commitment = TaggedHash("SimplicityUnchained/PolicySigningCommitment/v1",
    profile_hash || genesis_hash || CMR || SHA256(exact_script_data))
service_key = BIP341 TapTweak(base_service_key, root = commitment)
```

The [portable kernel](../policy/README.md) defines the registry, fingerprint, context verification and approval preimages. The [Liquid profile](../policy/LIQUID.md) defines its asset semantics and genesis-bound signing rules.

## Execution API

For Bitcoin, use `policy::policy_cmr` to decode a program without its witness, then `policy::prepare_policy` or `PreparedPolicy::new` to validate the transaction and obtain an immutable `context()` and serializable `summary()`.

The profile accepts version 2, one to eight same-contract inputs and one to eight outputs, with SIGHASH_DEFAULT script-path signing. It rejects duplicate inputs, missing or conflicting parents, overspending and finalized witnesses.

`evaluate_default(witness)` uses a 10,000,000-milliweight cap. `evaluate(witness, Cost)` and `evaluate_milliweight(witness, u32)` can lower it. Cost is checked before BitMachine allocation and is a static bound, not elapsed time. Errors distinguish decoding, invalid context, policy rejection, execution limits and VM failure. Signing prepares and evaluates again rather than trusting a previous evaluation.

## Licence

See the [LICENCE](../LICENCE) file for details.
