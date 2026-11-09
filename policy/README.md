# Portable policy kernel

`simplicity-unchained-policy` / `simplicity_unchained_policy` implements the
`bitcoin-policy-v1` off-chain authorization profile used by the `policy` CLI and
Bitcoin policy API. It has no dependency on `core`, the service, native plugins,
a resolver, a clock or secrets.
It builds natively and for `wasm32-unknown-unknown`.

The [`liquid-policy-v1`](LIQUID.md) module provides confidential multi-asset PSET
support, verified disclosures and a portable VM. The sections below describe
the Bitcoin profile.

The 55 custom jet identities commit to semantic contracts and standard
Simplicity types under `SimplicityUnchained/PolicyJetIdentity/v1`. These are
application-specific identities, not formally derived Bitcoin consensus jets.

## Registry and fingerprint

`Builtin::ALL` is ordered J01–J55, wire IDs 0–54. Methods provide names, standard
`TypeName`s, bit widths, identities, wire encodings, fixed costs, and full
semantic contracts. `manifest()` serializes the base and policy jet metadata,
contracts and limits. Jet codes are:

```text
0 || CoreExtension code
1 || id:u6, most significant bit first
```

IDs 55–63 are reserved/invalid. This is the jet code, without the enclosing
Simplicity node encoding. `TypeName` uses the dependency's standard alphabet:
`1` unit, `2` bit, `c` u8, `s` u16, `i` u32, `l` u64, `h` u256, `+` sum, `*`
product. These encodings are verified against `simplicity-lang` 0.9.

`profile_hash()` is single SHA256 of `manifest().canonical_bytes()`: compact
UTF-8 serde JSON of `ManifestBody` in declared field order, not generic
alphabetically sorted JSON. The `profile_hash` field is excluded. Jet identities
do not include that resulting fingerprint, preventing circular hashing.
Contracts, ordered types, encodings, CMRs, costs, and all limits are included.
Registry changes require a new profile version.

Export the complete client registry:

```sh
cargo run -p simplicity-unchained-policy --example manifest --locked
```

## Validated context

```text
Context::new(
    &bitcoin::psbt::Psbt,
    input_index: usize,
    cmr: [u8; 32],
    script_data: &[u8],
    configured_network: bitcoin::Network,
    base_service_pubkey: bitcoin::XOnlyPublicKey,
    user_pubkey: bitcoin::XOnlyPublicKey,
    recovery_hash: bitcoin::TapNodeHash,
) -> Result<Context, Error>
```

The immutable context accepts version exactly 2, 1–8 inputs and outputs, and
output scripts/script data up to 10,000 bytes. Input/output map counts must
match. Every input requires both `non_witness_utxo` and `witness_utxo`; computed
parent txid, vout, and exact referenced TxOut equality are checked. Duplicate
outpoints, money-range violations (including totals), arithmetic failure,
overspend, non-default sighashes, and nonempty final witnesses are rejected.
Only Bitcoin, Testnet, and Testnet4 are accepted; configuration is external.

Evidence and serialized PSBTs are limited to 2 MiB. The context retains only the
unsigned transaction and verified prevouts. HTTP request decoding,
program/witness limits and execution timeout/admission are the caller's
responsibility. The profile VM admission ceiling is 10,000,000
milliweight; each policy jet costs 10,000, including bounded scans of at most eight
cached entries and at most 321 total source/target frame bits.

Parent verification proves **content only**: not confirmation, chain inclusion,
consensus validity, or current unspentness. `ContextSummary` always reports
`provenance = "parent-txid-verified"` and `chain_status_verified = false`.
CSV/CLTV report declared transaction conditions, not chain maturity; RBF reports
explicit signaling, not mempool acceptance.

`cooperative_output(...)` reconstructs public funding data without a PSBT.
`signing_commitment(cmr, script_data, network)` and
`tweak_public_key(base_key, cmr, script_data, network)` share this derivation.
`Context` exposes only immutable getters for its transaction, verified prevouts,
keys, leaf, scriptPubKey, control block, signing commitment, and actual sighash.
`summary()` is serializable and includes exact output summaries for review.

## Commitments and approval preimages

`TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`.
Every hash uses `Hash::to_byte_array`, **never explorer display reversal**.
All fields below are fixed-width 32 bytes except the explicit input index.

```text
commitment = TaggedHash(
  "SimplicityUnchained/PolicySigningCommitment/v1",
  profile_hash || genesis_hash || cmr || SHA256(exact script_data))

service_key = BIP341 TapTweak(base_service_key, root = commitment)
```

The canonical leaf is `<service_xonly> CHECKSIG <user_xonly> CHECKSIGADD 2 EQUAL`
(leaf version `0xc0`). The output uses the standard NUMS internal key and a
depth-one cooperative leaf plus a depth-one hidden recovery hash. Every input
must spend this reconstructed output. Signing uses the BIP341 script-path
`SIGHASH_DEFAULT` with all verified prevouts, no annex and the default
code-separator position.

```text
J54 = TaggedHash("SimplicityUnchained/PolicyTransactionApproval/v1",
  profile_hash || genesis_hash || commitment || unsigned_tx_hash ||
  prevouts_hash || cooperative_leaf_hash || recovery_hash)
J53 = TaggedHash("SimplicityUnchained/PolicyInputApproval/v1",
  J54 || input_index:u32-big-endian || actual_default_sighash)
```

J54 deliberately permits reuse across all same-contract inputs of this exact
transaction. J53 is input-specific. Sign decoded digest bytes directly with
BIP-340; approvals do not provide a one-use permission registry.

J44 is single SHA256 of stripped consensus transaction bytes. J45 is single
SHA256 of the consensus TxOut vector in input order. J46/J47 are single SHA256
of unsigned input/output vectors. **Every vector includes its CompactSize
count.** These differ from BIP341 component hashes. Outpoints use
raw txid bytes and little-endian vout; consensus amounts/sequences/locktimes are
little-endian; only jet words and approval input indices are big-endian.
J55 is stripped byte size, a conservative final-vsize lower bound.

## Pure execution and vectors

`Context::evaluate(Builtin, &BitValue)` is independent of VM/FFI.
`BitValue { bytes, bit_len }` packs bits MSB-first with exact byte length and
zero low trailing padding. Products concatenate. Sums contain a tag, zero
padding on the left of the active payload, then that payload.
`Either<(), T>` is `0 || zeroes` or `1 || T`; bool is one actual bit, and `Check`
returns zero-bit unit or an explicit error. Invalid source shapes are errors.

`tests/fixtures/golden.json` freezes the manifest hash, first/last identities,
raw transaction/vector preimages, public keys/tree, both input sighashes,
J53/J54, and summary. The vectors were independently checked with
Python's hashlib and pure-integer secp256k1 arithmetic, including BIP341
preimages and the output TapTweak. Tests cover every jet, bounds, sums/options,
accounting, malformed proofs, CSV/CLTV flags and units, and replay mutations.
Synthetic parents do not assert chain validity.

```sh
cargo test -p simplicity-unchained-policy --locked
cargo clippy -p simplicity-unchained-policy --all-targets --locked -- -D warnings
cargo check -p simplicity-unchained-policy --target wasm32-unknown-unknown --locked
```
