# Bitcoin policy templates (experimental)

These SimplicityHL 0.8 programs target `bitcoin-policy-v1`. Do not fund the
example keys: their private keys are the publicly known integers 1, 2 and 3.

| File | Committed rule |
|---|---|
| `recipient_allowlist.simf` | Inspect every output; allow two exact script hashes or an exact-script return. |
| `capped_debit.simf` | The same allowlist, at most 100,000 sat all-input debit (including fees), at most 2,000 sat absolute fee. |
| `approvals_2_of_3.simf` | Two of three distinct committed keys approve J54 for all inputs of one transaction. |
| `approvals_2_of_3_per_input.simf` | The same threshold over input-specific J53; new approvals for each selected input. |
| `constrained_source.simf` | Every input outpoint has a fixed source authority's signature, vout 0–7, at least 16-block CSV; selected-input CLTV height 1,000; all outputs have exact P2TR shape. |

Each file demonstrates a separate policy. Combine the checks you need before
compiling and funding. The source/shape example does not restrict recipient keys,
and the approval examples do not impose fee or debit caps.

## Review and customize before funding

1. Replace example keys with independently generated, validated x-only public
   keys. Keep the pairwise distinctness assertions: repeated keys, or the same
   signature copied into another key's slot, must not satisfy the threshold.
2. Derive recipient scripts from independently verified addresses on the intended
   network. Hash the **raw complete scriptPubKey bytes** with SHA256, not an
   address, hex text, recovery script, or PSBT change label. The literal examples:
   - `00141111111111111111111111111111111111111111`
     → `82d2c7b9ded542f3024bfe1babe73021e1a4894db8b8be6215f96be6737c975b`.
   - `512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
     → `0a22f58e8e4eb93ec82d86a4f4a9d2be3a172665648449f5e9a6747caaf12ca1`.
   Exact-script returns compare J22 with J19, not the recovery script or an
   untrusted declaration of change.
3. Review satoshi caps, locktime literals and the fixed source-authority key.
   Source txids use raw consensus hash bytes, not explorer/display txid hex.
   A literal funding-parent txid compiled into its own output policy would be
   circular (the parent's txid depends on that policy's funding script).
   Instead this example permits only outpoints authenticated after funding by a
   **committed** source key, not an unauthenticated runtime allowlist.
4. Compile with the canonical Bitcoin policy jet hinter; confirm profile
   fingerprint, CMR, script data, base signer key and network against service
   capabilities. Derive the service key with `policy tweak` and the funding
   address with `policy address` **before** funding the cooperative output.
   Bitcoin Testnet4 is the native CLI/demo default; verify the configured network.
5. Test at/below/above each cap, mutations in the last output and last input,
   missing evidence, disabled CSV, final sequence, wrong locktime units, repeated
   keys, reused signatures, and both approval digest scopes.

There are eight unrolled, count-guarded input/output slots. Counts above eight
are rejected. Only slots beyond the validated count are skipped;
an accessor unexpectedly returning `None` for an existing slot fails closed.
J33 aggregates **all** verified same-script inputs and subtracts exact-script
returns. This is a per-transaction debit cap, not a daily budget or one-use quota.

`constrained_source.simf` uses profile class code 5 for P2TR plus exact length
and byte checks (`OP_1`, push-32). A class or prefix is not proof of recipient
authorization, valid key data, or safe arbitrary script behavior. CSV/CLTV
predicates check transaction conditions, not current height/time or maturity.

Source authorization uses `SOURCES: [Option<Signature>; 8]`, in input order,
with `None` for unused slots. Each actual input requires a BIP-340 signature
over the decoded digest:

```text
tag = SHA256(UTF8("SimplicityUnchained/PolicySourceOutpoint/v1"))
digest = SHA256(tag || tag || J03 || raw_txid || vout_u32_be)
```

J03 binds the profile, network, program and exact script data. Source signatures
can authorize multiple proposals spending that outpoint; combine them with
transaction approvals or debit limits to restrict destinations and fees.
Each signature binds a specific txid and output index. The example uses Core
SHA256/BIP-340 jets.

## Approvals and evidence

The approval witness is `APPROVALS: [Option<Signature>; 3]`, with each slot tied to
one fixed public key. An absent signer supplies `None`; an included invalid
signature rejects the policy, even if other slots could reach two. Sign the
**decoded 32-byte J53/J54 digest** directly with BIP-340, without another SHA256.
Approve only after locally constructing the context from every full parent and
the known untweaked service key; never blindly sign an HTTP summary.

Any transaction, prevout, script, profile, network, user/recovery-key or program
change needs fresh preparation and approvals. J54 intentionally excludes the
selected input so one approval can authorize all inputs of the same transaction;
J53 does not.

Parent txid verification proves amounts/scripts against supplied outpoints, **not
confirmation, active-chain validity, or unspentness**. This remains an off-chain
co-signer: possession of the spending key can bypass policy evaluation, and an
independently valid recovery leaf remains an alternative. See the
[CLI workflow](../../cli/README.md#bitcoin-policy-workflow).

## Reproducible compiler and execution fixtures

`compiled.json` pins the registry fingerprint, source
SHA256, encoded programs and CMRs. It also contains **negative-only** threshold
fixtures with the second key replaced by the first, while preserving all
distinctness checks. Never use those negative fixtures for funding.

The sibling web demo's native compiler example regenerates these vectors using
the same registry-backed hinter as the browser. From the backend root:

```bash
cargo run --manifest-path ../simplicity-unchained-web-demo/simplicity-lib/Cargo.toml \
  --example policy_templates --locked --quiet > examples/policy/compiled.json
cargo test -p cli --test policy_templates --locked
cargo test -p cli --test policy --locked
```

Execution tests run the compiled templates in the core VM without requiring the
sibling web checkout. They cover 1, 8 and 9 outputs, the final slot and zero-valued
outputs, eight-input accounting,
one-satoshi cap mutations, duplicate keys/signatures, J53/J54 scope, changes to
outputs/prevouts/sequences/locktime, authenticated sources, and CSV/CLTV/script
byte failures. Regenerate and review vectors when the source or registry changes.
All parent transactions are synthetic test content;
no tests fund addresses or broadcast transactions.

An ignored integration test exercises preparation, approvals, co-signing and
finalization against a running Testnet4 service using synthetic inputs. It also
checks that changed transactions with stale approvals are rejected:

```bash
SIMPLICITY_TEST_SERVICE_URL=http://127.0.0.1:30441 \
  cargo test -p cli --test policy_templates --locked \
  live_cli_compiled_policy_prepare_approve_cosign_and_verified_finalize -- --ignored
```

Only this synthetic integration test discovers its ephemeral service key from
capabilities. Real approval workflows must independently pin their known base
signer key.
