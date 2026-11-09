# Security review

Date: 2026-11-06

## Scope

Reviewed the native SU working tree based on `7a8853e`, including modified and
untracked policy code. This report does not commit or snapshot those changes.

The review covered service routes and admission limits, Bitcoin and Liquid
transaction evidence, policy commitments and approvals, execution bounds, CLI
signature verification and finalization, native plugin trust boundaries, and
locked Rust dependencies.

The browser demo, deployment configuration, infrastructure and operator key
storage were not audited. This was not a formal verification or penetration
test. No transactions were funded or broadcast, and the running service and
signer configuration were not changed.

## Findings

No application-level policy bypass or fund-theft exploit was confirmed. RustSec
identified two affected dependencies. Confidence below refers to the affected
locked version, not to exploitability through SU's current request paths.
Severity reflects review triage priority.

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟡 MEDIUM | [Cargo.lock](Cargo.lock) | 267-270 | `bytes` 1.11.0: integer overflow in `BytesMut::reserve` can cause memory corruption | 10/10 |
| 2 | ⚪ LOW | [Cargo.lock](Cargo.lock) | 577-580 | `h2` 0.3.27: empty DATA frames can accumulate without limit | 10/10 |

### 1. bytes: RUSTSEC-2026-0007

The dependency is used by both the service and CLI. In release builds, an
unchecked capacity addition can wrap and permit out-of-bounds access.

The upstream reproduction requires a reservation near `usize::MAX` after
splitting a buffer. No SU request path reaching that condition was identified;
the public policy routes limit request bodies to 2 MiB. The advisory's unsafe
reproduction was not executed.

Upgrade `bytes` to **1.11.1 or later** and re-run the relevant tests.

Source: [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0007.html).

### 2. h2: RUSTSEC-2026-0258

The affected dependency chain is:

```text
cli -> reqwest 0.11.27 -> hyper 0.14.32 -> h2 0.3.27
```

A peer can supply empty HTTP/2 DATA frames that consume no flow-control bytes
but still occupy receive-queue entries. Undrained streams can exhaust memory.

The signing service does not depend on this `h2` version and is built with
HTTP/1 support only. The CLI's current native-TLS features do not enable ALPN,
and it does not request HTTP/2 prior knowledge. No active HTTP/2 exposure was
identified in the reviewed build.

The fix is **h2 0.4.16 or later**. Since the current Hyper dependency requires
the 0.3 series, update the HTTP client dependency chain rather than forcing an
incompatible `h2` version.

Source: [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0258.html).

## Other observations

- RustSec also reported unmaintained `pin-utils` and `rustls-pemfile`, and
  unsoundness warnings for `anyhow`, `rand` and `tokio`. These were not counted as
  demonstrated SU vulnerabilities.
- The [native plugin loader](core/src/plugin/loader.rs) documents a race between
  optional file-hash verification and opening the library. Keep plugin files and
  their directories protected from untrusted writes. Plugins are operator-trusted
  native code and are not loaded through the policy endpoints.
- Parent transaction verification establishes content, not confirmation or
  unspentness. Stateless caps, independent recovery paths and operator-held
  signing keys are documented trust constraints, not guarantees established by
  this review.

## Verification

RustSec advisories were fetched during the review. `cargo audit` scanned 248
locked dependencies and exited with two vulnerabilities and five warnings.
Dependency and feature trees confirmed the package chains and HTTP/2 conditions.

| Command | Result |
|---|---|
| `cargo audit` | Failed with the two dependency advisories above. |
| `cargo tree --locked --offline -i h2@0.3.27` | Passed; dependency is CLI-only. |
| `cargo tree --locked --offline -i bytes@1.11.0` | Passed; dependency is shared by service and CLI. |
| `cargo tree --locked --offline -e features -i reqwest` | Passed; native-TLS ALPN feature is absent. |
| `cargo tree --locked --offline -e features -i axum` | Passed; service HTTP/2 feature is absent. |
| `cargo test -p service -p simplicity-unchained-policy -p core --locked` | Core: 30 passed, 1 ignored. Service unit tests: 20 passed. Startup: 7 passed, 1 failed with a connection reset; run stopped before the kernel tests. |
| `cargo test -p simplicity-unchained-policy --locked` | Passed: 20 Bitcoin kernel tests and 11 Liquid tests. |
| `cargo test -p service --test startup explicit_read_only_configuration_starts_and_serves_requests --locked -- --exact --test-threads=1` | Passed: the initially failing startup test. |
| `cargo test -p service --test startup --locked -- --test-threads=1` | Passed: all 8 startup tests. |
| `cargo test -p cli --test policy --test liquid_policy --test public_surface --test policy_templates --locked` | Passed: 32 tests, 1 ignored. |

After reruns, **121 distinct selected tests passed; two were ignored**. These
included parent/proof tampering, stale approvals, wrong keys and signatures,
profile/network mismatches, multi-input finalization, body limits, admission
timeouts and preallocation cost rejection. Passing tests do not establish the
absence of other vulnerabilities.

## Remediation status

No fixes were applied. Update the affected dependencies, review the resulting
HTTP client behavior, and repeat the audit and tests before deployment.
