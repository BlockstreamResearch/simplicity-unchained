# Simplicity Unchained (Prototype Phase)

Simplicity Unchained brings [Simplicity](https://simplicity-lang.org/) to Bitcoin networks. It acts as an off-chain oracle that executes a committed Simplicity policy and, on success, co-signs a transaction.

The primary target is **Bitcoin**, using `bitcoin-policy-v1`, with confidential multi-asset support for Liquid through `liquid-policy-v1`. The CLI and demo default to Bitcoin Testnet4 and Liquid Testnet.

> ⚠️ **Warning: Project Under Development**
>
> This project has not been independently audited and is **not safe for use in production environments**.

## How It Works

See [core/README.md](core/README.md) for the unchained model, Taproot tree structure and policy co-signing flow.

## Project Structure

- [`core`](core/README.md): Executes Simplicity policies and provides cryptographic, Taproot and transaction-environment utilities.

- [`service`](service/README.md): Web service for policy-bound key derivation, transaction preparation, evaluation and co-signing.

- [`cli`](cli/README.md): Command-line policy workflows and key generation.

- [`policy`](policy/README.md): Portable Bitcoin and Liquid policy kernels and registries, shared by native clients and the browser/WASM implementation.

Each component has its own README with more detailed information.

## Web Demo

The [web demo](https://github.com/BlockstreamResearch/simplicity-unchained-web-demo) provides a browser interface for writing SimplicityHL policies, compiling them, deriving funding addresses and co-signing transactions on Bitcoin Testnet4 or Liquid Testnet. It opens on a landing page, with the interactive workflow at `/demo`.

## Capabilities demoed so far

### Bitcoin

The [Bitcoin demo script](cli/scripts/demo_btc.sh) uses `bitcoin-policy-v1` on Bitcoin Testnet4:

1. Check the service's profile, network and known signing key.
2. Derive a policy-bound P2TR address before funding.
3. Prepare and review a PSBT using full parent transactions.
4. Evaluate the policy with its witness and request the service signature.
5. Add the user's signature and finalize locally.

See the [CLI readme](cli/README.md#demo) for setup and the [policy examples](examples/policy/README.md) for recipient restrictions, debit and fee caps, and transaction approvals.

### Elements / Liquid

The [`liquid-policy` CLI](cli/README.md#liquid-policy-workflow) supports confidential PSETs and multiple assets. It verifies asset/value disclosure proofs and per-asset accounting before evaluation and signing. See the [Liquid profile](policy/LIQUID.md) for schemas and asset semantics.

## Licence

See the [LICENCE](LICENCE) file for details.

## Original Idea

This project is inspired by [Smart Contracts Unchained](https://zmnscpxj.github.io/bitcoin/unchained.html), a concept proposed by ZmnSCPxj in 2019.
