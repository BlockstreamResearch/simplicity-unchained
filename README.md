# Simplicity Unchained (Prototype Phase)

Simplicity Unchained brings [Simplicity](https://simplicity-lang.org/) to Bitcoin networks. It acts as an off-chain oracle that executes a committed Simplicity policy and, on success, co-signs a transaction.

The primary target is **Bitcoin**, using `bitcoin-policy-v1`, with confidential multi-asset support for Liquid through `liquid-policy-v1`. The CLI and demo default to Bitcoin Testnet4 and Liquid Testnet.

> ⚠️ **Warning: Project Under Development**
>
> This project has not been independently audited and is **not safe for use in production environments**.

## How It Works

See [core/README.md](core/README.md) for the unchained model, Taproot tree structure and policy co-signing flow.

## Run your own SU service

The [published image](https://github.com/BlockstreamResearch/simplicity-unchained/pkgs/container/simplicity-unchained)
runs the policy co-signer, not a Bitcoin or Liquid full node. You need Docker
Engine (or Docker Desktop) and `curl`; no Rust build or repository checkout is
required. This release targets `linux/amd64`; ARM hosts need amd64 emulation.
Use testnet keys and coins only.

### 1. Provision the signing key

Run once in a POSIX shell. The configuration is stored in a Docker volume with a
fresh random key, readable only by the container's service user (UID 1000).
The command refuses to overwrite an existing configuration.
For an existing funded service, reuse its private configuration instead of
generating a replacement key.

```sh
IMAGE=ghcr.io/blockstreamresearch/simplicity-unchained:v0.1.0-alpha.0
docker pull --platform linux/amd64 "$IMAGE"
docker volume create su-config

docker run --rm --platform linux/amd64 --user 0:0 \
  --entrypoint /bin/sh \
  --mount type=volume,src=su-config,dst=/config \
  "$IMAGE" -euc '
    set -C
    umask 077
    if [ -e /config/config.toml ]; then
      echo "Configuration exists; reuse it." >&2
      exit 1
    fi
    key=$(od -vAn -N32 -tx1 /dev/urandom | tr -d " \n")
    [ "${#key}" -eq 64 ]
    printf "%s\n" \
      "[service]" \
      "port = 30431" \
      "private_key = \"$key\"" \
      "bitcoin_network = \"testnet4\"" \
      "liquid_network = \"liquidtestnet\"" \
      > /config/config.toml
    chown 1000:1000 /config/config.toml
  '
```

### 2. Start the service

In the same shell:

```sh
docker run -d --name simplicity-unchained \
  --platform linux/amd64 \
  --restart unless-stopped \
  --publish 127.0.0.1:30431:30431 \
  --mount type=volume,src=su-config,dst=/app/config,readonly \
  "$IMAGE" start --config /app/config/config.toml
```

The service runs as UID 1000 and reads its configuration from a read-only mount.
The API is available only on the Docker host. For remote clients, put it behind
an HTTPS reverse proxy; the service itself does not provide TLS.

### 3. Check the API

```sh
curl -fsS http://127.0.0.1:30431/simplicity-unchained/version
curl -fsS http://127.0.0.1:30431/simplicity-unchained/policy/bitcoin/capabilities
curl -fsS http://127.0.0.1:30431/simplicity-unchained/policy/liquid/capabilities
```

The version response is `{"version":"0.1.0"}`. Capabilities report each profile,
network and `base_public_key_hex`; pin that public key in clients before funding.
Use `docker logs simplicity-unchained` to diagnose startup failures.

Stop with `docker stop simplicity-unchained` and start again with
`docker start simplicity-unchained`. Keep a secure backup of the private
configuration in `su-config`; deleting the volume or changing its key changes
the signer identity and can make cooperative spending impossible.
See the [service documentation](service/README.md) for configuration and API schemas.

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
