# Simplicity Unchained CLI

Command-line interface for communicating with the Simplicity Unchained service and accessing various ecosystem utilities.

## Commands

You can easily access command descriptions and information about available arguments by using the `--help` flag with any command. There is no need to duplicate this information here.

```man
A CLI tool for Simplicity Unchained utilities

Usage: simplicity-unchained <COMMAND>

Commands:
  address  Address operations
  keypair  Keypair operations
  tx       Transaction operations
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Demo

You can run the [demo script](scripts/demo.sh) to see example usages of the CLI commands and an example of Simplicity Unchained capabilities.

Service supports P2SH, P2WSH and P2TR transaction types.

Firstly, ensure you have the Simplicity Unchained service running.

```bash
cd service
cargo run --quiet -- start
```

Then, in a separate terminal, navigate to the `cli` directory and execute the demo script:

```bash
cd cli
./scripts/demo.sh p2sh/p2wsh/p2tr
```

> ⚠️ **Warning: Too many requests**
>
> The demo script interacts with the Liquid Testnet Faucet, which imposes a rate limit of 3 requests per minute per IP address. If you exceed this limit, the script may fail. If this happens, please wait at least one minute before running the script again.

## Licence

See the [LICENCE](../LICENCE) file for details.
