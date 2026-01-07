# Simplicity Unchained (Prototype Phase)

Simplicity Unchained is the concept of an oracle that executes Simplicity programs in a flexible and extensible environment, independently of any blockchain such as Bitcoin or Elements.

The successful execution of these programs can produce side effects, such as co-signing transactions, triggering events, or performing any other action that a server is capable of.

> ⚠️ **Warning: Project Under Development**
>
> This project is still in active development and conceptualization. It is **not safe for use in production environments** at this time. Features and functionality may change, and there may be critical bugs or incomplete implementations.

## Project Structure

- [`core`](core/README.md): Contains the fundamental logic for executing Simplicity programs and interacting with the Elements blockchain. (Note: In the future, parts of this logic may be migrated to [hal-simplicity](https://github.com/BlockstreamResearch/hal-simplicity))

- [`service`](service/README.md): Implements a web service providing endpoints to interact with Simplicity Unchained. Currently, it supports a 2-of-2 multisig side effect triggered by Simplicity program execution.

- [`cli`](cli/README.md): Command-line interface for communicating with the Simplicity Unchained service and accessing various ecosystem utilities. (Note: In there future, parts of this CLI will use [hal-simplicity](https://github.com/BlockstreamResearch/hal-simplicity))

Each componenet of the project has its own README file with more detailed information.

## Capabilities demoed so far

You can explore the currently supported capabilities by running the [demo script](cli/scripts/demo.sh). This demo guides you through the essential steps:

1. Creating a 2-of-2 multisig UTXO.
2. Creating a spending transaction.
3. Using the Simplicity Unchained service to co-sign the transaction, after the successful execution of a Simplicity program.
4. Broadcasting the valid transaction to the Liquid Testnet.

To run the demo, follow the instructions in the [CLI readme](cli/README.md).

## Licence

See the [LICENCE](LICENCE) file for details.
