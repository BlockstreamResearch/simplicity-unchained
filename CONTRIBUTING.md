# Contributing to Simplicity Unchained

Contributions of all kinds are welcome — bug reports, documentation improvements, and tests.

## Project Structure

The workspace is organised into focused crates. Keep changes scoped to the appropriate crate and discuss cross-crate changes in an issue first.

- [`core`](core/README.md): Simplicity execution engine, Bitcoin/Elements environments, and the dynamic jet loading API.
- [`jet_plugins`](jet_plugins/README.md): Procedural macro that derives the `Jet` trait and C FFI for custom jet plugins.
- [`service`](service/README.md): Axum HTTP service exposing the sign/PSBT, sign/PSET, and key-tweak endpoints.
- [`cli`](cli/README.md): `clap`-based CLI for interacting with the service and accessing ecosystem utilities.
- `plugin_tests/`: Example and integration-test jet plugins for Bitcoin, Elements, and opcode pubkey variants.

## Issues

If this is just a bug report or a feature request, please open an issue first so it can be discussed. PRs for bug fixes are also welcome and can be discussed directly in the PR. However, for larger changes, it is better to open an issue first to discuss the proposed change before implementing it.

### Pull Requests

1. Fork the repository and create a branch from `development`.
2. Make your changes, including tests where applicable.
3. Ensure CI checks pass.
4. Open a PR against `development` describing what was changed and why.
5. Keep PRs focused, one logical change per PR. Split large changes into sequential PRs if needed.

## Coding Conventions

- Run `cargo fmt` before every commit.
- The project targets zero `clippy` warnings with `-D warnings`. Fix all warnings introduced by your changes.
- Use `thiserror` for library errors. Avoid `unwrap()` outside of tests and examples.
- Keep the public API surface minimal. Only `pub` what downstream crates genuinely need, and add `///` doc comments to all new public items.
- Adding a new dependency requires justification. Prefer `[workspace.dependencies]` entries and avoid floating version requirements.
- Add unit tests under a `#[cfg(test)]` module in the same file.

## Adding Custom Jets

Custom jets are the primary extension point. To add a new jet plugin:

1. Create a new crate that depends on `jet_plugins` and `simplicity_unchained_core`, declare it as a `cdylib`:

   ```toml
   # Cargo.toml
   [lib]
   crate-type = ["cdylib"]
   ```

2. Define your jet functions matching the expected signature:

   ```rust
   fn my_jet(_dst: &mut CFrameItem, _src: CFrameItem, _env: &BitcoinUnchainedEnv) -> bool {
       // return true on success
       todo!()
   }
   ```

3. Register them with the `register_jets!` macro:

   ```rust
   use jet_plugins::register_jets;
   use simplicity_unchained_core::jets::environments::BitcoinUnchainedEnv;
   use hal_simplicity::simplicity::ffi::CFrameItem;

   register_jets!(
       hal_simplicity::simplicity::jet::Core,   // base jet set
       BitcoinUnchainedEnv,                     // environment type
       "my_jet_name" => my_jet, b"h", b"h",     // (name, fn, source_type, target_type)
   );
   ```

4. Pass the compiled `.so`/`.dylib` path to the core runner via the dynamic loading API. See `core/src/jets/jet_dyn.rs` and `cli/assets/custom_jet_dlls/` for reference.

## Running the Service Locally

```bash
cd service
cargo run --quiet -- start
```

The service reads `config.toml` from the current directory by default. You can point it at a custom file with `--config`:

```bash
cargo run --quiet -- start --config path/to/your/config.toml
```

To exercise CLI commands against the running service, use the demo scripts:

```bash
# Bitcoin regtest demo
cd cli && ./scripts/demo_btc.sh

# Elements / Liquid testnet demo
cd cli && ./scripts/demo_elements.sh
```

## Docker

The multi-stage `Dockerfile` builds the `service` binary. To build and run:

```bash
docker build -t simplicity-unchained-service .
docker run -p 8080:8080 simplicity-unchained-service
```

The container runs as a non-root user (`uid=1000`). Ensure mounted config files are readable by that user.

## Reporting Bugs

Open a GitHub issue including:

1. What happened vs. what you expected.
2. A minimal command sequence or code snippet to reproduce the issue.
3. Your OS, Rust version (`rustc --version`), and commit hash.
4. Relevant error output with sensitive data redacted.

For security-sensitive issues, please follow responsible disclosure and contact the maintainers privately before opening a public issue.

## Licence

By contributing to this project you agree that your contributions are released under the [CC0 1.0 Universal](LICENCE) licence, the same licence that covers the project.
