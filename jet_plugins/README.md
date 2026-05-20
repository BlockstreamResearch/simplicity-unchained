# Jet Plugins

Procedural macros for deriving the `Jet` trait for custom jets.

## Capabilities

Given a set of base jets and custom jets, this crate derives the `Jet` trait alongside a C FFI for dynamic jet loading.

Current Limitations:

- Does not support deriving traits based solely on custom functions.

- Does not support deriving traits over arbitrary jet sets (other than Bitcoin and Elements). This is due to API limitations within certain internal components of rust-simplicity.

## Usage example

```rust
use jet_plugins::register_jets;
use simplicity_unchained_core::jets::environments::ElementsUnchainedEnv;
use simplicity_unchained_core::__simplicity::simplicity::ffi::CFrameItem;

fn custom_jet1(_dst: &mut CFrameItem, src: CFrameItem, env: &ElementsUnchainedEnv) -> bool {
    false
}
fn custom_jet2(_dst: &mut CFrameItem, src: CFrameItem, env: &ElementsUnchainedEnv) -> bool {
    false
}

register_jets!(
    simplicity_unchained_core::__simplicity::simplicity::jet::Elements,
    simplicity_unchained_core::jets::environments::ElementsUnchainedEnv,
    "custom_jet1" => custom_jet1, b"h", b"h", // source/target type
    "custom_jet2" => custom_jet2, b"h", b"h", // source/target type
);
```
