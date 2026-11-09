# Custom jet plugins

## General plugin loading flow

1. The plugin provider writes its jets as `unsafe extern "C"` functions and lists them in
   `jet_plugin_abi::register_jets!`. The macro creates a static, plain-data descriptor
   (ABI version, `simplicity-sys` version, base jet set) with an array of jets, each holding
   its name, types, cost, encoding, CMR and function pointer, and exports a function
   returning it from the dynamic library.
2. The host uses `declare_plugin!` to declare a handle type and generate its `PluginTrait`
   impl. `Handle::load(path, sha256)` then loads the library, reads its descriptor, validates
   it and stores the result in the handle for the rest of the process.
3. Programs are parsed and run with `PluginJet<Handle>` and `PluginEnv<Handle>`. Base jets run
   through the host's own implementation; custom jets are called through the function
   pointers from the descriptor.

## Policy integration

Native plugins are loaded by a Rust host, not by the policy service endpoints.
`bitcoin-policy-v1` and `liquid-policy-v1` use fixed portable registries. Adding a
jet to a policy profile requires a versioned registry and matching compiler, VM,
service and WASM implementations.

See the [script_jets example](../../../plugin_tests/script_jets/src/lib.rs) for
a plugin implementation and the [loader test](tests.rs) for host setup.
