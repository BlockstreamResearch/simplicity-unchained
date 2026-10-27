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
