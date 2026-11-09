use std::sync::Arc;

use simplicity::elements::Script;
use simplicity::jet::Jet;
use simplicity::node::CoreConstructible;
use simplicity::{BitMachine, ConstructNode, Word, types};

use super::{LoadError, PluginEnv, PluginJet, PluginTrait};
use crate::jets::elements::ElementsExtension;
use crate::jets::environments::UnchainedEnv;
use crate::jets::tests::dummy_elements_env;

/// `OP_2 <33-byte key> <33-byte key> OP_2 OP_CHECKMULTISIG`, 71 bytes.
const SCRIPT: &str = "5221033523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf21025eb4655feae15a304653e27441ca8e8ced2bef89c22ab6b20424b4c07b3d14cc52ae";

/// `plugin_tests/script_jets`, built next to this test binary as a dev-dependency.
fn script_jets_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.with_file_name(format!(
        "{}script_jets{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ))
}

#[test]
fn loads_dynamic_library() {
    crate::declare_plugin!(ScriptJets: ElementsExtension);
    crate::declare_plugin!(Unused: ElementsExtension);

    let path = script_jets_path();
    let sha256 =
        simplicity::hashes::sha256::Hash::hash(&std::fs::read(&path).unwrap()).to_byte_array();

    assert!(matches!(
        Unused::load(&path, Some([0; 32])),
        Err(LoadError::HashMismatch { .. })
    ));
    assert!(matches!(
        Unused::load(path.with_file_name("missing.so"), None),
        Err(LoadError::Io(_)) | Err(LoadError::Open(_))
    ));
    assert!(Unused::get().is_none());

    ScriptJets::load(&path, Some(sha256)).unwrap();
    let plugin = ScriptJets::get().unwrap();
    assert_eq!(
        plugin.custom_names().collect::<Vec<_>>(),
        ["script_len", "opcode_at"]
    );

    let redeem = types::Context::with_context(|ctx| {
        let jet =
            |name| Arc::<ConstructNode>::jet(&ctx, &PluginJet::<ScriptJets>::parse(name).unwrap());
        let actual = jet("script_len");
        let expected = Arc::<ConstructNode>::const_word(&ctx, Word::u16(71));
        let pair = Arc::<ConstructNode>::pair(&actual, &expected).unwrap();
        let check = Arc::<ConstructNode>::comp(&pair, &jet("eq_16")).unwrap();
        Arc::<ConstructNode>::comp(&check, &jet("verify"))
            .unwrap()
            .finalize_unpruned()
            .unwrap()
    });
    let env = PluginEnv::<ScriptJets>::new(UnchainedEnv::new(
        Script::from_hex_no_prefix(SCRIPT).unwrap(),
        dummy_elements_env(),
    ));
    let mut mac = BitMachine::for_program(&redeem).unwrap();
    mac.exec(&redeem, &env).unwrap();
}
