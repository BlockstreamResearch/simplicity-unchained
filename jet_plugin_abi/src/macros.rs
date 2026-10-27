/// Exports a plugin descriptor declaring the given jets.
///
/// Each jet is named after the function implementing it, which must be a [`JetFn`] in scope.
/// Types use `TypeName` notation; the remaining fields are those of [`CustomJetDesc`].
///
/// ```ignore
/// jet_plugin_abi::register_jets! {
///     base: Elements,
///     jets: {
///         script_len: "1" -> "s" {
///             cost_milliweight: 100,
///             code: 0b1111_1110,
///             code_len: 8,
///             cmr: [0x11; 32],
///         },
///     },
/// }
/// ```
///
/// A crate can invoke it at most once, as it defines the [`DESCRIPTOR_SYMBOL`] export.
///
/// [`JetFn`]: crate::JetFn
/// [`CustomJetDesc`]: crate::CustomJetDesc
/// [`DESCRIPTOR_SYMBOL`]: crate::DESCRIPTOR_SYMBOL
#[macro_export]
macro_rules! register_jets {
    (
        base: $base:ident,
        jets: {
            $(
                $name:ident : $source:literal -> $target:literal {
                    cost_milliweight: $cost:expr,
                    code: $code:expr,
                    code_len: $code_len:expr,
                    cmr: $cmr:expr $(,)?
                }
            ),* $(,)?
        } $(,)?
    ) => {
        const _: () = {
            const JETS: &[$crate::CustomJetDesc] = &[$(
                $crate::CustomJetDesc {
                    name: $crate::utils::Bytes::new(stringify!($name).as_bytes()),
                    cmr: $cmr,
                    source_ty: $crate::utils::Bytes::new($source.as_bytes()),
                    target_ty: $crate::utils::Bytes::new($target.as_bytes()),
                    cost_milliweight: $cost,
                    code: $code,
                    code_len: $code_len,
                    func: Some($name as $crate::JetFn),
                }
            ),*];

            static DESCRIPTOR: $crate::PluginDescriptor = $crate::PluginDescriptor {
                abi_version: $crate::ABI_VERSION,
                simplicity_sys_version: $crate::utils::Bytes::new(
                    $crate::SIMPLICITY_SYS_VERSION.as_bytes(),
                ),
                base_set: $crate::BaseSet::$base as u32,
                jets: JETS.as_ptr(),
                jets_len: JETS.len(),
            };

            // Must match `DESCRIPTOR_SYMBOL`.
            #[unsafe(no_mangle)]
            extern "C" fn unchained_jet_plugin() -> *const $crate::PluginDescriptor {
                &DESCRIPTOR
            }
        };
    };
}
