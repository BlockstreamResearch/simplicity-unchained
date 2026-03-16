#![recursion_limit = "256"]
use quote::quote;
use syn::{
    Ident, LitByteStr, LitStr, Token,
    parse::{Parse, ParseStream},
    parse2,
    punctuated::Punctuated,
};

mod c_wrappers;
mod decode_trees;
mod helpers;
mod jet_trait;
mod static_tokens;
use helpers::snake_to_pascal_case;

use crate::{
    c_wrappers::impl_c_ffi, helpers::pascal_to_snake_case, jet_trait::jet_trait_full,
    static_tokens::StaticTokenInfo,
};

const CUSTOM_JET_COST: u32 = 1000;

/// Implements `Jet` trait and C FFI compatible with `simplicity_unchained_core::jets::jet_dyn` interface.
///
/// ## Arguments
/// - `base_type` - a collection of jets the extension will be built on;
/// - `env` - environment type;
/// - `name: literal` - name of jet in snake case;
/// - `function: Fn(CFrameItem, CFrameItem, &ElementsUnchainedEnv)`;
///
/// see `simplicity::jet::type_name`
///
/// - `source_type: &[u8]`
/// - `target_type: &[u8]`
///
/// # Note
/// Right now macro will **panic** if `base_type` other than `Bitcoin` or `Elements` provided due to issue
/// with `decode()` implementation.
///
/// ## Prerequisites
/// Make sure that input env type implements `Into<T>`, where T is type, which base jets use as env for `c_jet_ptr()`.
///
/// ## Usage
/// ```rust
/// use jet_plugins::register_jets;
/// use simplicity_unchained_core::jets::environments::ElementsUnchainedEnv;
/// use simplicity_unchained_core::__simplicity::simplicity::ffi::CFrameItem;
///
/// fn custom_jet1(_dst: &mut CFrameItem, src: CFrameItem, env: &ElementsUnchainedEnv) -> bool {
///     false
/// }
///
/// fn custom_jet2(_dst: &mut CFrameItem, src: CFrameItem, env: &ElementsUnchainedEnv) -> bool {
///     false
/// }
/// register_jets!(
///     simplicity_unchained_core::__simplicity::simplicity::jet::Elements,
///     simplicity_unchained_core::jets::environments::ElementsUnchainedEnv,
///     "custom_jet1" => custom_jet1, b"h", b"h", // source/target type
///     "custom_jet2" => custom_jet2, b"h", b"h", // source/target type
/// );
/// ```
#[proc_macro]
pub fn register_jets(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: JetsInput = parse2(input.into()).expect("Failed to parse JetsInput");

    let base_type = &input.base_type;
    let unchained_env = &input.env_type;
    let names = build_custom_fields(&input);

    let base_type_str = base_type
        .segments
        .last()
        .expect("Path should contain last Ident")
        .ident
        .to_string();

    let self_impl = self_impl_full(base_type, &names);
    let jet_trait_impl = jet_trait_full(base_type, unchained_env, &names, &input, &base_type_str);
    let c_ffi = impl_c_ffi(base_type, unchained_env);

    quote! {
        #self_impl
        #jet_trait_impl
        #c_ffi
    }
    .into()
}

pub(crate) struct JetsInput {
    base_type: syn::Path,
    _comma1: Token![,],
    env_type: syn::Path,
    _comma2: Token![,],
    jets: Punctuated<JetDef, Token![,]>,
}

impl Parse for JetsInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(JetsInput {
            base_type: input.parse()?,
            _comma1: input.parse()?,
            env_type: input.parse()?,
            _comma2: input.parse()?,
            jets: input.parse_terminated(JetDef::parse, Token![,])?,
        })
    }
}

struct JetDef {
    name: LitStr,
    _arrow: Token![=>],
    pub func: Ident,
    _comma1: Token![,],
    source_type: LitByteStr,
    _comma2: Token![,],
    target_type: LitByteStr,
}

impl Parse for JetDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(JetDef {
            // TODO: guarantee that its non-empty and starts from letter
            name: input.parse()?,
            _arrow: input.parse()?,
            func: input.parse()?,
            _comma1: input.parse()?,
            source_type: input.parse()?,
            _comma2: input.parse()?,
            target_type: input.parse()?,
        })
    }
}

fn self_impl_full(base_type: &syn::Path, names: &[proc_macro2::Ident]) -> proc_macro2::TokenStream {
    let definition = enum_definition_impl(base_type, names);
    let all_impl = all_constant_impl(base_type, names);

    quote! {
        #definition
        #all_impl
    }
}

fn enum_definition_impl(
    base_type: &syn::Path,
    variants: &[proc_macro2::Ident],
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    quote! {
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
        pub enum #enum_ident {
            BaseJets(#base_type),
            #( #variants, )*
        }
    }
}

fn build_custom_fields(jets: &JetsInput) -> Vec<proc_macro2::Ident> {
    jets.jets
        .iter()
        .map(|jet| quote::format_ident!("{}", snake_to_pascal_case(&jet.name.value())))
        .collect::<Vec<_>>()
}

fn all_constant_impl(
    base_type: &syn::Path,
    variants: &[proc_macro2::Ident],
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let custom_jets_num = variants.len();
    let jet_self_handle = StaticTokenInfo::jet_self_handle();

    quote! {
        impl #enum_ident {

            // TODO: BaseJets local elements instead of dep
            pub const ALL_JETS_NUM: usize = #base_type::ALL.len() + #custom_jets_num;
            pub const ALL: [Self; Self::ALL_JETS_NUM] = Self::build_all_variants();

            const fn build_all_variants() -> [Self; Self::ALL_JETS_NUM] {

                // consider moving it outside of macro
                struct AllVariantsBuilder<const LEN: usize, Enum: Copy> {
                    data: [std::mem::MaybeUninit<Enum>; LEN],
                    len: usize,
                }

                impl<const LEN: usize, Enum: Copy> AllVariantsBuilder<LEN, Enum> {
                    const fn new() -> Self {
                        Self {
                            data: [std::mem::MaybeUninit::uninit(); LEN],
                            len: 0,
                        }
                    }

                    const fn push(&mut self, item: Enum) {
                        assert!(self.len < self.data.len());

                        self.data[self.len].write(item);
                        self.len += 1;
                    }

                    const fn finalize(self) -> [Enum; LEN] {
                        assert!(self.len == LEN);

                        let ptr = &self.data as *const [std::mem::MaybeUninit<Enum>; LEN] as *const [Enum; LEN];
                        let res = unsafe { std::ptr::read(ptr) };

                        std::mem::forget(self.data);

                        res
                    }
                }

                let mut builder = AllVariantsBuilder::new();

                let mut i = 0;

                while i < #base_type::ALL.len() {
                    builder.push(#enum_ident::BaseJets(#base_type::ALL[i]));
                    i += 1;
                }

                #(builder.push(#enum_ident::#variants);)*
                builder.finalize()
            }

            /// Returns index of `self` inside `Self::ALL` array
            pub fn variant_to_index(&self) -> usize {
                Self::ALL.iter().position(|x| x == self).expect("ALL must contain all enum's variants")
            }

            pub fn variant_from_index(idx: usize) -> Self {
                Self::ALL[idx]
            }

            pub fn to_base_jet(&self) -> Option<#base_type> {
                match self {
                    Self::BaseJets(jet) => Some(*jet),
                    _ => None
                }
            }

            pub fn from_base_jet(jet: #base_type) -> Self {
                Self::BaseJets(jet)
            }
        }

        impl Into<#jet_self_handle> for &#enum_ident {
            fn into(self) -> #jet_self_handle {
                #jet_self_handle {
                    index: self.variant_to_index()
                }
            }
        }
    }
}
