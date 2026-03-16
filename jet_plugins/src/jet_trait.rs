use crate::{
    CUSTOM_JET_COST, JetsInput, StaticTokenInfo,
    decode_trees::{bitcoin_decode_tree, elements_decode_tree},
    helpers::{JET_ENC_BITLEN, JetBranchCode, JetDecodeTree, cmr},
    pascal_to_snake_case,
};
use quote::quote;

pub(crate) fn jet_trait_full(
    base_type: &syn::Path,
    unchained_env: &syn::Path,
    names: &[proc_macro2::Ident],
    jets: &JetsInput,
    base_type_str: &str, // remove this when issue with decode resolved. it dispatches hardcoded tree inside decode
) -> proc_macro2::TokenStream {
    let associated_types = associated_types_impl(unchained_env);
    let c_jet_env = c_jet_env_impl();
    let cmr = cmr_impl(names);

    let src_ty = src_trg_ty_impl(names, &build_source_tys(jets), "source");
    let trgt_ty = src_trg_ty_impl(names, &build_target_tys(jets), "target");

    let jet_codes = build_jet_codes(names);

    let jet_encode = encode_impl(names, &jet_codes);
    //let jet_decode_unsafe = decode_unsafe_impl(base_type, jet_codes);
    let jet_decode = decode_impl();
    let jet_decode_hardcoded = decode_hardcoded_impl(base_type, base_type_str, jet_codes);

    let c_jet_ptr = c_jet_ptr_impl();
    let c_jet_ptr_builder = c_jet_ptr_table_impl(base_type, unchained_env, names, jets);
    let cost = cost_impl();

    let jet_trait_path = StaticTokenInfo::jet_trait_path();
    let enum_ident = StaticTokenInfo::enum_ident();

    let invalid_jet_err = StaticTokenInfo::invalid_jet_err();
    let end_of_stream_err = StaticTokenInfo::end_of_stream_err();

    let fmt_impl = fmt_trait_full(names);
    let from_str_impl = from_str_trait_full(base_type, names);

    quote! {
        // maybe consider moving it somewhere
        macro_rules! decode_bits {
            ($bits:ident, {}) => {
                Err(#invalid_jet_err.into())
            };
            ($bits:ident, {$jet:expr}) => {
                Ok($jet)
            };
            ($bits:ident, { 0 => $false_branch:tt, 1 => $true_branch:tt }) => {
                match $bits.next() {
                    None => Err(#end_of_stream_err.into()),
                    Some(false) => decode_bits!($bits, $false_branch),
                    Some(true) => decode_bits!($bits, $true_branch),
                }
            };
        }
        #c_jet_ptr_builder
        impl #enum_ident {
            //#jet_decode_unsafe
            #jet_decode_hardcoded
        }
        impl #jet_trait_path for #enum_ident {
            #associated_types
            #c_jet_env
            #cmr
            #src_ty
            #trgt_ty
            #jet_encode
            #jet_decode
            #c_jet_ptr
            #cost
        }

        #fmt_impl
        #from_str_impl
    }
}

// TODO: settle on namings
fn from_str_trait_full(
    base_type: &syn::Path,
    names: &[proc_macro2::Ident],
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let snake_case_names = names
        .iter()
        .map(|name| pascal_to_snake_case(&name.to_string()));
    let simpl_err_ty = StaticTokenInfo::simplicity_error_ty();
    quote! {
        impl std::str::FromStr for #enum_ident {
            type Err = #simpl_err_ty;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#snake_case_names => Ok(Self::#names), )*
                    _ => {
                        let inner_jet = s.parse::<#base_type>()?;
                        Ok(Self::BaseJets(inner_jet))
                    }
                }
            }
        }
    }
}

// TODO: settle on namings
fn fmt_trait_full(names: &[proc_macro2::Ident]) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let snake_case_names = names
        .iter()
        .map(|name| pascal_to_snake_case(&name.to_string()));
    quote! {
        impl std::fmt::Display for #enum_ident {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::BaseJets(inner_jet) => f.write_str(&inner_jet.to_string()),
                    #(Self::#names => f.write_str(#snake_case_names), )*
                }
            }
        }
    }
}

fn cost_impl() -> proc_macro2::TokenStream {
    let cost_path = StaticTokenInfo::cost_path();
    quote! {
        fn cost(&self) -> #cost_path {
            match self {
                Self::BaseJets(inner_jet) => inner_jet.cost(),
                _ => #cost_path::from_milliweight(#CUSTOM_JET_COST)
            }
        }
    }
}

fn c_jet_ptr_impl() -> proc_macro2::TokenStream {
    let c_frame_path = StaticTokenInfo::cframe_item_path();

    quote! {
        fn c_jet_ptr(&self) -> &dyn Fn(&mut #c_frame_path, #c_frame_path, &Self::CJetEnvironment) -> bool {
            C_JET_PTRS.get(self).expect("All enum variants should be initialized")
        }
    }
}

/// May have issues with env casting
fn c_jet_ptr_table_impl(
    base_type: &syn::Path,
    unchained_env: &syn::Path,
    names: &[proc_macro2::Ident],
    inputs: &JetsInput,
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let c_frame_item = StaticTokenInfo::cframe_item_path();
    let jet_trait = StaticTokenInfo::jet_trait_path();
    let funcs = inputs.jets.iter().map(|jet| jet.func.clone());

    quote! {
        static C_JET_PTRS: std::sync::LazyLock<
            std::collections::HashMap<
                #enum_ident,
                &'static (
                             dyn Fn(
                    &mut #c_frame_item,
                    #c_frame_item,
                    &#unchained_env,
                ) -> bool
                                 + Send
                                 + Sync
                        ),
            >,
        > = std::sync::LazyLock::new(|| build_c_jet_ptrs());

        fn build_c_jet_ptrs()
            -> std::collections::HashMap<
                #enum_ident,
                &'static (
                             dyn Fn(
                    &mut #c_frame_item,
                    #c_frame_item,
                    &#unchained_env,
                ) -> bool
                                 + Send
                                 + Sync
                         ),
            > {
                    #enum_ident::ALL
                    .iter()
                    .map(|jet| {
                        let boxed: Box<
                            dyn Fn(&mut #c_frame_item, #c_frame_item, &#unchained_env) -> bool + Send + Sync,
                        > = match jet {
                            #enum_ident::BaseJets(inner_jet) => Box::new(
                                move |dst: &mut #c_frame_item, src: #c_frame_item, env: &#unchained_env| -> bool {
                                    <#base_type as #jet_trait>::c_jet_ptr(inner_jet)(dst, src, env.into())
                                },
                            ),
                            // custom jets
                            #(#enum_ident::#names => Box::new(
                                move |dst: &mut #c_frame_item, src: #c_frame_item, env: &#unchained_env| -> bool {
                                    #funcs(dst, src, env)
                                },
                            ), )*
                        };
                        let leaked: &'static (
                                     dyn Fn(&mut #c_frame_item, #c_frame_item, &#unchained_env) -> bool
                                         + Send
                                         + Sync
                                 ) = Box::leak(boxed);
                        (*jet, leaked)
                    })
                    .collect()
        }
    }
}

fn decode_impl() -> proc_macro2::TokenStream {
    let bit_iter = StaticTokenInfo::bit_iter_path();
    let decode_err = StaticTokenInfo::decode_err();
    let _enum_ident = StaticTokenInfo::enum_ident();

    quote! {
        fn decode<I: Iterator<Item = u8>>(bits: &mut #bit_iter<I>) -> Result<Self, #decode_err> {

            // Uncomment when issue with iter rewinding will be resolved
            //#enum_ident::decode_unsafe(bits)
            todo!("Trait impl is empty while issue with iterator rewind not resolved. Use FFI version instead")
        }
    }
}

fn decode_hardcoded_impl(
    base_type: &syn::Path,
    base_type_str: &str,
    codes: Vec<JetBranchCode>,
) -> proc_macro2::TokenStream {
    let custom_tree: proc_macro2::TokenStream = JetDecodeTree::from_branches(codes).into();
    let decode_err = StaticTokenInfo::decode_err();

    let decode_tree = match base_type_str {
        "Core" => bitcoin_decode_tree(custom_tree, base_type),
        "Elements" => elements_decode_tree(custom_tree, base_type),
        _ => unreachable!("decode: unkown tree dispatcher"),
    };

    quote! {
        fn decode_hardcoded(bits: &mut dyn Iterator<Item=bool>) -> Result<Self, #decode_err> {
            #decode_tree
        }
    }
}

/// Deprecated while issue with iterator rewind not resolved.
#[allow(dead_code)]
fn decode_unsafe_impl(
    base_type: &syn::Path,
    codes: Vec<JetBranchCode>,
) -> proc_macro2::TokenStream {
    let custom_decode_tree: proc_macro2::TokenStream = JetDecodeTree::from_branches(codes).into();
    let decode_err = StaticTokenInfo::decode_err();
    let bit_iter = StaticTokenInfo::bit_iter_path();
    let jet_trait = StaticTokenInfo::jet_trait_path();

    quote! {
        pub fn decode_unsafe<I: Iterator<Item = u8>>(bits: &mut #bit_iter<I>) -> Result<Self, #decode_err> {
            let (mut elements_iter, mut custom_iter) =
                unsafe { (std::ptr::read(bits), std::ptr::read(bits)) };

            let bits_read = bits.n_total_read();

            let try_elements = <#base_type as #jet_trait>::decode(&mut elements_iter);

            if let Ok(jet) = try_elements {
                for _ in 0..(elements_iter.n_total_read() - bits_read) {
                    bits.next();
                }

                std::mem::forget(elements_iter);
                std::mem::forget(custom_iter);

                return Ok(Self::BaseJets(jet));
            }

            let custom_iter_ref = &mut custom_iter;
            let try_custom = decode_bits!(custom_iter_ref, {
                #custom_decode_tree
            });

            if try_custom.is_ok() {
                for _ in 0..(custom_iter.n_total_read() - bits_read) {
                    bits.next();
                }
            }

            std::mem::forget(elements_iter);
            std::mem::forget(custom_iter);

            try_custom
        }
    }
}

fn encode_impl(
    variants: &[proc_macro2::Ident],
    codes: &[JetBranchCode],
) -> proc_macro2::TokenStream {
    let code_len = JET_ENC_BITLEN;
    let codes_bits = codes
        .iter()
        .map(|code| code.bits | (15 << (JET_ENC_BITLEN - 4))); // remove when hardcoded decode trees resolved
    let bit_writer = StaticTokenInfo::bit_writer_path();

    quote! {
        fn encode<W: std::io::Write>(&self, w: &mut #bit_writer<W>) -> std::io::Result<usize> {
            if let Self::BaseJets(inner_jet) = self {
                return inner_jet.encode(w);
            }

            let (n, len) = match self {
                #(Self::#variants => (#codes_bits, #code_len), )*
                _ => unreachable!("encode: all custom variants should be listed"),
            };

            w.write_bits_be(n as u64, len)
        }
    }
}

fn src_trg_ty_impl(
    variants: &[proc_macro2::Ident],
    types: &[Vec<u8>],
    mode: &str,
) -> proc_macro2::TokenStream {
    let type_name_path = StaticTokenInfo::type_name_path();
    let source_or_target_ty = match mode {
        "source" => quote::format_ident!("source_ty"),
        "target" => quote::format_ident!("target_ty"),
        _ => unreachable!("src/trg_ty: unknown dispatcher"),
    };
    quote! {
        fn #source_or_target_ty(&self) -> #type_name_path {
            if let Self::BaseJets(inner_jet) = self {
                return inner_jet.#source_or_target_ty();
            }

            let name = match self {
                #(Self::#variants => &[#(#types,)*],)*
                _ => unreachable!("src/trg_ty: all custom variants should be listed"),
            };

            #type_name_path(name)
        }
    }
}

fn cmr_impl(variants: &[proc_macro2::Ident]) -> proc_macro2::TokenStream {
    let cmr_by_path = StaticTokenInfo::cmr_path();
    let cmrs = variants
        .iter()
        .map(|ident| {
            let ident_str = ident.to_string();
            cmr(&pascal_to_snake_case(&ident_str))
        })
        .collect::<Vec<_>>();

    quote! {
        fn cmr(&self) -> #cmr_by_path {
            if let Self::BaseJets(inner_jet) = self {
                return inner_jet.cmr();
            }

            let bytes = match self {
                #(Self::#variants => [#(#cmrs,)*],)*
                _ => unreachable!("cmr: all custom variants should be listed"),
            };

            #cmr_by_path::from_byte_array(bytes)
        }
    }
}

fn c_jet_env_impl() -> proc_macro2::TokenStream {
    quote! {
            fn c_jet_env(env: &Self::Environment) -> &Self::CJetEnvironment {
            // For the time being, we are goint to use the initial environment for unchained jets,
            // as we are going to implement them in rust.
            env
        }
    }
}

fn associated_types_impl(unchained_env: &syn::Path) -> proc_macro2::TokenStream {
    quote! {
        type Environment = #unchained_env;
        type CJetEnvironment = #unchained_env;
    }
}

fn build_jet_codes(variants: &[proc_macro2::Ident]) -> Vec<JetBranchCode> {
    variants
        .iter()
        .map(|ident| JetBranchCode::from_ident_fixed(ident.clone()))
        .collect()
}

fn build_target_tys(jets: &JetsInput) -> Vec<Vec<u8>> {
    jets.jets
        .iter()
        .map(|jet| jet.target_type.value())
        .collect()
}

fn build_source_tys(jets: &JetsInput) -> Vec<Vec<u8>> {
    jets.jets
        .iter()
        .map(|jet| jet.source_type.value())
        .collect()
}
