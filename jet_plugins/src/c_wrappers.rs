//! C FFI for Jet trait.
//! See core::jet_dyn for interface on caller's side.
use crate::static_tokens::StaticTokenInfo;
use quote::quote;

pub(crate) fn impl_c_ffi(
    base_type: &syn::Path,
    unchained_env: &syn::Path,
) -> proc_macro2::TokenStream {
    let cmp = cmp_c_wrapper();
    let partial_cmp = partial_cmp_c_wrapper();
    let hash = hash_c_wrapper();
    let debug_fmt = debug_fmt_c_wrapper();
    let display_fmt = display_fmt_c_wrapper();
    let all_jets = all_jets();

    let cmr_c_wrapper = cmr_c_wrapper();
    let src_ty_c_wrapper = src_trg_ty_c_wrapper("source");
    let trg_ty_c_wrapper = src_trg_ty_c_wrapper("target");
    let encode_c_wrapper = encode_c_wrapper();
    let decode_c_wrapper = decode_c_wrapper();
    let cost_c_wrapper = cost_c_wrapper();
    let c_jet_ptr_wrapper = c_jet_ptr_wrapper(unchained_env);
    let from_str = from_str_c_wrapper();
    let to_base_jet = to_base_jet();
    let from_base_jet = from_base_jet(base_type);

    quote! {
        #cmp
        #partial_cmp
        #hash
        #debug_fmt
        #display_fmt
        #all_jets
        #cmr_c_wrapper
        #src_ty_c_wrapper
        #trg_ty_c_wrapper
        #encode_c_wrapper
        #decode_c_wrapper
        #cost_c_wrapper
        #c_jet_ptr_wrapper
        #from_str
        #to_base_jet
        #from_base_jet
    }
}

fn cost_c_wrapper() -> proc_macro2::TokenStream {
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_trait = StaticTokenInfo::jet_trait_path();
    let cost_handle = StaticTokenInfo::cost_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _cost(_self: #jet_self) -> *const #cost_handle {
            let jet = #enum_ident::variant_from_index(_self.index);
            let boxed = Box::new(
                <#enum_ident as #jet_trait>::cost(&jet)
            );
            Box::into_raw(boxed) as *const #cost_handle
        }
    }
}

fn c_jet_ptr_wrapper(unchained_env: &syn::Path) -> proc_macro2::TokenStream {
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let c_frame_item = StaticTokenInfo::cframe_item_path();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _c_jet_ptr(_self: #jet_self) -> *const () {
            let jet = #enum_ident::variant_from_index(_self.index);
            let boxed: Box<
                &'static (
                    dyn Fn(
                        &mut #c_frame_item,
                        #c_frame_item,
                        &#unchained_env,
                    ) -> bool
                    + Send
                    + Sync
                )>
                = Box::new(*C_JET_PTRS
                    .get(&jet)
                    .expect("All enum's variants should be initialized")
                );
            // * &'static dyn Fn(&mut CFrameItem, CFrameItem, &Self::CJetEnvironment) -> bool
            Box::into_raw(boxed) as *const ()
        }
    }
}

fn decode_c_wrapper() -> proc_macro2::TokenStream {
    let bititer_handle = StaticTokenInfo::bititer_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let decode_res_handle = StaticTokenInfo::decode_res_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _decode(bits: *mut #bititer_handle) -> #decode_res_handle {
            let bits: &mut dyn Iterator<Item = bool> = unsafe { (*bits).data };
            let decode_res = #enum_ident::decode_hardcoded(bits);

            let res = Box::new(match decode_res {
                Ok(jet) => {
                    let index = #enum_ident::variant_to_index(&jet);
                    Ok(#jet_self {
                        index
                    })
                }
                Err(err) => Err(err)
            });

            // Mocked to 0 to not bother with restructuring output again.
            // Original iterator is already shifted correctly by `decode()` action
            //let bits_read = bit_iter.n_total_read();
            let bits_read = 0;

            #decode_res_handle {
                // *Result<CCustomJet, simplicity::decode::Error>
                jet: Box::into_raw(res) as *const (),
                bits_read
            }
        }
    }
}

/// Deprecated while issue with iterator rewind is not resolved
#[allow(dead_code)]
fn decode_c_wrapper_deprecated() -> proc_macro2::TokenStream {
    let bititer_handle = StaticTokenInfo::bititer_handle();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_trait = StaticTokenInfo::jet_trait_path();
    let bit_iter = StaticTokenInfo::bit_iter_path();
    let decode_res_handle = StaticTokenInfo::decode_res_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _decode(w: *mut #bititer_handle) -> #decode_res_handle
         {

            let data: &[u8] = unsafe { (*w).data };
            let mut bit_iter = #bit_iter::from(data);

            let decode_res = <#enum_ident as #jet_trait>::decode(&mut bit_iter);

            let res = Box::new(match decode_res {
                Ok(jet) => {
                    let index = #enum_ident::variant_to_index(&jet);
                    Ok(#jet_self {
                        index
                    })
                }
                Err(err) => Err(err)
            });
            let bits_read = bit_iter.n_total_read();

            #decode_res_handle {
                // *Result<CCustomJet, simplicity::decode::Error>
                jet: Box::into_raw(res) as *const (),
                bits_read
            }

        }
    }
}

fn encode_c_wrapper() -> proc_macro2::TokenStream {
    let bitwriter_handle = StaticTokenInfo::bitwriter_handle();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_trait = StaticTokenInfo::jet_trait_path();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _encode(_self: #jet_self, w: *mut #bitwriter_handle) -> *const () {
            let jet = #enum_ident::variant_from_index(_self.index);
            let bit_writer = unsafe {
                &mut (*w)._writer
            };
            let boxed = Box::new(<#enum_ident as #jet_trait>::encode(&jet, bit_writer));
            // *std::io::Result<usize>
            Box::into_raw(boxed) as *const ()
        }
    }
}

fn src_trg_ty_c_wrapper(mode: &str) -> proc_macro2::TokenStream {
    let src_trg_ty = quote::format_ident!("{}", {
        match mode {
            "source" | "target" => format!("{}_ty", mode),
            _ => unreachable!(),
        }
    });

    let fn_name = quote::format_ident!("{}", {
        match mode {
            "source" | "target" => format!("_{}_ty", mode),
            _ => unreachable!(),
        }
    });

    let typename_handle = StaticTokenInfo::typename_handle();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_trait = StaticTokenInfo::jet_trait_path();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn #fn_name(_self: #jet_self) -> *const #typename_handle {
            let jet = #enum_ident::variant_from_index(_self.index);
            let boxed = Box::new(<#enum_ident as #jet_trait>::#src_trg_ty(&jet));
            Box::into_raw(boxed) as *const #typename_handle
        }
    }
}

fn cmr_c_wrapper() -> proc_macro2::TokenStream {
    let cmr_handle = StaticTokenInfo::cmr_handle();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_trait = StaticTokenInfo::jet_trait_path();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _cmr(_self: #jet_self) -> *const #cmr_handle {
            let jet = #enum_ident::variant_from_index(_self.index);
            let boxed = Box::new(<#enum_ident as #jet_trait>::cmr(&jet));
            Box::into_raw(boxed) as *const #cmr_handle
        }
    }
}

fn all_jets() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let all_jets_handle = StaticTokenInfo::all_jets_handle();
    let jet_self_handle = StaticTokenInfo::jet_self_handle();

    quote! {

        static ALL_JETS_HANDLE: std::sync::LazyLock<Box<[#jet_self_handle]>> = std::sync::LazyLock::new(|| {
            #enum_ident::ALL.iter().map(|jet| jet.into()).collect::<Vec<_>>().into_boxed_slice()
        });

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _all_jets() -> #all_jets_handle {
            #all_jets_handle {
                jets: ALL_JETS_HANDLE.as_ptr(),
                len: ALL_JETS_HANDLE.len()
            }
        }
    }
}

fn from_base_jet(base_type: &syn::Path) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self_handle = StaticTokenInfo::jet_self_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _from_base_jet(jet_ptr: *const ()) -> #jet_self_handle {
            let jet = unsafe { &*(jet_ptr as *const #base_type) };
            (&#enum_ident::from_base_jet(*jet)).into()
        }
    }
}

fn to_base_jet() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self_handle = StaticTokenInfo::jet_self_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _to_base_jet(_self: #jet_self_handle) -> *const () {
            let inner_jet = #enum_ident::variant_from_index(_self.index);
            let try_to_base = Box::new(inner_jet.to_base_jet());

            // * Option<BaseJetType>
            Box::into_raw(try_to_base) as *const ()
        }
    }
}

fn from_str_c_wrapper() -> proc_macro2::TokenStream {
    let str_handle = StaticTokenInfo::str_handle();
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _from_str(name: *const #str_handle) -> *const () {
            if name.is_null() {
                panic!("null ptr at name");
            }
            let _str = unsafe { (*name)._str };
            let parsing_res = <#enum_ident as std::str::FromStr>::from_str(_str.as_ref());
            let boxed = Box::new(
                match parsing_res {
                    Ok(jet) => {
                        let index = #enum_ident::variant_to_index(&jet);
                        Ok(#jet_self {
                            index
                        })
                    },
                    Err(err) => Err(err)
                }
            );
            Box::into_raw(boxed) as *const ()
        }
    }
}

fn display_fmt_c_wrapper() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let fmt_handle = StaticTokenInfo::fmt_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _display_fmt(_self: #jet_self, fmt_handle: *mut #fmt_handle) -> *const () {
            let jet = #enum_ident::variant_from_index(_self.index);
            let formatter = unsafe { &mut (*fmt_handle)._formatter };
            let boxed = Box::new(<#enum_ident as std::fmt::Display>::fmt(&jet, formatter));
            Box::into_raw(boxed) as *const ()
        }
    }
}

fn debug_fmt_c_wrapper() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let fmt_handle = StaticTokenInfo::fmt_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _debug_fmt(_self: #jet_self, fmt_handle: *mut #fmt_handle) -> *const () {
            let jet = #enum_ident::variant_from_index(_self.index);
            let formatter = unsafe { &mut (*fmt_handle)._formatter };
            let boxed = Box::new(<#enum_ident as core::fmt::Debug>::fmt(&jet, formatter));
            Box::into_raw(boxed) as *const ()
        }
    }
}

fn hash_c_wrapper() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let hasher_handle = StaticTokenInfo::hasher_handle();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _hash(_self: #jet_self, hasher_handle: *mut #hasher_handle) {
            let jet = #enum_ident::variant_from_index(_self.index);
            let hasher = unsafe { &mut (*hasher_handle)._hasher };
            <#enum_ident as std::hash::Hash>::hash(&jet, hasher)
        }
    }
}

fn partial_cmp_c_wrapper() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let c_option_ordering = StaticTokenInfo::c_option_ordering();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _partial_cmp(_self: #jet_self, other: #jet_self) -> #c_option_ordering {
            let lhs = #enum_ident::variant_from_index(_self.index);
            let rhs = #enum_ident::variant_from_index(other.index);
            #c_option_ordering::from(lhs.partial_cmp(&rhs))
        }
    }
}

fn cmp_c_wrapper() -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();
    let jet_self = StaticTokenInfo::jet_self_handle();
    let c_ordering = StaticTokenInfo::c_ordering();

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _cmp(_self: #jet_self, other: #jet_self) -> #c_ordering {
            let lhs = #enum_ident::variant_from_index(_self.index);
            let rhs = #enum_ident::variant_from_index(other.index);
            #c_ordering::from(lhs.cmp(&rhs))
        }
    }
}
