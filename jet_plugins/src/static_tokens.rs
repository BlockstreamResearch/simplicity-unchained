const STRUCT_EXTENSION_NAME: &str = "JetExtension";

const JET_TRAIT_PATH: &str = "simplicity_unchained_core::__simplicity::simplicity::jet::Jet";
const BIT_WRITER_PATH: &str = "simplicity_unchained_core::__simplicity::simplicity::BitWriter";
const BIT_ITER_PATH: &str = "simplicity_unchained_core::__simplicity::simplicity::BitIter";
const CMR_PATH: &str = "simplicity_unchained_core::__simplicity::simplicity::Cmr";
const COST_PATH: &str = "simplicity_unchained_core::__simplicity::simplicity::Cost";
const INVALID_JET_ERR: &str =
    "simplicity_unchained_core::__simplicity::simplicity::decode::Error::InvalidJet";
const END_OF_STREAM_ERR: &str =
    "simplicity_unchained_core::__simplicity::simplicity::decode::Error::EndOfStream";
const DECODE_ERR_TY: &str = "simplicity_unchained_core::__simplicity::simplicity::decode::Error";
const TYPE_NAME_PATH: &str =
    "simplicity_unchained_core::__simplicity::simplicity::jet::type_name::TypeName";
const CFRAME_ITEM_PATH: &str =
    "simplicity_unchained_core::__simplicity::simplicity::ffi::CFrameItem";
const SIMPLICITY_ERROR_TY: &str = "simplicity_unchained_core::__simplicity::simplicity::Error";

// C FFI stuff
const JET_SELF_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::CCustomJet";
const CMR_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::CmrHandle";
const TYPENAME_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::TypeNameHandle";
const BIT_WRITER_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::BitWriterHandle";
const BIT_ITER_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::BitIterHandle";
const C_ORDERING: &str = "simplicity_unchained_core::jets::jet_dyn::COrdering";
const C_OPTION_ORDERING: &str = "simplicity_unchained_core::jets::jet_dyn::COptionOrdering";
const HASHER_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::HasherHandle";
const FMT_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::FmtHandle";
const STR_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::StrHandle";
const COST_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::CostHandle";
const ALL_JETS_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::AllJetsHandle";
const DECODE_RES_HANDLE: &str = "simplicity_unchained_core::jets::jet_dyn::DecodeResHandle";

pub(crate) struct StaticTokenInfo {}

impl StaticTokenInfo {
    pub fn enum_ident() -> proc_macro2::Ident {
        quote::format_ident!("{}", STRUCT_EXTENSION_NAME)
    }

    pub fn jet_trait_path() -> syn::Path {
        syn::parse_str(JET_TRAIT_PATH).expect("Failed to find Jet trait by given path")
    }

    pub fn bit_iter_path() -> syn::Path {
        syn::parse_str(BIT_ITER_PATH).expect("Failed to find BitIter by given path")
    }

    pub fn bit_writer_path() -> syn::Path {
        syn::parse_str(BIT_WRITER_PATH).expect("Failed to find BitWriter by given path")
    }

    pub fn invalid_jet_err() -> syn::Path {
        syn::parse_str(INVALID_JET_ERR)
            .expect("Failed to find simplicity::decode::Error::InvalidJet by given path")
    }

    pub fn end_of_stream_err() -> syn::Path {
        syn::parse_str(END_OF_STREAM_ERR)
            .expect("Failed to find simplicity::decode::Error::EndOfStream by given path")
    }

    pub fn decode_err() -> syn::Path {
        syn::parse_str(DECODE_ERR_TY)
            .expect("Failed to find simplicity::decode::Error by given path")
    }

    pub fn cmr_path() -> syn::Path {
        syn::parse_str(CMR_PATH).expect("Failed to find Cmr by given path")
    }

    pub fn cost_path() -> syn::Path {
        syn::parse_str(COST_PATH).expect("Failed to find Cost by given path")
    }

    pub fn type_name_path() -> syn::Path {
        syn::parse_str(TYPE_NAME_PATH).expect("Failed to find TypeName by given path")
    }

    pub fn cframe_item_path() -> syn::Path {
        syn::parse_str(CFRAME_ITEM_PATH).expect("Failed to find CFrame by given path")
    }

    pub fn simplicity_error_ty() -> syn::Path {
        syn::parse_str(SIMPLICITY_ERROR_TY).expect("Failed to find simplicity::Error by given path")
    }

    pub fn jet_self_handle() -> syn::Path {
        syn::parse_str(JET_SELF_HANDLE).expect("Failed to find JetSelfHandle by given path")
    }

    pub fn cmr_handle() -> syn::Path {
        syn::parse_str(CMR_HANDLE).expect("Failed to find CmrHandle by given path")
    }

    pub fn typename_handle() -> syn::Path {
        syn::parse_str(TYPENAME_HANDLE).expect("Failed to find TypeNameHandle by given path")
    }

    pub fn bitwriter_handle() -> syn::Path {
        syn::parse_str(BIT_WRITER_HANDLE).expect("Failed to find BitWriterHandle by given path")
    }

    pub fn bititer_handle() -> syn::Path {
        syn::parse_str(BIT_ITER_HANDLE).expect("Failed to find BitIterHandle by given path")
    }

    pub fn c_ordering() -> syn::Path {
        syn::parse_str(C_ORDERING).expect("Failed to find COrdering by given path")
    }

    pub fn c_option_ordering() -> syn::Path {
        syn::parse_str(C_OPTION_ORDERING).expect("Failed to find COptionOrdering by given path")
    }

    pub fn hasher_handle() -> syn::Path {
        syn::parse_str(HASHER_HANDLE).expect("Failed to find HasherHandle by given path")
    }

    pub fn fmt_handle() -> syn::Path {
        syn::parse_str(FMT_HANDLE).expect("Failed to find FmtHandle by given path")
    }

    pub fn str_handle() -> syn::Path {
        syn::parse_str(STR_HANDLE).expect("Failed to find StrHandle by given path")
    }

    pub fn cost_handle() -> syn::Path {
        syn::parse_str(COST_HANDLE).expect("Failed to find CostHandle by given path")
    }

    pub fn all_jets_handle() -> syn::Path {
        syn::parse_str(ALL_JETS_HANDLE).expect("Failed to find AllJetsHandle by given path")
    }

    pub fn decode_res_handle() -> syn::Path {
        syn::parse_str(DECODE_RES_HANDLE).expect("Failed to find DecodeResHandle by given path")
    }
}
