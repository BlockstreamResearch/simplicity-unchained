pub mod base;
pub mod bitcoin;
pub mod elements;
pub mod environments;
pub mod exec;

#[cfg(test)]
pub(crate) mod tests {
    use std::ptr;
    use std::sync::Arc;

    use hex_literal::hex;
    use simplicity::Cmr;
    use simplicity::elements::taproot::ControlBlock;
    use simplicity::elements::{
        AssetIssuance, BlockHash, LockTime, OutPoint, Sequence, Transaction, TxIn, TxInWitness,
    };
    use simplicity::jet::elements::ElementsEnv;

    use crate::jets::environments::{ElementsUnchainedEnv, UnchainedEnv};
    use crate::jets::{bitcoin::CoreExtension, elements::ElementsExtension};
    use simplicity::elements::Script;
    use simplicity::elements::opcodes::all::OP_PUSHNUM_2;
    use simplicity::ffi::CFrameItem;
    use simplicity::ffi::c_jets::c_frame::uword_width;
    use simplicity::ffi::ffi::UWORD;
    use simplicity::jet::{Jet, JetEnvironment};
    use simplicity::{BitIter, BitWriter};

    #[test]
    fn test_new_jets_decode() {
        for expected_jet in ElementsExtension::ALL {
            let mut source = vec![];
            let mut writer = BitWriter::new(&mut source as &mut dyn std::io::Write);

            let _ = expected_jet.encode(&mut writer).unwrap();

            writer.flush_all().unwrap();

            let mut iter = BitIter::from(&source[..]);

            let decoded_jet = ElementsExtension::decode(&mut iter);

            assert!(decoded_jet.is_ok());
            assert_eq!(decoded_jet.unwrap(), expected_jet);
        }

        for expected_jet in CoreExtension::ALL {
            let mut source = vec![];
            let mut writer = BitWriter::new(&mut source as &mut dyn std::io::Write);

            let _ = expected_jet.encode(&mut writer).unwrap();

            writer.flush_all().unwrap();

            let mut iter = BitIter::from(&source[..]);

            let decoded_jet = CoreExtension::decode(&mut iter);

            assert!(decoded_jet.is_ok());
            assert_eq!(decoded_jet.unwrap(), expected_jet);
        }
    }

    #[test]
    fn test_get_opcode() {
        let script = Script::from_hex_no_prefix(
            "5221033523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf21025eb4655feae15a304653e27441ca8e8ced2bef89c22ab6b20424b4c07b3d14cc52ae"
        ).unwrap();

        let env = UnchainedEnv::new(script, dummy_elements_env());

        let output_uwords = uword_width(8);
        let mut dst_data = vec![0 as UWORD; output_uwords];

        unsafe {
            let src_data: Vec<UWORD> = vec![0; 1];

            let src_frame = CFrameItem::new_read(8, src_data.as_ptr());

            let mut dst_frame = CFrameItem::new_write(8, dst_data.as_mut_ptr().add(output_uwords));

            let jet = ElementsExtension::GetOpcodeFromScript;
            let jet_fn = ElementsUnchainedEnv::c_jet_ptr(&jet);
            let result = jet_fn(&mut dst_frame, src_frame, &env);

            assert!(result);

            for us in &mut dst_data {
                *us = us.swap_bytes().to_be();
            }

            let opcode = dst_data[0] as u8;

            assert_eq!(opcode, OP_PUSHNUM_2.into_u8());
        }
    }

    #[test]
    fn test_get_pubkey_from_script() {
        let script = Script::from_hex_no_prefix(
            "5221033523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf21025eb4655feae15a304653e27441ca8e8ced2bef89c22ab6b20424b4c07b3d14cc52ae"
        ).unwrap();

        let env = UnchainedEnv::new(script, dummy_elements_env());

        const OUTPUT_BITS: usize = 256;
        let output_uwords = uword_width(OUTPUT_BITS);
        let mut dst_data = vec![0 as UWORD; output_uwords];

        unsafe {
            let src_data: Vec<UWORD> = vec![1];

            let src_frame = CFrameItem::new_read(8, src_data.as_ptr());

            let mut dst_frame =
                CFrameItem::new_write(OUTPUT_BITS, dst_data.as_mut_ptr().add(output_uwords));

            let jet = ElementsExtension::GetPubkeyFromScript;
            let jet_fn = ElementsUnchainedEnv::c_jet_ptr(&jet);
            let result = jet_fn(&mut dst_frame, src_frame, &env);

            assert!(result);

            for us in &mut dst_data {
                *us = us.swap_bytes().to_be();
            }

            let mut output_bytes = vec![0u8; 32];
            ptr::copy_nonoverlapping(
                dst_data.as_ptr() as *const u8,
                output_bytes.as_mut_ptr(),
                32,
            );

            output_bytes.reverse();

            let expected = hex!("3523982d58e94be3b735731593f8225043880d53727235b566c515d24a0f7baf");

            assert_eq!(output_bytes, expected.to_vec());
        }
    }

    pub(crate) fn dummy_elements_env() -> ElementsEnv<Arc<Transaction>> {
        let ctrl_blk: [u8; 33] = [
            0xc0, 0xeb, 0x04, 0xb6, 0x8e, 0x9a, 0x26, 0xd1, 0x16, 0x04, 0x6c, 0x76, 0xe8, 0xff,
            0x47, 0x33, 0x2f, 0xb7, 0x1d, 0xda, 0x90, 0xff, 0x4b, 0xef, 0x53, 0x70, 0xf2, 0x52,
            0x26, 0xd3, 0xbc, 0x09, 0xfc,
        ];

        ElementsEnv::new(
            Arc::new(Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::default(),
                    is_pegin: false,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    asset_issuance: AssetIssuance::default(),
                    witness: TxInWitness::default(),
                }],
                output: Vec::default(),
            }),
            vec![],
            0,
            Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&ctrl_blk).unwrap(),
            None,
            BlockHash::from_byte_array([0; 32]),
        )
    }
}
