#[cfg(test)]
mod tests {
    use crate::jets::environments::UnchainedEnv;
    use crate::jets::unchained::CoreExtension;
    use simplicity::ffi::CFrameItem;
    use simplicity::ffi::c_jets::c_frame::uword_width;
    use simplicity::ffi::ffi::UWORD;
    use simplicity::jet::{Core, Jet};
    use simplicity::{BitIter, BitWriter};

    #[test]
    fn test_new_jets_decode() {
        // TODO(ivanlele): Discard default Unchained jets once more new jets are added
        let test_jets = vec![
            CoreExtension::WalletIDHash,
            CoreExtension::Core(Core::Add16),
            CoreExtension::Core(Core::Sha256Block),
            CoreExtension::Core(Core::Verify),
        ];

        for expected_jet in test_jets {
            let mut source = vec![];
            let mut writer = BitWriter::new(&mut source);

            let _ = expected_jet.encode(&mut writer).unwrap();

            writer.flush_all().unwrap();

            let mut iter = BitIter::from(&source[..]);

            println!("Decoding jet from bits: {:?}", expected_jet);

            let decoded_jet = CoreExtension::decode(&mut iter).unwrap();

            assert_eq!(decoded_jet, expected_jet);
        }
    }

    #[test]
    fn test_wallet_id_hash_c_jet_ptr() {
        use std::ptr;

        let wallet_id = [
            0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777,
            0x88888888,
        ];
        let env = UnchainedEnv::new(wallet_id);

        let src_data: Vec<UWORD> = vec![0; 1];

        const OUTPUT_BITS: usize = 256;
        let output_uwords = uword_width(OUTPUT_BITS);
        let mut dst_data = vec![0 as UWORD; output_uwords];

        unsafe {
            let src_frame = CFrameItem::new_read(0, src_data.as_ptr());
            let mut dst_frame =
                CFrameItem::new_write(OUTPUT_BITS, dst_data.as_mut_ptr().add(output_uwords));

            let jet = CoreExtension::WalletIDHash;
            let jet_fn = jet.c_jet_ptr();
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

            let expected_bytes: Vec<u8> = wallet_id.iter().flat_map(|&w| w.to_be_bytes()).collect();

            assert_eq!(output_bytes, expected_bytes);
        }
    }
}
