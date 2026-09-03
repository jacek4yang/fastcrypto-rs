//! Differential fuzzing: our HKDF-SHA256 against RustCrypto hkdf, plus the
//! invariants from RFC 5869.
//!
//! The input is split deterministically into salt, IKM, info and an output
//! length, so the fuzzer explores short, empty, and oversized cases alike.

#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

const MAX_OUT: usize = 255 * 32;

#[derive(Debug)]
struct Input {
    salt: Vec<u8>,
    ikm: Vec<u8>,
    info: Vec<u8>,
    out_len: u16,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Self {
            salt: Vec::arbitrary(u)?,
            ikm: Vec::arbitrary(u)?,
            info: Vec::arbitrary(u)?,
            out_len: u16::arbitrary(u)?,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = Input::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };
    let out_len = usize::from(input.out_len);

    let mut ours = vec![0u8; out_len];
    let ours_result = fastcrypto::hkdf_sha256(&input.salt, &input.ikm, &input.info, &mut ours);

    let (_, rc) = hkdf::Hkdf::<Sha256>::extract(Some(&input.salt), &input.ikm);
    let mut theirs = vec![0u8; out_len];
    let theirs_result = rc.expand(&input.info, &mut theirs);

    // Both must accept or reject together: the RFC limit is 255 blocks.
    assert_eq!(ours_result.is_ok(), theirs_result.is_ok(), "length {out_len}");
    if ours_result.is_ok() {
        assert_eq!(ours, theirs, "length {out_len}");
    }

    // Prefix stability: expanding to L and to L+1 must agree on the first L
    // bytes, which is what a TLS key schedule relies on.
    if out_len < MAX_OUT {
        let mut longer = vec![0u8; out_len + 1];
        fastcrypto::hkdf_sha256(&input.salt, &input.ikm, &input.info, &mut longer).unwrap();
        assert_eq!(&longer[..out_len], &ours[..]);
    }
});

