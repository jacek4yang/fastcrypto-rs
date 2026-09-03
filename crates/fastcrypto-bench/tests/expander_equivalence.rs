//! Equivalence tests for the prepared-key HKDF expander.
//!
//! The expander is an optimization, so it has to be proven equal to the
//! straightforward path, to a reference implementation, and across
//! backends - not just self-consistent.

use fastcrypto::HkdfSha256;
use sha2::Sha256;

fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(T[usize::from(b >> 4)] as char);
        s.push(T[usize::from(b & 0xf)] as char);
    }
    s
}

/// The prepared-key expander must agree with RustCrypto hkdf, label by label,
/// not just with itself.
#[test]
fn expander_matches_rustcrypto_for_every_label() {
    for salt_len in [0usize, 13, 32] {
        for ikm_len in [0usize, 22, 48] {
            let salt: Vec<u8> = (0..salt_len)
                .map(|i| (i * 5 + 1).to_le_bytes()[0])
                .collect();
            let ikm: Vec<u8> = (0..ikm_len).map(|i| (i * 3 + 7).to_le_bytes()[0]).collect();

            let ours = HkdfSha256::new(&salt, &ikm);
            let (_, rc) = hkdf::Hkdf::<Sha256>::extract(Some(&salt), &ikm);

            let mut expander = ours.expander();
            for label_len in [0usize, 1, 16, 64] {
                let label: Vec<u8> = (0..label_len)
                    .map(|i| (i * 11 + 3).to_le_bytes()[0])
                    .collect();
                for out_len in [1usize, 16, 32, 88, 255 * 32] {
                    let mut a = vec![0u8; out_len];
                    let mut b = vec![0u8; out_len];
                    expander.expand_into(&label, &mut a).unwrap();
                    rc.expand(&label, &mut b).unwrap();
                    assert_eq!(
                        hex(&a),
                        hex(&b),
                        "salt {salt_len} ikm {ikm_len} label {label_len} out {out_len}"
                    );
                }
            }
        }
    }
}

/// Reusing one expander across many labels must not drift from a fresh
/// expansion per label.
#[test]
fn prepared_key_reuse_equals_fresh_expansion() {
    let prk = HkdfSha256::new(b"salt", b"input key material");
    let labels: [&[u8]; 6] = [
        b"key",
        b"iv",
        b"derived",
        b"finished",
        b"resumption",
        b"exporter",
    ];
    let mut expander = prk.expander();
    let mut reused = [0u8; 48];
    let mut fresh = [0u8; 48];
    for label in labels {
        expander.expand_into(label, &mut reused).unwrap();
        prk.expand_into(label, &mut fresh).unwrap();
        assert_eq!(hex(&reused), hex(&fresh), "label {label:?}");
    }
}

/// The dispatched expander must match the portable backend's expander.
#[test]
fn expander_is_backend_independent() {
    use fastcrypto_core::hkdf::HkdfSha256 as CoreHkdf;
    use fastcrypto_core::sha256::Compressor;

    for compressor in [
        Compressor::PORTABLE,
        Compressor::new(fastcrypto_x86::sha256::compress_blocks),
    ] {
        let core_prk = CoreHkdf::with_compressor(b"salt", b"ikm", compressor);
        let mut core_expander = core_prk.expander();
        let dispatched = HkdfSha256::new(b"salt", b"ikm");
        let mut dispatched_expander = dispatched.expander();

        let labels: [&[u8]; 4] = [b"a", b"bb", b"ccc", b"dddd"];
        for label in labels {
            let mut a = [0u8; 42];
            let mut b = [0u8; 42];
            core_expander.expand_into(label, &mut a).unwrap();
            dispatched_expander.expand_into(label, &mut b).unwrap();
            assert_eq!(hex(&a), hex(&b), "label {label:?}");
        }
    }
}
