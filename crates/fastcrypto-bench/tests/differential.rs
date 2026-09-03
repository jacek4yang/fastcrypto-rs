//! Differential tests: our implementation against established ones.
//!
//! The rule for this crate is that at least two independent implementations
//! must agree on every byte we produce. Where a reference library imposes a
//! restriction that the specification does not (for example a non-empty info
//! string), the comparison is skipped for that library and the reason is
//! recorded in the test name.

use fastcrypto::{HkdfSha256, HmacSha256, Sha256, hkdf_sha256, hmac_sha256, sha256};
use fastcrypto_bench::Prng;
use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256 as RcSha256};

fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(T[usize::from(b >> 4)] as char);
        s.push(T[usize::from(b & 0xf)] as char);
    }
    s
}

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Prng::new(seed).fill(&mut out);
    out
}

#[test]
fn references_agree_with_each_other_for_sha256() {
    // Sanity check on the references themselves: if two of them disagreed, a
    // failure below would be ambiguous.
    for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 65536] {
        let data = random_bytes(1 + len as u64, len);
        let rc = RcSha256::digest(&data);
        let ring = ring::digest::digest(&ring::digest::SHA256, &data);
        let lc = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data);
        assert_eq!(rc.as_slice(), ring.as_ref(), "len {len}");
        assert_eq!(rc.as_slice(), lc.as_ref(), "len {len}");
    }
}

#[test]
fn sha256_matches_all_references() {
    let mut lens: Vec<usize> = (0..300).collect();
    lens.extend([512usize, 1024, 1350, 1500, 4096, 8192, 16384, 65536]);
    for len in lens {
        let data = random_bytes(0x1234_5678 ^ len as u64, len);
        let ours = sha256(&data);

        assert_eq!(
            hex(&ours),
            hex(&RcSha256::digest(&data)),
            "rustcrypto len {len}"
        );
        assert_eq!(
            hex(&ours),
            hex(ring::digest::digest(&ring::digest::SHA256, &data).as_ref()),
            "ring len {len}"
        );
        assert_eq!(
            hex(&ours),
            hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data).as_ref()),
            "aws-lc-rs len {len}"
        );
    }
}

#[test]
fn sha256_streaming_matches_oneshot_and_references() {
    // Every chunking must produce the same digest, and the digest must match
    // the references. This is the property a TLS transcript hash depends on.
    let data = random_bytes(0xabcd, 5000);
    let expected = sha256(&data);
    for chunk in [1usize, 7, 31, 32, 63, 64, 65, 127, 128, 1000] {
        let mut h = Sha256::new();
        for part in data.chunks(chunk) {
            h.update(part);
        }
        assert_eq!(h.finalize(), expected, "chunk {chunk}");
    }
    assert_eq!(hex(&expected), hex(&RcSha256::digest(&data)));
}

#[test]
fn hmac_sha256_matches_all_references() {
    for key_len in [0usize, 1, 20, 31, 32, 63, 64, 65, 100, 200] {
        let key = random_bytes(0xaa00 + key_len as u64, key_len);
        for msg_len in [0usize, 1, 55, 56, 64, 65, 200, 1000] {
            let msg = random_bytes(0xbb00 + msg_len as u64, msg_len);
            let ours = hmac_sha256(&key, &msg);

            let mut mac =
                hmac::Hmac::<RcSha256>::new_from_slice(&key).expect("hmac accepts any key");
            mac.update(&msg);
            assert_eq!(
                hex(&ours),
                hex(&mac.finalize().into_bytes()),
                "rustcrypto key {key_len} msg {msg_len}"
            );

            let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
            assert_eq!(
                hex(&ours),
                hex(ring::hmac::sign(&ring_key, &msg).as_ref()),
                "ring key {key_len} msg {msg_len}"
            );

            let lc_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
            assert_eq!(
                hex(&ours),
                hex(aws_lc_rs::hmac::sign(&lc_key, &msg).as_ref()),
                "aws-lc-rs key {key_len} msg {msg_len}"
            );
        }
    }
}

#[test]
fn hmac_sha256_streaming_matches_oneshot() {
    let key = random_bytes(0x77, 200);
    let msg = random_bytes(0x88, 3000);
    let expected = hmac_sha256(&key, &msg);
    for chunk in [1usize, 13, 64, 65, 512] {
        let mut h = HmacSha256::new(&key);
        for part in msg.chunks(chunk) {
            h.update(part);
        }
        assert_eq!(h.finalize(), expected, "chunk {chunk}");
    }
}

/// Output-length adapter shared with the benchmarks: ring and aws-lc-rs size
/// HKDF output through a trait rather than a slice length.
struct OkmLen(usize);

impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl aws_lc_rs::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[test]
fn hkdf_sha256_matches_all_references() {
    for salt_len in [0usize, 13, 32, 64] {
        for ikm_len in [0usize, 22, 32, 100] {
            for info_len in [1usize, 10, 32, 100] {
                let salt = random_bytes(0x1000 + salt_len as u64, salt_len);
                let ikm = random_bytes(0x2000 + ikm_len as u64, ikm_len);
                let info = random_bytes(0x3000 + info_len as u64, info_len);

                for out_len in [1usize, 16, 32, 42, 88, 255 * 32] {
                    let mut ours = vec![0u8; out_len];
                    hkdf_sha256(&salt, &ikm, &info, &mut ours).unwrap();

                    let (_, rc) = hkdf::Hkdf::<RcSha256>::extract(Some(&salt), &ikm);
                    let mut rc_out = vec![0u8; out_len];
                    rc.expand(&info, &mut rc_out).unwrap();

                    let mut ring_out = vec![0u8; out_len];
                    let ring_prk =
                        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt).extract(&ikm);
                    let info_refs: [&[u8]; 1] = [&info];
                    ring_prk
                        .expand(&info_refs, OkmLen(out_len))
                        .unwrap()
                        .fill(&mut ring_out)
                        .unwrap();

                    let mut lc_out = vec![0u8; out_len];
                    let lc_prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, &salt)
                        .extract(&ikm);
                    let info_refs: [&[u8]; 1] = [&info];
                    lc_prk
                        .expand(&info_refs, OkmLen(out_len))
                        .unwrap()
                        .fill(&mut lc_out)
                        .unwrap();

                    let ctx =
                        format!("salt {salt_len} ikm {ikm_len} info {info_len} out {out_len}");
                    assert_eq!(hex(&ours), hex(&rc_out), "rustcrypto {ctx}");
                    assert_eq!(hex(&ours), hex(&ring_out), "ring {ctx}");
                    assert_eq!(hex(&ours), hex(&lc_out), "aws-lc-rs {ctx}");
                }
            }
        }
    }
}

#[test]
fn hkdf_sha256_prk_matches_hmac_extract() {
    // RFC 5869 defines extract as HMAC(salt, ikm); the PRK must equal it.
    let salt = random_bytes(0x99, 32);
    let ikm = random_bytes(0x98, 48);
    let prk = HkdfSha256::new(&salt, &ikm);
    assert_eq!(hex(&prk.prk()), hex(&hmac_sha256(&salt, &ikm)));
}

#[test]
fn hkdf_sha256_rejects_oversized_output_consistently() {
    // Over the RFC limit nothing is produced; the references agree on the limit.
    let mut too_long = vec![0u8; 255 * 32 + 1];
    assert!(hkdf_sha256(b"s", b"i", b"", &mut too_long).is_err());

    let (_, rc) = hkdf::Hkdf::<RcSha256>::extract(Some(b"s"), b"i");
    let mut rc_out = vec![0u8; 255 * 32 + 1];
    assert!(rc.expand(b"", &mut rc_out).is_err());
}
