//! HKDF-SHA256 (RFC 5869), portable backend.
//!
//! HKDF is the extract-then-expand construction used by the TLS 1.3 key
//! schedule. It is layered on `HmacSha256` with no intermediate
//! allocations: `expand_into` writes directly into the caller's buffer.

use zeroize::Zeroize;

use crate::hmac::HmacSha256;
use crate::sha256::Compressor;
use crate::sha256::DIGEST_LEN;

/// Length of an HKDF-SHA256 pseudorandom key in bytes.
pub const PRK_LEN: usize = DIGEST_LEN;
/// Maximum output length of a single HKDF-SHA256 expansion: 255 blocks.
pub const MAX_OUTPUT_LEN: usize = 255 * DIGEST_LEN;

/// HKDF-SHA256 extract step: PRK = HMAC(salt, ikm).
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    extract_with(salt, ikm, Compressor::PORTABLE)
}

/// HKDF-SHA256 extract step using the given compression backend.
#[must_use]
pub fn extract_with(salt: &[u8], ikm: &[u8], compressor: Compressor) -> [u8; PRK_LEN] {
    let mut mac = HmacSha256::with_compressor(salt, compressor);
    mac.update(ikm);
    mac.finalize()
}

/// HKDF-SHA256 in one call: extract, then expand `okm.len()` bytes.
///
/// # Errors
///
/// Returns `Error::OutputTooLong` when more than `MAX_OUTPUT_LEN`
/// bytes are requested.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
    HkdfSha256::new(salt, ikm).expand_into(info, okm)
}

/// HKDF-SHA256 with an explicit compression backend.
///
/// # Errors
///
/// Returns the same errors as the expansion step.
pub fn hkdf_sha256_with(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
    compressor: Compressor,
) -> crate::Result<()> {
    HkdfSha256::with_compressor(salt, ikm, compressor).expand_into(info, okm)
}

/// An HKDF-SHA256 pseudorandom key, ready to be expanded.
///
/// # Example
///
/// ```
/// use fastcrypto_core::HkdfSha256;
///
/// let prk = HkdfSha256::new(b"salt", b"input key material");
/// let mut okm = [0u8; 32];
/// prk.expand_into(b"tls13 label", &mut okm).unwrap();
/// ```
pub struct HkdfSha256 {
    prk: [u8; PRK_LEN],
    compressor: Compressor,
}

impl core::fmt::Debug for HkdfSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfSha256").finish_non_exhaustive()
    }
}

impl Drop for HkdfSha256 {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

impl Zeroize for HkdfSha256 {
    fn zeroize(&mut self) {
        self.prk.zeroize();
    }
}

impl HkdfSha256 {
    /// Runs the extract step over the given salt and input key material.
    #[must_use]
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        Self::with_compressor(salt, ikm, Compressor::PORTABLE)
    }

    /// Runs the extract step with the given compression backend.
    #[must_use]
    pub fn with_compressor(salt: &[u8], ikm: &[u8], compressor: Compressor) -> Self {
        Self {
            prk: extract_with(salt, ikm, compressor),
            compressor,
        }
    }

    /// Builds an instance from an already extracted pseudorandom key.
    #[must_use]
    pub const fn from_prk(prk: [u8; PRK_LEN]) -> Self {
        Self {
            prk,
            compressor: Compressor::PORTABLE,
        }
    }

    /// Returns the pseudorandom key.
    #[must_use]
    pub const fn prk(&self) -> [u8; PRK_LEN] {
        self.prk
    }

    /// Returns an expander that reuses one prepared HMAC key state across
    /// several labels.
    #[must_use]
    pub fn expander(&self) -> HkdfExpander {
        HkdfExpander::new(&self.prk, self.compressor)
    }

    /// Runs the expand step, writing `okm.len()` bytes of output.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` when more than `MAX_OUTPUT_LEN`
    /// bytes are requested.
    pub fn expand_into(&self, info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
        if okm.len() > MAX_OUTPUT_LEN {
            return Err(crate::Error::OutputTooLong {
                requested: okm.len(),
                max: MAX_OUTPUT_LEN,
            });
        }

        let requested = okm.len();
        // One HMAC key state for the whole chain: every block of HKDF-Expand
        // is authenticated under the same PRK, so preparing the ipad/opad
        // states once and resetting between blocks saves two compressions
        // per block. reset() restores exactly the state of a freshly
        // constructed HMAC under the same key, so the output is unchanged.
        let mut h = HmacSha256::with_compressor(&self.prk, self.compressor);
        let mut block = [0u8; DIGEST_LEN];
        for (i, out) in okm.chunks_mut(DIGEST_LEN).enumerate() {
            // The length check above bounds the block count at 255, so the
            // RFC 5869 one-byte counter always fits.
            let counter = u8::try_from(i + 1).map_err(|_| crate::Error::OutputTooLong {
                requested,
                max: MAX_OUTPUT_LEN,
            })?;
            if i > 0 {
                h.reset();
                h.update(&block[..DIGEST_LEN]);
            }
            h.update(info);
            h.update(&[counter]);
            h.finalize_into(&mut block);
            out.copy_from_slice(&block[..out.len()]);
        }
        block.zeroize();
        Ok(())
    }
}

/// An HKDF-SHA256 expander that keeps one prepared HMAC key state.
///
/// TLS 1.3 expands several labels from the same pseudorandom key. Doing that
/// through `HkdfSha256::expand_into` prepares the
/// ipad/opad states again for every call, which costs two compressions per
/// label. This type prepares them once and resets between labels, which is
/// byte-for-byte identical output
/// because reset restores exactly the post-ipad state of a fresh HMAC under
/// the same key.
pub struct HkdfExpander {
    hmac: HmacSha256,
}

impl core::fmt::Debug for HkdfExpander {
    /// Deliberately opaque: it holds key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfExpander").finish_non_exhaustive()
    }
}

impl HkdfExpander {
    /// Prepares an expander for the given pseudorandom key.
    #[must_use]
    pub fn new(prk: &[u8; PRK_LEN], compressor: Compressor) -> Self {
        Self {
            hmac: HmacSha256::with_compressor(prk, compressor),
        }
    }

    /// Runs the expand step, writing as many bytes as the output buffer holds.
    ///
    /// Each call is independent: the prepared key state is restored first, so
    /// expanding many labels from one PRK — which is what a TLS 1.3 key
    /// schedule does, sixteen times per handshake — needs no bookkeeping from
    /// the caller. Restoring costs a struct rebuild from the cached ipad
    /// state, not a re-keying, so the whole point of preparing the key is
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` when more than 255 blocks are requested.
    pub fn expand_into(&mut self, info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
        if okm.len() > MAX_OUTPUT_LEN {
            return Err(crate::Error::OutputTooLong {
                requested: okm.len(),
                max: MAX_OUTPUT_LEN,
            });
        }
        self.hmac.reset();

        let requested = okm.len();
        let mut block = [0u8; DIGEST_LEN];
        for (i, out) in okm.chunks_mut(DIGEST_LEN).enumerate() {
            let counter = u8::try_from(i + 1).map_err(|_| crate::Error::OutputTooLong {
                requested,
                max: MAX_OUTPUT_LEN,
            })?;
            if i > 0 {
                self.hmac.reset();
                self.hmac.update(&block[..DIGEST_LEN]);
            }
            self.hmac.update(info);
            self.hmac.update(&[counter]);
            self.hmac.finalize_into(&mut block);
            out.copy_from_slice(&block[..out.len()]);
        }
        block.zeroize();
        Ok(())
    }
}

#[cfg(test)]
mod expander_independence {
    use super::{HkdfSha256, PRK_LEN};

    /// Regression: expanding a second label without any caller bookkeeping.
    ///
    /// The expander used to carry the previous label's message state into the
    /// next call, so the first label was right and every one after it was
    /// silently wrong. A TLS 1.3 key schedule expands sixteen labels from one
    /// PRK, so this produced wrong key material on every handshake after the
    /// first derivation — with no error and no test catching it, because every
    /// test reset in between.
    #[test]
    fn each_label_is_independent_without_an_explicit_reset() {
        let prk = HkdfSha256::new(b"salt", b"input key material");
        let labels: [&[u8]; 4] = [b"c hs traffic", b"s hs traffic", b"key", b"iv"];

        let mut reused = prk.expander();
        for label in labels {
            let mut from_reused = [0u8; 40];
            reused.expand_into(label, &mut from_reused).expect("expand");

            let mut fresh_expander = prk.expander();
            let mut from_fresh = [0u8; 40];
            fresh_expander
                .expand_into(label, &mut from_fresh)
                .expect("expand");

            let mut from_prk = [0u8; 40];
            prk.expand_into(label, &mut from_prk).expect("expand");

            assert_eq!(from_reused, from_fresh, "label {label:?} vs fresh expander");
            assert_eq!(from_reused, from_prk, "label {label:?} vs one-shot API");
        }
    }

    /// The same expander must also survive multi-block outputs, where the
    /// per-block chaining is the state that previously leaked between labels.
    #[test]
    fn multi_block_outputs_stay_independent() {
        let prk = HkdfSha256::new(b"salt", b"ikm");
        let mut reused = prk.expander();
        let mut first = [0u8; PRK_LEN * 3 + 7];
        let mut second = [0u8; PRK_LEN * 3 + 7];
        reused.expand_into(b"first", &mut first).expect("expand");
        reused.expand_into(b"second", &mut second).expect("expand");

        let mut expected = [0u8; PRK_LEN * 3 + 7];
        prk.expand_into(b"second", &mut expected).expect("expand");
        assert_eq!(second, expected);
        assert_ne!(first, second);
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::{HkdfSha256, MAX_OUTPUT_LEN, extract, hkdf_sha256};
    use crate::Error;

    fn hex(bytes: &[u8]) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(T[usize::from(b >> 4)] as char);
            s.push(T[usize::from(b & 0xf)] as char);
        }
        s
    }

    /// RFC 5869 test case 1 (SHA-256).
    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];

        let prk = extract(&salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        HkdfSha256::from_prk(prk)
            .expand_into(&info, &mut okm)
            .unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// RFC 5869 test case 3 (SHA-256): zero-length salt and info.
    #[test]
    fn rfc5869_case_3() {
        let ikm = [0x0bu8; 22];
        let mut okm = [0u8; 42];
        let prk = extract(&[], &ikm);
        assert_eq!(
            hex(&prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        HkdfSha256::new(&[], &ikm)
            .expand_into(&[], &mut okm)
            .unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn zero_length_okm_is_accepted() {
        let mut okm = [];
        assert!(hkdf_sha256(b"salt", b"ikm", b"info", &mut okm).is_ok());
    }

    #[test]
    fn too_long_output_is_rejected() {
        let mut okm = [0u8; MAX_OUTPUT_LEN + 1];
        let err = hkdf_sha256(b"s", b"i", b"", &mut okm).unwrap_err();
        assert_eq!(
            err,
            Error::OutputTooLong {
                requested: MAX_OUTPUT_LEN + 1,
                max: MAX_OUTPUT_LEN
            }
        );
        // The maximum length itself must succeed.
        let mut okm = [0u8; MAX_OUTPUT_LEN];
        assert!(hkdf_sha256(b"s", b"i", b"", &mut okm).is_ok());
    }

    #[test]
    fn expand_is_prefix_stable() {
        // Expanding to N+1 bytes must keep the first N bytes identical, which
        // is the property TLS relies on when it expands several secrets from
        // the same PRK with different lengths.
        let prk = HkdfSha256::new(b"salt", b"ikm");
        let mut short = [0u8; 31];
        let mut long = [0u8; 96];
        prk.expand_into(b"label", &mut short).unwrap();
        prk.expand_into(b"label", &mut long).unwrap();
        assert_eq!(&long[..31], &short[..]);
    }

    /// The prepared-key expander must be byte-for-byte identical to a fresh
    /// expansion, for every label and length. This is the whole justification
    /// for the type.
    #[test]
    fn expander_matches_expand_into() {
        let prk = HkdfSha256::new(b"salt", b"ikm");
        let mut expander = prk.expander();
        for label_len in [0usize, 1, 16, 100] {
            let label: alloc::vec::Vec<u8> = (0..label_len)
                .map(|i| (i * 3 + 1).to_le_bytes()[0])
                .collect();
            for out_len in [1usize, 16, 32, 33, 88, 200] {
                let mut from_expander = alloc::vec![0u8; out_len];
                let mut from_prk = alloc::vec![0u8; out_len];
                expander.expand_into(&label, &mut from_expander).unwrap();
                prk.expand_into(&label, &mut from_prk).unwrap();
                assert_eq!(
                    from_expander, from_prk,
                    "label {} out {}",
                    label_len, out_len
                );
            }
        }
    }

    /// Reusing the same expander across labels must not leak state between
    /// them.
    #[test]
    fn expander_labels_are_independent() {
        let prk = HkdfSha256::new(b"salt", b"ikm");
        let mut expander = prk.expander();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        expander.expand_into(b"first", &mut a).unwrap();
        expander.expand_into(b"second", &mut b).unwrap();
        expander.expand_into(b"first", &mut c).unwrap();
        let mut reference = [0u8; 32];
        prk.expand_into(b"first", &mut reference).unwrap();
        assert_eq!(a, c);
        assert_eq!(a, reference);
        assert_ne!(a, b);
    }

    #[test]
    fn max_output_matches_rfc_block_boundary() {
        let prk = HkdfSha256::new(b"salt", b"ikm");
        let mut a = [0u8; MAX_OUTPUT_LEN];
        prk.expand_into(b"x", &mut a).unwrap();
        let mut b = [0u8; 255 * 32 - 1];
        prk.expand_into(b"x", &mut b).unwrap();
        assert_eq!(&a[..b.len()], &b[..]);
    }
}
