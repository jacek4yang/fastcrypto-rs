//! HKDF-SHA384 (RFC 5869), portable.
//!
//! Only SHA-384 is provided, because that is the only member of the SHA-512
//! family rust-reality derives keys with: the `AES-256-GCM-SHA384` suite's key
//! schedule performs three Extracts and sixteen Expand-Labels per handshake.
//! HKDF-SHA512 has no caller and is deliberately absent — this repository
//! implements the surface rust-reality uses, not the surface HKDF defines.

use zeroize::Zeroize;

use crate::hmac512::HmacSha384;
use crate::sha512::SHA384_DIGEST_LEN;

/// Pseudorandom key length, one SHA-384 digest.
pub const PRK_LEN: usize = SHA384_DIGEST_LEN;

/// Longest output RFC 5869 permits: 255 hash-length blocks.
pub const MAX_OUTPUT_LEN: usize = 255 * PRK_LEN;

/// RFC 5869 §2.2: `PRK = HMAC(salt, IKM)`, with an all-zero salt when absent.
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    let zero = [0u8; PRK_LEN];
    let salt = if salt.is_empty() { &zero[..] } else { salt };
    crate::hmac512::hmac_sha384(salt, ikm)
}

/// Extract followed by expand, for callers that derive one output from one PRK.
///
/// # Errors
///
/// Returns `Error::OutputTooLong` when more than [`MAX_OUTPUT_LEN`] is asked
/// for.
pub fn hkdf_sha384(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
    HkdfSha384::from_prk(extract(salt, ikm)).expand_into(info, okm)
}

/// An extracted pseudorandom key.
pub struct HkdfSha384 {
    prk: [u8; PRK_LEN],
}

impl core::fmt::Debug for HkdfSha384 {
    /// Deliberately opaque: it holds key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfSha384").finish_non_exhaustive()
    }
}

impl Drop for HkdfSha384 {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

impl Zeroize for HkdfSha384 {
    fn zeroize(&mut self) {
        self.prk.zeroize();
    }
}

impl HkdfSha384 {
    /// Runs the extract step.
    #[must_use]
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        Self {
            prk: extract(salt, ikm),
        }
    }

    /// Wraps an already extracted pseudorandom key.
    #[must_use]
    pub const fn from_prk(prk: [u8; PRK_LEN]) -> Self {
        Self { prk }
    }

    /// Returns the pseudorandom key.
    #[must_use]
    pub const fn prk(&self) -> [u8; PRK_LEN] {
        self.prk
    }

    /// Returns an expander that keeps one prepared HMAC key state across
    /// labels, which is the shape a TLS key schedule uses sixteen times.
    #[must_use]
    pub fn expander(&self) -> HkdfExpander384 {
        HkdfExpander384::new(&self.prk)
    }

    /// Runs the expand step, writing `okm.len()` bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` above [`MAX_OUTPUT_LEN`].
    pub fn expand_into(&self, info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
        self.expander().expand_into(info, okm)
    }
}

/// An expander holding one prepared HMAC key state.
pub struct HkdfExpander384 {
    hmac: HmacSha384,
}

impl core::fmt::Debug for HkdfExpander384 {
    /// Deliberately opaque: it holds key state.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfExpander384").finish_non_exhaustive()
    }
}

impl HkdfExpander384 {
    /// Prepares an expander for the given pseudorandom key.
    #[must_use]
    pub fn new(prk: &[u8; PRK_LEN]) -> Self {
        Self {
            hmac: HmacSha384::new(prk),
        }
    }

    /// Runs the expand step, writing as many bytes as `okm` holds.
    ///
    /// Each call is independent: the prepared key state is restored first, so
    /// expanding many labels from one PRK needs no bookkeeping from the caller.
    /// This is the defect #3 found in the SHA-256 expander, avoided here by
    /// construction rather than by documentation.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` above [`MAX_OUTPUT_LEN`].
    pub fn expand_into(&mut self, info: &[u8], okm: &mut [u8]) -> crate::Result<()> {
        if okm.len() > MAX_OUTPUT_LEN {
            return Err(crate::Error::OutputTooLong {
                requested: okm.len(),
                max: MAX_OUTPUT_LEN,
            });
        }
        self.hmac.reset();

        let requested = okm.len();
        let mut block = [0u8; PRK_LEN];
        for (i, out) in okm.chunks_mut(PRK_LEN).enumerate() {
            let counter = u8::try_from(i + 1).map_err(|_| crate::Error::OutputTooLong {
                requested,
                max: MAX_OUTPUT_LEN,
            })?;
            if i > 0 {
                self.hmac.reset();
                self.hmac.update(&block);
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
mod tests {
    use alloc::vec;

    use super::{HkdfSha384, extract, hkdf_sha384};

    /// The TLS shape: many labels from one PRK, with no caller bookkeeping.
    #[test]
    fn each_label_is_independent_without_an_explicit_reset() {
        let prk = HkdfSha384::new(b"salt", b"input key material");
        let labels: [&[u8]; 4] = [b"c hs traffic", b"s hs traffic", b"key", b"iv"];
        let mut reused = prk.expander();
        for label in labels {
            let mut from_reused = [0u8; 48];
            reused.expand_into(label, &mut from_reused).expect("expand");
            let mut from_fresh = [0u8; 48];
            prk.expand_into(label, &mut from_fresh).expect("expand");
            assert_eq!(from_reused, from_fresh, "label {label:?}");
        }
    }

    /// Multi-block output exercises the per-block chaining.
    #[test]
    fn multi_block_output_is_independent_per_label() {
        let prk = HkdfSha384::new(b"salt", b"ikm");
        let mut reused = prk.expander();
        let mut first = vec![0u8; PRK_LEN_TIMES_3 + 5];
        let mut second = vec![0u8; PRK_LEN_TIMES_3 + 5];
        reused.expand_into(b"first", &mut first).expect("expand");
        reused.expand_into(b"second", &mut second).expect("expand");
        let mut expected = vec![0u8; PRK_LEN_TIMES_3 + 5];
        prk.expand_into(b"second", &mut expected).expect("expand");
        assert_eq!(second, expected);
        assert_ne!(first, second);
    }
    const PRK_LEN_TIMES_3: usize = super::PRK_LEN * 3;

    /// An absent salt is an all-zero hash-length salt, RFC 5869 §2.2.
    #[test]
    fn empty_salt_is_a_zero_block() {
        assert_eq!(extract(b"", b"ikm"), extract(&[0u8; 48], b"ikm"));
    }

    #[test]
    fn oversized_output_is_refused() {
        let mut okm = vec![0u8; super::MAX_OUTPUT_LEN + 1];
        assert!(hkdf_sha384(b"salt", b"ikm", b"info", &mut okm).is_err());
    }
}
