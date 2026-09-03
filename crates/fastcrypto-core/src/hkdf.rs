//! HKDF-SHA256 (RFC 5869), portable backend.
//!
//! HKDF is the extract-then-expand construction used by the TLS 1.3 key
//! schedule. It is layered on `HmacSha256` with no intermediate
//! allocations: `expand_into` writes directly into the caller's buffer.

use zeroize::Zeroize;

use crate::hmac::HmacSha256;
use crate::sha256::DIGEST_LEN;

/// Length of an HKDF-SHA256 pseudorandom key in bytes.
pub const PRK_LEN: usize = DIGEST_LEN;
/// Maximum output length of a single HKDF-SHA256 expansion: 255 blocks.
pub const MAX_OUTPUT_LEN: usize = 255 * DIGEST_LEN;

/// HKDF-SHA256 extract step: PRK = HMAC(salt, ikm).
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    crate::hmac::hmac_sha256(salt, ikm)
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
        Self {
            prk: extract(salt, ikm),
        }
    }

    /// Builds an instance from an already extracted pseudorandom key.
    #[must_use]
    pub const fn from_prk(prk: [u8; PRK_LEN]) -> Self {
        Self { prk }
    }

    /// Returns the pseudorandom key.
    #[must_use]
    pub const fn prk(&self) -> [u8; PRK_LEN] {
        self.prk
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
        let mut block = [0u8; DIGEST_LEN];
        for (i, out) in okm.chunks_mut(DIGEST_LEN).enumerate() {
            // The length check above bounds the block count at 255, so the
            // RFC 5869 one-byte counter always fits.
            let counter = u8::try_from(i + 1).map_err(|_| crate::Error::OutputTooLong {
                requested,
                max: MAX_OUTPUT_LEN,
            })?;
            let mut h = HmacSha256::new(&self.prk);
            if i > 0 {
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
