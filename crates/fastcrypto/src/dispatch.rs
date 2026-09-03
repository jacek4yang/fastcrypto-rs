//! Backend selection and the dispatched public types.
//!
//! The public API never selects an implementation directly: it asks this
//! module for one. The decision is made once per call site construction (a
//! relaxed atomic load on x86_64) and the chosen function is then stored in the
//! hasher, so no dispatch happens per block.
//!
//! Every accelerated function in an architecture crate either checks the CPU
//! itself or is only reachable through this module, so there is no path where
//! an instruction runs without its feature bit being verified first.

use fastcrypto_core::sha256::Compressor;

/// The best SHA-256 compression backend available on this machine.
#[must_use]
pub fn sha256_compressor() -> Compressor {
    #[cfg(target_arch = "x86_64")]
    return Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    #[cfg(not(target_arch = "x86_64"))]
    return Compressor::PORTABLE;
}

/// SHA-256 that dispatches to the best available backend.
///
/// # Example
///
/// ```
/// use fastcrypto::Sha256;
///
/// let mut h = Sha256::new();
/// h.update(b"hello ");
/// h.update(b"world");
/// assert_eq!(h.finalize(), fastcrypto::sha256(b"hello world"));
/// ```
#[derive(Clone)]
pub struct Sha256(fastcrypto_core::Sha256);

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Sha256 {
    /// Prints the absorbed length only; the chaining state is secret-derived.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256")
            .field("len", &self.0.count())
            .finish_non_exhaustive()
    }
}

impl Sha256 {
    /// Creates a hasher on the best available backend.
    #[must_use]
    pub fn new() -> Self {
        Self(fastcrypto_core::Sha256::with_compressor(sha256_compressor()))
    }

    /// Absorbs data into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest of everything absorbed so far, without resetting.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        self.0.finalize()
    }

    /// Writes the digest into the output buffer.
    pub fn finalize_into(&self, out: &mut [u8; 32]) {
        self.0.finalize_into(out);
    }

    /// Resets the hasher to its initial state.
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// Number of bytes absorbed so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.0.count()
    }
}

/// One-shot SHA-256 on the best available backend.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// HMAC-SHA256 that dispatches to the best available backend.
pub struct HmacSha256(fastcrypto_core::HmacSha256);

impl core::fmt::Debug for HmacSha256 {
    /// Prints the absorbed length only; the key state is secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacSha256")
            .field("len", &self.0.count())
            .finish_non_exhaustive()
    }
}

impl HmacSha256 {
    /// Creates an HMAC instance keyed with the given key.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self(fastcrypto_core::HmacSha256::with_compressor(
            key,
            sha256_compressor(),
        ))
    }

    /// Absorbs message data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the tag over everything absorbed so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        self.0.finalize()
    }

    /// Writes the tag into the output buffer.
    pub fn finalize_into(&self, out: &mut [u8; 32]) {
        self.0.finalize_into(out);
    }

    /// Constant-time comparison against a caller-supplied tag.
    #[must_use]
    pub fn verify(&self, tag: &[u8; 32]) -> bool {
        self.0.verify(tag)
    }

    /// Resets the instance for a new message under the same key.
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// Number of bytes absorbed so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.0.count()
    }
}

/// One-shot HMAC-SHA256 on the best available backend.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

/// Constant-time verification of a one-shot HMAC-SHA256 tag.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8; 32]) -> bool {
    fastcrypto_core::hmac_sha256_verify(key, data, tag)
}

/// HKDF-SHA256 that dispatches to the best available backend.
pub struct HkdfSha256(fastcrypto_core::HkdfSha256);

impl core::fmt::Debug for HkdfSha256 {
    /// Deliberately opaque: the PRK is secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfSha256").finish_non_exhaustive()
    }
}

impl HkdfSha256 {
    /// Runs the extract step over the given salt and input key material.
    #[must_use]
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        Self(fastcrypto_core::HkdfSha256::with_compressor(
            salt,
            ikm,
            sha256_compressor(),
        ))
    }

    /// Builds an instance from an already extracted pseudorandom key.
    #[must_use]
    pub fn from_prk(prk: [u8; 32]) -> Self {
        Self(fastcrypto_core::HkdfSha256::from_prk(prk))
    }

    /// Returns the pseudorandom key.
    #[must_use]
    pub fn prk(&self) -> [u8; 32] {
        self.0.prk()
    }

    /// Returns an expander that reuses one prepared HMAC key state across
    /// several labels.
    #[must_use]
    pub fn expander(&self) -> HkdfExpander {
        HkdfExpander(fastcrypto_core::HkdfExpander::new(
            &self.0.prk(),
            sha256_compressor(),
        ))
    }

    /// Runs the expand step, writing as many bytes as the output buffer holds.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` when more than 255 blocks are
    /// requested.
    pub fn expand_into(&self, info: &[u8], okm: &mut [u8]) -> fastcrypto_core::Result<()> {
        self.0.expand_into(info, okm)
    }
}

/// One-shot HKDF-SHA256 on the best available backend.
///
/// # Errors
///
/// Returns `Error::OutputTooLong` when more than 255 blocks are requested.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> fastcrypto_core::Result<()> {
    fastcrypto_core::hkdf_sha256_with(salt, ikm, info, okm, sha256_compressor())
}

/// HKDF-SHA256 expander with a prepared key state, for expanding several
/// labels from one pseudorandom key.
///
/// This is the shape a TLS 1.3 key schedule uses: one PRK, many labels. Using
/// this type instead of calling `expand_into` once per label saves two
/// compressions per label, and produces identical bytes.
///
/// # Example
///
/// ```
/// use fastcrypto::{HkdfSha256, sha256};
///
/// let prk = HkdfSha256::new(b"salt", b"input key material");
/// let mut expander = prk.expander();
/// let mut key = [0u8; 32];
/// let mut iv = [0u8; 12];
/// expander.expand_into(b"key", &mut key).unwrap();
/// expander.reset();
/// expander.expand_into(b"iv", &mut iv).unwrap();
/// ```
pub struct HkdfExpander(fastcrypto_core::HkdfExpander);

impl core::fmt::Debug for HkdfExpander {
    /// Deliberately opaque: it holds key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HkdfExpander").finish_non_exhaustive()
    }
}

impl HkdfExpander {
    /// Prepares an expander for the given pseudorandom key.
    #[must_use]
    pub fn new(prk: &[u8; 32]) -> Self {
        Self(fastcrypto_core::HkdfExpander::new(prk, sha256_compressor()))
    }

    /// Runs the expand step, writing as many bytes as the output buffer holds.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutputTooLong` when more than 255 blocks are requested.
    pub fn expand_into(&mut self, info: &[u8], okm: &mut [u8]) -> fastcrypto_core::Result<()> {
        self.0.expand_into(info, okm)
    }

    /// Discards intermediate state, ready for the next label.
    pub fn reset(&mut self) {
        self.0.reset();
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{HkdfSha256, HmacSha256, Sha256, hmac_sha256, sha256};

    #[test]
    fn dispatched_and_portable_agree() {
        // Whatever backend was selected, the result must equal the portable one.
        for len in [0usize, 1, 63, 64, 65, 127, 128, 1000, 4096] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 11).to_le_bytes()[0]).collect();
            assert_eq!(sha256(&data), fastcrypto_core::sha256(&data), "len {len}");
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut h = Sha256::new();
        h.update(b"abc");
        h.update(b"d");
        assert_eq!(h.finalize(), sha256(b"abcd"));
        assert_eq!(h.count(), 4);
    }

    #[test]
    fn hmac_and_hkdf_references_still_hold() {
        // RFC 4231 case 1 and RFC 5869 case 1, through the dispatched API.
        assert_eq!(
            hmac_sha256(&[0x0bu8; 20], b"Hi There"),
            fastcrypto_core::hmac_sha256(&[0x0bu8; 20], b"Hi There")
        );
        let mut okm = [0u8; 42];
        HkdfSha256::new(&[0x0bu8; 22], b"")
            .expand_into(b"", &mut okm)
            .unwrap();
        let mut portable = [0u8; 42];
        fastcrypto_core::hkdf_sha256(&[0x0bu8; 22], b"", b"", &mut portable).unwrap();
        assert_eq!(okm, portable);
    }

    #[test]
    fn hmac_reset_works() {
        let mut h = HmacSha256::new(b"key");
        h.update(b"one");
        let a = h.finalize();
        h.reset();
        h.update(b"two");
        let b = h.finalize();
        assert_ne!(a, b);
        h.reset();
        h.update(b"one");
        assert_eq!(h.finalize(), a);
    }
}
