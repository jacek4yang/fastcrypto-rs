//! HMAC-SHA256 (RFC 2104, FIPS 198-1), portable backend.
//!
//! HMAC is built directly on the portable SHA-256 compression function: the
//! key blocks (ipad/opad) are compressed once at construction time and the
//! resulting mid-stream states are reused for every message. That is the
//! "reuse initialized state" pattern a TLS 1.3 key schedule needs, and it is
//! why `HmacSha256` is a type rather than a free function.

use zeroize::Zeroize;

use crate::sha256::{BLOCK_LEN, DIGEST_LEN, Sha256};
use crate::util::{ct_eq, xor_into};

/// HMAC-SHA256 tag length in bytes.
pub const TAG_LEN: usize = DIGEST_LEN;
/// HMAC-SHA256 block (and maximum key-first-hash) length in bytes.
pub const KEY_LEN: usize = BLOCK_LEN;

/// Number of bytes already absorbed when an HMAC key block has been mixed in.
const PREFIX_LEN: u64 = BLOCK_LEN as u64;

/// Incremental HMAC-SHA256.
///
/// # Example
///
/// ```
/// use fastcrypto_core::HmacSha256;
///
/// let mut h = HmacSha256::new(b"key");
/// h.update(b"the quick brown fox");
/// let tag = fastcrypto_core::hmac_sha256(b"key", b"the quick brown fox");
/// assert!(h.verify(&tag));
/// ```
pub struct HmacSha256 {
    /// Live hasher over the ipad-prefixed key block plus the message.
    inner: Sha256,
    /// State after absorbing the ipad key block, kept so that reset is free.
    inner_state: [u32; 8],
    /// State after absorbing the opad key block.
    outer_state: [u32; 8],
}

impl core::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacSha256")
            .field("len", &self.inner.count())
            .finish_non_exhaustive()
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        self.inner_state.zeroize();
        self.outer_state.zeroize();
    }
}

impl Zeroize for HmacSha256 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        self.inner_state.zeroize();
        self.outer_state.zeroize();
    }
}

impl HmacSha256 {
    /// Creates an HMAC-SHA256 instance keyed with the given key.
    ///
    /// Keys longer than one SHA-256 block are hashed first, as required by
    /// RFC 2104. The key material is not retained after construction.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let hashed = crate::sha256::sha256(key);
            k[..DIGEST_LEN].copy_from_slice(&hashed);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        xor_into(&mut ipad, &k);
        xor_into(&mut opad, &k);
        k.zeroize();

        let mut inner = Sha256::new();
        inner.update(&ipad);
        let inner_state = inner.state();
        let mut outer = Sha256::new();
        outer.update(&opad);
        let outer_state = outer.state();
        ipad.zeroize();
        opad.zeroize();

        Self {
            inner,
            inner_state,
            outer_state,
        }
    }

    /// Absorbs message data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Returns the tag over everything absorbed so far.
    ///
    /// Like `Sha256::finalize` this does not reset the instance.
    #[must_use]
    pub fn finalize(&self) -> [u8; TAG_LEN] {
        let mut out = [0u8; TAG_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Writes the tag over everything absorbed so far into the output buffer.
    pub fn finalize_into(&self, out: &mut [u8; TAG_LEN]) {
        let mut inner_tag = [0u8; DIGEST_LEN];
        self.inner.finalize_into(&mut inner_tag);
        let mut outer = Sha256::from_state(self.outer_state, PREFIX_LEN);
        outer.update(&inner_tag);
        outer.finalize_into(out);
        inner_tag.zeroize();
    }

    /// Compares a caller-supplied tag against the computed tag in
    /// constant time with respect to the tag contents.
    #[must_use]
    pub fn verify(&self, tag: &[u8; TAG_LEN]) -> bool {
        let computed = self.finalize();
        ct_eq(&computed, tag)
    }

    /// Resets the instance so it can authenticate a new message under the same
    /// key, without recomputing the key blocks.
    pub fn reset(&mut self) {
        self.inner = Sha256::from_state(self.inner_state, PREFIX_LEN);
    }
}

/// One-shot HMAC-SHA256.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

/// Verifies a one-shot HMAC-SHA256 tag in constant time.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8; TAG_LEN]) -> bool {
    ct_eq(&hmac_sha256(key, data), tag)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{HmacSha256, hmac_sha256, hmac_sha256_verify};

    fn hex(bytes: &[u8]) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(T[usize::from(b >> 4)] as char);
            s.push(T[usize::from(b & 0xf)] as char);
        }
        s
    }

    /// RFC 4231 test case 1.
    #[test]
    fn rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 test case 2.
    #[test]
    fn rfc4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 test case 3.
    #[test]
    fn rfc4231_case_3() {
        assert_eq!(
            hex(&hmac_sha256(&[0xaau8; 20], &[0xddu8; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// RFC 4231 test case 4.
    #[test]
    fn rfc4231_case_4() {
        let key: [u8; 25] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        assert_eq!(
            hex(&hmac_sha256(&key, &[0xcdu8; 50])),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    /// RFC 4231 test case 5: output truncated to 128 bits.
    #[test]
    fn rfc4231_case_5_truncated() {
        // The RFC truncates the tag to 16 bytes; the truncated value must be
        // the prefix of the full tag.
        assert_eq!(
            hex(&hmac_sha256(&[0x0cu8; 20], b"Test With Truncation")[..16]),
            "a3b6167473100ee06e0c796c2955552b"
        );
    }

    /// RFC 4231 test case 6: key longer than one block must be hashed first.
    #[test]
    fn rfc4231_case_6() {
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaau8; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn reset_reuses_key_state() {
        let mut h = HmacSha256::new(&[0xaau8; 20]);
        h.update(b"msg-1");
        let t1 = h.finalize();
        h.reset();
        h.update(b"msg-2");
        let t2 = h.finalize();
        assert_eq!(t1, hmac_sha256(&[0xaau8; 20], b"msg-1"));
        assert_eq!(t2, hmac_sha256(&[0xaau8; 20], b"msg-2"));
    }

    #[test]
    fn verify_accepts_and_rejects() {
        let tag = hmac_sha256(b"key", b"data");
        assert!(hmac_sha256_verify(b"key", b"data", &tag));
        assert!(!hmac_sha256_verify(b"key", b"datb", &tag));
        let mut flipped = tag;
        flipped[31] ^= 1;
        assert!(!hmac_sha256_verify(b"key", b"data", &flipped));
    }

    #[test]
    fn chunking_does_not_change_tag() {
        let data: Vec<u8> = (0..512u32).map(|i| (i * 13 + 1).to_le_bytes()[0]).collect();
        let expected = hmac_sha256(b"some key", &data);
        for chunk in [1usize, 7, 63, 64, 65, 128] {
            let mut h = HmacSha256::new(b"some key");
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(h.finalize(), expected, "chunk {chunk}");
        }
    }

    /// Keys of every length around the block boundary must work, including
    /// exactly 64 bytes (no pre-hash) and 65 bytes (pre-hash).
    #[test]
    fn key_length_boundaries() {
        for len in [0usize, 1, 31, 32, 63, 64, 65, 100, 200] {
            let key: Vec<u8> = (0..len).map(|i| (i * 5 + 2).to_le_bytes()[0]).collect();
            let mut h = HmacSha256::new(&key);
            h.update(b"boundary");
            assert_eq!(h.finalize(), hmac_sha256(&key, b"boundary"), "len {len}");
        }
    }
}
