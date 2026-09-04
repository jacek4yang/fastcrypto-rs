//! HMAC-SHA512 and HMAC-SHA384 (RFC 2104, FIPS 198-1), portable.
//!
//! rust-reality needs both: HMAC-SHA512 authenticates the Xray certificate
//! binding once per session, and HMAC-SHA384 is the MAC under the
//! `AES-256-GCM-SHA384` suite's Finished message and key schedule.
//!
//! Same construction as [`crate::hmac`]: the ipad and opad key blocks are
//! compressed once when the key is installed and the resulting mid-stream
//! states are reused for every message, which is what a TLS key schedule wants
//! and why this is a type rather than a free function.

use zeroize::Zeroize;

use crate::sha512::{BLOCK_LEN, IV_384, IV_512, SHA384_DIGEST_LEN, SHA512_DIGEST_LEN, Sha512Core};
use crate::util::{ct_eq, xor_into};

/// HMAC block length, and the length above which a key is hashed first.
pub const KEY_LEN: usize = BLOCK_LEN;

/// Bytes already absorbed once a key block has been mixed in.
const PREFIX_LEN: u64 = BLOCK_LEN as u64;

/// Shared HMAC machinery for the SHA-512 family.
///
/// Parameterised by initial state and tag length, which is the only difference
/// between HMAC-SHA512 and HMAC-SHA384.
#[derive(Clone)]
struct Core {
    /// Live hasher over the ipad key block plus the message.
    inner: Sha512Core,
    /// State after absorbing the ipad key block, so reset is free.
    inner_state: [u64; 8],
    /// State after absorbing the opad key block.
    outer_state: [u64; 8],
}

impl Drop for Core {
    fn drop(&mut self) {
        self.inner_state.zeroize();
        self.outer_state.zeroize();
    }
}

impl Core {
    fn new(iv: [u64; 8], key: &[u8], hash_key: fn(&[u8], &mut [u8])) -> Self {
        // RFC 2104 §2: a key longer than the block is replaced by its hash,
        // then zero-padded to the block length.
        let mut block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let mut digest = [0u8; SHA512_DIGEST_LEN];
            hash_key(key, &mut digest);
            let len = digest.len().min(BLOCK_LEN);
            block[..len].copy_from_slice(&digest[..len]);
            digest.zeroize();
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let mut pad = [0x36u8; BLOCK_LEN];
        xor_into(&mut pad, &block);
        let mut inner = Sha512Core::with_state(iv);
        inner.update(&pad);
        let inner_state = inner.state();

        let mut pad_out = [0x5cu8; BLOCK_LEN];
        xor_into(&mut pad_out, &block);
        let mut outer = Sha512Core::with_state(iv);
        outer.update(&pad_out);
        let outer_state = outer.state();

        block.zeroize();
        pad.zeroize();
        pad_out.zeroize();

        Self {
            inner: Sha512Core::from_state(inner_state, PREFIX_LEN),
            inner_state,
            outer_state,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into<const N: usize>(&self, out: &mut [u8; N]) {
        let mut inner_tag = [0u8; SHA512_DIGEST_LEN];
        self.inner.finalize_into(&mut inner_tag);
        let mut outer = Sha512Core::from_state(self.outer_state, PREFIX_LEN);
        // The inner hash is truncated to the tag length before the outer pass,
        // which is what makes HMAC-SHA384 differ from a truncated HMAC-SHA512.
        outer.update(&inner_tag[..N]);
        outer.finalize_into(out);
        inner_tag.zeroize();
    }

    fn reset(&mut self) {
        self.inner = Sha512Core::from_state(self.inner_state, PREFIX_LEN);
    }

    const fn count(&self) -> u64 {
        self.inner.count() - PREFIX_LEN
    }
}

macro_rules! hmac_type {
    ($name:ident, $tag:expr, $iv:expr, $hash:path, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Cloning duplicates the installed key state and the message absorbed
        /// so far, which is what makes a keyed instance usable as a template.
        /// Each clone clears its own key state on drop.
        #[derive(Clone)]
        pub struct $name(Core);

        impl core::fmt::Debug for $name {
            /// Deliberately opaque: it holds key state.
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl $name {
            /// Tag length in bytes.
            pub const TAG_LEN: usize = $tag;

            /// Installs a key. Any length is accepted, per RFC 2104.
            #[must_use]
            pub fn new(key: &[u8]) -> Self {
                Self(Core::new($iv, key, |k, out| {
                    let digest = $hash(k);
                    out[..digest.len()].copy_from_slice(&digest);
                }))
            }

            /// Absorbs message bytes.
            pub fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            /// Returns the tag over everything absorbed so far.
            #[must_use]
            pub fn finalize(&self) -> [u8; $tag] {
                let mut out = [0u8; $tag];
                self.0.finalize_into(&mut out);
                out
            }

            /// Writes the tag into `out`.
            pub fn finalize_into(&self, out: &mut [u8; $tag]) {
                self.0.finalize_into(out);
            }

            /// Compares a candidate tag in constant time.
            #[must_use]
            pub fn verify(&self, tag: &[u8]) -> bool {
                ct_eq(&self.finalize(), tag)
            }

            /// Discards the message, keeping the installed key.
            pub fn reset(&mut self) {
                self.0.reset();
            }

            /// Message bytes absorbed since the last reset.
            #[must_use]
            pub const fn count(&self) -> u64 {
                self.0.count()
            }
        }
    };
}

hmac_type!(
    HmacSha512,
    SHA512_DIGEST_LEN,
    IV_512,
    crate::sha512::sha512,
    "Incremental HMAC-SHA512."
);
hmac_type!(
    HmacSha384,
    SHA384_DIGEST_LEN,
    IV_384,
    crate::sha512::sha384,
    "Incremental HMAC-SHA384."
);

/// One-shot HMAC-SHA512.
#[must_use]
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; SHA512_DIGEST_LEN] {
    let mut h = HmacSha512::new(key);
    h.update(message);
    h.finalize()
}

/// One-shot HMAC-SHA384.
#[must_use]
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; SHA384_DIGEST_LEN] {
    let mut h = HmacSha384::new(key);
    h.update(message);
    h.finalize()
}

#[cfg(test)]
mod tests {
    /// Both SHA-512-family templates clone the same way HMAC-SHA256 does:
    /// rust-reality keys HMAC-SHA384 once per handshake for the Finished
    /// message and HMAC-SHA512 once per session for the certificate binding.
    #[test]
    fn keyed_templates_clone_independently() {
        let template384 = HmacSha384::new(b"key");
        let mut a = template384.clone();
        let mut b = template384.clone();
        a.update(b"alpha");
        b.update(b"beta");
        assert_eq!(a.finalize(), hmac_sha384(b"key", b"alpha"));
        assert_eq!(b.finalize(), hmac_sha384(b"key", b"beta"));

        let template512 = HmacSha512::new(b"key");
        let mut c = template512.clone();
        c.update(b"gamma");
        assert_eq!(c.finalize(), hmac_sha512(b"key", b"gamma"));
        // The template itself absorbed nothing and still tags the empty message.
        assert_eq!(template512.finalize(), hmac_sha512(b"key", b""));
    }

    use alloc::string::String;
    use alloc::vec;

    use super::{HmacSha384, HmacSha512, hmac_sha384, hmac_sha512};

    fn hex(bytes: &[u8]) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(T[usize::from(b >> 4)] as char);
            s.push(T[usize::from(b & 15)] as char);
        }
        s
    }

    /// RFC 4231 test cases 1, 2 and 7. Case 7 uses a 131-byte key, which
    /// exercises the RFC 2104 §2 rule that an over-long key is hashed first —
    /// and for SHA-384 that the *truncated* 48-byte inner digest feeds the
    /// outer pass, which is what distinguishes HMAC-SHA-384 from a truncated
    /// HMAC-SHA-512.
    #[test]
    fn rfc4231_vectors() {
        assert_eq!(
            hex(&hmac_sha512(&[0x0b; 20], b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(
            hex(&hmac_sha384(&[0x0b; 20], b"Hi There")),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6"
        );
        assert_eq!(
            hex(&hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(
            hex(&hmac_sha384(b"Jefe", b"what do ya want for nothing?")),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );

        let long_key = [0xaa_u8; 131];
        let long_msg: &[u8] = b"This is a test using a larger than block-size key and a \
larger than block-size data. The key needs to be hashed before being used by the HMAC \
algorithm.";
        assert_eq!(
            hex(&hmac_sha512(&long_key, long_msg)),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        );
        assert_eq!(
            hex(&hmac_sha384(&long_key, long_msg)),
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
             a678cc31e799176d3860e6110c46523e"
        );
    }

    /// Reuse must not depend on the caller remembering to reset, and reset must
    /// return exactly to the keyed state — the defect #3 found in the HKDF
    /// expander.
    #[test]
    fn reset_returns_to_the_keyed_state() {
        let mut m = HmacSha512::new(b"key");
        m.update(b"discarded");
        m.reset();
        m.update(b"message");
        assert_eq!(m.finalize(), hmac_sha512(b"key", b"message"));
        assert_eq!(m.count(), 7);
    }

    /// Finalising must not consume the MAC, so a tag can be taken and the
    /// message continued — and taking it twice must agree.
    #[test]
    fn finalize_is_idempotent() {
        let mut m = HmacSha384::new(b"key");
        m.update(b"abc");
        let first = m.finalize();
        assert_eq!(first, m.finalize());
        assert_eq!(first, hmac_sha384(b"key", b"abc"));
    }

    #[test]
    fn verify_accepts_only_the_right_tag() {
        let m = {
            let mut m = HmacSha512::new(b"key");
            m.update(b"message");
            m
        };
        let tag = hmac_sha512(b"key", b"message");
        assert!(m.verify(&tag));
        let mut wrong = tag;
        wrong[0] ^= 1;
        assert!(!m.verify(&wrong));
        assert!(!m.verify(&tag[..63]));
    }

    /// Incremental updates in arbitrary pieces must equal the one-shot tag.
    #[test]
    fn incremental_matches_one_shot() {
        let msg = vec![0x5a_u8; 300];
        for chunk in [1usize, 7, 63, 64, 127, 128, 129] {
            let mut m = HmacSha384::new(b"a longer key than usual, but under a block");
            for part in msg.chunks(chunk) {
                m.update(part);
            }
            assert_eq!(
                m.finalize(),
                hmac_sha384(b"a longer key than usual, but under a block", &msg),
                "chunk {chunk}"
            );
        }
    }
}
