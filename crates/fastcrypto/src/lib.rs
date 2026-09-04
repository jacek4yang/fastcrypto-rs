//! Experimental high-performance cryptography for HTTPS/TLS workloads.
//!
//! This is the safe public API, and it is complete: every primitive
//! `fastcrypto-core` implements is reachable from here. Reaching into
//! `fastcrypto-core` directly is not a shortcut — for SHA-256 and the
//! constructions keyed by it, it is how a caller silently loses the SHA-NI
//! backend that [`dispatch`] selects.
//!
//! Everything below this crate is dispatch: the architecture-specific crates
//! (`fastcrypto-x86`, `fastcrypto-aarch64`) supply the feature detection the
//! accelerated backends select on.
//!
//! # Status
//!
//! Experimental research code. Not audited, not constant-time verified, and
//! not yet competitive with the established libraries it is benchmarked
//! against. See `PROJECT_STATUS.md` and `docs/SECURITY_MODEL.md`.
//!
//! # Guarantees
//!
//! * The public API is 100% safe Rust; `unsafe` may only appear inside
//!   backends, behind feature detection, with a SAFETY comment.
//! * No allocation in any primitive operation: all state is fixed-size and
//!   lives on the stack.
//! * Secret-carrying types zeroize on drop (`zeroize`).
//!
//! # Example
//!
//! ```
//! use fastcrypto::{Sha256, HkdfSha256, sha256};
//!
//! // One-shot hashing.
//! let digest = sha256(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // Incremental hashing.
//! let mut h = Sha256::new();
//! h.update(b"hello ");
//! h.update(b"world");
//! assert_eq!(h.finalize(), digest);
//!
//! // TLS 1.3 style key schedule step.
//! let prk = HkdfSha256::new(b"salt", b"input key material");
//! let mut okm = [0u8; 42];
//! prk.expand_into(b"label", &mut okm).unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

// Tests build small vectors; the library itself never allocates.
#[cfg(test)]
extern crate alloc;

pub mod backend;
pub mod dispatch;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod x25519;

// SHA-256 and everything keyed by it go through `dispatch`, which is where the
// SHA-NI decision is made. Importing these from `fastcrypto_core` instead
// still compiles and silently gives up hardware acceleration, which is exactly
// the mistake this facade exists to prevent.
pub use dispatch::{
    HkdfExpander, HkdfSha256, HmacSha256, Sha256, hkdf_sha256, hmac_sha256, hmac_sha256_verify,
    sha256,
};

// The SHA-512 family has no dispatched backend: there is one implementation,
// so re-exporting it through `dispatch` would add a wrapper that forwards and
// nothing else. If an accelerated SHA-512 is ever added, these move to
// `dispatch` and the paths callers already use do not change.
pub use fastcrypto_core::{
    HkdfExpander384, HkdfSha384, HmacSha384, HmacSha512, Sha384, Sha512, hkdf_sha384, hmac_sha384,
    hmac_sha512, sha384, sha512,
};

pub use fastcrypto_core::Error;
pub use fastcrypto_core::Result;
pub use fastcrypto_core::hkdf::{MAX_OUTPUT_LEN, PRK_LEN};
pub use fastcrypto_core::hmac::TAG_LEN;
pub use fastcrypto_core::sha256::{BLOCK_LEN, DIGEST_LEN};

/// Re-export of the zeroization trait so that callers can clear their own key
/// material without adding a dependency on a specific zeroize version.
pub use zeroize::Zeroize;

/// Crate version, useful for benchmark reports and bug reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::{
        HkdfExpander384, HkdfSha256, HkdfSha384, HmacSha384, HmacSha512, Sha256, Sha384, Sha512,
        hkdf_sha384, hmac_sha256, hmac_sha384, hmac_sha512, sha256, sha384, sha512,
    };

    /// Smoke test that the public re-exports line up with the core crate.
    #[test]
    fn public_api_is_reachable() {
        let d = sha256(b"abc");
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(h.finalize(), d);
        assert_eq!(hmac_sha256(b"k", b"m").len(), 32);
        let mut okm = [0u8; 16];
        HkdfSha256::new(b"s", b"i")
            .expand_into(b"l", &mut okm)
            .unwrap();
    }

    /// Every primitive `fastcrypto-core` implements has to be reachable from
    /// here, because a consumer who cannot find one reaches into
    /// `fastcrypto-core` instead — and for anything keyed by SHA-256 that
    /// silently drops the dispatched backend.
    #[test]
    fn the_facade_covers_the_whole_sha512_family() {
        assert_eq!(sha384(b"abc").len(), 48);
        assert_eq!(sha512(b"abc").len(), 64);

        let mut h384 = Sha384::new();
        h384.update(b"a");
        h384.update(b"bc");
        assert_eq!(h384.finalize(), sha384(b"abc"));

        let mut h512 = Sha512::new();
        h512.update(b"a");
        h512.update(b"bc");
        assert_eq!(h512.finalize(), sha512(b"abc"));

        assert_eq!(hmac_sha384(b"k", b"m").len(), 48);
        assert_eq!(hmac_sha512(b"k", b"m").len(), 64);
        assert_eq!(HmacSha384::new(b"k").finalize().len(), 48);
        assert_eq!(HmacSha512::new(b"k").finalize().len(), 64);

        let mut okm = [0u8; 32];
        HkdfSha384::new(b"s", b"i")
            .expand_into(b"l", &mut okm)
            .unwrap();
        let mut second = [0u8; 32];
        hkdf_sha384(b"s", b"i", b"l", &mut second).unwrap();
        assert_eq!(okm, second);

        let prk = HkdfSha384::new(b"s", b"i").prk();
        let mut expander = HkdfExpander384::new(&prk);
        let mut third = [0u8; 32];
        expander.expand_into(b"l", &mut third).unwrap();
        assert_eq!(okm, third);
    }

    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
