//! Experimental high-performance cryptography for HTTPS/TLS workloads.
//!
//! This is the safe public API. Everything below it is dispatch: today every
//! primitive is served by the portable backend in `fastcrypto-core`, and
//! the architecture-specific crates (`fastcrypto-x86`, `fastcrypto-aarch64`)
//! supply the feature detection those backends will select on.
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
#[cfg(target_arch = "x86_64")]
pub mod x25519;

pub use dispatch::{
    HkdfExpander, HkdfSha256, HmacSha256, Sha256, hkdf_sha256, hmac_sha256, hmac_sha256_verify,
    sha256,
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
    use super::{HkdfSha256, Sha256, hmac_sha256, sha256};

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

    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
