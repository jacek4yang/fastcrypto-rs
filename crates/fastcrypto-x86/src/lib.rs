//! x86_64 backend for fastcrypto-rs: CPU feature detection and the
//! architecture-specific primitives that build on it.
//!
//! # Scope
//!
//! * [`detect`] — a cached, allocation-free, branch-light CPU feature probe,
//!   the dispatch foundation everything else here selects on.
//! * [`sha256`] — SHA-256 using Intel SHA Extensions (SHA-NI).
//! * [`x25519`] — X25519, from s2n-bignum's assembly, integrated with
//!   `global_asm!` so that it needs no build script and no C toolchain.
//!
//! # Safety policy
//!
//! Every unsafe block in this crate must carry a SAFETY comment stating the
//! invariant that makes it sound, and must be gated behind the matching
//! runtime feature check exported here.

#![no_std]

// Only the tests need allocation; the library itself is allocation-free.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(target_arch = "x86_64")]
pub mod detect;
#[cfg(target_arch = "x86_64")]
pub mod sha256;
#[cfg(target_arch = "x86_64")]
pub mod x25519;

#[cfg(not(target_arch = "x86_64"))]
pub mod detect {
    //! Feature probing is meaningless on non-x86_64 targets; the API is kept
    //! identical so that dependent code needs no conditional compilation.

    /// CPU features relevant to this library, on non-x86_64 targets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Features {
        _private: (),
    }

    impl Features {
        /// Every feature is reported as unavailable.
        #[must_use]
        pub const fn detect() -> Self {
            Self { _private: () }
        }

        /// Every feature is reported as unavailable.
        #[must_use]
        pub const fn cached() -> Self {
            Self { _private: () }
        }

        /// Always false.
        #[must_use]
        pub const fn sha_ni(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn aes_ni(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn pclmulqdq(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn avx2(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn vaes(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn vpclmulqdq(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn avx512f(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn bmi2(&self) -> bool {
            false
        }

        /// Always false.
        #[must_use]
        pub const fn adx(&self) -> bool {
            false
        }
    }
}

pub use detect::Features;

/// Convenience probe: are Intel SHA Extensions (SHA-NI) available?
#[must_use]
pub fn has_sha_ni() -> bool {
    Features::cached().sha_ni()
}

/// Convenience probe: are AES-NI and PCLMULQDQ both available?
#[must_use]
pub fn has_aes_ni() -> bool {
    let f = Features::cached();
    f.aes_ni() && f.pclmulqdq()
}
