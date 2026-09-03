//! AArch64 backend for fastcrypto-rs: CPU feature detection and the
//! architecture-specific primitives that build on it.
//!
//! # Scope
//!
//! * feature detection for the ARMv8 SHA-2 instructions, whose SHA-256 backend
//!   is deferred until the portable baseline has been profiled (see
//!   ``PROJECT_STATUS.md``);
//! * `x25519` — X25519, from s2n-bignum's assembly, integrated with
//!   `global_asm!` so that it needs no build script and no C toolchain.
//!   AArch64 Linux only, because the imported assembly emits ELF directives.
//!
//! # Detection and no_std
//!
//! There is no core-only equivalent of the aarch64 feature probe, so this
//! crate offers two modes:
//!
//! * with the `std` feature: use the platform feature probe (Linux
//!   HWCAP / macOS sysctl / Windows IsProcessorFeaturePresent) through
//!   `std::arch::is_aarch64_feature_detected`;
//! * without it (bare-metal, or when the caller wants a fixed baseline): every
//!   feature reports as unavailable and the portable backends are used.
//!
//! Both modes share the same cached, allocation-free API.

#![no_std]

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub mod x25519;

// Only needed for the optional platform feature probe.
#[cfg(feature = "std")]
extern crate std;

use core::sync::atomic::{AtomicU32, Ordering};

/// Bit set once the cache has been populated.
const CACHED: u32 = 1 << 31;

const BIT_NEON: u32 = 1 << 0;
const BIT_AES: u32 = 1 << 1;
const BIT_SHA2: u32 = 1 << 2;
const BIT_SHA3: u32 = 1 << 3;
// Note: ARMv8.2 SHA-512 instructions have no std runtime probe in Rust
// 1.98 (only sha2 and sha3 are exposed), so they are not reported here
// until a raw HWCAP read is implemented.
const BIT_PMULL: u32 = 1 << 4;

/// Process-wide feature cache.
static CACHE: AtomicU32 = AtomicU32::new(0);

/// CPU features that this library knows how to use on AArch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    bits: u32,
}

impl Features {
    /// Probes the CPU directly.
    ///
    /// Without the `std` feature this reports no features: on a target
    /// with no operating-system query available, claiming otherwise would be
    /// unsound.
    #[must_use]
    pub fn detect() -> Self {
        // Without the std probe below, bits is never mutated.
        #[allow(unused_mut)]
        let mut bits = 0;
        #[cfg(all(target_arch = "aarch64", feature = "std"))]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                bits |= BIT_NEON;
            }
            if std::arch::is_aarch64_feature_detected!("aes") {
                bits |= BIT_AES;
            }
            if std::arch::is_aarch64_feature_detected!("sha2") {
                bits |= BIT_SHA2;
            }
            if std::arch::is_aarch64_feature_detected!("sha3") {
                bits |= BIT_SHA3;
            }
            if std::arch::is_aarch64_feature_detected!("pmull") {
                bits |= BIT_PMULL;
            }
        }
        Self { bits }
    }

    /// Returns the cached feature set, probing at most once per process.
    #[must_use]
    pub fn cached() -> Self {
        let v = CACHE.load(Ordering::Relaxed);
        if v & CACHED != 0 {
            return Self { bits: v & !CACHED };
        }
        let f = Self::detect();
        CACHE.store(f.bits | CACHED, Ordering::Relaxed);
        f
    }

    /// Clears the cache. Only useful for tests that want to re-detect.
    pub fn reset_cache() {
        CACHE.store(0, Ordering::Relaxed);
    }

    /// Advanced SIMD (NEON), baseline on AArch64.
    #[must_use]
    pub const fn neon(&self) -> bool {
        self.bits & BIT_NEON != 0
    }

    /// ARMv8 AES instructions (AESE/AESD).
    #[must_use]
    pub const fn aes(&self) -> bool {
        self.bits & BIT_AES != 0
    }

    /// ARMv8 SHA-2 instructions (SHA256H/SHA256SU0/SHA256SU1).
    #[must_use]
    pub const fn sha2(&self) -> bool {
        self.bits & BIT_SHA2 != 0
    }

    /// ARMv8 SHA-3 instructions (EOR3, RAXI, XAR, BCAX).
    #[must_use]
    pub const fn sha3(&self) -> bool {
        self.bits & BIT_SHA3 != 0
    }

    /// Polynomial multiplication (PMULL/PMULL2), needed for GHASH.
    #[must_use]
    pub const fn pmull(&self) -> bool {
        self.bits & BIT_PMULL != 0
    }
}

/// Convenience probe: are the ARMv8 SHA-2 instructions available?
#[must_use]
pub fn has_sha2() -> bool {
    Features::cached().sha2()
}

#[cfg(test)]
mod tests {
    use super::Features;

    #[test]
    fn detect_is_idempotent() {
        assert_eq!(Features::detect(), Features::detect());
    }

    #[test]
    fn cached_agrees_with_detect() {
        Features::reset_cache();
        assert_eq!(Features::cached(), Features::detect());
        assert_eq!(Features::cached(), Features::detect());
    }
}
