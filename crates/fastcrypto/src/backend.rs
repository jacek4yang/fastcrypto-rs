//! Backend selection and reporting.
//!
//! Dispatch is deliberately boring: for each primitive there is exactly one
//! compiled implementation today (the portable one). This module exists so that
//! benchmarks and bug reports can record which backend produced a number, and
//! so that adding a dispatched backend later does not change the public API.

use core::fmt;

/// An implementation of a primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// Portable safe Rust, no SIMD, works everywhere.
    Portable,
    /// x86_64 Intel SHA Extensions (SHA-NI).
    X86ShaNi,
    /// AArch64 ARMv8 SHA-2 instructions.
    Aarch64Sha2,
}

impl Backend {
    /// Backend that SHA-256 dispatches to on this machine.
    ///
    /// Reporting only: callers must not branch on it for correctness, and
    /// every backend produces identical digests.
    #[must_use]
    pub fn for_sha256() -> Self {
        #[cfg(target_arch = "x86_64")]
        if fastcrypto_x86::has_sha_ni() {
            return Self::X86ShaNi;
        }
        Self::Portable
    }

    /// Whether this machine has the hardware acceleration that a future
    /// SHA-256 backend would use.
    #[must_use]
    pub fn sha256_hardware_support() -> bool {
        hardware_sha256()
    }

    /// Stable name used in benchmark output and bug reports.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Portable => "portable-rust",
            Self::X86ShaNi => "x86_64-sha-ni",
            Self::Aarch64Sha2 => "aarch64-sha2",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(target_arch = "x86_64")]
fn hardware_sha256() -> bool {
    fastcrypto_x86::has_sha_ni()
}

#[cfg(target_arch = "aarch64")]
fn hardware_sha256() -> bool {
    fastcrypto_aarch64::has_sha2()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn hardware_sha256() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::Backend;

    #[test]
    fn name_is_stable_and_non_empty() {
        assert_eq!(Backend::Portable.name(), "portable-rust");
        assert_eq!(Backend::X86ShaNi.name(), "x86_64-sha-ni");
        assert_eq!(Backend::Aarch64Sha2.name(), "aarch64-sha2");
    }

    #[test]
    fn display_matches_name() {
        assert_eq!(Backend::Portable.to_string(), Backend::Portable.name());
    }

    /// Dispatch must select a hardware backend exactly when one both exists
    /// *and* is implemented.
    ///
    /// The earlier form of this test asserted that hardware support always
    /// implies a non-portable backend. That is false on AArch64, which reports
    /// its ARMv8 SHA-2 instructions while no backend uses them yet — and it
    /// went unnoticed because nothing ran this suite on AArch64 until the
    /// QEMU runner arrived with the X25519 port.
    #[test]
    fn sha256_dispatches_to_the_backend_that_exists() {
        let backend = Backend::for_sha256();
        if cfg!(target_arch = "x86_64") && Backend::sha256_hardware_support() {
            assert_eq!(backend, Backend::X86ShaNi);
        } else {
            assert_eq!(backend, Backend::Portable);
        }
    }
}
