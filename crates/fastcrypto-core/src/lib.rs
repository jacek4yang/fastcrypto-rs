//! Portable, `no_std`, allocation-free cryptographic primitives.
//!
//! This crate contains the architecture-independent ("portable") backends used
//! by the `fastcrypto` public crate when no architecture-specific backend
//! is available, plus the shared types (errors, zeroization policy) that all
//! backends agree on.
//!
//! # Guarantees
//!
//! * `no_std` and `forbid(unsafe_code)` - the portable backends are
//!   100% safe Rust.
//! * No heap allocations, no `Vec`, no `String`, no interior mutability.
//! * Fixed-size stack state only; every primitive exposes fixed-size output
//!   arrays.
//! * Secret-bearing types implement `zeroize::Zeroize` and zeroize on drop.
//!
//! # Constant-time
//!
//! The code in this crate avoids secret-dependent branches and
//! secret-dependent memory addressing. See ```docs/SECURITY_MODEL.md``` in the
//! repository root for the threat model, the residual risks, and the parts of
//! this claim that still require generated-code review.
//!
//! # Status
//!
//! Experimental research code. Not audited. Not constant-time-verified.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    clippy::std_instead_of_core,
    clippy::alloc_instead_of_core,
    clippy::missing_const_for_fn
)]

// `alloc` is only needed by the in-crate tests (test vectors use `Vec`/`String`).
// The library itself is allocation-free, so the crate is not linked normally.
#[cfg(test)]
extern crate alloc;

pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod sha256;
mod util;

pub use error::Error;
pub use hkdf::{HkdfSha256, hkdf_sha256};
pub use hmac::{HmacSha256, hmac_sha256, hmac_sha256_verify};
pub use sha256::{Sha256, sha256};

/// Library result type.
pub type Result<T> = core::result::Result<T, Error>;
