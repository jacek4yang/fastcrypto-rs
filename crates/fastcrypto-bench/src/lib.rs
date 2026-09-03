//! Shared tooling for the benchmark and differential-testing laboratory.
//!
//! Nothing in this crate is part of the shipped library: it exists to produce
//! reproducible measurements and to compare our primitives against established
//! implementations.

pub mod env;
pub mod prng;
pub mod sizes;

pub use env::report as environment_report;
pub use prng::Prng;
pub use sizes::TLS_SIZES;
