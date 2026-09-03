//! Shared benchmark harness configuration and input generation.
//!
//! Every group uses identical inputs, identical warmup, and identical
//! statistical settings so that numbers collected on different days stay
//! comparable.

#![allow(dead_code)]

use std::time::Duration;

use criterion::{Criterion, Throughput};
use fastcrypto_bench::{Prng, TLS_SIZES};

/// Criterion configuration used by every benchmark group.
///
/// * warmup long enough to reach steady state after CPU frequency ramp-up;
/// * measurement time long enough that a single scheduling hiccup cannot move
///   the mean;
/// * a noise threshold that surfaces regressions instead of hiding them.
pub(crate) fn criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_millis(1500))
        .sample_size(60)
        .confidence_level(0.95)
        .noise_threshold(0.03)
}

/// Byte throughput annotation for a group.
pub(crate) fn throughput(len: usize) -> Throughput {
    Throughput::Bytes(len as u64)
}

/// The standard TLS size ladder.
pub(crate) fn sizes() -> &'static [usize] {
    TLS_SIZES
}

/// Human-readable size label used in benchmark IDs.
pub(crate) fn label(len: usize) -> String {
    fastcrypto_bench::sizes::label(len)
}

/// Deterministic 32-byte value, e.g. a private scalar.
pub(crate) fn key32(seed: u64) -> [u8; 32] {
    Prng::new(seed).array32()
}

/// Deterministic message of the requested length.
///
/// Identical bytes are fed to every implementation under test: comparing
/// implementations on different data would compare the data, not the code.
pub(crate) fn message(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Prng::new(0x5eed_1234).fill(&mut out);
    out
}

/// Deterministic key material of the requested length.
pub(crate) fn key(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Prng::new(0x1eaf_beef).fill(&mut out);
    out
}
