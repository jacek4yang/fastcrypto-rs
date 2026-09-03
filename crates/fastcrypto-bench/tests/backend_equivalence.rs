//! Portable vs accelerated backend equivalence.
//!
//! The differential tests in differential.rs now exercise whichever backend
//! dispatch selected, so they already prove the accelerated path against three
//! reference implementations. This file proves the stronger property directly:
//! the accelerated backend and the portable backend must agree byte for byte,
//! on every length and under every chunking, on the same machine.

#![cfg(target_arch = "x86_64")]

use fastcrypto_bench::Prng;
use fastcrypto_core::sha256::{Compressor, Sha256};

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Prng::new(seed).fill(&mut out);
    out
}

fn digest_with(compressor: Compressor, data: &[u8], chunk: usize) -> [u8; 32] {
    let mut h = Sha256::with_compressor(compressor);
    if chunk == 0 {
        h.update(data);
    } else {
        for part in data.chunks(chunk) {
            h.update(part);
        }
    }
    h.finalize()
}

#[test]
fn sha_ni_matches_portable_for_every_length() {
    let accelerated = Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    for len in 0..600usize {
        let data = random_bytes(0x1234_5678 ^ len as u64, len);
        let portable = digest_with(Compressor::PORTABLE, &data, 0);
        let fast = digest_with(accelerated, &data, 0);
        assert_eq!(portable, fast, "length {len}");
    }
}

#[test]
fn sha_ni_matches_portable_at_block_boundaries() {
    // The padding and buffering edge cases: 55/56/57/63/64/65 and the
    // multi-block tail cases around 119/120.
    let accelerated = Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    for len in [
        55usize, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 191, 192, 193,
    ] {
        let data = random_bytes(0xaa11 + len as u64, len);
        assert_eq!(
            digest_with(Compressor::PORTABLE, &data, 0),
            digest_with(accelerated, &data, 0),
            "length {len}"
        );
    }
}

#[test]
fn sha_ni_matches_portable_under_every_chunking() {
    // A transcript hash is built from many updates of different sizes; the
    // buffered-tail path is backend-independent state handling, but the split
    // between "whole blocks" and "buffered tail" differs per chunking, so this
    // is where a dispatch bug would show up.
    let accelerated = Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    let data = random_bytes(0x5eed, 5000);
    for chunk in [
        1usize, 3, 15, 16, 31, 32, 55, 56, 57, 63, 64, 65, 127, 128, 1000, 4096,
    ] {
        assert_eq!(
            digest_with(Compressor::PORTABLE, &data, chunk),
            digest_with(accelerated, &data, chunk),
            "chunk {chunk}"
        );
    }
}

#[test]
fn sha_ni_matches_portable_for_long_inputs() {
    let accelerated = Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    for len in [64 * 1024usize, 64 * 1024 + 1, 64 * 1024 + 63, 100_000] {
        let data = random_bytes(0x77 ^ len as u64, len);
        assert_eq!(
            digest_with(Compressor::PORTABLE, &data, 0),
            digest_with(accelerated, &data, 0),
            "length {len}"
        );
    }
}

#[test]
fn non_destructive_finalize_is_backend_independent() {
    let accelerated = Compressor::new(fastcrypto_x86::sha256::compress_blocks);
    for compressor in [Compressor::PORTABLE, accelerated] {
        let mut h = Sha256::with_compressor(compressor);
        h.update(b"abc");
        let first = h.finalize();
        h.update(b"d");
        let second = h.finalize();
        assert_eq!(first, fastcrypto_core::sha256(b"abc"));
        assert_eq!(second, fastcrypto_core::sha256(b"abcd"));
        assert_eq!(h.count(), 4);
    }
}
