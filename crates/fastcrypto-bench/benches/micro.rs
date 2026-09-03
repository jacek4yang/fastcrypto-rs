//! Deterministic instruction-count benchmarks (Valgrind Callgrind).
//!
//! Wall-clock benchmarks on a shared or virtualised machine are noisy.
//! Callgrind counts instructions instead, which makes small kernel-level
//! optimizations visible even in a cloud VM. Run these when a change is too
//! small to show up reliably in the Criterion numbers:
//!
//! ```sh
//! cargo bench -p fastcrypto-bench --bench micro
//! IAI_CALLGRIND_ALLOW_ASLR=true cargo bench -p fastcrypto-bench --bench micro
//! ```
//!
//! Requires the iai-callgrind-runner binary and valgrind on PATH. In a
//! container that blocks setarch, set `IAI_CALLGRIND_ALLOW_ASLR=true`.
//! Results are written to
//! `target/iai-callgrind/`.

// The iai-callgrind macros generate modules and constants without doc
// comments; their missing_docs warnings are not actionable here.
#![allow(missing_docs)]

use iai_callgrind::{library_benchmark, library_benchmark_group, main};

use fastcrypto_bench::Prng;

fn message(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Prng::new(0x5eed_1234).fill(&mut out);
    out
}

#[library_benchmark]
#[bench::empty(0)]
#[bench::small(64)]
#[bench::record(1500)]
#[bench::streaming(8192)]
fn sha256_fastcrypto(len: usize) -> [u8; 32] {
    let data = message(len);
    fastcrypto::sha256(&data)
}

#[library_benchmark]
#[bench::empty(0)]
#[bench::small(64)]
#[bench::record(1500)]
#[bench::streaming(8192)]
fn sha256_rustcrypto(len: usize) -> Vec<u8> {
    use sha2::Digest;
    let data = message(len);
    sha2::Sha256::digest(&data).to_vec()
}

#[library_benchmark]
#[bench::empty(0)]
#[bench::small(64)]
#[bench::record(1500)]
#[bench::streaming(8192)]
fn sha256_ring(len: usize) -> Vec<u8> {
    let data = message(len);
    ring::digest::digest(&ring::digest::SHA256, &data)
        .as_ref()
        .to_vec()
}

library_benchmark_group!(
    name = sha256_group;
    benchmarks = sha256_fastcrypto, sha256_rustcrypto, sha256_ring
);

main!(library_benchmark_groups = sha256_group);
