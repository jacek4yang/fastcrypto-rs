# fastcrypto-rs

Experimental, benchmark-driven cryptography research for HTTPS/TLS workloads,
written in Rust.

> **Status: experimental research code.**
> Not audited. Not constant-time verified. Our SHA-256 now measures within
> about 1% of ring and aws-lc-rs at 1 KiB and above, and HKDF-SHA256 is
> within about 29% on the TLS-shaped workload, but none of that is a claim of
> being faster: those are single-run numbers from a shared container, and
> this project requires a dedicated machine and a measurement recorded
> under `benchmarks/results/` before any performance claim.

## Why

TLS is not slow because of one primitive: it is slow because of the *pipeline* -
HKDF extract, HKDF expand, key initialisation, per-record AEAD setup, and the
fixed overheads that dominate small records. This project exists to measure
those costs honestly and to reduce them without ever changing the
cryptographic construction.

The rules of the project:

1. **Correctness first.** Standardised constructions only. Every primitive is
   tested against published known-answer vectors and differentially against
   established implementations.
2. **Measurements second.** No optimisation is merged before a benchmark
   records the baseline.
3. **Optimization third.** An optimisation that does not show up in a
   measurement, or that regresses another measurement, is reverted.
4. **Claims last.** Nothing is described as faster, constant-time, or safe
   until the evidence is in the repository.

## Current state

| Area | Status |
| --- | --- |
| Workspace, lint gates, quality scripts | done |
| Portable SHA-256 | done (safe Rust, KAT + differential tested) |
| Portable HMAC-SHA256 | done (RFC 4231 vectors) |
| Portable HKDF-SHA256 | done (RFC 5869 vectors), plus a prepared-key expander for the TLS multi-label shape |
| x86_64 feature detection (CPUID, cached, no_std) | done, cross-checked against `std::arch` |
| AArch64 feature detection (feature-gated probe) | done |
| Benchmark laboratory (Criterion) | done |
| Differential tests vs RustCrypto / ring / aws-lc-rs | done |
| x86_64 SHA-NI SHA-256 | done, selected at runtime, equivalence tested |
| ChaCha20-Poly1305, AES-GCM, X25519 | benchmarks only, not implemented |

See `PROJECT_STATUS.md` for the current handover note,
`docs/ROADMAP.md` for what comes next, and `benchmarks/results/`
for measurements.

## Where the numbers stand (2026-09-03, shared cloud container, AMD EPYC 9K65)

| benchmark | first portable baseline | today | best competitor in the same run |
|---|---|---|---|
| SHA-256, 0 B | 282.4 ns | 67.4 ns | aws-lc-rs 61.6 ns |
| SHA-256, 64 KiB | 225.9 us | 36.0 us | aws-lc-rs 35.9 us |
| HKDF extract + expand to 88 B | 4346 ns | 880.5 ns | RustCrypto hkdf 656.8 ns |
| HKDF, four labels from one PRK | 1375 ns (per-label API) | 627.3 ns | RustCrypto hkdf 486.5 ns |

Five optimization steps got there, all recorded with their measurements -
including two rejected variants - in `benchmarks/results/`.

## Repository layout

```
.
├── Cargo.toml                # workspace manifest
├── crates/
│   ├── fastcrypto/           # public safe API + dispatch
│   ├── fastcrypto-core/      # portable, no_std, allocation-free primitives
│   ├── fastcrypto-x86/       # x86_64 backend: CPUID detection, future SIMD
│   ├── fastcrypto-aarch64/   # AArch64 backend: feature probe, future SIMD
│   └── fastcrypto-bench/     # benchmark and differential-test laboratory
├── benchmarks/results/       # recorded measurements (Markdown)
├── docs/                     # architecture, benchmarking, security model, roadmap
├── fuzz/                     # cargo-fuzz targets (separate workspace)
├── scripts/                  # quality gates
└── PROJECT_STATUS.md
```

Layering is strict, and it is the point of the repository:

```
safe Rust public API   ->   fastcrypto
                              |
                        dispatch layer (backend selection)
                              |
              +---------------+---------------+
              |                               |
     portable backend                 architecture backends
     fastcrypto-core              fastcrypto-x86 / fastcrypto-aarch64
     (forbid unsafe_code)         (unsafe allowed, gated, documented)
```

## Quick start

```sh
# quality gates (what CI runs)
./scripts/check.sh

# benchmark environment report - attach this to every recorded result
cargo run --release --bin bench-env

# baseline benchmarks
cargo bench -p fastcrypto-bench --bench sha256
cargo bench -p fastcrypto-bench --bench hkdf
cargo bench -p fastcrypto-bench --bench aead
cargo bench -p fastcrypto-bench --bench x25519
```

## Using the library

```rust
use fastcrypto::{Sha256, HkdfSha256, sha256};

let digest = sha256(b"hello world");

let mut h = Sha256::new();
h.update(b"hello ");
h.update(b"world");
assert_eq!(h.finalize(), digest);

// TLS 1.3 style key schedule step
let prk = HkdfSha256::new(b"salt", b"input key material");
let mut okm = [0u8; 42];
prk.expand_into(b"label", &mut okm).unwrap();
```

The API is allocation-free, `no_std`-capable
(`default-features = false`), and safe end to end. Secret-carrying types
zeroize on drop.

## Documentation

* `docs/ARCHITECTURE.md` - layering, crate responsibilities, dispatch design.
* `docs/BENCHMARKING.md` - how to produce reproducible measurements.
* `docs/SECURITY_MODEL.md` - threat model, unsafe policy, what is not yet
  verified.
* `docs/ROADMAP.md` - milestones and the order they are done in.
* `SECURITY.md` - how to report a vulnerability in experimental code.

## Scope

This is an independent research project. It implements standardised primitives
(FIPS 180-4, RFC 2104, RFC 5869 and friends) and optimises *implementations*
only; it does not invent constructions, and it does not weaken cryptographic
semantics to win a benchmark.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

