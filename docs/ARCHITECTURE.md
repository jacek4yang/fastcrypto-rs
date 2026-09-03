# Architecture

## Goal

A TLS cryptography library where the *fast path is readable* and every
optimization is justified by a measurement. The architecture exists to make
that possible: strict layering, so that an optimization in one backend cannot
quietly change behaviour somewhere else, and an explicit dispatch seam, so that
"which code ran" is answerable at any time.

## Layers

```
safe Rust public API        crates/fastcrypto
                            - no unsafe, no allocation, fixed-size outputs
                            - re-exports the primitives, owns the dispatch seam
                                    |
                            dispatch (fastcrypto::backend)
                                    |
                +-------------------+-------------------+
                |                                       |
portable backend                            architecture backends
crates/fastcrypto-core                      crates/fastcrypto-x86
- #![no_std]                                crates/fastcrypto-aarch64
- #![forbid(unsafe_code)]                   - CPU feature detection (cached)
- SHA-256, HMAC-SHA256, HKDF-SHA256         - future SIMD/instruction backends
- zeroize on drop                           - unsafe allowed, gated, documented
```

Crate responsibilities:

| Crate | May contain unsafe | Allocation | std | Purpose |
| --- | --- | --- | --- | --- |
| `fastcrypto` | no | no | optional feature | public API, dispatch |
| `fastcrypto-core` | forbidden by lint | no | no | portable primitives |
| `fastcrypto-x86` | yes, gated on CPUID | no | no | x86_64 backend |
| `fastcrypto-aarch64` | yes, gated on probe | no | optional | AArch64 backend |
| `fastcrypto-bench` | no | yes (benchmarks only) | yes | laboratory |

Competitor and reference libraries (ring, aws-lc-rs, RustCrypto) appear **only**
in `fastcrypto-bench` as dev-dependencies. They are never dependencies of
the shipped library.

## Dispatch design

Dispatch answers one question: which implementation of a primitive runs on this
machine?

* Feature detection is done once per process and cached in an `AtomicU32`
  (`fastcrypto-x86/src/detect.rs`). Detection is idempotent, so racing
  initialisations recompute the same value instead of needing a lock. That keeps
  the hot path to a relaxed atomic load.
* On x86_64 the probe is implemented directly with CPUID/XGETBV: the std macro
  `is_x86_feature_detected` is std-only, and this crate must stay
  `no_std`. A unit test cross-checks every flag against that macro.
* On AArch64 there is no core-only probe, so the platform probe is behind the
  `std` feature; without it every feature reports as unavailable and the
  portable backend is used. Reporting "no features" is the safe direction: an
  over-report would select instructions that fault.
* `fastcrypto::backend::Backend` reports the selected backend and the
  available hardware acceleration. Benchmarks record it, so a number always
  carries its backend with it.

Today every primitive dispatches to `Backend::Portable`. The seam is in
place so that adding a SHA-NI backend changes no public API and no benchmark.

## Data flow and ownership rules

1. No heap allocation in any primitive. State is fixed-size and lives in the
   caller's frame (`Sha256` is 8 words of state plus one 64-byte block).
2. Inputs are read, never copied: complete blocks are compressed straight out of
   the caller's slice; only a trailing partial block is buffered.
3. Padding is materialised in a fixed 128-byte stack scratch buffer and zeroized
   before returning.
4. Fixed-size outputs are returned as `[u8; N]`, never `Vec`.
5. Secret-bearing types implement `zeroize::Zeroize` and zeroize on drop;
   `Debug` prints metadata only, never state.

## Error handling

`fastcrypto_core::Error` is a small `Copy` enum
(`OutputTooLong`, `InvalidKeyLength`). Errors are returned, never
panicked, and constructing an error never allocates. Lengths that are
impossible by construction (a 4-byte chunk from `chunks_exact(4)`) use
`expect` with a comment rather than adding error paths that cannot run.

## Unsafe policy

* `fastcrypto-core` forbids unsafe entirely.
* Backends may use unsafe only when there is a measurable reason, and every
  `unsafe` block carries a SAFETY comment naming the invariant that makes it
  sound (see `crates/fastcrypto-x86/src/detect.rs` for the XGETBV example:
  OSXSAVE set implies XGETBV is executable).
* Runtime dispatch gates every accelerated path behind the matching feature
  check; there is no path where an instruction can execute without its feature
  bit.
* `#![deny(unsafe_op_in_unsafe_fn)]` is set workspace-wide.

## Testing architecture

```
                 our implementation
                          |
   +----------------------+----------------------+
   |                      |                      |
known-answer tests   differential tests     property tests
(FIPS, RFC vectors)  (vs ring, aws-lc-rs,   (chunking, prefix
                      RustCrypto)            stability, boundaries)
```

* Known-answer tests live next to the code in `fastcrypto-core` (FIPS 180-4
  for SHA-256, RFC 4231 for HMAC, RFC 5869 for HKDF).
* Differential tests live in `crates/fastcrypto-bench/tests/differential.rs`
  and compare against three independent implementations over every length in
  0..300 plus the TLS sizes, for HMAC across key lengths including the
  64/65-byte pre-hash boundary, and for HKDF across output lengths including
  the 255-block limit.
* Fuzz targets live in `fuzz/` (separate workspace, cargo-fuzz).

## Deliberate non-goals (for now)

* No assembly. Intrinsics first; assembly only if generated code shows LLVM
  leaving measurable performance on the table.
* No new constructions, no non-standard protocols, no "fused" variants that
  change the algorithm's output.
* No global allocator, no async, no dynamic dispatch in hot paths.

