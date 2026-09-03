# Roadmap

Ordered by what unlocks the most measurement per unit of risk. Nothing here is a
commitment to a date; each milestone is done when its quality gates and its
benchmarks are done.

## Milestone 0 - Foundation (done)

* Cargo workspace, pinned toolchain, `rustfmt`/`clippy` gates.
* Crate split: portable / x86_64 / AArch64 / public API / laboratory.
* README, SECURITY.md, architecture, benchmarking, security model, roadmap.
* `scripts/check.sh`: fmt, check, clippy `-D warnings`, tests.

## Milestone 1 - Baseline laboratory (done)

* Criterion harness with the TLS size ladder and deterministic inputs.
* Baselines for SHA-256, HKDF-SHA256, ChaCha20-Poly1305, AES-128-GCM, X25519
  against RustCrypto, ring, aws-lc-rs, x25519-dalek.
* Portable SHA-256, HMAC-SHA256, HKDF-SHA256 with known-answer vectors
  (FIPS 180-4, RFC 4231, RFC 5869) and differential tests against three
  independent implementations.
* First primitive selected: **SHA-256** (rationale in PROJECT_STATUS.md).

## Milestone 2 - SHA-256: measure, then optimize

1. Profile the portable baseline (`perf`, and iai-callgrind instruction
   counts) to establish where the time actually goes.
2. Message schedule improvements that do not change semantics: circular
   16-word schedule instead of a 64-word array, fewer live values, better
   instruction scheduling. Each one is a separate commit with a benchmark.
3. x86_64 SHA-NI backend behind the existing CPUID gate (the test machine has
   SHA-NI, so the win is measurable immediately).
4. AArch64 ARMv8 SHA-2 backend behind the existing feature probe.
5. Runtime dispatch with the cached feature probe; verify portable and
   accelerated outputs match for every length in 0..300 and for random inputs.
6. Keep or revert each step per the recorded numbers.

Exit criteria: SHA-256 throughput and small-message latency at or better than
the best competitor on a dedicated machine, with the portable path unchanged in
correctness and still passing every test.

## Milestone 3 - HMAC and HKDF on top of the fast hash

* HMAC-SHA256 with the ipad/opad state prepared once (already the design).
* Fewer copies in the TLS 1.3 key schedule: derive several labels from one
  prepared PRK without re-keying HMAC per label.
* Benchmark the real "extract -> expand -> traffic keys" path end to end.

## Milestone 4 - AEAD: ChaCha20-Poly1305

* Portable ChaCha20 and Poly1305, tested against RFC 8439 vectors and
  differentially against the references already in the lab.
* Small-record specialization: this is where TLS lives (0-1500 B).
* SIMD: AVX2/NEON ChaCha20 block functions, gated on detection.
* Fused seal path that avoids the extra copy between plaintext and tag.

## Milestone 5 - AEAD: AES-GCM

* AES-128/256 with AES-NI/VAES, GHASH with PCLMULQDQ/VPCLMULQDQ (or ARMv8
  AES/PMULL), key schedule prepared once and reused per record.
* Constant-time GHASH without table lookups.

## Milestone 6 - X25519

* Portable field arithmetic, then the optimized 64-bit implementation.
* Differential tests against x25519-dalek and aws-lc-rs including the
  contributory-behaviour edge cases.

## Milestone 7 - TLS pipelines

* Handshake transcript hashing with reusable contexts.
* Record protection as one pass: no temporary buffers, no repeated feature
  detection, no repeated key expansion.
* Benchmarks that measure the pipeline, not the primitive.

## Later / only if justified by measurements

* SHA-384, HMAC-SHA384, HKDF-SHA384 (TLS 1.3 cipher suites need them).
* P-256, ECDSA, Ed25519 - only with evidence that HTTPS/TLS workload profiles
  justify the implementation and audit cost.
* AVX-512 paths - only where a real workload keeps the CPU in a wide-register
  state long enough to pay for the transition.

## Explicitly not planned

* New cryptographic constructions or non-standard protocol variants.
* Weakening a check to win a benchmark.
* Assembly before intrinsics have been shown insufficient.

