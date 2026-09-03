# Project status

*Last updated: 2026-09-03. Repository state: Milestones 0 and 1 complete,
Milestone 2 in progress (portable schedule done, SHA-NI backend done), all
quality gates green.*

## What this is

An independent, benchmark-driven Rust cryptography project aimed at HTTPS/TLS
workloads. It implements standardised primitives itself, measures them against
ring / aws-lc-rs / RustCrypto, and only then optimizes. It is experimental,
unaudited, and currently **slower** than everything it is benchmarked against.

Read this file together with:

* ``docs/ARCHITECTURE.md`` - layering, dispatch, unsafe policy
* ``docs/BENCHMARKING.md`` - how to reproduce the numbers
* ``docs/SECURITY_MODEL.md`` - threat model and what is not verified
* ``docs/ROADMAP.md`` - milestone order
* ``benchmarks/results/`2026-09-03-amd-epyc-9k65-shared-cloud.md` - the numbers

## State of the repository

| Component | State |
| --- | --- |
| Workspace, pinned toolchain, lint gates | done |
| `fastcrypto-core` (portable, no_std, no unsafe) | SHA-256, HMAC-SHA256, HKDF-SHA256, prepared-key expander |
| `fastcrypto-x86` | CPUID feature detection, cached, cross-checked against std |
| `fastcrypto-aarch64` | feature probe (std-gated), cross-compiles |
| `fastcrypto` (public API) | safe re-exports + `backend` reporting |
| `fastcrypto-bench` | Criterion + iai-callgrind harness, differential and backend-equivalence tests |
| `fuzz/` | two cargo-fuzz targets, both run clean |
| SIMD / instruction backends | x86_64 SHA-NI SHA-256: done and selected at runtime |

Quality gates (all passing):

```sh
./scripts/check.sh
# cargo fmt --all -- --check
# cargo check --workspace --all-targets
# cargo clippy --workspace --all-targets -- -D warnings
# cargo test --workspace --all-features
```

Also verified: `cargo check --target aarch64-unknown-linux-gnu` for
`fastcrypto-aarch64` and `fastcrypto`.

## First primitive: SHA-256

Chosen over ChaCha20 for five reasons, in order of weight:

1. **TLS relevance.** TLS 1.3 uses HKDF-SHA256 for the entire key schedule and
   SHA-256 for the transcript hash; every handshake touches it several times,
   and small inputs (labels, 32-byte secrets) dominate, which is exactly the
   regime where implementation quality shows up as fixed per-call cost.
2. **Scope.** SHA-256 is one compression function with a published constant
   set. Getting it bit-exact is achievable and testable today.
3. **Benchmarkability.** Competitors already in the lab (ring, aws-lc-rs,
   RustCrypto) all expose it, so there is a fair, dense comparison surface.
4. **Optimization headroom with a clear path.** The CPU in this environment has
   Intel SHA Extensions (verified by our own CPUID probe), and the portable
   path itself has measurable headroom (see bottlenecks). Both directions are
   available without changing the public API.
5. **Verifiability.** FIPS 180-4 KAT vectors exist for the primitive, and
   HMAC-SHA256 / HKDF-SHA256 (RFC 4231, RFC 5869) sit directly on top of it, so
   one primitive validates three.

HMAC-SHA256 and HKDF-SHA256 were implemented alongside it because they are
small, they are what TLS actually calls, and they give the lab real baselines
for the HKDF-SHA256 group.

## Correctness status

| Check | Result |
| --- | --- |
| FIPS 180-4 SHA-256 vectors (empty, "abc", 448-bit, streaming) | pass |
| SHA-256 differential vs RustCrypto `sha2`, ring, aws-lc-rs | pass for every length in 0..300 plus 512 B - 64 KiB |
| Chunking independence (1..1000-byte updates) | pass |
| RFC 4231 HMAC-SHA256 cases 1-6 (incl. truncated case 5, long-key case 6) | pass |
| HMAC differential vs RustCrypto `hmac`, ring, aws-lc-rs | pass over key lengths 0, 1, 20, 31, 32, 63, 64, 65, 100, 200 |
| RFC 5869 HKDF-SHA256 cases 1 and 3 | pass |
| HKDF differential vs RustCrypto `hkdf`, ring, aws-lc-rs | pass across salt/IKM/info lengths and output lengths up to 255 blocks |
| Oversized HKDF output rejected consistently | pass |
| Cross-reference agreement (references must agree with each other) | pass |
| cargo-fuzz: `sha256` (200k runs), `hkdf_sha256` (300k runs) | no crashes |

One vector was wrong during development (RFC 4231 case 6 input string) and was
caught by the differential comparison with three independent libraries; the
value from the RFC text was then used verbatim. That is the intended workflow.

## Benchmark summary (2026-09-03, shared cloud container, AMD EPYC 9K65)

Full tables in `benchmarks/results/`. Headline numbers:

* SHA-256 one-shot at 64 KiB: **35.9 us** for us, ring **35.9 us**, aws-lc-rs
  **35.9 us** - indistinguishable in this run. At 0 B: **70.5 ns** for us,
  ring 79.2 ns, aws-lc-rs 61.6 ns, so the fixed-cost gap at small sizes
  narrowed from about 58% behind the best competitor to about 14%.
* SHA-256 improvement today: about **-70%** at small sizes and **-82%** at
  64 KiB versus the first portable baseline, in three measured steps
  (message schedule, SHA-NI, zeroization scope).
* Streaming 64 KiB in 1 KiB updates: 36.3 us vs ring 36.1 us.
* HKDF-SHA256 extract + expand to 88 bytes: **922.9 ns**, vs RustCrypto hkdf
  657.8 ns, ring 785.2 ns, aws-lc-rs 811.2 ns. On the TLS-shaped workload
  (four labels from one PRK, using the prepared-key expander added today):
  **640.2 ns** vs RustCrypto hkdf 482.8 ns, down from 1200 ns with the
  per-label API. It was 4346 ns at the start of the day.
* AEAD and X25519 groups are still reference numbers only; those primitives are
  not implemented yet.

Competitiveness, stated precisely: at 1 KiB and above our SHA-256 is
indistinguishable from ring and aws-lc-rs in these runs (within 1%). At
small sizes we are within about 14% of the best competitor at 0 B and
still behind aws-lc-rs. HKDF-SHA256 is about 1.8x slower than RustCrypto
hkdf. Every one of those statements is a single-run measurement on a
shared container, so none of them is a claim of being faster: they are
the numbers a dedicated machine has to confirm or refute.

## Current bottlenecks, in priority order

1. **HKDF-SHA256 fixed costs (~1.4x against RustCrypto hkdf for a single
   expand chain rebuilds its ipad/opad key states (two extra compressions each)
   and every finalize zeroizes a 128-byte padding scratch with volatile writes.
   A TLS key schedule expands several labels from one PRK, so preparing the HMAC
   key once and reusing it is the fix. Measured at 1369 ns vs 648 ns for a full
   extract + expand to 88 bytes (1205.7 ns vs 656.6 ns).
2. **Zeroization fixed costs (construction 26.3 ns, finalize scratch).** Hasher
   construction is 26.3 ns against 2.4 ns for RustCrypto: zeroization on drop
   (9 words plus a 64-byte block of volatile writes). Deliberate trade-off, but
   it now dominates below 256 bytes, which is the range TLS handshake hashing
   lives in.
3. **Remaining portable headroom (~1.27x against RustCrypto soft).** Only worth
   another pass after the two items above.
4. **No AArch64 SHA-2 backend yet.** The probe exists; the compression does not.

## Optimization log

Every optimization attempt is recorded with its measurement, including the ones
that were reverted:

* `benchmarks/results/2026-09-03-hkdf-key-reuse.md` - reuse the HMAC
  key state across the HKDF expand chain and add HkdfExpander for the
  TLS-shaped multi-label case: -29% on expand, -47% on four labels.
* `benchmarks/results/2026-09-03-zeroization-scope.md` - narrow the
  zeroization in finalize to the bytes actually written: -27.7% at 0 B,
  -12% to -16% on HKDF, no change to the security property.
* `benchmarks/results/2026-09-03-sha256-sha-ni.md` - x86_64 SHA-NI backend:
  -62% to -81% per size, plus the safe dispatch seam (Compressor) that let
  the public API stay forbid(unsafe_code).
* `benchmarks/results/2026-09-03-sha256-message-schedule.md` - portable
  schedule rework: five variants, two rejected (one of them faster on 64 KiB
  but slower on a single block), net -6.2% to -21.6% per size.

## Next concrete optimization task

**Remove the remaining per-call zeroization costs.** Two items, measured, each
with its own commit and benchmark run:

1. finalize: avoid the 128-byte padding scratch entirely for messages whose tail
   fits in one block, and zeroize only the tail bytes that hold message data.
2. construction: 26.3 ns per hasher, all of it volatile zeroization on drop of
   the state and the block buffer. Decide, with numbers, whether to keep it as
   is (documented trade-off) or to make zeroization explicit at the API level
   for callers that hash public data.

After that: the AArch64 ARMv8 SHA-2 backend, then AEAD (ChaCha20-Poly1305).

## Reproducing everything here

```sh
./scripts/check.sh                       # quality gates
cargo run --release --bin bench-env      # environment report
cargo bench -p fastcrypto-bench          # all groups (~11 min)
cargo bench -p fastcrypto-bench --bench micro   # instruction counts
  # (add IAI_CALLGRIND_ALLOW_ASLR=true in containers that block setarch)

# portable-vs-portable SHA-256 (forces RustCrypto onto its soft backend)
RUSTFLAGS='--cfg sha2_backend="soft"' cargo bench -p fastcrypto-bench --bench sha256

cd fuzz && cargo +nightly fuzz run sha256 -- -runs=200000 -max_len=2048
```

## Handover notes for the next engineer

* Do not add a dependency to the library crates without a recorded reason;
  competitor libraries belong in `fastcrypto-bench` only.
* Every `unsafe` block needs a SAFETY comment and a feature gate.
  `fastcrypto-core` forbids `unsafe` outright - keep it that way.
* Benchmark numbers from this container are iteration-only. Before quoting any
  absolute figure, re-run on a dedicated machine with a fixed clock and attach
  `bench-env` output.
* The iai-callgrind group exists for exactly the situation above: when a change
  is too small for wall-clock timing on a noisy machine, count instructions.
* The HKDF group is the one to watch after any SHA-256 change: it is the
  end-to-end shape TLS actually uses.

