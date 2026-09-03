# Project status

*Last updated: 2026-09-03. Repository state: Milestone 0 and Milestone 1
complete, all quality gates green.*

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
| `fastcrypto-core` (portable, no_std, no unsafe) | SHA-256, HMAC-SHA256, HKDF-SHA256 |
| `fastcrypto-x86` | CPUID feature detection, cached, cross-checked against std |
| `fastcrypto-aarch64` | feature probe (std-gated), cross-compiles |
| `fastcrypto` (public API) | safe re-exports + `backend` reporting |
| `fastcrypto-bench` | Criterion + iai-callgrind harness, differential tests |
| `fuzz/` | two cargo-fuzz targets, both run clean |
| SIMD / instruction backends | not started |

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

Full tables in ``benchmarks/results/``. Headline numbers:

* SHA-256 one-shot at 64 KiB: **190.9 us** for us vs **36.0 us** for the
  SHA-NI-backed implementations (5.3x). At 0 B: 254.6 ns vs 58-79 ns.
* Portable-vs-portable (RustCrypto forced to its soft backend): ours is
  **1.27x slower** at 64 KiB - about 10.2 vs 8.1 cycles/byte on the estimated
  3.69 GHz clock. It was 1.52x before the schedule rework.
* HKDF-SHA256 extract+expand to 88 bytes: 4346 ns vs 650 ns (RustCrypto) and
  796 ns (ring).
* AEAD and X25519 groups contain **reference numbers only**; those primitives
  are not implemented yet. ChaCha20-Poly1305 seal of an empty record: 222 ns
  (ring) / 226 ns (aws-lc-rs). X25519 fixed-key: 18.7 us (aws-lc-rs) vs
  42.0 us (x25519-dalek).

No claim of being faster than any competitor is made anywhere. The current
implementation is slower at every size.

## Current bottlenecks, in priority order

1. **No hardware-accelerated path (~5.3x at 64 KiB).** Every competitor in the
   lab uses Intel SHA Extensions on this CPU. The feature probe already reports
   `sha=true`, the cached CPUID path exists, and the dispatch seam
   (`fastcrypto::backend::Backend`) is in place, so this is implementation work,
   not design work.
2. **Remaining portable headroom (~1.27x).** Against RustCrypto's soft backend
   we now run about 10.2 cycles/byte versus 8.1 at 64 KiB (it was 12.3 before
   the schedule rework). Worth another pass only after the SHA-NI path exists,
   because that is where the order of magnitude is.
3. **Fixed per-call cost (254.6 ns for a 0-byte digest).** One compression of a
   64-byte block dominates; the padding path adds a 128-byte stack scratch plus
   volatile zeroization. This is the number to attack for handshake-sized
   inputs once SHA-NI lands.
4. **Zeroization cost on construction (19.5 ns vs 2.4 ns).** `Sha256` zeroizes on
   drop (9 words + 64-byte block, volatile writes). Deliberate trade-off; it is
   now a larger share of small-message cost than before, because the hash got
   cheaper.

## Optimization log

Every optimization attempt is recorded with its measurement, including the ones
that were reverted:

* `benchmarks/results/2026-09-03-sha256-message-schedule.md` - portable
  schedule rework: five variants, two rejected (one of them faster on 64 KiB
  but slower on a single block), net -6.2% to -21.6% per size.

## Next concrete optimization task

**Implement the x86_64 SHA-NI backend.** Ordered steps, each with its own
commit, tests and benchmark run:

1. Baseline is recorded (this status file plus the results directory).
2. Add `fastcrypto-x86::sha256` implementing the compression with
   `sha256msg1`/`sha256msg2`/`sha256rnds2` (plus `pshufd`/`palignr` for the
   schedule), gated on `Features::cached().sha_ni()`, every `unsafe` block
   carrying a SAFETY comment and the target-feature invariant.
3. Wire it into `fastcrypto` dispatch so `Backend::for_sha256()` reports
   `X86ShaNi` when it is selected, keeping the portable path as the fallback.
4. Verify: every length in 0..300 and random inputs must produce identical
   digests from both paths; add that as a differential test, not just a check.
5. Benchmark the full ladder. Keep only if every size improves; otherwise
   revert and record why.
6. Then the AArch64 ARMv8 SHA-2 backend behind the existing probe.

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

