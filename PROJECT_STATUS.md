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

* SHA-256 one-shot at 64 KiB: **225.9 us** for us vs **35.9 us** for the
  SHA-NI-backed implementations (6.3x). At 0 B: 282 ns vs 58-79 ns.
* Portable-vs-portable (RustCrypto forced to its soft backend): ours is
  **1.5x slower** at 64 KiB - about 12.3 vs 8.1 cycles/byte on the estimated
  3.69 GHz clock.
* HKDF-SHA256 extract+expand to 88 bytes: 4346 ns vs 650 ns (RustCrypto) and
  796 ns (ring).
* AEAD and X25519 groups contain **reference numbers only**; those primitives
  are not implemented yet. ChaCha20-Poly1305 seal of an empty record: 222 ns
  (ring) / 226 ns (aws-lc-rs). X25519 fixed-key: 18.7 us (aws-lc-rs) vs
  42.0 us (x25519-dalek).

No claim of being faster than any competitor is made anywhere. The current
implementation is slower at every size.

## Current bottlenecks, in priority order

0. **Evidence from instruction counts.** Callgrind says one SHA-256 of 8192
   bytes costs 594k instructions for us, 341k for ring. That is only 1.7x
   more instructions for 6x more time, so the portable loop is not just
   doing more work - it is doing the work badly (dependency chains and
   spilling). Instruction count and cycles-per-instruction both need to
   come down.

1. **Message schedule materialization (portable, ~1.5x).** `compress` builds a
   `[u32; 64]` schedule on the stack before running 64 rounds. At 64 KiB the
   cost is about 12.3 cycles/byte against about 8.1 for RustCrypto's soft
   backend on the same compiler with no SIMD. The hypothesis is register
   pressure and store-to-load forwarding on the schedule array; the fix is a
   16-word circular schedule with the round body restructured so the eight
   working variables stay in registers. Needs a profile to confirm before any
   code changes.
2. **No hardware-accelerated path (~6x).** Every competitor here uses SHA-NI.
   The CPU reports `sha=true`, the cached CPUID probe is in place, and the
   dispatch seam (`fastcrypto::backend::Backend`) already exists, so this is
   implementation work, not design work.
3. **Fixed per-call cost (282 ns for a 0-byte digest).** One compression of a
   64-byte block dominates. It shrinks with bottlenecks 1 and 2, and by
   trimming the padding path (a 128-byte scratch buffer plus volatile
   zeroization per call).
4. **Zeroization cost on construction (19.8 ns vs 2.4 ns).** `Sha256` zeroizes
   on drop (9 words + 64-byte block, volatile writes). Deliberate trade-off;
   revisit once the hash itself is fast enough for this to matter.

## Next concrete optimization task

**Profile and restructure the portable SHA-256 compression function.** Ordered
steps, each with its own commit, tests, and benchmark run:

1. Record the current state as the baseline (already in
   ``benchmarks/results/``).
2. Profile: `cargo bench -p fastcrypto-bench --bench micro` for instruction
   counts (Valgrind/Callgrind, deterministic), and
   `perf record/report` if available, to confirm that the schedule array -
   not the round arithmetic - is the cost.
3. Rewrite `compress` with a 16-word circular message schedule; keep the
   64-round loop but restructure the round body so the working variables stay
   live in registers.
4. Keep the always-inlined compression only if the measurement still supports
   it.
5. Re-run `cargo test --workspace` (KAT plus differential) and
   `cargo bench -p fastcrypto-bench --bench sha256`.
6. Keep the change only if every size improves and nothing regresses; otherwise
   revert and record why.

After that: the x86_64 SHA-NI backend behind the existing CPUID gate, verified
against the portable path for every length in 0..300 and for random inputs.

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

