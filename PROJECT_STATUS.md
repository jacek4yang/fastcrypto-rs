# Readiness matrix

*Last updated 2026-09-03, against rust-reality `0436370`.*

This file is the per-primitive technical matrix. Research narrative, decisions
and rejected hypotheses belong in this repository's GitHub issues, not here —
one authority per kind of state.

## Status vocabulary

| status | meaning |
| --- | --- |
| `RESEARCH_ONLY` | exists, not a candidate for anything |
| `API_STABLE_FOR_INTEGRATION` | the shape it would have inside rust-reality is settled |
| `CORRECTNESS_PROVEN` | published KATs **and** differential against an independent implementation |
| `FUZZED` | a cargo-fuzz target exists and has run clean |
| `SIDE_CHANNEL_REVIEW_REQUIRED` | no secret-dependent-control-flow review has been done |
| `PERFORMANCE_CHARACTERIZED` | measured at rust-reality's shapes, on a real measurement host, against the incumbent |
| `INTEGRATION_CANDIDATE` | beats or materially simplifies the incumbent with no regression |
| `PRODUCTION_READY_FOR_RUST_REALITY` | integrated, gated, and accepted by whole-product A/B |
| `DELEGATED` | rust-reality keeps a mature provider; researched and deliberately not replaced |
| `REJECTED` | measured and refused, with the reason recorded |

Nothing is `PRODUCTION_READY_FOR_RUST_REALITY`, and nothing is an
`INTEGRATION_CANDIDATE` yet: X25519 is the first primitive whose correctness
case is complete, and it becomes a candidate only when `k` is measured.

## What rust-reality actually performs

Audited from rust-reality source at `0436370`. Frequencies are per public
REALITY session unless stated. This is the requirement list; anything not on it
is out of scope.

| operation | site | per session | shape |
| --- | --- | ---: | --- |
| X25519 variable-base — REALITY auth | `protocol/reality/auth.rs` | 1 | configured static key, imported once per config generation |
| X25519 basepoint + variable-base — TLS ECDHE | `tls13/handshake.rs` | 1 + 1 | ephemeral, consumed once |
| Ed25519 sign — CertificateVerify | `tls13/messages.rs` | 1 | 130 B (SHA-256 suite) / 146 B; key held for process lifetime |
| HMAC-SHA512 — Xray certificate binding | `tls13/messages.rs` | 1 | 32 B key, 32 B message |
| AES-256-GCM open — REALITY session id | `protocol/reality/auth.rs` | 1 | 32 B ciphertext, fixed nonce |
| HKDF-SHA256 — REALITY auth key | `protocol/reality/auth.rs` | 1 | 20 B salt, 32 B IKM, `"REALITY"` info, 32 B out |
| SHA-256/384 transcript | `tls13/keys.rs`, `handshake.rs` | 1 | **6 updates + 4 clone snapshots**, ~944 B (X25519) or ~3.2 KiB (hybrid) |
| HKDF-Extract | `tls13/keys.rs` | **3** | hash-length salt and IKM |
| HKDF-Expand-Label | `tls13/keys.rs` | **16** | hash-length PRK, RFC 8446 label, hash-length output |
| HMAC — TLS Finished | `tls13/keys.rs` | **2** | hash-length key and input |
| AES-128-GCM seal/open | `tls13/record.rs` | per record | TLS record sizes |
| ML-KEM-768 encapsulation | `tls13/handshake.rs` | 1 (hybrid group only) | — |
| Ed25519 keygen, X25519 keygen/probe/handoff | various | not per session | cannot move the primary metric |

Two constraints that decide more than performance does:

- `tls13/{keys,record,messages}.rs` and `reality/client_hello.rs` are inside
  rust-reality's **enforced `no_std + alloc` protocol core**
  (ADR 0016, `tests/protocol_core_boundary.rs`). A `std`-only crate cannot go
  there without an explicit architecture decision — this is why `aws-lc-rs`
  holds X25519 but not Ed25519.
- The deployment envelope is **1–2 vCPU virtualized Linux on AMD Zen with
  SHA-NI, AES-NI, retpolines and no PTI**. A mechanism that only pays on a
  many-core Intel laptop is characterization, not a candidate.

## Per-primitive status

### SHA-256 — `RESEARCH_ONLY`

Portable implementation plus an x86_64 SHA-NI backend selected at runtime.

| property | state |
| --- | --- |
| correctness | FIPS 180-4 KATs + differential vs RustCrypto / ring / aws-lc-rs |
| fuzzing | `FUZZED` — differential target, runs clean |
| `no_std`, allocation-free | yes |
| zeroization | finalize zeroizes only what it wrote; buffer high-water mark tracked |
| side channel | `SIDE_CHANNEL_REVIEW_REQUIRED` (SHA-256 has no secret-dependent control flow by construction, but no review has been recorded) |
| performance | **not** `PERFORMANCE_CHARACTERIZED` — but the incumbent comparison **has** been run, and fastcrypto loses at every measured size (see below) |

**The portable round function was the problem, and it is fixed.** Measured on an
i3-8100 — no SHA-NI, so both sides run their portable paths and this compares
the round function itself. The deficit scaled with block count (~+1,150
instructions per 64-byte block), because `portable_compress_blocks` was 411
instructions executed 64 times against RustCrypto's 3,390-instruction
straight-line body: the loop never unrolled. Restructuring it into eight groups
of eight rounds with compile-time name rotation left:

| input | instructions vs RustCrypto | cycles vs RustCrypto |
| ---: | ---: | ---: |
| 0 B | +239 | +38 |
| 32 B | +361 | +97 |
| 517 B | +1,402 | **−187** |
| 1400 B | +3,340 | **−149** |

At handshake sizes the portable path is now slightly *faster in cycles* than
RustCrypto. The residual +38 to +97 cycles at 0–32 B is genuine fixed per-call
cost: backend dispatch through a function pointer, and a 128-byte zeroed
scratch in `finalize_into`.

**And that is where SHA-256 work stops.** rust-reality performs roughly ten
finalisations per session, so the residual is about 0.03% of session CPU.
Trading the audited zeroization high-water mark for something invisible is not
an improvement. The digest family's remaining value is correctness, `no_std`,
and suite-level dependency elimination — not cycles.

**Still unmeasured:** rust-reality's *shapes* — the incremental transcript with
clone snapshots, and 16 Expand-Label calls from one PRK — on a dedicated host,
and anything on SHA-NI hardware, where both implementations use hardware
compression and this change moves nothing.

### HMAC-SHA256 — `RESEARCH_ONLY`

RFC 4231 vectors. Same gaps as SHA-256: rust-reality performs HMAC twice per
session at hash-length sizes, where per-call construction cost dominates, and
that shape has not been measured on a dedicated host.

### HKDF-SHA256 — `RESEARCH_ONLY`

RFC 5869 vectors, plus a prepared-key expander that reuses HMAC key state
across labels — the right idea for TLS, where one PRK feeds 16 Expand-Label
calls per session.

A correctness defect was found and fixed here that no one-shot RFC vector could
have caught: the expander produced **wrong material from the second expansion
onwards**, because correctness depended on the caller resetting the HMAC state
first. Reusable crypto state must be correct by construction, and the tests now
cover repeated expansion, cloning, multiple TLS labels from one PRK, multi-block
output and boundary lengths rather than one-shot vectors alone.

The recorded ~29% deficit against RustCrypto `hkdf` predates the SHA-256 round
function fix that removed ~1,000 instructions per block, so it is stale rather
than refuted; it has not been re-measured on a dedicated host.

### SHA-384 / SHA-512, HMAC over them, HKDF-SHA384 — implemented

rust-reality needs SHA-384 (alternate-suite transcript and key schedule),
HMAC-SHA512 (certificate binding) and HKDF-SHA384. All now exist, verified
against FIPS 180-4, RFC 4231 and RFC 5869 vectors.

HMAC-SHA384 is **not** truncated HMAC-SHA512: the outer hash absorbs the
48-byte inner tag, not 64 bytes truncated afterwards. That distinction is the
one a from-scratch implementation gets wrong, and it has its own test.

SHA-NI does not accelerate the SHA-512 family, so these are portable-only and
will stay that way until measurement says otherwise.

### X25519 — `PERFORMANCE_CHARACTERIZED`, `INTEGRATION_CANDIDATE`, x86_64 Linux only

**The earlier "delegate it" conclusion was wrong, and the reason is worth
keeping.** It assumed the choice was *reimplement the arithmetic or keep
`aws-lc-rs`*. It is not: `aws-lc-rs` computes X25519 with s2n-bignum's
assembly, under a licence (`Apache-2.0 OR ISC OR MIT-0`) that permits taking
those routines directly. The question was never "can we beat s2n-bignum" but
"must we carry 2.6 MB of C libcrypto to run 164 KB of it".

Imported: four routines, byte-for-byte, integrated with `global_asm!` — no
build script, no C toolchain, no CMake, no bindgen. Provenance, the pinned
revision, the exact transformation and the narrow verification claim are in
[`docs/PROVENANCE.md`](docs/PROVENANCE.md).

| property | state |
| --- | --- |
| correctness | RFC 7748 §5.2 and §6.1 including the 1,000-iteration vector; differential against **both** `aws-lc-rs` and `x25519-dalek` over randomised secrets, randomised peer encodings, the ignored high bit and the canonical low-order points |
| fuzzing | `FUZZED` — differential target against `x25519-dalek` |
| `no_std`, allocation-free | yes; entropy is the caller's, so the primitive takes 32 bytes rather than an RNG |
| zeroization | all three secret types zeroize on drop; no secret bytes in any `Debug` |
| side channel | `SIDE_CHANNEL_REVIEW_REQUIRED` — the arithmetic is upstream's and unmodified, but no timing experiment has been recorded here |
| generated code | the machine code `global_asm!` emits is byte-identical to GNU `as` output for all four routines |
| performance | **k = 0.99–1.00** at both production shapes, on a quiet pinned P-core, measured twice (see below) |
| portability | x86_64 **Linux** only — the imported assembly emits ELF directives. AArch64 is the next port; s2n-bignum ships the ARM routines under the same licence |

**Measured against the incumbent**, i5-1240P P-core pinned with `taskset`,
machine verified quiet, Criterion 60 samples, two runs ten minutes apart:

| shape, per session | `aws-lc-rs` | fastcrypto | k |
| --- | ---: | ---: | ---: |
| static agreement (REALITY auth) | 17.34 µs | 17.30 µs | **0.994 / 1.000** |
| ephemeral session (keygen + share + agree) | 24.45 µs | 24.33 µs | **0.993 / 0.995** |

Parity on the first, about −0.5% on the second. Per session that is
41.79 µs → 41.63 µs, and X25519 is 14.6% of session CPU, so **−0.06% of server
CPU** — below any whole-product measurement floor.

The verdict is therefore **`ACCEPTED_ARCHITECTURAL_CONSOLIDATION_PERFORMANCE_NEUTRAL`**,
not a performance win, and the reason `k` is where it is is not cleverness:
both sides run the same upstream arithmetic. The value is that ~2.6 MB of
vendored C libcrypto and its CMake build become ~164 KB of `.text` + `.rodata`
with no build script and no C toolchain.

**Remaining blockers before `aws-lc-rs` can be removed from rust-reality:** the
AArch64 port, a whole-product A/B on uninstrumented schedstat CPU/session, and
a recorded side-channel review.

### AEAD (AES-GCM, ChaCha20-Poly1305) — `DELEGATED` (provisionally)

Not implemented; benchmark harness only. `ring` beat `aws-lc-rs` at every
measured production record size and is `no_std`-clean, so it sits inside the
protocol core legitimately. Vision Direct also keeps steady-state payload off
the record path, which caps what AEAD work can be worth end to end.

### Ed25519 — `DELEGATED`

Not implemented. rust-reality measured `aws-lc-rs` at ~1.9–2.0x over
`ed25519-dalek` and **still rejected it**: the whole-session ceiling is ~2.0%
and the faster provider is `std`-only, so it cannot enter the enforced protocol
core. `ring` — the only `no_std`-clean alternative — is 23–40% *slower* than
dalek. A native implementation would have to beat dalek while being
`no_std`-clean and constant-time, for a ceiling of ~2%.

### ML-KEM / PQ — `DELEGATED`, out of scope

High implementation risk, no measured headroom. Mature implementation stays.

## Cross-cutting gaps

| gap | consequence |
| --- | --- |
| X25519 `k` unmeasured | the one number that decides the highest-value migration |
| X25519 is x86_64 only | `aws-lc-rs` cannot be removed from rust-reality until AArch64 is ported, because that would silently regress an ARM release |
| never measured at rust-reality's *shapes* | the incremental transcript (6 updates, 4 clone snapshots) and the 16-labels-from-one-PRK schedule are the operations that decide digest integration |
| no whole-product A/B | no primitive can be accepted without one |
| no side-channel review recorded | required before anything ships; for X25519 the arithmetic is upstream's and unmodified, which is an argument, not evidence |
| shared-container measurements | the numbers under `benchmarks/results/` are directional only |

## Quality gates

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

Also verified: `cargo check --target aarch64-unknown-linux-gnu`, and
`fastcrypto-core` builds `no_std`.
