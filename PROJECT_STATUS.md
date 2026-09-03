# Readiness matrix

*Last updated 2026-09-03, against rust-reality `0a1dacb`.*

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

Nothing is `PRODUCTION_READY_FOR_RUST_REALITY`. Nothing is an
`INTEGRATION_CANDIDATE`.

## What rust-reality actually performs

Audited from rust-reality source at `0a1dacb`. Frequencies are per public
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

**Measured against the incumbent, SHA-NI on both sides** (AMD EPYC 9K65, shared
container, so directional):

| input | fastcrypto | RustCrypto `sha2` | fastcrypto is |
| ---: | ---: | ---: | --- |
| 0 B | 97.5 ns | 58.6 ns | **+66%** |
| 32 B | 104.4 ns | 57.2 ns | **+83%** |
| 512 B | 378.8 ns | 326.1 ns | +16% |
| 1400 B | 871.8 ns | 830.8 ns | +4.9% |
| 64 KiB | 36,097 ns | 35,949 ns | +0.4% |

Parity arrives only at sizes rust-reality never hashes. **Its inputs are the
small ones** — a 517 B ClientHello, a ~944 B transcript absorbed in six chunks
of 6–517 B, and 32 B HMAC inputs — which is exactly where fastcrypto is 66–83%
behind. The gap is fixed per-call overhead, not compression throughput.

**Blocker:** the deficit is at small inputs. Closing it is a specific,
tractable problem (initialisation and finalisation cost, not the round
function), but until it closes, SHA-256 is not an integration candidate. What
has still never been measured is rust-reality's *shapes* — the incremental
transcript with clone snapshots, and 16 Expand-Label calls from one PRK — on a
dedicated host.

### HMAC-SHA256 — `RESEARCH_ONLY`

RFC 4231 vectors. Same gaps as SHA-256, plus: rust-reality performs HMAC 2× per
session at hash-length sizes, where per-call construction cost dominates, and
`HMAC-SHA512` (which rust-reality also needs, once per session) does not exist
here.

### HKDF-SHA256 — `RESEARCH_ONLY`, currently losing

RFC 5869 vectors, plus a prepared-key expander that reuses HMAC key state
across labels — the right idea for TLS, where one PRK feeds 16 Expand-Label
calls per session.

**This repository's own measurement puts it ~29% slower than RustCrypto `hkdf`
on the TLS-shaped workload.** That is the incumbent. Until that inverts on a
real measurement host, HKDF is not a candidate.

### SHA-384 / SHA-512 — not implemented

rust-reality needs SHA-384 (alternate suite transcript and key schedule) and
HMAC-SHA512 (certificate binding, once per session). Neither exists here. Note
that SHA-NI does **not** accelerate the SHA-512 family, so this is a different
optimisation problem from SHA-256 and the SHA-NI backend does not help it.

### X25519 — `DELEGATED` (provisionally)

Not implemented; benchmark harness only. The bar is `aws-lc-rs`, which is worth
a measured **−12.3% of server CPU per session** in production. A native
implementation must beat s2n-bignum's assembly on Zen while remaining
constant-time. That is a large, high-risk undertaking with a strong incumbent.

Delegating X25519 through the unified API is the expected outcome unless
evidence says otherwise.

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
| no measurement on a dedicated host | every recorded number is directional only |
| never measured at rust-reality's *shapes* | the incremental transcript (6 updates, 4 clone snapshots) and the 16-labels-from-one-PRK schedule are the operations that decide integration |
| small-input deficit unclosed | rust-reality's inputs are 32–1400 B, where fastcrypto trails the incumbent by 5–83% |
| no whole-product A/B | no primitive can be accepted without one |
| no side-channel review recorded | required before anything ships |
| SHA-384/512 absent | rust-reality needs both per session |

## Quality gates

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

Also verified: `cargo check --target aarch64-unknown-linux-gnu`, and
`fastcrypto-core` builds `no_std`.
