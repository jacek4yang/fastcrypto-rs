# Security model

**This project is experimental research code. It is not audited and it is not
constant-time verified. Do not use it to protect anything.**

This document states what the code currently does, what it assumes, and what has
not been checked. It is the checklist for the review that would have to happen
before the words "constant time" could be used without qualification.

## Threat model

In scope:

* Remote timing observers who can measure the time our primitives take as a
  function of secret inputs (keys, PRKs, message authentication tags,
  transcript contents).
* Attackers who can observe cache access patterns indirectly through timing.
* Adversarially chosen inputs: wrong lengths, empty inputs, oversized outputs.

Out of scope (documented, not solved):

* Physical access, power/EM analysis, fault injection.
* Attackers who can run code on the same core (SMT timing channels are the
  practical version of this, and are *not* fully mitigated by any current
  primitive here).
* Compromise of the build toolchain or of a dependency.

## What the code does today

| Property | Status | Where |
| --- | --- | --- |
| No secret-dependent branches in SHA-256/HMAC/HKDF | by construction; no branch depends on secret data | ``crates/fastcrypto-core/`src/sha256.rs` |
| No secret-dependent memory addressing | by construction; all indices are compile-time or length-derived | same |
| No table lookups | none; the message schedule is computed arithmetically | same |
| Tag comparison in constant time | yes, full-length accumulate | ``crates/fastcrypto-core/`src/util.rs` (`ct_eq`) |
| Zeroization of secrets | yes on drop, via `zeroize` | `Sha256`, `HmacSha256`, `HkdfSha256` |
| Debug output does not leak state | yes; `Debug` prints lengths only | `Sha256::fmt` |
| Backends gated on CPU feature detection | yes | `fastcrypto-x86`, `fastcrypto-aarch64` |
| X25519 does no input-dependent work | **measured**, see below | `fastcrypto-x86/src/x25519.rs`, `fastcrypto-aarch64/src/x25519.rs` |

## X25519: what was measured, and what it does and does not show

X25519 is imported assembly, so the usual worry — that the compiler turns a
branchless source into a branch — does not apply: `global_asm!` emits exactly
what is written, and that was checked byte-for-byte against GNU `as` on both
architectures. What remained to check is the assembly itself and the Rust
wrapper around it.

### The measurement

`scripts/constant-time-x25519.sh` runs one operation per process under Valgrind
and compares counts. Valgrind is deterministic, so "the same count for every
input" is a repeatable claim rather than a timing impression on a noisy machine.

Reviewed on an i5-1240P, for **every compiled variant**, not only the dispatched
one — the others ship and would run on other hardware:

| variant | measurement | result |
| --- | --- | --- |
| dispatch, baseline, adx | instructions, 24 secret scalars, variable-base | one value each |
| dispatch, baseline, adx | instructions, 24 peer encodings, variable-base | one value each |
| dispatch, baseline, adx | instructions, 24 secret scalars, fixed-base | one value each |
| dispatch, baseline, adx | data references, D1 and LL misses, 12 secret scalars, both operations | one value each |

The 24 peer encodings are not decoration: they include the canonical low-order
points, the non-canonical field encodings of them, and all-ones — the inputs an
attacker actually gets to choose.

### What that supports

* **No input-dependent control flow.** Executed-instruction counts do not move
  with the secret scalar or with the peer encoding. A secret-dependent branch or
  a variable loop bound would show here.
* **No input-dependent data-access volume**, and, for the fixed-base routine,
  **no input-dependent cache footprint**. That last one matters most: the
  fixed-base path reads a 48,576-byte precomputed table, and a table *indexed*
  by scalar digits would touch different cache lines for different secrets and
  move the D1 miss count. It does not, which is consistent with upstream's
  documented constant-time table scan.

### What it does not support, and must not be read as

* **Identical counts are not identical addresses.** A pattern that touches the
  same number of lines at secret-dependent addresses would pass this. Ruling
  that out needs taint analysis (ctgrind-style), which has not been run.
* **Nothing here measures a real CPU.** Valgrind models a cache; it says nothing
  about prefetchers, store-forwarding, port contention, or SMT.
* **Absolute counts are not portable between runs.** They shift by a few with
  the process environment, because that moves the initial stack and therefore
  cache-set alignment. Only within-run comparison means anything, and the script
  only compares within a run.
* **This is not a proof and not an audit.** It is evidence that a specific class
  of defect is absent on one machine, for one build.

One earlier run — before the script labelled each measurement with its input —
reported two distinct D1-miss counts for the baseline variable-base routine,
differing by 145 with identical data references and identical LL misses. It did
not reproduce: 24 inputs across two passes, plus eight repeats of a single
input, all gave one value. Recorded because a non-reproducing observation is
still an observation, and because the labelled script exists so that a
recurrence names the inputs that disagreed instead of only the numbers.

That first version of the script also *could not fail*: it joined every run's
measurement into one line, so `sort -u` always saw a single value. It reported
PASS on data it had not actually compared. Fixed, and worth stating plainly,
because a check that cannot fail is worse than no check.

### The Rust wrapper

* The RFC 7748 §6.1 rejection accumulates all 32 bytes rather than returning at
  the first non-zero one (`fastcrypto::x25519::is_zero`), so it does not leak
  where a shared secret first differs from zero.
* Dispatch branches on cached CPU features, never on key material.
* The scalar is **not** clamped by the wrapper, because the assembly clamps
  internally — proved by a test rather than assumed, so no duplicate work and no
  second copy of the secret.
* All three secret types zeroize on drop and no `Debug` implementation prints
  key bytes.

## What has NOT been verified

These are the open items, and they are the reason the project does not claim
constant-time behaviour:

1. **Generated machine code has not been inspected.** The Rust source avoids
   secret-dependent branches, but the compiler is free to introduce them (for
   example by turning a select into a branch, or vectorising a loop with a
   data-dependent trip count). Verification requires reading the assembly for
   every backend at every optimisation level, and ideally a tool such as
   `dudect`/ctgrind or a formal check.
2. **No leakage measurement.** No statistical timing test has been run against
   any primitive.
3. **Zeroization is best-effort.** `zeroize` uses volatile writes and an
   optimisation barrier, but a sufficiently clever optimiser, a copy the
   compiler made into a register or spill slot, or a swap to disk can leave
   copies behind. Secrets held by the caller are the caller's responsibility.
4. **HKDF/HMAC key reuse is not enforced.** `HmacSha256::reset` reuses the
   key state on purpose (that is the TLS pattern); callers must not reuse an
   HMAC key across security contexts where the construction forbids it.
5. **No SMT/core-local timing guarantees.** Nothing here partitions cores.
6. **Imported assembly has had the review above, and no more than that.** The
   X25519 routines are upstream s2n-bignum, unmodified, and their upstream
   HOL Light proofs cover upstream's build rather than ours. What this
   repository has is the instruction- and access-count evidence above, RFC 7748
   vectors, and differential agreement with two independent implementations.
   Ed25519, AEAD and anything else added later needs its own.

## Compiler and CPU assumptions

* Compiled with a current stable rustc (see `rust-toolchain.toml`), release
  profile, no `-C target-cpu=native` requirement for correctness. Accelerated
  paths are selected at runtime, so a portable build stays correct on every CPU
  and fast on capable ones.
* `u32` rotates and wrapping addition compile to the single instructions
  (`rorl`, `addl`) on x86_64 and AArch64; if a backend ever relies on
  that, it is asserted by benchmark, not assumed silently.
* Timing behaviour of `u32::rotate_right`, `wrapping_add`, and bitwise
  operations is assumed to be data-independent on the target CPUs (true on
  x86_64 and AArch64 for the instructions LLVM emits). This is an assumption
  about hardware, stated here rather than hidden.
* CPU feature detection assumes CPUID/XGETBV behave architecturally (x86_64)
  and that the OS probe (`getauxval` and friends) is truthful (AArch64).

## Unsafe code policy

* `fastcrypto-core` forbids `unsafe` with a crate-level lint.
* Backend crates may use `unsafe`, and every block must carry a SAFETY
  comment that names the invariant. Current example:
  ``crates/fastcrypto-x86/`src/detect.rs` guards `_xgetbv` behind the OSXSAVE
  bit, because executing XGETBV without XSAVE enabled faults.
* `#![deny(unsafe_op_in_unsafe_fn)]` applies workspace-wide.
* No `unsafe` is introduced for readability, convenience, or "looking
  optimized". If it cannot be justified by a measurement or by an instruction
  that has no safe abstraction, it does not go in.

## Error handling and robustness

* Lengths are validated at the API boundary; impossible-by-construction cases
  use `expect` with a comment rather than unreachable error paths.
* Oversized HKDF output is rejected rather than truncated (`Error::OutputTooLong`).
* Panics are avoided in library code; `Debug` never prints secret state.

## Reporting

Security issues: see ``SECURITY.md``. For this repository the honest answer
today is "assume every bug is exploitable until measured", and the fastest way
to help is a failing differential or known-answer test.

