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
6. **Assembly, when it is added, will need its own review.** Intrinsics keep us
   inside LLVM's code generator today; handwritten assembly removes that
   guarantee.

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

