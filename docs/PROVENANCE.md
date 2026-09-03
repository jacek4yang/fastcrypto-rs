# Provenance and licensing of adapted implementations

fastcrypto-rs is allowed to study, port and adapt mature cryptographic
implementations rather than deriving everything from specifications alone.
Optimised field arithmetic and hand-tuned assembly represent years of work that
would be irresponsible to reinvent from memory, and the accepted output of this
repository is destined for rust-reality's production tree.

That permission carries an obligation: **every line of adapted implementation
code must be traceable to a licensed source before it is written down here.**

This document is the register. It is also the rule.

## The rule

Before copying or adapting *any* implementation code:

1. Identify the upstream project and its canonical repository URL.
2. Identify the exact commit or tag — not "main", not "latest".
3. Identify the exact source path(s).
4. Identify the license and confirm it is compatible with Apache-2.0 and with
   rust-reality's `cargo deny` policy.
5. Preserve every required copyright and license notice.
6. Add a row to the register below **in the same change** that introduces the
   code.

If a useful implementation is unsuitably licensed, or its provenance cannot be
established with confidence, the answer is not to copy it carefully. The answer
is to return to the RFC, specification or paper and implement the mechanism
independently.

**Never import code with unknown licensing.** A permissive-looking file in a
repository with no LICENSE, a vendored copy with stripped headers, or a snippet
from a blog post or an answer site is not a usable source.

## Compatible licenses

Acceptable, in rough order of preference:

- public domain dedications (CC0, Unlicense) and 0BSD
- MIT, ISC, BSD-2-Clause, BSD-3-Clause
- Apache-2.0 (this repository's own license)
- MIT OR Apache-2.0 dual licensing

Not acceptable for imported implementation code:

- GPL, LGPL, AGPL and other copyleft licenses — incompatible with
  rust-reality's distribution model
- OpenSSL's pre-3.0 license
- anything requiring advertising clauses
- anything with no license statement at all

Specifications, RFCs, papers and published test vectors are **not** code and may
be used freely as the basis for an independent implementation. Copying a
*reference implementation* printed in a specification is still copying code, and
still needs a license check.

## What "adapted" obliges us to record

For each entry the register states what was taken and what was changed, because
those are different questions with different consequences.

Rewriting a routine's structure while preserving its arithmetic does not make it
original work. Translating C to Rust does not make it original work. Both remain
derived and both keep their attribution.

**Formal verification does not survive modification.** Several high-quality
implementations — HACL\*, fiat-crypto, s2n-bignum — are machine-generated or
machine-checked. If code from such a source is edited, reformatted, specialised
or re-scheduled, the upstream proof no longer covers the result and this
repository **must not claim that it does**. Either keep the generated artefact
byte-for-byte and say so, or state plainly that the proof applies to the
original and not to our variant.

The same discipline applies to the phrase "constant time". Inheriting it from an
upstream description is not evidence about our build, our compiler, or our
target.

## Migration into rust-reality

When an implementation is accepted and moves into rust-reality, its provenance
moves with it. The register entry, the upstream notice, and any retained
copyright header travel to rust-reality's own third-party notice surface in the
same change that carries the code. Production security documentation must not be
reachable only through an archived staging repository.

## Register

The SHA, HMAC and HKDF implementations in `crates/fastcrypto-core/` are not
adapted from anything: they were written against FIPS 180-4, RFC 2104, RFC 5869
and RFC 8446 with published test vectors, and against `core::arch` intrinsics
documented by Intel. They have no entry here because they need none.

Every entry below takes this shape:

| field | content |
| --- | --- |
| primitive | which algorithm and which part of it |
| upstream project | name |
| upstream URL | canonical repository |
| commit / tag | exact revision |
| source paths | exact files |
| license | SPDX identifier |
| notices | copyright lines that must be preserved, and where they now live |
| copied | what was taken essentially unchanged |
| rewritten | what was reimplemented rather than taken |
| structural changes | API, state layout, specialisation to rust-reality shapes |
| verification status | whether any upstream proof or audit still applies, and why |

<!-- Add entries below. Keep them in the order the code was imported. -->

### 1. X25519 scalar multiplication, x86_64

| field | content |
| --- | --- |
| primitive | X25519 variable-base and fixed-base scalar multiplication, x86_64 only |
| upstream project | s2n-bignum |
| upstream URL | <https://github.com/awslabs/s2n-bignum> |
| commit / tag | `7948ca132c8cdd22fbd7372bd14a4f4ae0a2da7c` (2026-09-03; no release tags exist) |
| source paths | `x86_att/curve25519/curve25519_x25519{,_alt,base,base_alt}.S`, `include/_internal_s2n_bignum_x86_att.h`, `LICENSE` |
| license | `Apache-2.0 OR ISC OR MIT-0` — declared in the `LICENSE` file and repeated as an SPDX header in every imported `.S` |
| notices | `Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.` retained verbatim at the head of each vendored file; the full upstream `LICENSE` is vendored beside them at `crates/fastcrypto-x86/src/x25519/upstream/LICENSE` |
| copied | all four routines, byte-for-byte, as `crates/fastcrypto-x86/src/x25519/upstream/*.S` |
| rewritten | nothing — no arithmetic, scheduling, register allocation or memory layout was touched |
| structural changes | the committed `.s` files are the C-preprocessor expansion of those `.S` files with exported symbols namespaced (below); a Rust wrapper adds dispatch and the RFC 7748 §6.1 zero check that upstream deliberately omits |
| verification status | **the upstream HOL Light proofs do not travel with this import.** See below. |

**Why this import exists.** rust-reality already runs this exact upstream
project's X25519, reached through `aws-lc-rs` → `aws-lc-sys` → a vendored
~2.6 MB C libcrypto with a CMake/C build. Importing the four routines directly
keeps the arithmetic and drops the build system: `global_asm!`, no build script,
no C toolchain, and about 164 KB of `.text` plus `.rodata` instead of 2.6 MB.

**Exact transformation.** For each of the four units:

```sh
cpp -P -I upstream -U__APPLE__ -U__CET__ -D__ELF__ -D__linux__ \
    -DS2N_BN_HIDE_SYMBOLS upstream/<unit>.S \
  | sed -E 's/\bcurve25519_/fastcrypto_curve25519_/g' > <unit>.s
```

That is macro expansion plus a symbol prefix, and nothing else. The prefix is
applied at word boundaries so upstream's local labels keep their names and stay
recognisable in a profile; it exists because a binary may legitimately contain
both this import and AWS-LC's copy during A/B measurement, and two definitions
of `curve25519_x25519` would collide at link time.

Every conditional in upstream's header is pinned on the command line so the
result cannot depend on how the host compiler was configured. `-U__CET__` is
the one that bites: a distribution defaulting to `-fcf-protection` defines it,
which pulls in glibc's `cet.h` and spells the same ENDBR64 as a mnemonic while
adding a `.note.gnu.property` section. Upstream's own explicit byte sequence
assembles to identical machine code, needs no glibc header, and is what is
committed. `-D__ELF__ -D__linux__` fix the output to the ELF form, which is why
the module is gated to Linux.

`fastcrypto_x86::x25519::tests::regenerating_the_assembly_reproduces_it`
re-runs that pipeline and compares, so the claim is checked rather than
asserted, and
`fastcrypto_x86::x25519::tests::vendored_upstream_matches_the_recorded_digests`
pins the vendored inputs by SHA-256.

**Relationship to what AWS-LC ships.** `aws-lc-sys` 0.45.0 vendors an *older*
import of the same files. They differ in three upstream commits, none of which
touches the arithmetic: `#428` (loop alignment for the Skylake JCC erratum),
`#242` and `#446` (moving the 48,576-byte precomputed table into `.rodata` and
fixing its Mach-O references). This import is therefore the same routines at a
newer revision, not a copy of AWS-LC's artefact, and the difference is recorded
here rather than glossed as "identical".

**Required CPU features and dispatch.** `curve25519_x25519` and
`curve25519_x25519base` use BMI2 and ADX. The `_alt` routines are baseline
x86_64. Both are compiled in and selected by a cached CPUID probe, mirroring
AWS-LC's own `use_s2n_bignum_alt()`, so a generic release binary cannot execute
an instruction the CPU lacks.

**ABI.** System V AMD64: `RDI` = result, `RSI` = scalar, `RDX` = point; no
return value; the routines preserve `RBX`, `RBP` and `R12`–`R15` themselves,
allocate their own frame (about 416 bytes for the variable-base routine), do not
use the red zone, and require that the result not alias either input. Inputs
and outputs are little-endian 32-byte encodings. Both routines clamp the scalar
internally per RFC 7748; neither performs the §6.1 zero check.

**Verification status, stated narrowly.** s2n-bignum's routines are accompanied
by machine-checked HOL Light proofs in the upstream repository. Those proofs
cover upstream's source; this repository has neither reproduced them nor
extended them to its own build, and **must not claim otherwise**. Nothing in
the arithmetic was modified, but "unmodified" is not the same as "proved", and
the assembler, linker and build configuration here are not upstream's.

What this repository has actually demonstrated, and will say instead:

- the machine code Rust's `global_asm!` emits is **byte-identical** to what GNU
  `as` produces from the same input, for all four routines' `.text` and both
  `.rodata` tables — so the integration introduces no codegen divergence. To
  reproduce, for each unit:

  ```sh
  as --64 -o gnu.o crates/fastcrypto-x86/src/x25519/<unit>.s
  printf '#![no_std]\ncore::arch::global_asm!(include_str!("%s"), options(att_syntax));\n' \
    "$PWD/crates/fastcrypto-x86/src/x25519/<unit>.s" > /tmp/unit.rs
  rustc --edition 2021 --crate-type lib --emit=obj -O -o llvm.o /tmp/unit.rs
  for section in .text .rodata; do
      objcopy -O binary --only-section=$section gnu.o a.bin
      objcopy -O binary --only-section=$section llvm.o b.bin
      cmp a.bin b.bin
  done
  ```

- RFC 7748 §5.2 and §6.1 vectors pass, including the 1,000-iteration one;
- results match **two independent implementations**, `aws-lc-rs` and
  `x25519-dalek`, over randomised secrets, randomised peer encodings, the
  ignored high bit, and the canonical low-order points;
- a differential fuzz target against `x25519-dalek` exists.

Constant-time behaviour is inherited from upstream's design, not measured here.
Until a timing experiment is recorded, the honest phrasing is "no
secret-dependent control flow was found by source review", not "constant-time
verified".

### 2. X25519 scalar multiplication, AArch64

| field | content |
| --- | --- |
| primitive | X25519 variable-base and fixed-base scalar multiplication, AArch64 only |
| upstream project | s2n-bignum |
| upstream URL | <https://github.com/awslabs/s2n-bignum> |
| commit / tag | `7948ca132c8cdd22fbd7372bd14a4f4ae0a2da7c` — the same revision as entry 1 |
| source paths | `arm/curve25519/curve25519_x25519_byte{,_alt}.S`, `arm/curve25519/curve25519_x25519base_byte{,_alt}.S`, `include/_internal_s2n_bignum_arm.h`, `LICENSE` |
| license | `Apache-2.0 OR ISC OR MIT-0`, declared in `LICENSE` and repeated as an SPDX header in every imported `.S` |
| notices | `Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.` retained verbatim, together with upstream's own attribution comment naming the two projects below; the full upstream `LICENSE` is vendored at `crates/fastcrypto-aarch64/src/x25519/upstream/LICENSE` |
| copied | all four routines, byte-for-byte, as `crates/fastcrypto-aarch64/src/x25519/upstream/*.S` |
| rewritten | nothing |
| structural changes | macro expansion and symbol namespacing, by the same pinned pipeline as entry 1; a Rust wrapper adds MIDR-based dispatch and the RFC 7748 §6.1 zero check |
| verification status | no upstream proof is claimed. See below. |

**The attribution chain is longer here, and collapsing it would be wrong.**
Upstream's own header states that this code is *substantially derived from*:

| project | URL | license |
| --- | --- | --- |
| Emil Lenngren's X25519-AArch64 | <https://github.com/Emill/X25519-AArch64> | **CC0-1.0** (public domain dedication) |
| the SLOTHY re-scheduling of it, by Abdulrahman, Becker, Kannwischer and Klein | <https://github.com/slothy-optimizer/slothy> | **MIT** (Arm Limited, Hanno Becker, Amin Abdulrahman, Matthias Kannwischer) |

Both were checked at import time and both are permissive and compatible. The
chain is recorded because "it is Apache-2.0 because Amazon says so" is not a
licence review — the question is whether *everything it descends from* permits
this use, and here it does.

**Why both variants ship.** Unlike x86_64, neither AArch64 variant needs an
optional instruction: both execute on every ARMv8 CPU, and the `_alt` routines
are simply tuned for cores with a wide multiplier. Dispatch mirrors AWS-LC's
`use_s2n_bignum_alt()` — read `MIDR_EL1` (guarded by `HWCAP_CPUID`, because the
`MRS` would fault where the kernel does not emulate ID-register reads) and take
`_alt` for Neoverse V1, V2 and V3. AWS-LC also prefers `_alt` on Apple silicon,
but reaches that conclusion through a macOS `sysctl`, not through MIDR on Linux;
this port does not add a rule it cannot test. A failed probe selects the
standard routines, which is always correct — the worst case is unclaimed
throughput, never an illegal instruction.

**ABI.** AAPCS64: `X0` = result, `X1` = scalar, `X2` = point, no return value,
callee-saved registers and stack frame managed by the routine, result must not
alias either input. Little-endian 32-byte encodings; the scalar is clamped
internally; the §6.1 zero check is the caller's.

**Verification status, stated narrowly.** As with entry 1, upstream's
machine-checked proofs cover upstream's build and are not claimed here. What is
demonstrated:

- the machine code `global_asm!` emits is **byte-identical** to
  `aarch64-linux-gnu-as` output, for all four routines' `.text` and both
  `.rodata` tables;
- RFC 7748 §5.2 and §6.1 vectors pass, including the 1,000-iteration one, **for
  both variants**, executed on real AArch64 instructions under user-mode QEMU
  rather than merely compiled;
- the committed assembly is the mechanical expansion of the vendored upstream,
  checked by a test;
- the vendored upstream is pinned by SHA-256, checked by a test.

Differential testing against `aws-lc-rs` and `x25519-dalek` runs on x86_64. On
AArch64 the same *implementation* is exercised against RFC 7748 vectors and
against the other variant, which is weaker, and that difference is deliberate:
cross-building the C incumbent for AArch64 to run it under emulation would
compare two emulated implementations rather than validate ours.

## Candidate upstreams and their licenses

Recorded now so the licensing question is answered before the engineering
question, not after. Verify the license at the exact revision at import time —
this table is a starting point, not a substitute for step 4.

| project | typical license | relevance |
| --- | --- | --- |
| fiat-crypto | MIT / Apache-2.0 / BSD-1-Clause | machine-generated, proven field arithmetic for Curve25519 |
| HACL\* / hacl-star | Apache-2.0 | verified C, source for several primitives |
| s2n-bignum | Apache-2.0 | optimised assembly used by AWS-LC for X25519 |
| curve25519-dalek | BSD-3-Clause | idiomatic Rust field arithmetic and strategies |
| ring | ISC-style, with BoringSSL portions | AEAD and digest assembly heritage |
| BoringSSL | Apache-2.0 / OpenSSL-derived portions | mixed; check per file |
| RustCrypto | MIT OR Apache-2.0 | portable backends, `no_std` structure |
| supercop / SUPERCOP | public domain (varies) | reference implementations |

BoringSSL in particular is **not uniformly licensed**; some files retain the
original OpenSSL/SSLeay terms. Check the individual file, not the repository.
