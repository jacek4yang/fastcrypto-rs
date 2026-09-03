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

*No adapted implementation code has been imported yet.* Everything currently in
`crates/` was written against FIPS 180-4, RFC 2104 and RFC 5869 with published
test vectors, and against `core::arch` intrinsics documented by Intel.

The table below is the shape every future entry takes.

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
