# HMAC key-state reuse in HKDF (2026-09-03)

Fourth optimization of the day. Same machine, toolchain and session as the
SHA-NI results file.

## What changed

1. HkdfSha256::expand_into now prepares the HMAC key state (ipad/opad) once for
   the whole expand chain and calls HmacSha256::reset() between blocks, instead
   of constructing a new HMAC per block. reset() restores exactly the post-ipad
   state a fresh HMAC would have, so the output is unchanged: it is a dataflow
   change, not an algorithm change. Saves two compressions per block after the
   first.
2. New HkdfExpander (in fastcrypto-core, and dispatched in the public crate): it
   owns one prepared HMAC key state and can expand many labels from one
   pseudorandom key. This is the TLS 1.3 shape, where calling
   HkdfSha256::expand_into once per label was re-preparing the key every time.

## Measurements

| benchmark | before | after | change |
| --- | --- | --- | --- |
| expand to 88 B | 904.0 ns | 638.8 ns | -29% |
| extract + expand to 88 B | 1205.7 ns | 922.9 ns | -23% |
| extract (single HMAC) | 297.8 ns | 306.3 ns | within noise |
| four labels, per-label API | 1224.7 ns | 1200.0 ns | within noise |
| four labels, prepared-key API | - | **640.2 ns** | -47% vs the per-label API |

The last row is the one that matters for TLS: one PRK, several labels, which is
what a TLS 1.3 key schedule does. Against the same-session reference number for
that group (RustCrypto hkdf 482.8 ns), the prepared-key API moved us from about
2.5x slower to about 1.3x slower on the workload that looks like a real
handshake.

## Correctness

* fastcrypto-core unit tests: the expander must equal HkdfSha256::expand_into
  byte for byte across 4 label lengths x 6 output lengths, and labels must be
  independent of each other.
* crates/fastcrypto-bench/tests/expander_equivalence.rs: the expander matches
  RustCrypto hkdf label by label across 3 salt lengths x 3 IKM lengths x 4 label
  lengths x 5 output lengths (including the 255-block maximum), matches a fresh
  expansion per label, and is backend independent (portable vs SHA-NI).
* All other known-answer, differential and backend-equivalence tests unchanged.

## Analysis

HKDF-SHA256 extract + expand to 88 bytes went from 4346 ns at the start of the
day (all portable) to 922.9 ns: about 4.7x. The remaining gap to RustCrypto
(657.8 ns) is now per-HMAC overhead rather than compressions: every finalize
still builds and zeroizes a padding scratch, and hasher construction still costs
26 ns because of zeroization on drop.

## Next

Reduce the per-finalize and per-construction fixed costs, then move on to the
AArch64 SHA-2 backend and to AEAD. Both fixed costs are already measured and
documented in PROJECT_STATUS.md.

