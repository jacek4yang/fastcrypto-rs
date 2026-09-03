# Narrowing the zeroization scope (2026-09-03)

Third optimization of the day. Same machine, same toolchain, same session as
[2026-09-03-sha256-sha-ni.md](2026-09-03-sha256-sha-ni.md).

## What changed

`Sha256::finalize_into` materialises the padded tail in a fixed 128-byte stack
scratch and then zeroizes it. It was zeroizing all 128 bytes; it now zeroizes
only the bytes it wrote (`blocks * 64`, at most 128, and 64 for every message
shorter than 56 bytes).

The zeroized region still covers every byte the function wrote, so the security
property is unchanged: no message byte survives the call. What changed is that
we no longer pay volatile stores for bytes that were never touched.

## Why it matters now

Volatile byte writes cost roughly 0.3 ns each, so zeroizing 128 bytes costs
about 40 ns per finalize. That was noise when a compression cost 800 ns; with
SHA-NI a compression costs about 40 ns, so it became one of the largest fixed
costs in the library - especially for HKDF, where every HMAC finalizes twice.

## Measurements

SHA-256, one-shot:

| size | before | after | change |
| --- | --- | --- | --- |
| 0 B | 97.5 ns | 70.5 ns | -27.7% |
| 64 B | 134.9 ns | 107.6 ns | -20.2% |
| 1500 B | 911.8 ns | 879.8 ns | -3.5% |
| 64 KiB | 36.10 us | 35.91 us | -0.5% |

HKDF-SHA256:

| benchmark | before | after | change | best competitor in this run |
| --- | --- | --- | --- | --- |
| extract | 353.8 ns | 297.8 ns | -15.8% | aws-lc-rs 55.9 ns |
| expand to 88 B | 1017.1 ns | 904.0 ns | -11.1% | rustcrypto-hkdf 392.8 ns |
| extract + expand to 88 B | 1369.5 ns | 1205.7 ns | -12.0% | rustcrypto-hkdf 656.6 ns |
| four labels of 32 B | 1375.2 ns | 1190.2 ns | -13.4% | rustcrypto-hkdf 483.6 ns |

Hasher construction is unchanged at 26.3 ns (it is dominated by zeroization on
drop, which this change deliberately did not touch).

## Correctness

All known-answer vectors, differential tests and backend-equivalence tests pass
unchanged. The change only narrows *how much* is zeroized, never *whether* the
written bytes are zeroized.

## Analysis

At 0 B our SHA-256 is now 70.5 ns against ring 79.2 ns and aws-lc-rs 61.6 ns
(from the run one step earlier in this session): ahead of ring, behind
aws-lc-rs, on a machine and a run that cannot resolve differences this small.
The honest statement is that the fixed-cost gap at small sizes narrowed from
about 58% behind the best competitor to about 14%, and that confirming it needs
a dedicated machine.

HKDF is still about 1.8x slower than RustCrypto hkdf. The remaining causes are
structural, not incidental:

1. Every HMAC in the expand chain compresses its ipad and opad key blocks from
   scratch (two compressions per HMAC). A TLS key schedule expands several
   labels from one PRK, so that work should be prepared once per PRK.
2. Hasher construction still costs 26.3 ns because of zeroization on drop.

## Next

Prepare the HMAC key state once per PRK and reuse it across the expand chain.
That is the single largest remaining item for the TLS key schedule.

