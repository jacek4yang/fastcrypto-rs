# Narrowing the finalize zeroization further (2026-09-03)

Fifth optimization of the day, on the same machine and toolchain as the SHA-NI
results file.

## What changed

Sha256::finalize_into was zeroizing the whole padded region it built
(blocks * 64 bytes, so 64 for any message shorter than 56 bytes). Only two parts
of that region ever hold data this function did not create:

* the message tail plus the 0x80 delimiter, [0, block_len + 1);
* the eight length bytes at the end of the block.

Everything in between is a zero written by the function itself, so it needs no
volatile zeroization. It now zeroizes exactly those two ranges: 9 stores for an
empty message instead of 64, and 73 instead of 128 for a two-block tail.

## Measurements

| benchmark | before | after | change |
| --- | --- | --- | --- |
| SHA-256, 0 B | 70.5 ns | 67.4 ns | -4.4% |
| SHA-256, 64 B | 107.6 ns | 103.6 ns | -3.7% |
| SHA-256, 1500 B | 879.8 ns | 878.6 ns | noise |
| SHA-256, 64 KiB | 35.91 us | 35.96 us | noise |
| HKDF extract | 306.3 ns | 287.0 ns | -6.3% |
| HKDF expand to 88 B | 638.8 ns | 603.5 ns | -5.5% |
| HKDF extract + expand to 88 B | 922.9 ns | 880.5 ns | -4.6% |
| HKDF four labels, per-label API | 1200.0 ns | 1172.6 ns | -2.3% |
| HKDF four labels, prepared key | 640.2 ns | 627.3 ns | -2.0% |

Same-session references for the HKDF groups: RustCrypto hkdf 656.8 ns for
extract + expand, 486.5 ns for the four-label group; ring 788.4 ns; aws-lc-rs
801.2 ns.

Hasher construction is unchanged at 26.5 ns.

## Correctness

Unchanged in property, narrowed in scope: every byte that held caller data is
still zeroized with volatile stores. All known-answer, differential,
backend-equivalence and expander-equivalence tests pass.

## Analysis

The 0 B digest is now 67.4 ns against aws-lc-rs 61.6 ns and ring 79.2 ns from
the runs earlier in this session: about 9% behind the best competitor and ahead
of ring, on numbers a shared container cannot resolve. The dominant remaining
fixed cost is construction at 26.5 ns, all of it zeroization on drop of the
chaining state and the 64-byte block buffer.

That is a deliberate security property (mid-stream chaining state can be
secret-derived, and the block buffer keeps the most recent message bytes), so
the next step is not to delete it but to decide, with numbers, whether to make
zeroization explicit at the API level for callers that hash public data.

