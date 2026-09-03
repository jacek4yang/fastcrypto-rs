# Optimization log: SHA-256 message schedule (2026-09-03)

Workflow: baseline -> profile -> change -> tests -> benchmark -> keep or revert.
Every number below comes from this repository's own harness on the same
machine, same session unless stated otherwise.

Environment: AMD EPYC 9K65, 8 visible cores, shared cloud container, rustc
1.98.0 / LLVM 22.1.8, baseline x86_64 target features, estimated 3690 MHz.
Wall clock: Criterion (warmup 500 ms, 1500 ms measurement, 60 samples).
Deterministic: Callgrind instruction counts via `cargo bench --bench micro`.

## Baseline (variant A)

Portable SHA-256 with the FIPS 180-4 recurrence materialised into a
`[u32; 64]` array, then a single 64-iteration round loop.

* 64 KiB: 225.9 us (290 MB/s, about 12.3 cycles/byte)
* 0 B: 282.4 ns - one 64-byte compression dominates
* Callgrind instructions for one 8192-byte hash: 594,063

## Hypothesis

The 64-word schedule (256 bytes) does not stay in registers; the round loop
pays store-to-load forwarding for every schedule word. A 16-word circular
schedule should keep the working set in registers. Evidence behind the
hypothesis: we were 1.5x slower than RustCrypto's soft backend on identical
hardware with no SIMD on either side.

## Variants measured

| variant | description | instructions (8192 B) | 0 B | 1500 B | 64 KiB | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| A | `[u32; 64]` schedule, one 64-round loop | 594,063 | 282.4 ns | 5239.3 ns | 225.9 us | baseline |
| B | 16-word ring, schedule update every round | 743,881 (+25%) | 300.7 ns (+6.5%, p<0.05) | 5.12 us (-2.3%) | 214.5 us (-5.1%, p=0.56) | reverted: small records regress |
| C | ring, update guarded by `if i < 48` | 796,754 (+7% vs B) | not measured | - | - | rejected on instruction count |
| D | four groups of 16 rounds, update guarded by `if j < 3` | 647,032 (+9% vs A) | 270.6 ns | 4.40 us | 181.8 us | **kept** |
| E | D with the last group split out (no per-round branch) | 647,032 (identical) | 242.3 ns | 4.54 us | 181.8 us | rejected: within noise of D (p>0.05) and duplicates the round body |

Notes:

* Variant B is the interesting negative result: it is faster on 64 KiB and
  slower on a single block, because it computes 16 schedule words that no
  round consumes. Small TLS records matter more than streaming here, so it was
  reverted even though the large-buffer number improved.
* Variant D wins even though it executes ~9% *more* instructions than A. The
  instructions it executes are cheaper (no stack traffic for the schedule),
  which is why instruction count alone was not used as the decision criterion.
* Variant E shows the `if j < 3` branch costs nothing measurable: LLVM
  already produced identical code, so the duplicated round body bought nothing.

## Kept change (variant D)

`crates/fastcrypto-core/src/sha256.rs`: the message schedule is a 16-entry
ring, and the round loop is structured as four groups of sixteen rounds so that
the schedule index is the inner counter. Within a group, after unrolling, every
schedule index is a constant and the eight working variables stay in registers.
Rounds 48..63 skip the schedule update, because no round consumes those words.

Semantics are unchanged: same recurrence, same constants, same padding. All
known-answer vectors and all differential tests still pass.

## Result

| size | before | after | change |
| --- | --- | --- | --- |
| 0 B | 282.4 ns | 254.6 ns | -9.8% |
| 16 B | 283.9 ns | 266.2 ns | -6.2% |
| 32 B | 289.7 ns | 261.6 ns | -9.7% |
| 64 B | 494.8 ns | 444.5 ns | -10.2% |
| 128 B | 714.5 ns | 608.0 ns | -14.9% |
| 256 B | 1163.7 ns | 984.1 ns | -15.4% |
| 512 B | 1999.0 ns | 1638.4 ns | -18.0% |
| 1 KiB | 3717.4 ns | 3220.7 ns | -13.4% |
| 1350 B | 4675.5 ns | 3944.5 ns | -15.6% |
| 1400 B | 5032.5 ns | 4155.6 ns | -17.4% |
| 1500 B | 5239.3 ns | 4301.1 ns | -17.9% |
| 4 KiB | 14.45 us | 11.33 us | -21.6% |
| 8 KiB | 27.34 us | 23.51 us | -14.0% |
| 16 KiB | 55.85 us | 47.90 us | -14.2% |
| 64 KiB | 225.9 us | 190.9 us | -15.5% |

Streaming (64 KiB in 1 KiB updates): 215.5 us -> 191.4 us (-11.2%).
Construction: 19.8 ns -> 19.5 ns (unchanged; still dominated by zeroization).

## Where that leaves the gaps

* Against the SHA-NI implementations (64 KiB, 36.0 us) we are still about 5.3x
  slower. Closing that needs the SHA-NI backend, not more portable work.
* Against RustCrypto's portable (soft) backend we were 1.52x slower before;
  that comparison needs re-running now that the schedule changed. It is the
  next measurement.
* Construction cost (19.5 ns vs 2.4 ns) is now a larger share of the small-
  message cost than before, because the hash itself got cheaper.


## Portable-vs-portable gap after the change

Re-measured with RustCrypto sha2 forced onto its soft backend (no SHA-NI on
either side). The gap narrowed from 1.52x to 1.27x at 64 KiB:

| size | fastcrypto | rustcrypto soft | ratio |
|---|---|---|---|
| 0 B | 264.3 ns | 203.6 ns | 1.30x |
| 64 B | 432.5 ns | 312.4 ns | 1.38x |
| 128 B | 619.4 ns | 610.5 ns | 1.01x |
| 256 B | 955.7 ns | 958.0 ns | 1.00x |
| 1 KiB | 3041.4 ns | 2635.4 ns | 1.15x |
| 1500 B | 4377.8 ns | 3708.5 ns | 1.18x |
| 4 KiB | 11.30 us | 9.04 us | 1.25x |
| 16 KiB | 46.50 us | 36.99 us | 1.26x |
| 64 KiB | 181.7 us | 143.0 us | 1.27x |

Cycles/byte at 64 KiB: 10.2 for us (was 12.3), 8.1 for RustCrypto soft.

Caveat: this run used RUSTFLAGS with the soft cfg, and cargo does not always
rebuild when only that flag changes - the sha2 crate was cleaned explicitly
before the run, and the other implementations were re-run afterwards to
confirm they were back on their SHA-NI path.

## Next

The remaining 5.3x against ring/aws-lc-rs is the missing hardware path, not
portable code quality. Next task: the x86_64 SHA-NI backend behind the
existing cached CPUID probe, verified against this portable path for every
length in 0..300 and for random inputs.
