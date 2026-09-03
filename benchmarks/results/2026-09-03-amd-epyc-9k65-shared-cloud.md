# Baseline measurements - 2026-09-03

**Machine class: shared cloud container (not a dedicated machine).** These
numbers are for iteration and for relative comparisons within a single run.
Absolute numbers must be re-measured on dedicated hardware before any claim of
"faster than X" is made (see `docs/BENCHMARKING.md`).

Harness: Criterion 0.8, warmup 500 ms, measurement 1500 ms, 60 samples, 95%
confidence interval, byte throughput annotation. Numbers below are the mean
point estimates in nanoseconds; MB/s is computed from the same estimate.

## Environment

```
           project: fastcrypto-rs 0.1.0
           backend: portable-rust
          hw accel: sha256-accelerated=true
              arch: x86_64
                os: linux Linux 5.4.241-1-tlinux4-0025.10
               cpu: AMD EPYC 9K65 192-Core Processor
         cpu cores: 8
       scaling gov: unknown
             rustc: rustc 1.98.0 (88d9e12ae 2026-08-18)
              llvm: LLVM version: 22.1.8
           profile: release (debug_assertions off)
   target features: fxsr sse sse2
         rustflags: <unset>
        target cpu: <unset>
     estimated mhz: 3690 (dependent-add estimate)
         criterion: 0.8 (wall clock, warmup + statistics)
```

Notes on this environment:

* The library is compiled with baseline x86_64 features (`fxsr sse sse2`), so
  any acceleration has to come from runtime dispatch - which is exactly the
  design being built.
* Our own CPUID probe reports `sha_ni=true aes_ni=true pclmulqdq=true avx2=true
  vaes=true vpclmulqdq=true avx512f=true` on this CPU, so a SHA-NI backend would
  be selected here.
* The container exposes neither `cpu MHz` nor `cpufreq`, so the clock was
  estimated with a dependent add chain (`bench-env` does this). Treat
  cycles/byte as +-10%.
* ring, aws-lc-rs **and** RustCrypto `sha2` 0.11 all dispatch to Intel SHA-NI at
  runtime on this CPU, which is why their SHA-256 numbers are clustered. The
  portable-only section at the end of the SHA-256 tables forces RustCrypto onto
  its soft backend for a like-for-like comparison.

## What is being measured

* **fastcrypto** = this repository, portable safe Rust, no SIMD (Milestone 1
  baseline).
* **ring**, **aws-lc-rs**, **rustcrypto**, **x25519-dalek** = established
  implementations, used as references only. They are dev-dependencies of the
  benchmark crate and never dependencies of the library.


## SHA-256

| size | fastcrypto | ring | rustcrypto-sha2 | aws-lc-rs |
|---|---|---|---|---|
| 0B | 282.4 ns | 79.2 ns | 58.3 ns | 61.5 ns |
| 16B | 283.9 ns (56 MB/s) | 77.8 ns (206 MB/s) | 59.2 ns (270 MB/s) | 61.5 ns (260 MB/s) |
| 32B | 289.7 ns (110 MB/s) | 79.0 ns (405 MB/s) | 57.5 ns (557 MB/s) | 61.7 ns (519 MB/s) |
| 64B | 494.8 ns (129 MB/s) | 87.6 ns (730 MB/s) | 81.2 ns (788 MB/s) | 79.2 ns (809 MB/s) |
| 128B | 714.5 ns (179 MB/s) | 123.7 ns (1034 MB/s) | 116.3 ns (1101 MB/s) | 114.8 ns (1115 MB/s) |
| 256B | 1163.7 ns (220 MB/s) | 194.3 ns (1318 MB/s) | 192.6 ns (1329 MB/s) | 182.6 ns (1402 MB/s) |
| 512B | 1999.0 ns (256 MB/s) | 334.6 ns (1530 MB/s) | 325.3 ns (1574 MB/s) | 324.8 ns (1576 MB/s) |
| 1KiB | 3717.4 ns (275 MB/s) | 618.5 ns (1656 MB/s) | 605.1 ns (1692 MB/s) | 603.5 ns (1697 MB/s) |
| 1350B | 4675.5 ns (289 MB/s) | 795.3 ns (1698 MB/s) | 783.7 ns (1723 MB/s) | 782.0 ns (1726 MB/s) |
| 1400B | 5032.5 ns (278 MB/s) | 834.5 ns (1678 MB/s) | 826.3 ns (1694 MB/s) | 826.9 ns (1693 MB/s) |
| 1500B | 5239.3 ns (286 MB/s) | 860.2 ns (1744 MB/s) | 854.6 ns (1755 MB/s) | 851.1 ns (1762 MB/s) |
| 4KiB | 14445.5 ns (284 MB/s) | 2299.5 ns (1781 MB/s) | 2338.5 ns (1752 MB/s) | 2280.8 ns (1796 MB/s) |
| 8KiB | 27340.2 ns (300 MB/s) | 4537.9 ns (1805 MB/s) | 4537.1 ns (1806 MB/s) | 4523.5 ns (1811 MB/s) |
| 16KiB | 55851.6 ns (293 MB/s) | 8995.4 ns (1821 MB/s) | 9001.7 ns (1820 MB/s) | 8994.9 ns (1821 MB/s) |
| 64KiB | 225941.5 ns (290 MB/s) | 35984.5 ns (1821 MB/s) | 35968.7 ns (1822 MB/s) | 35904.4 ns (1825 MB/s) |

Estimated clock 3690 MHz, so at 64 KiB this is about 12.7 cycles/byte for us
and 2.0 cycles/byte for the SHA-NI implementations.

### Portable-only comparison: SHA-256 one-shot

RustCrypto sha2 forced to its soft (portable) backend with
RUSTFLAGS carrying the sha2_backend=soft cfg, against our portable
implementation. This is the apples-to-apples number for the current code:
no SHA-NI on either side.

| size | fastcrypto (portable) | rustcrypto-sha2 (soft) | ratio |
|---|---|---|---|
| 0B | 277.3 ns | 176.9 ns | 1.57x slower |
| 16B | 279.8 ns | 186.1 ns | 1.50x slower |
| 32B | 277.8 ns | 189.1 ns | 1.47x slower |
| 64B | 495.4 ns | 299.2 ns | 1.66x slower |
| 128B | 701.6 ns | 605.0 ns | 1.16x slower |
| 256B | 1112.5 ns | 922.2 ns | 1.21x slower |
| 512B | 1921.9 ns | 1498.8 ns | 1.28x slower |
| 1KiB | 3785.3 ns | 2685.7 ns | 1.41x slower |
| 1350B | 4590.5 ns | 3534.4 ns | 1.30x slower |
| 1400B | 4942.5 ns | 3315.8 ns | 1.49x slower |
| 1500B | 5147.6 ns | 3519.1 ns | 1.46x slower |
| 4KiB | 13832.2 ns | 9519.9 ns | 1.45x slower |
| 8KiB | 28498.0 ns | 17630.8 ns | 1.62x slower |
| 16KiB | 53791.2 ns | 35340.5 ns | 1.52x slower |
| 64KiB | 218395.4 ns | 143229.3 ns | 1.52x slower |

At 64 KiB that is about 12.3 cycles/byte for us versus 8.1 for
RustCrypto soft, using the estimated 3690 MHz clock.

### SHA-256 streaming (64 KiB in 1 KiB updates)

| implementation | time |
|---|---|
| rustcrypto-sha2 | 36161.3 ns |
| ring | 36354.5 ns |
| aws-lc-rs | 36377.0 ns |
| fastcrypto | 215506.0 ns |

### SHA-256 construction cost

Ours includes zeroization on drop (volatile writes); see the analysis.

| implementation | time |
|---|---|
| rustcrypto-sha2 | 2.4 ns |
| fastcrypto | 19.8 ns |

## HKDF-SHA256

### Extract (32-byte salt, 32-byte IKM)

| implementation | time |
|---|---|
| aws-lc-rs | 55.6 ns |
| rustcrypto-hkdf | 267.1 ns |
| ring | 314.3 ns |
| fastcrypto | 1112.0 ns |

### Expand to 88 bytes (two keys and two IVs)

| implementation | time |
|---|---|
| rustcrypto-hkdf | 390.5 ns |
| ring | 490.8 ns |
| aws-lc-rs | 772.9 ns |
| fastcrypto | 3411.6 ns |

### Extract + expand to 88 bytes

| implementation | time |
|---|---|
| rustcrypto-hkdf | 649.3 ns |
| ring | 795.6 ns |
| aws-lc-rs | 864.7 ns |
| fastcrypto | 4346.1 ns |

### Four labels of 32 bytes from one PRK

| implementation | time |
|---|---|
| rustcrypto-hkdf | 489.3 ns |
| fastcrypto | 4373.3 ns |

## AEAD

### ChaCha20-Poly1305 seal, reused key

| size | ring | aws-lc-rs | rustcrypto |
|---|---|---|---|
| 0B | 222.8 ns | 225.6 ns | 983.6 ns |
| 16B | 244.3 ns (65 MB/s) | 244.6 ns (65 MB/s) | 1207.0 ns (13 MB/s) |
| 32B | 246.2 ns (130 MB/s) | 253.5 ns (126 MB/s) | 1516.9 ns (21 MB/s) |
| 64B | 256.3 ns (250 MB/s) | 265.7 ns (241 MB/s) | 1516.8 ns (42 MB/s) |
| 128B | 271.6 ns (471 MB/s) | 275.3 ns (465 MB/s) | 1678.3 ns (76 MB/s) |
| 256B | 306.8 ns (834 MB/s) | 312.9 ns (818 MB/s) | 1588.7 ns (161 MB/s) |
| 512B | 442.6 ns (1157 MB/s) | 448.6 ns (1141 MB/s) | 1813.3 ns (282 MB/s) |
| 1KiB | 703.3 ns (1456 MB/s) | 718.2 ns (1426 MB/s) | 2300.5 ns (445 MB/s) |
| 1350B | 884.5 ns (1526 MB/s) | 898.3 ns (1503 MB/s) | 2876.7 ns (469 MB/s) |
| 1400B | 936.6 ns (1495 MB/s) | 939.5 ns (1490 MB/s) | 2878.1 ns (486 MB/s) |
| 1500B | 958.8 ns (1564 MB/s) | 980.7 ns (1530 MB/s) | 3214.5 ns (467 MB/s) |
| 4KiB | 2263.6 ns (1809 MB/s) | 2305.4 ns (1777 MB/s) | 5130.8 ns (798 MB/s) |
| 8KiB | 4207.2 ns (1947 MB/s) | 4226.4 ns (1938 MB/s) | 9050.6 ns (905 MB/s) |
| 16KiB | 8009.6 ns (2046 MB/s) | 8263.1 ns (1983 MB/s) | 16909.5 ns (969 MB/s) |
| 64KiB | 31745.4 ns (2064 MB/s) | 31473.8 ns (2082 MB/s) | 65049.9 ns (1007 MB/s) |

### ChaCha20-Poly1305 open, reused key

| size | ring | aws-lc-rs | rustcrypto |
|---|---|---|---|
| 0B | 212.7 ns | 208.0 ns | 984.7 ns |
| 16B | 218.0 ns (73 MB/s) | 210.7 ns (76 MB/s) | 1163.0 ns (14 MB/s) |
| 32B | 223.2 ns (143 MB/s) | 215.5 ns (149 MB/s) | 1478.3 ns (22 MB/s) |
| 64B | 229.8 ns (279 MB/s) | 222.9 ns (287 MB/s) | 1397.5 ns (46 MB/s) |
| 128B | 247.8 ns (516 MB/s) | 240.5 ns (532 MB/s) | 1506.8 ns (85 MB/s) |
| 256B | 285.3 ns (897 MB/s) | 276.0 ns (928 MB/s) | 1473.5 ns (174 MB/s) |
| 512B | 443.4 ns (1155 MB/s) | 496.6 ns (1031 MB/s) | 1697.6 ns (302 MB/s) |
| 1KiB | 627.1 ns (1633 MB/s) | 624.8 ns (1639 MB/s) | 2250.2 ns (455 MB/s) |
| 1350B | 811.9 ns (1663 MB/s) | 804.0 ns (1679 MB/s) | 2772.2 ns (487 MB/s) |
| 1400B | 813.5 ns (1721 MB/s) | 803.6 ns (1742 MB/s) | 2820.5 ns (496 MB/s) |
| 1500B | 856.5 ns (1751 MB/s) | 847.2 ns (1771 MB/s) | 3057.5 ns (491 MB/s) |
| 4KiB | 1874.0 ns (2186 MB/s) | 1858.4 ns (2204 MB/s) | 4940.8 ns (829 MB/s) |
| 8KiB | 3629.0 ns (2257 MB/s) | 3509.2 ns (2334 MB/s) | 8704.4 ns (941 MB/s) |
| 16KiB | 6789.7 ns (2413 MB/s) | 6796.9 ns (2411 MB/s) | 16003.1 ns (1024 MB/s) |
| 64KiB | 26661.4 ns (2458 MB/s) | 26658.6 ns (2458 MB/s) | 60294.3 ns (1087 MB/s) |

### AES-128-GCM seal, reused key

| size | ring | aws-lc-rs | rustcrypto |
|---|---|---|---|
| 0B | 85.4 ns | 92.0 ns | 84.1 ns |
| 16B | 113.8 ns (141 MB/s) | 123.4 ns (130 MB/s) | 131.3 ns (122 MB/s) |
| 32B | 114.8 ns (279 MB/s) | 127.5 ns (251 MB/s) | 141.5 ns (226 MB/s) |
| 64B | 115.4 ns (554 MB/s) | 123.6 ns (518 MB/s) | 133.8 ns (478 MB/s) |
| 128B | 112.5 ns (1137 MB/s) | 121.1 ns (1057 MB/s) | 147.7 ns (867 MB/s) |
| 256B | 130.6 ns (1961 MB/s) | 143.0 ns (1790 MB/s) | 184.8 ns (1385 MB/s) |
| 512B | 166.6 ns (3073 MB/s) | 189.0 ns (2710 MB/s) | 281.1 ns (1822 MB/s) |
| 1KiB | 224.6 ns (4559 MB/s) | 223.5 ns (4581 MB/s) | 384.5 ns (2664 MB/s) |
| 1350B | 310.2 ns (4351 MB/s) | 246.8 ns (5469 MB/s) | 519.7 ns (2597 MB/s) |
| 1400B | 318.3 ns (4399 MB/s) | 270.7 ns (5173 MB/s) | 626.4 ns (2235 MB/s) |
| 1500B | 380.2 ns (3945 MB/s) | 311.1 ns (4821 MB/s) | 625.7 ns (2397 MB/s) |
| 4KiB | 626.5 ns (6538 MB/s) | 526.5 ns (7779 MB/s) | 1429.5 ns (2865 MB/s) |
| 8KiB | 1095.8 ns (7476 MB/s) | 855.4 ns (9577 MB/s) | 2791.8 ns (2934 MB/s) |
| 16KiB | 2136.0 ns (7670 MB/s) | 1288.3 ns (12718 MB/s) | 5034.3 ns (3255 MB/s) |
| 64KiB | 8151.7 ns (8040 MB/s) | 4634.2 ns (14142 MB/s) | 18515.0 ns (3540 MB/s) |

### ChaCha20-Poly1305 key setup

| implementation | time |
|---|---|
| rustcrypto | 0.8 ns |
| ring | 20.1 ns |
| aws-lc-rs | 29.3 ns |

### AES-128-GCM key setup

| implementation | time |
|---|---|
| rustcrypto | 96.0 ns |
| ring | 116.3 ns |
| aws-lc-rs | 120.9 ns |

### ChaCha20-Poly1305, seal an empty record

The fixed floor a TLS record pays regardless of payload size.

| implementation | time |
|---|---|
| ring | 222.2 ns |

## X25519

### Shared secret from fixed keys

| implementation | time |
|---|---|
| aws-lc-rs | 18742.7 ns |
| x25519-dalek | 42000.4 ns |

### Ephemeral key generation + agreement

Includes RNG cost; not comparable with the fixed-key group.

| implementation | time |
|---|---|
| x25519-dalek | 42529.1 ns |
| ring | 49900.2 ns |

## Analysis

### SHA-256: where we stand

| comparison | 64 KiB | 0 B |
| --- | --- | --- |
| ours vs SHA-NI (ring / aws-lc-rs / sha2) | 6.3x slower | 3.6x slower |
| ours vs RustCrypto portable (soft backend) | 1.5x slower | 1.6x slower |

So two separate gaps exist, and they need different work:

1. **Portable code quality: ~1.5x.** At 64 KiB our compression runs about
   12.3 cycles/byte against about 8.1 for RustCrypto's soft backend. Same
   instruction set, same compiler, no SIMD on either side. The likely cause is
   the 64-word message schedule materialised as a `[u32; 64]` array on the
   stack: it does not stay in registers and the round loop does not get the
   scheduling a 16-word circular buffer would. This is the first thing to
   profile and fix - it is portable work, no SIMD required.
2. **Missing hardware path: ~6x.** Every competitor here uses SHA-NI. The
   feature probe already reports SHA-NI as available, so the backend is
   unblocked; it is Milestone 2's second task.

### Small messages are where the fixed cost shows

Our 0-byte digest costs about 282 ns, of which roughly 220 ns is a single
64-byte compression (the rest is construction, padding and zeroization). A
SHA-NI implementation pays about 58 ns. For TLS handshake transcripts this
fixed cost is the dominant term, so it is the number to attack after the
schedule.

Construction itself costs 19.8 ns for us and 2.4 ns for RustCrypto: our
`Sha256` zeroizes on drop, which is 9 words plus a 64-byte block of volatile
writes. That is a deliberate security trade-off, not an accident, and it is
recorded here so it can be revisited with numbers rather than vibes.

### HKDF-SHA256

Our HKDF inherits the SHA-256 gap: extract+expand to 88 bytes (one TLS 1.3
traffic secret derivation) is 4346 ns against 650 ns for RustCrypto and 796 ns
for ring. Because HKDF-Expand is a chain of HMACs, and HMAC is two extra
SHA-256 compressions per block, the HKDF numbers should improve linearly with
the hash. This is the primitive to re-measure immediately after any SHA-256
change.

The `four-labels` group is the one that matters for a full TLS 1.3 key
schedule (several labels expanded from one PRK); it is where reusing the
prepared HMAC key state should pay off later.

### AEAD baselines (references only, not yet implemented by us)

* ChaCha20-Poly1305: ring and aws-lc-rs are effectively tied across the whole
  size ladder; RustCrypto is roughly 2x slower here because its in-place API and
  portable Poly1305 differ. Small records (0-64 B) cost about 220-310 ns for
  ring/aws-lc-rs - dominated by fixed per-record work, not by the payload.
* AES-128-GCM: ring is fastest at every size (85 ns for an empty record,
  8.2 us for 64 KiB); aws-lc-rs is ahead of ring at 64 KiB (4.6 us vs 8.2 us),
  which suggests different vectorisation strategies above L2.
* Key setup is not free: ChaCha20-Poly1305 setup is 20 ns (ring) to 29 ns
  (aws-lc-rs); AES-128-GCM setup is 92-121 ns for every implementation. A
  connection that rotates keys or handles many short connections pays this.

### X25519 baselines (references only)

Fixed-key shared secret: aws-lc-rs 18.7 us, x25519-dalek 42.0 us. The
ephemeral group (key generation plus agreement) costs 49.9 us for ring and
42.5 us for x25519-dalek; it includes RNG cost and is reported separately on
purpose.

### Conclusion for this milestone

The laboratory works and produced the first honest baseline. Our portable
SHA-256 is correct (KAT plus three-way differential) and it is 1.5x off a good
portable implementation and 6.3x off SHA-NI. No performance claim is made, and
none should be made until Milestone 2 changes those numbers.


## Appendix: instruction counts (iai-callgrind)

Wall-clock timing on a shared container cannot resolve small changes, so the lab
also counts instructions under Valgrind Callgrind. Same code, same inputs, no
clock involved.

Command (this container blocks `setarch`, so ASLR stays on):

```sh
IAI_CALLGRIND_ALLOW_ASLR=true cargo bench -p fastcrypto-bench --bench micro
```

| benchmark | size | instructions | approx instructions/byte |
|---|---|---|---|
| fastcrypto | 0 B | 5,415 | - |
| ring | 0 B | 2,895 | - |
| rustcrypto-sha2 (SHA-NI) | 0 B | 3,761 | - |
| fastcrypto | 64 B | 10,127 | - |
| ring | 64 B | 5,663 | - |
| rustcrypto-sha2 (SHA-NI) | 64 B | 7,775 | - |
| fastcrypto | 1500 B | 110,423 | ~70 |
| ring | 1500 B | 62,926 | ~40 |
| rustcrypto-sha2 (SHA-NI) | 1500 B | 92,170 | ~59 |
| fastcrypto | 8192 B | 594,063 | ~71 |
| ring | 8192 B | 341,396 | ~40 |
| rustcrypto-sha2 (SHA-NI) | 8192 B | 500,226 | ~59 |

Caveat: each benchmark regenerates its input inside the measured function, so a
constant per-size allocation and fill (about 15k instructions at 8192 bytes) is
included for every implementation. Comparisons between implementations are
still valid; absolute per-byte numbers are a couple of instructions high.

Reading: we execute about 1.7x more instructions than ring for the same hash,
but we take about 6x longer. So the gap is not only instruction count - the
portable loop is also executing its instructions badly (dependency chains and
spilling around the 64-word schedule array). Both have to be fixed: fewer
instructions and a schedule that stays in registers, then the SHA-NI path.
