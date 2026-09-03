# Benchmarking

## Principle

A number without the machine that produced it is noise, and a number produced
once is an anecdote. Every result file in ``benchmarks/results/`` must contain
the environment report and must state whether the machine was dedicated or
shared.

## Tooling

* **Criterion** (wall clock, statistical) is the primary harness: warmup,
  outlier-robust estimates, HTML reports under `target/criterion/`.
* **iai-callgrind** (instruction counts under Valgrind) is available for
  deterministic, frequency-independent comparisons of small kernels.
* Divan was considered; Criterion plus iai-callgrind covers timing and
  instruction counts with one less dependency.

## Running

```sh
# 1. record the environment (mandatory before recording results)
cargo run --release --bin bench-env

# 2. run one group
cargo bench -p fastcrypto-bench --bench sha256

# 3. run everything
cargo bench -p fastcrypto-bench

# 4. deterministic instruction counts (needs valgrind; slow)
cargo bench -p fastcrypto-bench --bench micro

# in containers that block setarch/personality, keep ASLR on:
IAI_CALLGRIND_ALLOW_ASLR=true cargo bench -p fastcrypto-bench --bench micro
```

Useful filters:

```sh
cargo bench -p fastcrypto-bench --bench sha256 -- 'sha256/oneshot/64B'
cargo bench -p fastcrypto-bench --bench aead -- 'chacha20-poly1305/seal/reused-key/1500B'
cargo bench -p fastcrypto-bench -- --quick            # fast sanity run
cargo bench -p fastcrypto-bench -- --sample-size 200  # longer run
```

## Methodology rules encoded in the harness

1. **Identical inputs.** `common::message(len)` and `common::key(len)` are
   deterministic (xorshift64*), so every implementation under test hashes the
   same bytes.
2. **Setup outside the timed section.** AEAD benchmarks use
   `iter_batched` with a `clone()` setup, so buffer preparation is not
   measured; only the cryptographic operation is.
3. **Results cannot be optimised away.** Every result goes through
   `std::hint::black_box`.
4. **Warmup and steady state.** 500 ms warmup, 1500 ms measurement, 60 samples,
   95% confidence interval, 3% noise threshold (raised failure instead of
   hidden regression).
5. **Small messages matter.** Every group runs the full TLS ladder
   (0, 16, 32, 64, 128, 256, 512, 1 KiB, 1350, 1400, 1500, 4 KiB, 8 KiB,
   16 KiB, 64 KiB). 0-byte and sub-1 KiB cases are first-class results, not
   warmup.
6. **Throughput and latency.** Each group is annotated with
   `Throughput::Bytes` so Criterion reports both ns/op and MB/s.

## Competitors

| Primitive | Competitors in the harness | Notes |
| --- | --- | --- |
| SHA-256 | RustCrypto `sha2`, ring, aws-lc-rs | one-shot and streaming |
| HKDF-SHA256 | RustCrypto `hkdf`, ring, aws-lc-rs | extract, expand, full, multi-label |
| ChaCha20-Poly1305 | RustCrypto, ring, aws-lc-rs | seal/open, reused key and key init |
| AES-128-GCM | RustCrypto, ring, aws-lc-rs | seal, reused key and key init |
| X25519 | x25519-dalek, aws-lc-rs, ring | fixed-key and ephemeral groups |

ring is excluded from the *fixed-key* X25519 group: ring 0.17 offers no raw
X25519 private-key import, so it can only be measured on the ephemeral path,
which includes RNG cost and is reported separately rather than mixed in.

## Recording a result

```sh
cargo run --release --bin bench-env > `benchmarks/results/`2026-09-03-amd-epyc-9k65.md
cargo bench -p fastcrypto-bench 2>&1 | tee -a /tmp/bench.log
```

Then fill in the markdown table with the estimates from
`target/criterion/**/new/estimates.json` (fields: `mean.point_estimate`
and `mean.confidence_interval`). Keep the raw log or the criterion directory
if the numbers will be quoted later.

## Interpreting results

* **Cloud and shared machines are for iteration only.** Frequency scaling,
  noisy neighbours, and virtualised CPUID make absolute numbers
  non-reproducible. Use them to find relative regressions between two runs on
  the same session.
* **Final claims require a dedicated machine**: fixed frequency (performance
  governor), no other load, repeated runs, and the environment report attached.
* Compare *within one run* first: the interesting quantity is
  `ours / best-competitor` per size, not the absolute nanoseconds.
* Watch the small sizes separately. A change that improves 64 KiB by 20% and
  slows 64 B by 5% is usually a bad trade for TLS.

## Regression workflow

```
baseline -> profile -> identify hotspot -> change -> tests -> benchmark
   ^                                                            |
   +------------------- keep or revert -------------------------+
```

An optimization is kept only if (a) every correctness test still passes and
(b) the benchmark shows an improvement at the sizes that matter for the target
workload. Otherwise it is reverted, and the revert is recorded.

