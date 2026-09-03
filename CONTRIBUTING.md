# Contributing

## Rules of the road

1. **Correctness first.** Every primitive needs published known-answer vectors
   and differential tests against at least two independent implementations
   before any performance work on it starts.
2. **Measurements second.** No optimization without a recorded baseline.
3. **Optimization third.** If the benchmark does not improve, revert.
4. **Claims last.** No "faster than X" in code, comments, docs, or commit
   messages unless a recorded measurement in `benchmarks/results/` supports
   it for the specific CPU and size range.

## Quality gates

```sh
./scripts/check.sh          # fmt, check, clippy -D warnings, tests
cargo bench -p fastcrypto-bench --bench sha256
```

The gates are also run individually:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The pinned toolchain in `rust-toolchain.toml` is what CI uses. Bump it
deliberately and re-run the benchmarks: compiler changes move performance
numbers.

## Code expectations

* `fastcrypto-core`: `no_std`, no allocation, `forbid(unsafe_code)`,
  fixed-size arrays for fixed-size state.
* Backend crates: every `unsafe` block carries a SAFETY comment naming the
  invariant, and is gated behind the matching CPU feature check.
* Every public item has a doc comment (`missing_docs` is a warning, and
  warnings are errors in CI).
* No new dependencies in the library crates without a reason recorded in the PR
  description; competitor libraries stay in `fastcrypto-bench`.
* Suppress a lint only at the item that needs it, with a comment explaining
  why. Global suppression is not acceptable for the sake of a green build.
* Keep the hot path readable: if the generated assembly cannot be explained,
  the optimization is not understood yet.

## Commits

Logically scoped, one concern per commit, and the message states the evidence:
what changed, what the tests showed, and what the benchmark showed (numbers,
plus `cargo run --release --bin bench-env` context for anything
performance related).

## Tests to add with each change

* Known-answer vectors for anything standardized.
* Differential tests for anything an existing library also implements.
* Boundary tests: empty input, block-size boundaries (55/56/57/63/64/65),
  maximum output lengths.
* Property tests where a property exists (prefix stability of HKDF-Expand,
  chunking independence of hashes and MACs).
* Fuzz targets for parsers and for anything with adversarial input.

## Benchmarks

See `docs/BENCHMARKING.md`. Always attach
`cargo run --release --bin bench-env` output to a result, and label
cloud/virtualised results as iteration-only.

