# Fuzz targets

Differential fuzzing with cargo-fuzz (libFuzzer). Separate workspace: it is
excluded from the main build and can never become a dependency of the library.

## Requirements

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running

```sh
cd fuzz
cargo +nightly fuzz run sha256 -- -runs=1000000 -max_len=4096
cargo +nightly fuzz run hkdf_sha256 -- -runs=200000 -max_len=512

# corpus and crash artefacts live under fuzz/artifacts and fuzz/corpus
cargo +nightly fuzz list
```

## Targets

| Target | Property checked |
| --- | --- |
| `sha256` | digest equals RustCrypto `sha2`; chunking independent; `finalize` is non-destructive |
| `hkdf_sha256` | output equals RustCrypto `hkdf`; accept/reject behaviour matches at the 255-block limit; HKDF-Expand prefix stability |

A crash in these targets means either a real bug in our implementation or a
disagreement with the reference; both are bugs until proven otherwise. Every
crash should end up as a regression test in
`crates/fastcrypto-bench/tests/differential.rs`.

Artifacts are not committed.

